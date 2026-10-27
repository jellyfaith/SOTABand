"""Pytest 全局配置与夹具。

## 测试数据库隔离

每个 pytest 进程用一个**独立的临时 SQLite 文件**，绝不碰 ``storage/sotaband.db``。

⚠️ 设置 ``DATABASE_URL`` 必须发生在 **导入 config.settings 之前**：
``config.settings`` 在导入时就实例化 ``Settings()``，而 ``StorageConfig.database_url``
是通过 ``os.getenv`` 在实例化那一刻求值的 —— 导入完成后再改环境变量不会生效。

``config.settings._load_dotenv()`` 只填充「尚未存在于 os.environ」的键，所以这里
预先设置的 ``DATABASE_URL`` 优先于 ``.env`` 文件中的值。

本文件因此**不能**按常规把 import 全部提到文件顶部：下面那几行 import 必须排在
设置环境变量的语句之后。
"""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

# ── 必须在任何 core/ config 导入之前完成 ──────────────────────────────
#
# 默认用**临时目录里的 SQLite**（零依赖、快）。
# 若要跑 PostgreSQL 并发验证，用环境变量显式指定：
#
#   $env:SOTABAND_TEST_DATABASE_URL='postgresql+asyncpg://sotaband:sotaband@localhost:55432/sotaband_test'
#   python -m pytest tests/integration/test_network_concurrency.py -v
#
# 注意驱动必须是 asyncpg（psycopg 的 async 模式与 Windows 的 ProactorEventLoop
# 不兼容，而 Agent 子进程又必须 Proactor —— 详见 pyproject.toml 的注释）。
_EXPLICIT_TEST_DB = os.environ.get("SOTABAND_TEST_DATABASE_URL", "").strip()

_TEST_DB_DIR = Path(tempfile.mkdtemp(prefix="sotaband-test-")).resolve()
if _EXPLICIT_TEST_DB:
    os.environ["DATABASE_URL"] = _EXPLICIT_TEST_DB
else:
    os.environ["DATABASE_URL"] = (
        f"sqlite+aiosqlite:///{(_TEST_DB_DIR / 'test.db').as_posix()}"
    )
atexit.register(shutil.rmtree, _TEST_DB_DIR, True)

# bcrypt work factor 12 每次约 250ms，测试里几十次哈希会把整个套件拖到十几秒。
# 降到 4（测试不验证哈希强度，只验证"哈希 → 校验"的往返正确性）。
os.environ["SOTABAND_BCRYPT_ROUNDS"] = "4"
# 测试走 http，Cookie 不能带 Secure，否则客户端不会回传
os.environ["SOTABAND_COOKIE_SECURE"] = "0"

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

import core.db.models  # noqa: F401  确保 Base.metadata 里注册了全部表
from core.db.base import Base
from core.db.session import dispose_engine, get_engine, get_sessionmaker


@pytest.fixture
def test_config():
    """Provide a test configuration."""
    return {
        "storage": {"backend": "memory"},
        "scheduler": {"default": "cpu"},
    }


def _assert_test_database_is_isolated() -> None:
    """安全阀：确认当前连的确实是**测试库**，不是开发库。

    ``db_session`` 夹具会执行 ``drop_all``。如果 ``DATABASE_URL`` 因任何原因没生效
    （比如导入顺序被人改回"标准"写法），``drop_all`` 就会作用在**开发库**上。
    与其依赖"改动时小心"，不如让它在这里硬失败。

    两种合法情形：

    1. 默认：SQLite 临时目录里的库 —— 校验路径确实在 ``_TEST_DB_DIR`` 下；
    2. 显式指定（如 PostgreSQL 并发复验）：要求库名里含 ``test``。
       这一条是刻意保守的 —— 宁可要求"库名带 test"这种命名约定，也不给
       "误连到生产库然后 drop_all"留任何口子。
    """
    from config.settings import settings
    from core.db.session import resolve_database_url

    url = resolve_database_url(settings.storage.database_url)

    if _EXPLICIT_TEST_DB:
        if "test" not in url.lower():
            pytest.fail(
                "显式指定的测试库名必须包含 'test'，拒绝执行 drop_all。\n"
                f"  实际指向：{url}"
            )
        return

    db_file = Path(url.split("///", 1)[-1])
    if not db_file.is_relative_to(_TEST_DB_DIR):
        pytest.fail(
            "测试数据库不在临时目录，拒绝执行 drop_all 以免破坏开发库。\n"
            f"  期望位于：{_TEST_DB_DIR}\n"
            f"  实际指向：{db_file}\n"
            "  原因通常是 DATABASE_URL 未在导入 config.settings 之前设置。"
        )


@pytest_asyncio.fixture
async def db_session() -> AsyncIterator[AsyncSession]:
    """每个测试一个干净的表结构。

    用 ``Base.metadata.create_all`` 而不是跑 Alembic 迁移，理由有两点：

    1. **事件循环冲突** —— Alembic 的 ``command.upgrade()`` 在 async env.py 下会调用
       ``asyncio.run()``，在 pytest-asyncio 已经运行的事件循环里必然失败；
    2. 迁移与模型是否一致由 ``alembic check`` 单独把关（见
       ``docs/design-08-schema.md`` §6），不需要每个测试都重放一次迁移。
    """
    _assert_test_database_is_isolated()

    engine = get_engine()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    factory = get_sessionmaker()
    async with factory() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    # 释放连接池。
    #
    # pytest-asyncio 是**函数级事件循环**：每个测试一个新 loop。而连接池里的连接
    # 绑定在创建它的那个 loop 上 —— 不释放的话，下一个测试会拿到属于已关闭 loop
    # 的连接，报 "RuntimeError: Event loop is closed"（asyncpg 尤其明显，
    # ai sqlite 因为跑在线程里症状较轻）。
    await dispose_engine()


@pytest.fixture(autouse=True)
def _reset_limiters() -> Iterator[None]:
    """每个测试重置进程内限流状态。

    限流器是进程级单例（设计如此，见 ``core/auth/ratelimit.py``）。若不重置，
    前一个测试的失败计数会串到下一个测试，导致"偶尔 429"的诡异失败。
    """
    from core.auth.ratelimit import reset_all_limiters

    reset_all_limiters()
    yield
    reset_all_limiters()


@pytest_asyncio.fixture
async def api_client(db_session: AsyncSession) -> AsyncIterator[AsyncClient]:
    """带认证 Cookie 保持的 ASGI 测试客户端。

    两个关键点：

    1. **覆盖 ``get_db_session``** —— 让路由复用 ``db_session`` 那个事务，从而共享
       同一份已建表的数据库，不必额外建连接；
    2. **不触发 lifespan** —— httpx 的 ``ASGITransport`` 默认不跑 lifespan，所以
       不会在测试里拉起 Agent 子进程（那会极慢且不稳定）。
    """
    from httpx import ASGITransport, AsyncClient

    from app.main import app
    from core.db.session import get_db_session

    async def _override_session() -> AsyncIterator[AsyncSession]:
        yield db_session

    app.dependency_overrides[get_db_session] = _override_session
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            yield client
    finally:
        app.dependency_overrides.clear()
