"""网络授权 —— 契约 §6「授权判定顺序」的实现。

## 唯一入口原则

**所有网络资源操作必须且只能调用 :func:`authorize`。** 禁止各路由自己写
``if role == "owner"``：只在列表接口过滤、详情接口能猜 ID 直取，就是典型 IDOR
（契约 §8.3 的警告）。

## 判定顺序（契约 §6）

```text
1-4. 已认证 / 会话有效 / 激活租户 / 租户成员   ← 由 get_auth_context 保证
5.   网络存在且属于当前租户                    → 否则 404
6.   网络状态允许该动作                        → 否则 409（或 404，见下）
7.   是网络的 active 成员                      → 否则 404
8.   角色拥有该 permission                     → 否则 403
9-11. 资源归属 / publication / 配额            ← Step 5
```

**为什么 5 和 7 是 404 而不是 403**：403 等于确认"这个网络确实存在"。
同租户但非成员、跨租户，都必须表现为「不存在」（契约 §4）。
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.auth.context import AuthContext
from core.auth.permissions import NETWORK_ARCHIVE, has_permission, is_read_permission
from core.db.base import utcnow
from core.db.models import (
    NETWORK_ACTIVE,
    NETWORK_ARCHIVED,
    NETWORK_MEMBERSHIP_ACTIVE,
    NETWORK_ROLE_ADMIN,
    NETWORK_ROLE_OWNER,
    Network,
    NetworkMembership,
)
from core.errors import ConflictError, ForbiddenError, NotFoundError

#: 状态管理操作本身**不受状态门禁约束**。
#:
#: 否则会出现一个死锁：网络 archived 后所有非只读权限都被 409 拒绝，而
#: 「恢复归档」恰恰需要 ``network.archive`` 权限 —— 于是永远恢复不了。
#: 状态迁移的合法性由 ``core/network/service.py`` 的迁移表把关。
_STATUS_EXEMPT_PERMISSIONS = frozenset({NETWORK_ARCHIVE})


async def get_network(session: AsyncSession, network_id: uuid.UUID) -> Network | None:
    return await session.get(Network, network_id)


async def lock_network(session: AsyncSession, network_id: uuid.UUID) -> Network | None:
    """对 ``network`` 行加**排他锁**，把成员变更串行化。

    ## 为什么必须有这把锁

    「最后一位 Owner 不可被移除」是一个典型的 **check-then-act** 竞态：

    ```text
    T1: SELECT count(owner) -> 2   ✓
    T2: SELECT count(owner) -> 2   ✓     ← 两边都读到 2
    T1: UPDATE 移除 Bob  → 1
    T2: UPDATE 移除 Alice → 0           ← 网络变成无主孤儿
    ```

    在 SQLite 上**永远看不到**这个竞态：库级写锁让 T2 根本进不来。这就是为什么
    ADR-08-02 要求并发用例必须在 PostgreSQL 上复验 —— 实测确实复现了
    （``tests/integration/test_network_concurrency.py``）。

    ## 方言行为

    - PostgreSQL：``SELECT … FOR UPDATE`` 让第二个事务排队，等到 T1 提交后重读；
    - SQLite：方言不支持，SQLAlchemy 会**忽略**该子句 —— 但 SQLite 本来就是
      库级写锁，行为等价。

    ## 只用于写路径

    读接口（``GET /networks/{id}`` 等）**不要**加锁 —— 那会把只读请求也串行化，
    毫无必要地牺牲并发。
    """
    result = await session.execute(
        select(Network)
        .where(Network.id == network_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    return result.scalar_one_or_none()


async def get_active_membership(
    session: AsyncSession, *, network_id: uuid.UUID, user_id: uuid.UUID
) -> NetworkMembership | None:
    """取用户的 **active** 网络成员关系；已移除的返回 ``None``。"""
    result = await session.execute(
        select(NetworkMembership).where(
            NetworkMembership.network_id == network_id,
            NetworkMembership.user_id == user_id,
            NetworkMembership.status == NETWORK_MEMBERSHIP_ACTIVE,
        )
    )
    return result.scalar_one_or_none()


async def get_membership(
    session: AsyncSession, *, network_id: uuid.UUID, user_id: uuid.UUID
) -> NetworkMembership | None:
    """取成员关系**不论状态**（含已被移除的），供成员管理场景使用。"""
    result = await session.execute(
        select(NetworkMembership).where(
            NetworkMembership.network_id == network_id,
            NetworkMembership.user_id == user_id,
        )
    )
    return result.scalar_one_or_none()


async def resolve_network_role(
    session: AsyncSession, *, network_id: uuid.UUID, user_id: uuid.UUID
) -> str | None:
    """返回用户在该网络中的角色；非 active 成员返回 ``None``（契约 §1.3）。"""
    membership = await get_active_membership(
        session, network_id=network_id, user_id=user_id
    )
    return membership.role if membership else None


async def authorize(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    permission: str,
    network_id: uuid.UUID,
) -> Network:
    """判定通过则返回 :class:`Network`；否则抛领域异常（映射为 404/403/409）。

    调用方拿到返回值后可以安全地认为：网络存在、属于当前租户、状态允许该动作、
    调用者是 active 成员、且其角色拥有该权限。
    """
    user_id = uuid.UUID(ctx.user_id)
    tenant_id = uuid.UUID(ctx.tenant_id)

    # ── 5. 网络存在且属于当前租户 ──
    network = await get_network(session, network_id)
    if network is None or network.tenant_id != tenant_id:
        raise NotFoundError("网络不存在")

    # ── 7. 是 active 成员（先取角色，第 6 步的归档读规则需要它）──
    membership = await get_active_membership(
        session, network_id=network_id, user_id=user_id
    )
    if membership is None:
        raise NotFoundError("网络不存在")

    role = membership.role

    # ── 6. 网络状态允许该动作 ──
    #
    # suspended：读可以（便于排查问题），写/调用一律 409；
    # archived ：读也只对 owner/admin 开放（其余视作不存在），写/调用一律 409。
    #            但**状态管理操作本身例外**（否则归档后永远无法恢复，见上）。
    #
    # 用 409 而不是 403：状态是**暂时性**冲突，前端应提示"网络已暂停/归档"，
    # 而不是"权限不足" —— 后者会让人跑去改角色。
    if network.status != NETWORK_ACTIVE and permission not in _STATUS_EXEMPT_PERMISSIONS:
        if is_read_permission(permission):
            if network.status == NETWORK_ARCHIVED and role not in (
                NETWORK_ROLE_OWNER,
                NETWORK_ROLE_ADMIN,
            ):
                raise NotFoundError("网络不存在")
        else:
            raise ConflictError(f"网络当前状态为「{network.status}」，无法执行该操作")

    # ── 8. 角色拥有权限 ──
    if not has_permission(role, permission, policy=network.policy):
        raise ForbiddenError("权限不足")

    return network


async def count_active_owners(session: AsyncSession, *, network_id: uuid.UUID) -> int:
    """统计网络当前的 active Owner 数量 —— "最后一位 Owner"守卫的依据。

    ⚠️ 必须与角色变更在**同一事务内**调用，否则并发下会读到过期数字。
    SQLite 上没有行级锁，这个守卫依赖"事务内重新统计 + version 条件更新"，
    **并发用例必须在 PostgreSQL 上复验**（ADR-08-02）。
    """
    from sqlalchemy import func

    result = await session.execute(
        select(func.count())
        .select_from(NetworkMembership)
        .where(
            NetworkMembership.network_id == network_id,
            NetworkMembership.role == NETWORK_ROLE_OWNER,
            NetworkMembership.status == NETWORK_MEMBERSHIP_ACTIVE,
        )
    )
    return int(result.scalar_one())


def bump_version(membership: NetworkMembership) -> int:
    """返回条件更新时使用的期望 version，并把本地对象推进一版。

    调用方用 ``expected`` 做 ``UPDATE ... WHERE version = expected``；
    影响 0 行即并发冲突。
    """
    expected = membership.version
    membership.version = expected + 1
    return expected


def touch(membership: NetworkMembership) -> None:
    """更新 ``gmt_modified``（无外键方案下删除/改角色都靠应用层显式维护）。"""
    membership.gmt_modified = utcnow()


__all__ = [
    "authorize",
    "bump_version",
    "count_active_owners",
    "get_active_membership",
    "get_membership",
    "get_network",
    "lock_network",
    "resolve_network_role",
    "touch",
]
