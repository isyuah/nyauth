# Nyauth 双实例部署

Nyauth 的高可用形态是多个无状态应用实例共享外部 PostgreSQL 和 Redis。内置 Compose 数据容器只用于开发和小规模单机部署。

仓库中的 `docker-compose.ha.yml` 是双实例部署物，只包含一次性 `migrate`、`nyauth-a` 和 `nyauth-b`。它不创建 PostgreSQL/Redis 容器，不发布应用或数据端口；两个应用仅通过外部 proxy network 接收反向代理流量。

## 依赖要求

- PostgreSQL 提供高可用、备份、PITR 和连接上限管理。
- PostgreSQL 平台预先创建相互独立的迁移登录角色和 runtime 登录角色；迁移角色拥有目标数据库与应用 schema，runtime 角色不得拥有 superuser、createdb、createrole 或 schema CREATE 权限。
- Redis 使用认证、TLS、`noeviction` 和故障转移能力。
- 所有应用实例使用同一 issuer、master key、Cookie 配置和可信代理 CIDR。
- 反向代理只向 `/readyz` 返回成功的实例发送流量。
- 迁移由独立一次性任务执行，应用启动不隐式修改 schema。

## Compose 前置条件

外部 PostgreSQL 和 Redis 必须可从同一个 backend network 访问，反向代理必须加入 proxy network。两个网络都由平台预先创建并交给 Compose 引用，Compose 不负责创建或删除它们。

必须配置：

- `NYAUTH_IMAGE`：使用不可变镜像 digest。
- `NYAUTH_DATABASE_DSN_FILE`：仅含运行账号 DSN 的文件。
- `NYAUTH_DATABASE_MIGRATION_DSN_FILE`：仅含迁移账号 DSN 的文件。
- `NYAUTH_DATABASE_RUNTIME_ROLE`：运行账号角色名，默认 `nyauth_runtime`，必须与运行 DSN 中的 PostgreSQL `current_user` 完全一致。
- `NYAUTH_REDIS_ADDR` 和 `NYAUTH_REDIS_PASSWORD_FILE`：外部 Redis 地址与密码文件。
- `NYAUTH_AUTH_MASTER_KEY_FILE`：所有实例共享的 Base64 32 字节 master key。
- `NYAUTH_AUTH_ISSUER` 和 `NYAUTH_TRUSTED_PROXY_CIDRS`：公开 HTTPS issuer 与准确的反向代理 CIDR。
- `NYAUTH_BACKEND_NETWORK` 和 `NYAUTH_PROXY_NETWORK`：预置 Docker network 名称。

Redis TLS 默认启用。使用公共 CA 时无需额外文件；使用私有 CA 时，通过部署环境的 Compose override 将只读 CA 文件挂入两个应用和迁移容器，并设置 `NYAUTH_REDIS_TLS_ROOT_CA_FILE`。只有依赖网络已经提供等效的加密隔离时，才应显式设置 `NYAUTH_REDIS_TLS_ENABLED=false`。

外部 PostgreSQL 不会由 Compose 创建登录角色。DBA 至少要在目标数据库中先执行等价操作，并将密码只写入运行 DSN secret：

```sql
CREATE ROLE nyauth_runtime LOGIN PASSWORD '<secret>'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
```

迁移角色必须拥有目标数据库和应用 schema，或具备向 runtime 角色授予 `CONNECT`、schema `USAGE`、现有对象权限及 default privileges 的 grant option。runtime 角色不得属于任何其他 PostgreSQL 角色，以免通过 `SET ROLE` 绕过权限边界。`nyauth migrate` 在 schema 成功建立后原子授予业务表 DML、sequence、function 和 type 权限，并把 `schema_migrations` 收紧为只读；runtime 角色不存在、存在角色成员关系或迁移角色无权授权时，迁移任务会失败。生产 `serve` 启动还会验证 `current_user` 等于 `NYAUTH_DATABASE_RUNTIME_ROLE`，并拒绝高权限属性、角色成员关系、应用 schema `CREATE` 权限及 `schema_migrations` 写权限。

展开配置不会连接依赖，也不会启动容器：

```bash
docker compose -f docker-compose.ha.yml config --quiet
```

首次启动或破坏性版本切换时，先停止所有旧版本实例，再启动新栈。`migrate` 成功退出后，Compose 才会启动两个应用：

```bash
docker compose -f docker-compose.ha.yml up -d
docker compose -f docker-compose.ha.yml ps
```

反向代理 upstream 使用 `nyauth-a:8080` 和 `nyauth-b:8080`，只把 `/readyz` 成功的实例纳入流量。不要从宿主机发布 `8080`，也不需要粘性会话。

## 一致性模型

- Session、授权码和 Token 安全状态由共享 Redis 保证。
- JWK 轮换由 PostgreSQL advisory lock 保证单写者。
- Provider 变更通过 PostgreSQL `LISTEN/NOTIFY` 通知，并使用周期 reconciliation 修复丢失通知。
- 管理员高风险变更与审计记录必须在同一数据库事务中完成。
- 审计日志按 UTC 月分区；分区预创建和保留清理由独立迁移账号运行 `nyauth maintenance`，应用实例不执行 DDL。

## 发布顺序

当前开发版本不承诺滚动升级兼容。部署新破坏性基线时应停止旧实例、运行一次性迁移、启动单个新实例完成 smoke test，再扩容第二实例。不得让不同数据库契约的应用版本同时处理流量。

## 故障验证

每次高可用发布至少验证：

- 任一应用实例终止后已有会话可通过另一实例继续使用。
- 同一授权码并发交换只有一个成功。
- 同一 refresh token 并发轮换只有一个成功，重复使用撤销整个 family。
- Provider 启停、删除和 JWK 轮换在所有实例收敛。
- 用户暂停、密码重置和会话撤销在所有实例立即生效。

CI 的真实 PostgreSQL/Redis 集成测试使用两个独立 HTTP Server、连接池和 Redis client，覆盖 Cookie 跨实例使用、用户暂停后的跨实例失效，以及通过 `/token` 并发交换同一授权码时只有一个请求成功。组件级测试继续覆盖 Provider 通知与 reconciliation、JWK advisory lock 和 Refresh family 并发轮换。完整部署仍应在目标反向代理和托管依赖上重复上述故障验证。
