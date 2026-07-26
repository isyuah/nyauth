# nyauth 0.3.0-dev

统一认证与用户系统，提供 OAuth 2.0 Authorization Server、OpenID Connect Provider 和第一方管理后台。

## 0.3.0 破坏性基线说明

`0.3.0` 是全新的破坏性开发基线，不提供旧数据库、配置、接口或 SDK 的兼容层：

- 第一方后台仅使用 `HttpOnly + SameSite=Lax` 会话 Cookie，并对修改请求强制校验 CSRF。
- OAuth 授权码客户端强制使用 PKCE S256；不支持 plain、implicit 或 hybrid 流程。
- JWT 固定使用 RS256，refresh token 采用 family 轮换与重复使用检测。
- 数据库迁移压缩为嵌入二进制的单一 `000001` 基线，服务启动只校验 schema，不再隐式迁移。
- 旧数据库、session、token、JWK、Provider 凭据和 OAuth 客户端注册均不兼容。
- 旧 Go/TypeScript SDK 已删除；OAuth/OIDC 集成以标准协议和成熟语言库为准。

> [!CAUTION]
> 升级前请备份需要保留的数据。旧 PostgreSQL/Redis volume 必须在运维人员核对环境、备份和准确 volume 名称并明确批准后，才可人工删除重建。应用和迁移命令不会自动删除 volume，也不要在未经确认时执行 `docker compose down -v`。

重建后需要重新注册 OAuth 客户端和外部 Provider。首次启动只会在空用户库中创建管理员；该管理员必须在首次登录后修改密码。

## 功能

- OAuth 2.0：Authorization Code + S256、Client Credentials、Refresh Token
- OpenID Connect：Discovery、JWKS、ID Token、UserInfo、RP-Initiated Logout
- 控制面认证：HttpOnly 会话、CSRF、强制首次改密、会话与令牌即时失效
- 外部身份：GitHub、Google、通用 HTTPS OIDC Provider；不按邮箱自动合并账户
- 管理后台：用户、客户端、Provider、审计与统计
- 账户安全中心：设备会话、OAuth 授权、近期重新认证、邮箱验证与密码恢复
- 运维：严格 readiness、JSON 日志、内部 Prometheus、可选 OTLP 与审计 outbox
- 集成方式：标准 OAuth/OIDC Discovery、成熟语言库与 BFF 会话模式

## 本地开发

### 前置要求

- Go 1.26.5+
- PostgreSQL 16+
- Redis 7+
- Node.js 20+

### 使用本机服务

```bash
cp config.example.yaml config.yaml
# 编辑 config.yaml 中的数据库、Redis 和开发配置

go run ./cmd/nyauth migrate -config config.yaml
go run ./cmd/nyauth serve -config config.yaml

# 建议由迁移账号按月执行；migrate 也会执行同一维护步骤
go run ./cmd/nyauth maintenance -config config.yaml
```

迁移命令使用数据库锁；多个实例同时执行时只有一个实例应用迁移。`migrate` 和 `maintenance` 使用迁移账号预创建审计月分区、应用 `audit.retention` 并清理已投递的旧 outbox；`serve` 不执行 DDL，不会修改 schema，数据库未迁移或版本不匹配时会拒绝启动。

配置文件采用严格解码，未知字段（包括已删除的旧 `providers` 配置）会直接导致启动失败。环境变量统一使用 `NYAUTH_` 前缀和下划线层级，例如 `server.trusted_proxy_cidrs` 对应 `NYAUTH_SERVER_TRUSTED_PROXY_CIDRS`。数据库 DSN、Redis 密码、master key、bootstrap 管理员密码、SMTP 密码和 OTLP Authorization 均支持 `*_FILE`；同一项不能同时设置直接值与文件值。

### 使用开发 Compose

```bash
docker compose up --build
```

开发 Compose 将应用、PostgreSQL 和 Redis 分别绑定到 `127.0.0.1:8080`、`127.0.0.1:5432` 和 `127.0.0.1:6379`，并通过一次性 `migrate` service 初始化空数据库。

## 生产部署

生产环境由外部反向代理终止 TLS。只有配置的可信代理 CIDR 可以提供转发头。

1. 复制生产配置模板并替换全部部署值：

   ```bash
   cp config.production.example.yaml config.production.yaml
   ```

2. 设置 `docker-compose.prod.yml` 要求的环境变量：

   - `NYAUTH_IMAGE`：建议使用不可变镜像 digest
   - `NYAUTH_DATABASE_DSN_FILE`：运行账号 DSN secret 文件
   - `NYAUTH_DATABASE_MIGRATION_DSN_FILE`：迁移账号 DSN secret 文件
   - 可选 `NYAUTH_DATABASE_RUNTIME_ROLE`：独立且不属于其他 PostgreSQL 角色的运行账号，默认 `nyauth_runtime`
   - `NYAUTH_DATABASE_RUNTIME_PASSWORD_FILE`：初始化运行账号所需的密码 secret 文件
   - `POSTGRES_PASSWORD_FILE`：PostgreSQL 迁移账号密码 secret 文件
   - `NYAUTH_REDIS_PASSWORD_FILE`：至少 16 字符的 Redis 密码 secret 文件
   - `NYAUTH_AUTH_MASTER_KEY_FILE`：标准 Base64 编码的随机 32 字节 master key secret 文件
   - `NYAUTH_AUTH_ISSUER`：生产 HTTPS issuer
   - `NYAUTH_TRUSTED_PROXY_CIDRS`：准确的反向代理 CIDR
   - `NYAUTH_PROXY_NETWORK`：已由反向代理平台创建并加入的外部 Docker network
   - 可选 `NYAUTH_BOOTSTRAP_ADMIN_USERNAME`、`NYAUTH_BOOTSTRAP_ADMIN_EMAIL`、`NYAUTH_BOOTSTRAP_ADMIN_PASSWORD`

3. 先检查 Compose 展开结果，再启动：

   ```bash
   docker compose -f docker-compose.prod.yml config --quiet
   docker compose -f docker-compose.prod.yml up -d
   ```

生产 Compose 不发布 PostgreSQL/Redis 端口，应用仅通过预先创建的 external proxy network 暴露 `8080`；Compose 不创建或删除该网络。应用与迁移容器使用非 root 用户、只读根文件系统、临时 `/tmp`、cap drop 和 `no-new-privileges`。

如果未提供 bootstrap 密码，空用户库会生成一次性随机管理员密码并只写入一次启动日志；如果通过环境变量提供密码，则不会回显。两种情况都要求首次登录修改密码。

生产切换到此基线时必须使用全新的 PostgreSQL/Redis 空 volume。删除旧 volume 是人工运维动作，应用不会自动执行。运行账号只拥有业务表 DML 权限；迁移账号由一次性 `migrate` service 和受控的 `maintenance` 调度使用。生产 Compose 可按月运行 `docker compose -f docker-compose.prod.yml run --rm migrate maintenance`，不得把迁移 DSN 提供给常驻应用容器。审计保留期可通过 `NYAUTH_AUDIT_RETENTION` 配置，默认 8760 小时。

Prometheus 指标默认由仅限内部网络访问的 `/metrics` 提供。可选 OTLP HTTP 导出使用 `NYAUTH_TELEMETRY_OTLP_ENABLED`、`NYAUTH_TELEMETRY_OTLP_ENDPOINT`、`NYAUTH_TELEMETRY_OTLP_EXPORT_INTERVAL` 和 `NYAUTH_TELEMETRY_OTLP_TIMEOUT`；collector Authorization 建议通过 `NYAUTH_TELEMETRY_OTLP_AUTHORIZATION_FILE` 注入，生产 endpoint 必须使用 HTTPS。

SMTP 使用 `NYAUTH_MAIL_*` 环境变量配置，密码优先通过 `NYAUTH_MAIL_SMTP_PASSWORD_FILE` 注入。常用变量包括 `NYAUTH_MAIL_ENABLED`、`NYAUTH_MAIL_FROM_ADDRESS`、`NYAUTH_MAIL_PUBLIC_BASE_URL`、`NYAUTH_MAIL_SMTP_HOST`、`NYAUTH_MAIL_SMTP_PORT`、`NYAUTH_MAIL_SMTP_USERNAME` 和 `NYAUTH_MAIL_SMTP_TLS_MODE`；生产环境禁止明文 SMTP，并要求公开邮件链接使用 HTTPS。

## 第一方会话 API

`POST /api/login` 创建会话 Cookie，不返回 OAuth access/refresh token。

| 方法 | 路径 | 描述 |
|---|---|---|
| POST | `/api/login` | 用户名密码登录并创建会话 |
| GET | `/api/session` | 返回用户、CSRF、`has_password`、`email_verified` 与最近认证时间 |
| POST | `/api/logout` | 销毁当前会话 |
| GET | `/api/me` | 当前用户资料 |
| PUT | `/api/me` | 修改 display name、avatar |
| POST | `/api/me/password` | 使用当前密码修改密码并轮换会话 |
| POST | `/api/me/password/set` | 外部身份账户在近期重新认证后设置本地密码 |
| POST | `/api/me/reauth/password` | 使用当前密码完成近期重新认证 |
| POST | `/api/me/reauth/{provider}` | 使用已绑定 Provider 完成近期重新认证 |
| POST | `/api/me/email/verification` | 请求邮箱验证邮件 |
| POST | `/api/me/email/change` | 请求邮箱变更确认邮件 |
| GET | `/api/me/sessions` | 查看设备会话 |
| DELETE | `/api/me/sessions/{id}` | 撤销指定设备会话 |
| POST | `/api/me/sessions/revoke-others` | 撤销当前会话以外的所有设备会话 |
| GET | `/api/me/authorizations` | 查看 OAuth 客户端授权 |
| DELETE | `/api/me/authorizations/{client_id}` | 撤销授权并立即失效既有 access/refresh token |
| GET | `/api/me/identities` | 当前用户的外部身份 |
| POST | `/api/me/identities/{provider}/bind` | 发起当前用户的身份绑定 |
| DELETE | `/api/me/identities/{id}` | 在近期重新认证后解绑身份 |
| GET/POST | `/api/my/clients` | 管理当前用户拥有的 OAuth 客户端 |
| POST | `/api/my/clients/{id}/rotate-secret` | 立即轮换 confidential client Secret，仅返回一次明文 |

除安全方法外，所有已认证 `/api` 请求都必须携带 `/api/session` 返回的 `X-CSRF-Token`。后台接口只接受会话 Cookie，不接受 OAuth Bearer token。

```typescript
const session = await fetch('/api/session', {
  credentials: 'same-origin',
}).then((response) => response.json());

await fetch('/api/me', {
  method: 'PUT',
  credentials: 'same-origin',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': session.csrf_token,
  },
  body: JSON.stringify({ display_name: 'Nya' }),
});
```

## OAuth 2.0 / OIDC 端点

| 方法 | 路径 | 描述 |
|---|---|---|
| GET | `/.well-known/openid-configuration` | OIDC Discovery |
| GET | `/.well-known/jwks.json` | 当前及仍处于验证生命周期内的公钥 |
| GET | `/authorize` | Authorization Code + S256 授权 |
| POST | `/token` | code、client credentials、refresh grant |
| GET/POST | `/userinfo` | OIDC UserInfo |
| POST | `/revoke` | 撤销属于调用客户端的 token |
| POST | `/introspect` | confidential client 查询自身 token |
| GET | `/end_session` | 清理会话并校验 post-logout redirect URI |

只有 authorization-code 请求显式申请并获准 `offline_access` 时才会签发 refresh token。Client Credentials 不会获得 refresh token。

OAuth 客户端支持 `post_logout_redirect_uris`。`/end_session` 仅允许跳转到与 ID token 客户端匹配的已注册 URI。

## 账户操作 API

密码找回始终返回相同的 `202`。一次性链接先进入前端确认页，再由 POST 原子消费；数据库只保存 Token 的 SHA-256 哈希。

| 方法 | 路径 | 描述 |
|---|---|---|
| POST | `/api/password/forgot` | 请求密码重置邮件 |
| POST | `/api/password/reset` | 原子消费 Token 并重置密码 |
| POST | `/api/email/verify` | 原子确认邮箱验证 |
| POST | `/api/email/change/confirm` | 原子确认邮箱变更 |

## 运行状态端点

| 方法 | 路径 | 描述 |
|---|---|---|
| GET | `/livez` | 仅表示进程仍可响应 |
| GET | `/readyz` | 检查 schema、PostgreSQL、Redis、活动 JWK 与 Provider 快照 |
| GET | `/metrics` | 仅允许内部或可信来源访问的 Prometheus 指标 |

旧 `/health` 已删除。`/readyz` 失败返回 503，响应不会包含数据库地址、原始依赖错误或 secret。

## 外部身份

| 方法 | 路径 | 描述 |
|---|---|---|
| GET | `/auth/{provider}/authorize` | 发起外部登录 |
| GET | `/auth/{provider}/callback` | 外部 Provider 回调 |
| POST | `/api/me/identities/{provider}/bind` | CSRF 保护的身份绑定入口 |

首次使用未绑定的外部身份登录时会创建外部账号，但不会根据 email 自动合并到已有账号。通用 OIDC Provider 的 discovery URL 必须使用 HTTPS。

Provider 不再从 YAML 或环境变量静态加载，只能由管理员写入数据库。Client secret 使用 master key envelope 加密；禁用或删除通过 PostgreSQL `LISTEN/NOTIFY` 刷新其他实例，并由 60 秒 reconciliation 修复丢失通知。Provider 配置检查只表示“配置有效”或“Discovery 可访问”，不伪称上游登录已经成功。

## 管理与运维 API

内部管理界面继续使用 Cookie + CSRF，不是稳定的自动化 API：

- `GET /api/admin/system/status`：版本、schema、PostgreSQL/Redis/JWK/Provider 状态与延迟。
- `GET /api/admin/audit-logs`：按事件、结果、风险、Actor、Target、IP 和时间筛选。
- `GET /api/admin/audit-logs/export`：按最多 31 天、50,000 条流式导出 NDJSON 或 CEF；CEF 可导入常见 SIEM。
- `POST /api/admin/clients/{id}/rotate-secret`：立即轮换客户端 Secret，新值仅展示一次。
- `GET /api/admin/users/{id}/sessions`、`DELETE /api/admin/users/{id}/sessions`：查看或撤销用户会话。

未来只有版本化 `/api/v1` 会作为自动化管理契约；在 Service Account、细粒度 scope、audience、幂等键和 OpenAPI 稳定前不发布专有 Management SDK。

## 应用集成

Nyauth 不要求使用专有 SDK。服务端应用应通过 Discovery 配置成熟的 OAuth/OIDC 库，并默认采用 BFF + HttpOnly 应用会话。请求 `openid` scope 时必须同时发送随机 `nonce`，授权码流程必须使用 S256 PKCE，并完整验证 ID Token 的签名、issuer、audience、时间和 nonce。

推荐库及安全约束见 [标准 OAuth/OIDC 集成指南](docs/oauth-oidc-integration.md)。近期不支持在浏览器中配置 confidential client secret，也不把 access/refresh token 持久化到 `localStorage`。

单机备份、WAL/PITR、master key 恢复与演练见 [备份与恢复](docs/operations/backup-restore.md)；双实例拓扑与故障语义见 [高可用部署](docs/operations/high-availability.md)。仓库还提供受保护环境下手动触发的 `Isolated recovery drill` 工作流，用一次性 PostgreSQL、空 Redis、带资源计数 manifest 的备份产物和只读 `nyauth verify-recovery` 命令生成恢复证据。

## 质量检查

```bash
go test -race ./...
go vet ./...
govulncheck ./...

cd web
npm ci
npm run check
npm run test:unit
npm run build

# 首次运行 E2E 时安装 Playwright 管理的 Chromium
npx playwright install chromium
npm run test:e2e

```

CI 同时执行真实 PostgreSQL/Redis 并发测试、axe 可访问性检查、Light Theme 视觉回归、开发与生产 Compose 配置检查，并在隔离 runner 上启动完整开发栈执行 readiness 与标准 OIDC smoke。安全工作流执行 `govulncheck`、秘密扫描、依赖审查与 Trivy；发布工作流构建 amd64/arm64 GHCR 镜像并附带 SBOM、provenance、Cosign 签名和不可变 digest。清理动作只删除 CI runner 的一次性测试资源，仓库中的应用与迁移命令不会删除本地或生产 volume。

## 许可证

MIT
