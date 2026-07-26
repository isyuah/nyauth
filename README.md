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
- 自助注册：关闭 / 邀请制 / 开放三种模式，域名白名单与邀请码均为运行时设置
- 动态邮件：数据库版本化 SMTP 配置、真实测试邮件、免重启激活/回滚、共享熔断
- 运维：严格 readiness、JSON 日志、内部 Prometheus、可选 OTLP 与审计 outbox
- 集成方式：标准 OAuth/OIDC Discovery、成熟语言库与 BFF 会话模式

## 本地开发

### 前置要求

- Go 1.26.5+
- PostgreSQL 16+
- Redis 7+
- Node.js 20+

### 使用开发 Compose（推荐）

在仓库根目录后台构建并启动完整开发栈：

```powershell
docker compose up -d --build
docker compose ps
docker compose logs --tail 100 migrate nyauth
```

访问 `http://localhost:8080`。空数据库的首次登录账号为 `admin`，密码为 `local-dev-only-admin`；登录后必须立即修改密码。这些值只用于本地开发，不得用于可被其他设备访问的环境。

检查 readiness，或持续查看应用日志：

```powershell
curl.exe --fail http://localhost:8080/readyz
docker compose logs --follow nyauth
```

开发 Compose 将应用、PostgreSQL 和 Redis 分别绑定到 `127.0.0.1:8080`、`127.0.0.1:5432` 和 `127.0.0.1:6379`，并通过一次性 `migrate` service 初始化空数据库。正常停止使用 `docker compose down`，数据会保留在命名 volume 中。不要使用 `docker compose down -v`；`-v` 会删除本地 PostgreSQL 数据。

### 使用本机服务

本机运行 Go 进程前必须先生成会被嵌入二进制的 `web/build`：

```powershell
Set-Location web
npm ci
npm run check
npm run build
Set-Location ..
Copy-Item config.example.yaml config.yaml
```

PostgreSQL 必须使用相互独立的 migrator 与 runtime 登录角色。以下是全新本地实例的开发示例；如果同名角色或数据库已经存在，应核对其权限，而不是重复执行创建命令：

```powershell
psql -U postgres -d postgres -c "CREATE ROLE nyauth_migrator LOGIN PASSWORD 'local-dev-only-migration-postgres' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"
psql -U postgres -d postgres -c "CREATE ROLE nyauth_runtime LOGIN PASSWORD 'local-dev-only-runtime-postgres' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"
psql -U postgres -d postgres -c "CREATE DATABASE nyauth OWNER nyauth_migrator"
```

启动 Redis 7，并配置密码与 `noeviction`。例如在另一个终端运行：

```powershell
redis-server --requirepass local-dev-only-redis --maxmemory-policy noeviction
```

先让迁移命令使用 migrator DSN，再让常驻服务使用 runtime DSN。bootstrap 密码只从环境变量或 secret 文件读取，不应写入 YAML：

```powershell
$env:NYAUTH_REDIS_PASSWORD = 'local-dev-only-redis'
$env:NYAUTH_DATABASE_RUNTIME_ROLE = 'nyauth_runtime'
$env:NYAUTH_BOOTSTRAP_ADMIN_PASSWORD = 'local-dev-only-admin'

$env:NYAUTH_DATABASE_DSN = 'postgres://nyauth_migrator:local-dev-only-migration-postgres@localhost:5432/nyauth?sslmode=disable'
go run ./cmd/nyauth migrate -config config.yaml

$env:NYAUTH_DATABASE_DSN = 'postgres://nyauth_runtime:local-dev-only-runtime-postgres@localhost:5432/nyauth?sslmode=disable'
go run ./cmd/nyauth serve -config config.yaml
```

建议由迁移账号按月执行 `go run ./cmd/nyauth maintenance -config config.yaml`，并在执行前把 `NYAUTH_DATABASE_DSN` 切回 migrator DSN。迁移命令使用数据库锁；多个实例同时执行时只有一个实例应用迁移。`migrate` 和 `maintenance` 使用迁移账号预创建审计月分区、应用 `audit.retention`、清理已投递的旧 outbox，并复用注册过期清理逻辑作为运维兜底。常驻 `serve` 实例会在启动后立即、此后每小时尝试清理超过各自持久化截止时间的待验证注册；PostgreSQL advisory lock 保证多实例每轮只有一个执行者。`serve` 不执行 DDL，数据库未迁移或版本不匹配时会拒绝启动。

配置文件采用严格解码，未知字段（包括已删除的旧 `providers` 配置）会直接导致启动失败。环境变量统一使用 `NYAUTH_` 前缀和下划线层级，例如 `server.trusted_proxy_cidrs` 对应 `NYAUTH_SERVER_TRUSTED_PROXY_CIDRS`。数据库 DSN、Redis 密码、master key、bootstrap 管理员密码、SMTP 密码和 OTLP Authorization 均支持 `*_FILE`；同一项不能同时设置直接值与文件值。

SMTP 的运行主配置保存在 PostgreSQL，可在服务运行期间按“候选 → 真实测试邮件 → 激活”流程修改，无需重启。`NYAUTH_MAIL_*` 与 SMTP password file 仅作为数据库尚未明确激活或禁用配置时的首次 fallback/bootstrap；完整的本地 PowerShell 操作、远程 `curl` 操作、回滚与熔断语义见 [动态 SMTP 配置与故障处理](docs/operations/runtime-mail.md)。Nyauth 只发信，不读取邮箱，因此无需 IMAP。

## 生产部署

生产环境由外部反向代理终止 TLS。只有配置的可信代理 CIDR 可以提供转发头。

> [!IMPORTANT]
> `auth.issuer` 必须与浏览器实际访问的公开地址完全一致（协议 + 域名）。第一方登录和账户操作接口会把请求的 `Origin` 与 issuer 比对，不一致会返回 `403 invalid request origin`。通过 Cloudflare Tunnel、frp 或任何反向代理暴露服务时，把 issuer 设为公开 HTTPS 域名，并只通过该域名访问后台。

完整的单机远程部署、secret 生成、反向代理、升级和回滚步骤见 [单机远程部署手册](docs/operations/single-host-deployment.md)。`docker-compose.prod.yml` 完全由环境变量和 Compose secret 配置，不读取 `config.production.yaml`，因此 Compose 部署不需要复制配置模板。`config.production.example.yaml` 只用于直接运行原生二进制的部署。

Compose 部署至少设置：

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

先检查 Compose 展开结果，再启动：

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml config --quiet
docker compose --env-file .env.production -f docker-compose.prod.yml up -d
```

生产 Compose 不发布 PostgreSQL/Redis 端口，应用仅通过预先创建的 external proxy network 暴露 `8080`；Compose 不创建或删除该网络。应用与迁移容器使用非 root 用户、只读根文件系统、临时 `/tmp`、cap drop 和 `no-new-privileges`。

如果未提供 bootstrap 密码，空用户库会生成一次性随机管理员密码并只写入一次启动日志；如果通过环境变量提供密码，则不会回显。两种情况都要求首次登录修改密码。

生产切换到此基线时必须使用全新的 PostgreSQL/Redis 空 volume。删除旧 volume 是人工运维动作，应用不会自动执行。运行账号只拥有业务表 DML 权限；迁移账号由一次性 `migrate` service 和受控的 `maintenance` 调度使用。生产 Compose 可按月运行 `docker compose -f docker-compose.prod.yml run --rm migrate maintenance`，不得把迁移 DSN 提供给常驻应用容器。审计保留期可通过 `NYAUTH_AUDIT_RETENTION` 配置，默认 8760 小时。

Prometheus 指标默认由仅限内部网络访问的 `/metrics` 提供。除 HTTP、OAuth、依赖和连接池指标外，还包含注册结果、邮箱验证耗时、SMTP 错误类别、共享熔断状态、outbox backlog 与最老待发邮件年龄；标签不会包含邮箱、用户名、用户 ID、邀请码、SMTP 主机或原始错误。可选 OTLP HTTP 导出使用 `NYAUTH_TELEMETRY_OTLP_ENABLED`、`NYAUTH_TELEMETRY_OTLP_ENDPOINT`、`NYAUTH_TELEMETRY_OTLP_EXPORT_INTERVAL` 和 `NYAUTH_TELEMETRY_OTLP_TIMEOUT`；collector Authorization 建议通过 `NYAUTH_TELEMETRY_OTLP_AUTHORIZATION_FILE` 注入，生产 endpoint 必须使用 HTTPS。

Nyauth 只通过 SMTP 发送邮件，不读取邮箱，也不需要 IMAP。生产 SMTP 应在服务启动后写入数据库：管理员先保存不可变候选，向指定地址实际发送测试邮件，再在测试成功后的十分钟内激活；后续可免重启切换候选、回滚上一数据库版本或在关闭注册后禁用。所有配置操作要求管理员最近十分钟内重新认证，密码使用 master key envelope encryption，API 只返回 `password_configured`。`NYAUTH_MAIL_*`、单机 `docker/compose.prod.smtp-password-file.yml` 和 HA `docker/compose.ha.smtp-password-file.yml` 仅保留为首次 fallback/bootstrap。详见 [动态 SMTP 配置与故障处理](docs/operations/runtime-mail.md)。

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
| POST | `/api/email/verification/resend` | 不可枚举地重发仍有效的待验证注册邮件，不延长截止时间 |
| POST | `/api/email/change/confirm` | 原子确认邮箱变更 |
| GET | `/api/registration` | 公开注册配置（模式、是否需验证、域名限制与当前 `available`） |
| POST | `/api/register` | 自助注册（closed/invite_only/open 由运行时设置控制） |

自助注册默认关闭。开启前必须存在已配置的邮件能力；邀请制模式下用户、注册生命周期、邀请码预占、验证 Token、邮件 outbox 和审计事件在同一事务内提交，失败会整体回滚。邀请码在邮箱验证后才计为已使用；删除或清理待验证用户会释放预占，删除已完成用户不会返还次数。SMTP 未配置、被禁用或熔断打开时，公开配置返回 `available=false`，注册请求在创建用户前返回 `503`；熔断状态同时返回 `Retry-After: 60`。

`pending_registration_ttl` 是可热更新的注册设置，默认 `72h`、允许 `1h` 至 `720h`。创建注册时会保存绝对截止时间，后续修改设置或重发验证邮件都不会改变既有截止时间。注册、邮箱验证、邀请码预占/消耗/释放及注册过期均写入审计 outbox。

## 运行状态端点

| 方法 | 路径 | 描述 |
|---|---|---|
| GET | `/livez` | 仅表示进程仍可响应 |
| GET | `/readyz` | 检查 schema、PostgreSQL、Redis、活动 JWK 与 Provider 快照 |
| GET | `/metrics` | 仅允许内部或可信来源访问的 Prometheus 指标 |

旧 `/health` 已删除。`/readyz` 失败返回 503，响应不会包含数据库地址、原始依赖错误或 secret。SMTP 故障不进入 `/readyz`，避免邮件降级让登录与 OAuth/OIDC 整体下线；管理员通过 `/api/admin/system/status` 的 `services.mail` 和邮件设置状态查看 `degraded/unavailable` 与熔断信息。

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
- `GET /api/admin/stats`：快照化的用户、会话、注册、邮件 backlog、24 小时失败尝试和 SMTP 熔断摘要。
- `GET /api/admin/stats/login-trend`、`registration-trend`、`mail-trend`：按 UTC 返回 7–90 天的补零趋势；注册趋势含邀请预占/消费/释放，邮件趋势区分其他失败尝试（不含永久拒收）、永久拒收与过期。
- `GET /api/admin/audit-logs`：按事件、结果、风险、Actor、Target、IP 和时间筛选。
- `GET /api/admin/audit-logs/export`：按最多 31 天、50,000 条流式导出 NDJSON 或 CEF；CEF 可导入常见 SIEM。
- `POST /api/admin/clients/{id}/rotate-secret`：立即轮换客户端 Secret，新值仅展示一次。
- `GET /api/admin/users/{id}/sessions`、`DELETE /api/admin/users/{id}/sessions`：查看或撤销用户会话。
- `GET/PUT /api/admin/settings/registration`：注册模式、邮箱验证要求、域名白名单、待验证期限与邀请默认值（运行时设置，免重启生效；修改要求近期重新认证）。
- `GET/POST /api/admin/invites`、`DELETE /api/admin/invites/{id}`：邀请码管理；明文 code 仅创建响应返回一次，库中只存哈希；列表分别返回已使用与待验证预占数。创建要求近期重新认证，紧急吊销不要求。
- `GET /api/admin/settings/mail`、`PUT /api/admin/settings/mail/candidate`，以及邮件设置下的 `candidate/test`、`activate`、`rollback`、`disable` POST：数据库动态 SMTP；候选必须实际测试成功并在十分钟内激活，所有读取和变更均要求近期重新认证，写操作还受 CSRF、限流和审计保护。

注册与邮件趋势使用业务事务内的低基数日聚合，后台快照每分钟在 PostgreSQL advisory lock 下刷新。30 日注册完成率按“最近 30 天创建的注册 cohort 中已完成的比例”计算，分母为空时返回 `null`。Schema 5 无法还原已重试成功或随用户删除的历史邮件投递事件，因此 schema 6 的响应通过 `mail_stats_available_from` / `available_from` 明确邮件统计起点，不把迁移前未知数据伪装成零。邮件成功投递不会逐封写审计日志；配置、熔断和现有注册/邀请生命周期事件仍按既定审计契约记录。

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
