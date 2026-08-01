# nyauth 0.6.0-dev

统一认证与用户系统，提供 OAuth 2.0 Authorization Server、OpenID Connect Provider 和第一方管理后台。

## 0.3.0 基线与 0.6.0 兼容演进

`0.3.0` 是全新的破坏性开发基线，不提供旧数据库、配置、接口或 SDK 的兼容层：

- 第一方后台仅使用 `HttpOnly + SameSite=Lax` 会话 Cookie，并对修改请求强制校验 CSRF。
- OAuth 授权码客户端强制使用 PKCE S256；不支持 plain、implicit 或 hybrid 流程。
- JWT 固定使用 RS256，refresh token 采用 family 轮换与重复使用检测。
- 数据库以嵌入二进制的 `000001_baseline` 建立破坏性发布基线，并通过兼容的 `000002` 至 `000014_oauth_application_identity` 加法迁移演进；当前 `0.6.0-dev` 要求 schema version 14，可从正式 `0.5.0` 的 schema version 13 继续迁移。服务启动只校验 schema，不再隐式迁移。
- 旧数据库、session、token、JWK、Provider 凭据和 OAuth 客户端注册均不兼容。
- 旧 Go/TypeScript SDK 已删除；OAuth/OIDC 集成以标准协议和成熟语言库为准。

> [!CAUTION]
> 升级前请备份需要保留的数据。旧 PostgreSQL/Redis volume 必须在运维人员核对环境、备份和准确 volume 名称并明确批准后，才可人工删除重建。应用和迁移命令不会自动删除 volume，也不要在未经确认时执行 `docker compose down -v`。

重建后需要重新注册 OAuth 客户端和外部 Provider。首次启动只会在空用户库中创建管理员；该管理员必须在首次登录后修改密码。

## 功能

- OAuth 2.0：Authorization Code + S256、Client Credentials、Refresh Token
- OpenID Connect：Discovery、JWKS、ID Token、UserInfo、RP-Initiated Logout
- OIDC 授权体验：运行时 Scope Catalog、客户端级 Scope/Claim 上限、可选权限声明、详细 Consent 和实际授权收敛
- OAuth 发布者可信状态：区分系统管理、用户注册未验证和管理员已审核；Consent 展示可信状态与实际回调来源
- OAuth 应用身份：受控应用 Logo、主页、隐私政策与服务条款，授权时保存身份快照并提示后续变化
- OAuth 授权变化：Consent 区分既有与新增 Scope/Claim；Redirect URI、Grant、访问策略或权限收紧会要求用户重新授权
- 控制面认证：HttpOnly 会话、CSRF、强制首次改密、会话与令牌即时失效
- 外部身份：GitHub、Google、通用 HTTPS OIDC Provider；不按邮箱自动合并账户
- 管理后台：用户、客户端、Provider、审计与统计
- 账户安全中心：设备会话、OAuth 授权、近期重新认证、TOTP、Passkey/WebAuthn、一次性恢复码、邮箱验证与密码恢复
- 自助注册：关闭 / 邀请制 / 开放三种模式，域名白名单与邀请码均为运行时设置
- 动态邮件：数据库版本化 SMTP 配置、结构化事务邮件模板、真实预览/测试、免重启激活/回滚与共享熔断
- 全站横幅：信息/警告/严重三级横幅，开始与结束时间可独立省略，浏览器按版本关闭，以及 SSE 实时同步
- 安全头像：浏览器 1:1 裁剪、服务端重编码、本地持久化或私有 S3、Provider 首次异步导入，以及版本化运行时 S3 配置与可续跑迁移
- 运行时服务控制：六类能力独立暂停、常用维护预设、多实例排空确认、定时恢复与 CLI 紧急解锁
- 运行时运营策略：动态限流、会话与近期认证期限、审计保留和用户客户端配额，revision CAS 与多实例同步
- 运行时可观测性：日志基线与临时 Debug、固定运营告警阈值、版本化 OTLP 候选/真实测试/激活/回滚
- 人机验证：适配器式运行时配置，首个 Provider 为 Cloudflare Turnstile；支持候选真实测试、激活/回滚/禁用/重新启用、自适应登录及公开账户入口保护
- 运维：严格 readiness、JSON 日志、内部 Prometheus、可选 OTLP 与审计 outbox
- 集成方式：标准 OAuth/OIDC Discovery、成熟语言库与 BFF 会话模式

## 本地开发

### 前置要求

- Go 1.26.5+
- PostgreSQL 16+
- Redis 7+
- Node.js 24+

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

开发 Compose 将应用、PostgreSQL 和 Redis 分别绑定到 `127.0.0.1:8080`、`127.0.0.1:5432` 和 `127.0.0.1:6379`，并通过一次性 `migrate` service 初始化空数据库。头像使用 `media` 命名 volume 挂载到 `/var/lib/nyauth/media`，与 PostgreSQL 的 `pgdata` 分开持久化。正常停止使用 `docker compose down`，两个 volume 都会保留。不要使用 `docker compose down -v`；`-v` 会同时删除本地 PostgreSQL 和头像数据。

更新已有开发栈时也必须使用完整的 `docker compose up -d --build`，让新镜像中的一次性 `migrate` 先完成 schema 升级，再由 Compose 启动应用。不要使用 `--no-deps` 单独替换 `nyauth`；`serve` 按设计只校验 schema，不执行 DDL。如果最初使用了 `docker compose -p <name>` 创建栈，后续所有构建、迁移和启动命令必须继续使用同一个 `-p <name>`；可先用 `docker compose ls` 核对项目名，避免误建第二套数据库和端口冲突。

若误设无限期暂停且管理界面无法恢复，可使用运行时数据库账号执行紧急解锁。该命令原子清空暂停、递增 revision、通知在线实例并写入审计；它不修改其他运行时设置：

```powershell
docker compose exec nyauth nyauth service-control reset -reason "local operator recovery"
```

若用户丢失了 MFA 凭据且无法通过正常的近期重新认证流程删除，可使用带审计的 break-glass CLI。必须精确指定一个用户、重置范围、原因，并再次输入目标标识作为人工确认；下面只删除 `admin` 的 Passkey，保留其 TOTP 与稳定 WebAuthn handle：

```powershell
docker compose exec nyauth nyauth mfa reset `
  -username admin -scope passkeys `
  -reason "operator confirmed lost Passkey" -confirm admin
```

`-scope` 支持 `passkeys`、`totp` 和 `all`（默认）。命令会确认重置后仍有密码、启用的 Provider 或剩余 Passkey 可用于主认证，随后在同一 PostgreSQL 事务中清除所选因素、推进 `auth_version` 并写入 `mfa.recovery_reset` 审计。若管理员强制 MFA 会让重置后的账号仍无法登录，命令默认拒绝；只有明确加入 `-disable-admin-mfa-requirement` 才会同时关闭该全局策略并额外写入 `settings.updated` 审计。原因不得包含密码、Token、DSN 或其他 secret。

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

头像默认使用 `media.backend=local` 和 `media.local.directory=data/media`。本机原生运行时应为该目录建立独立备份；Compose 则使用上述 `media` volume。用户上传只接受 JPEG、PNG 和静态 WebP，严格限制为 8 MiB、最大边 4096、最多 16,777,216 像素，并在服务端重新生成 64/128/256/512 四种 WebP，不保存原图或任意外部 URL。完整安全契约见 [安全头像媒体契约](docs/avatar-storage-design.md)。

SMTP 的运行主配置保存在 PostgreSQL，可在服务运行期间按“候选 → 真实测试邮件 → 激活”流程修改，无需重启。`NYAUTH_MAIL_*` 与 SMTP password file 仅作为数据库尚未明确激活或禁用配置时的首次 fallback/bootstrap；完整的本地 PowerShell 操作、远程 `curl` 操作、回滚与熔断语义见 [动态 SMTP 配置与故障处理](docs/operations/runtime-mail.md)。Nyauth 只发信，不读取邮箱，因此无需 IMAP。

## 生产部署

生产环境由外部反向代理终止 TLS。只有配置的可信代理 CIDR 可以提供转发头。

> [!IMPORTANT]
> `auth.issuer` 必须与浏览器实际访问的公开地址完全一致（协议 + 域名）。第一方登录和账户操作接口会把请求的 `Origin` 与 issuer 比对，不一致会返回 `403 invalid request origin`。WebAuthn 的 RP ID 固定取 issuer 的 hostname，origin 固定取其协议与 host；生产环境必须使用 HTTPS。更换公开 hostname 会使旧 Passkey 无法继续使用，不能作为普通热更新操作。通过 Cloudflare Tunnel、frp 或任何反向代理暴露服务时，把 issuer 设为公开 HTTPS 域名，并只通过该域名访问后台。

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
- 可选 `NYAUTH_MEDIA_BACKEND`、`NYAUTH_MEDIA_LOCAL_DIRECTORY`：单机默认分别为 `local` 和 `/var/lib/nyauth/media`
- 可选 `NYAUTH_BOOTSTRAP_ADMIN_USERNAME`、`NYAUTH_BOOTSTRAP_ADMIN_EMAIL`、`NYAUTH_BOOTSTRAP_ADMIN_PASSWORD`

先检查 Compose 展开结果，再启动：

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml config --quiet
docker compose --env-file .env.production -f docker-compose.prod.yml up -d
```

单机生产默认使用独立 `media` volume。需要从首次头像上传起使用 AWS S3、R2、MinIO 等私有 S3 兼容存储时，使用仓库中的 `docker-compose.media-s3.yml` override，并在所有 `config`、`up`、`maintenance`、升级和停止命令中保留同一组 `-f` 参数：

```bash
docker compose --env-file .env.production \
  -f docker-compose.prod.yml \
  -f docker-compose.media-s3.yml \
  config --quiet

docker compose --env-file .env.production \
  -f docker-compose.prod.yml \
  -f docker-compose.media-s3.yml \
  up -d
```

S3 override 要求 `NYAUTH_MEDIA_S3_REGION`、`NYAUTH_MEDIA_S3_BUCKET`、access key ID 与 secret access key 文件；可选配置 HTTPS endpoint、prefix 和 path-style。bucket 必须保持私有，浏览器始终通过 Nyauth 同源 `/media` 路由读取。该静态配置是数据库尚未激活动态 profile 时的 fallback。管理员可在 `/admin/settings/media` 保存不可变候选、执行真实 Put/Get/校验/Delete 测试，并在系统自动排空 `media_writes` 后把现有对象迁移到候选私有 S3。单实例若保留了部署时已挂载的本地 fallback，还可在相同排空、复制和回读校验流程中迁回本地；API 不接受任意本地路径，多实例环境禁止迁回非共享本地存储。详细 secret 与命令见 [单机远程部署手册](docs/operations/single-host-deployment.md)。

生产 Compose 不发布 PostgreSQL/Redis 端口，应用仅通过预先创建的 external proxy network 暴露 `8080`；Compose 不创建或删除该网络。应用与迁移容器使用非 root 用户、只读根文件系统、临时 `/tmp`、cap drop 和 `no-new-privileges`。

如果未提供 bootstrap 密码，空用户库会生成一次性随机管理员密码并只写入一次启动日志；如果通过环境变量提供密码，则不会回显。两种情况都要求首次登录修改密码。

生产切换到此基线时必须使用全新的 PostgreSQL/Redis 空 volume；本地头像模式还必须建立并纳入备份新的 `media` volume。删除旧 volume 是人工运维动作，应用不会自动执行。运行账号只拥有业务表 DML 权限；迁移账号由一次性 `migrate` service 和受控的 `maintenance` 调度使用。生产 Compose 可按月运行 `docker compose -f docker-compose.prod.yml run --rm migrate maintenance`，不得把迁移 DSN 提供给常驻应用容器；使用 S3 override 时该命令也必须追加相同 override。`NYAUTH_AUDIT_RETENTION` 仅是数据库尚无生命周期设置时的静态 fallback；保存运行时 `audit_retention_days` 后，`maintenance` 使用数据库中的权威值。缩短保留期只保存策略，真正删除仍由后续 maintenance 执行。

Prometheus 指标默认由仅限内部网络访问的 `/metrics` 提供。除 HTTP、OAuth、依赖和连接池指标外，还包含注册结果、邮箱验证耗时、SMTP 错误类别、共享熔断状态、outbox backlog、最老待发邮件年龄、头像处理、固定运营告警状态、限流启用状态和运行时设置 revision；标签不会包含邮箱、用户名、用户 ID、邀请码、SMTP 主机、头像 object key 或原始错误。OTLP HTTP 可在后台按“不可变候选 → 真实 collector 测试 → 十分钟内激活”免重启切换、回滚或禁用；Authorization 使用 master key 加密且不回显。`NYAUTH_TELEMETRY_OTLP_*` 仅在数据库仍为 `fallback` 时生效，生产 endpoint 必须使用 HTTPS。完整流程见 [运行时可观测性](docs/operations/runtime-observability.md)。

Nyauth 只通过 SMTP 发送邮件，不读取邮箱，也不需要 IMAP。生产 SMTP 应在服务启动后写入数据库：管理员先保存不可变候选，向指定地址实际发送测试邮件，再在测试成功后的十分钟内激活；后续可免重启切换候选、回滚上一数据库版本或在关闭注册后禁用。所有配置操作要求管理员最近十分钟内重新认证，密码使用 master key envelope encryption，API 只返回 `password_configured`。`NYAUTH_MAIL_*`、单机 `docker/compose.prod.smtp-password-file.yml` 和 HA `docker/compose.ha.smtp-password-file.yml` 仅保留为首次 fallback/bootstrap。详见 [动态 SMTP 配置与故障处理](docs/operations/runtime-mail.md)。

## 第一方会话 API

`POST /api/login` 在无需第二因素时直接创建会话 Cookie；已启用 MFA 的账户返回 `202 mfa_required`，只有完成临时 challenge 后才创建完整会话。第一方登录不返回 OAuth access/refresh token。

| 方法 | 路径 | 描述 |
|---|---|---|
| POST | `/api/login` | 用户名密码登录；返回完整会话或 `202 mfa_required` |
| POST | `/api/login/passkey/options` | 创建 discoverable Passkey 登录 ceremony；支持 Conditional UI |
| POST | `/api/login/passkey/verify` | 使用 `X-WebAuthn-Ceremony` 完成 Passkey 登录 |
| GET | `/api/login/mfa` | 恢复当前 5 分钟 MFA challenge |
| POST | `/api/login/mfa` | 使用 TOTP 或一次性恢复码完成登录/重新认证 challenge |
| POST | `/api/login/mfa/passkey/options` | 为当前 MFA challenge 创建 Passkey assertion options |
| POST | `/api/login/mfa/passkey/verify` | 原子消费 Passkey ceremony 与 MFA challenge |
| DELETE | `/api/login/mfa` | 取消当前 MFA challenge |
| GET | `/api/session` | 返回用户、CSRF、认证状态、会话绝对截止与近期认证截止时间 |
| POST | `/api/logout` | 销毁当前会话 |
| GET | `/api/me` | 当前用户资料 |
| PUT | `/api/me` | 修改 display name |
| POST | `/api/me/avatar` | 上传浏览器裁剪后的受控头像，返回更新后的用户资料 |
| DELETE | `/api/me/avatar` | 删除当前头像，返回更新后的用户资料 |
| GET | `/media/avatars/{avatar_id}/{size}.webp` | 读取 active 头像的 64/128/256/512 WebP 变体 |
| POST | `/api/me/password` | 使用当前密码修改密码并轮换会话 |
| POST | `/api/me/password/set` | 外部身份账户在近期重新认证后设置本地密码 |
| POST | `/api/me/reauth/password` | 使用当前密码完成近期重新认证 |
| POST | `/api/me/reauth/{provider}` | 使用已绑定 Provider 完成近期重新认证 |
| POST | `/api/me/reauth/passkey/options` | 使用已有 Passkey 创建近期重新认证 ceremony |
| POST | `/api/me/reauth/passkey/verify` | 使用 `X-WebAuthn-Ceremony` 完成近期重新认证 |
| GET | `/api/me/mfa` | 查看 TOTP、Passkey、恢复码余量和当前管理员强制策略 |
| POST | `/api/me/mfa/totp/enroll` | 近期重新认证后生成待确认 TOTP secret |
| POST | `/api/me/mfa/totp/enroll/confirm` | 校验首个 TOTP 并一次性返回 10 枚恢复码 |
| POST | `/api/me/mfa/recovery-codes` | 近期重新认证后替换全部恢复码，新值只返回一次 |
| DELETE | `/api/me/mfa/totp` | 近期重新认证后停用 TOTP，并使恢复码失效 |
| GET | `/api/me/passkeys` | 列出当前 RP 下的 Passkey 及 backup/clone 状态 |
| POST | `/api/me/passkeys/registration/options` | 近期重新认证后创建 discoverable credential 注册 ceremony |
| POST | `/api/me/passkeys/registration/verify` | 校验并保存 Passkey，推进 `auth_version` 后轮换当前会话 |
| PUT | `/api/me/passkeys/{id}` | 重命名 Passkey |
| DELETE | `/api/me/passkeys/{id}` | 近期重新认证后删除 Passkey，并校验登录方式与管理员 MFA 不变量 |
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
| GET/POST | `/api/my/clients` | 管理当前用户拥有的 OAuth 客户端；列表返回权威 `quota_used/quota_limit/quota_override` |
| PUT | `/api/my/clients/{id}` | 编辑本人应用的 OAuth 配置、主页和政策链接 |
| POST/DELETE | `/api/my/clients/{id}/logo` | 上传浏览器裁剪后的应用 Logo，或删除当前 Logo |
| POST | `/api/my/clients/{id}/rotate-secret` | 立即轮换 confidential client Secret，仅返回一次明文 |
| GET | `/media/client-logos/{logo_id}/{size}.webp` | 读取 active 应用 Logo 的 64/128/256/512 WebP 变体 |

所有已认证修改请求都必须携带完整会话返回的 `X-CSRF-Token`。MFA pending 使用独立的 `nyauth_mfa_pending` HttpOnly Cookie 和 challenge 响应中的临时 CSRF；临时令牌不得覆盖正式会话 CSRF。WebAuthn options 返回独立、不透明的 `ceremony_id`，完成请求通过 `X-WebAuthn-Ceremony` 携带；Conditional UI、显式登录和多标签页 ceremony 因此不会互相覆盖。pending 与 WebAuthn ceremony 都只保留约 5 分钟，不进入设备会话列表或活跃会话统计。后台接口只接受会话 Cookie，不接受 OAuth Bearer token。

TOTP 使用 RFC 6238 的 SHA-1、30 秒、6 位参数和 `±1` time-step 窗口，成功 step 会在 PostgreSQL 行锁事务中记录并拒绝重放。TOTP secret 使用 master key envelope encryption，恢复码只保存 selector 摘要与 Argon2id 哈希。Passkey 注册强制 discoverable credential 与 user verification，attestation 为 `none`；完整 WebAuthn credential 使用 master key envelope encryption，credential ID 仅用于索引，每次 assertion 都在行锁事务中同步 sign count、clone warning、backup state 与完整密文。clone warning 会保留并写高风险审计，但不会仅凭该信号立即锁死账户。

启用或停用因素会推进 `auth_version`，撤销既有浏览器会话与 OAuth refresh family，再为当前设备轮换新会话。密码和 Provider 重新认证均会在主因素后执行同一第二因素 challenge，不能只凭密码刷新近期认证时间。Passkey 可作为独立登录、MFA 第二因素和近期重新认证方式；TOTP 恢复码仍只属于 TOTP，不会被无依据地扩成账户级恢复凭据。

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

每个客户端的 `scopes` 是可请求权限上限；`optional_scopes` 必须是其中的子集，并只作用于 Authorization Code 用户授权；`allowed_claims` 再限制 ID Token 与 UserInfo 可以返回的用户字段。`openid` 始终是必需权限，且客户端至少保留一个必需 Scope。授权页从运行时 Scope Catalog 展示名称、说明、风险等级和实际 Claim，将请求分成必需和可选两组；用户可以逐项关闭可选权限，授权记录、授权码、Access/Refresh Token 都只保存实际获准集合与 Claim 白名单。若实际集合比请求集合更小，授权回调和 Token 响应都会返回实际 `scope`。现有客户端升级后 `optional_scopes` 默认为空，`allowed_claims` 按旧版本真实返回过的标准字段回填；例如旧 `email` 授权不会在升级后自动增加 `email_verified`。

客户端可保存 HTTPS 主页、隐私政策和服务条款，并上传与头像相同安全管线处理的方形 Logo；不接受任意外部图片 URL。每次同意会保存当时的应用名称、政策链接和客户端 revision，授权记录的 `last_used_at` 只在客户端真实换取 Access Token 或轮换 Refresh Token 后更新。后续新增 Scope/Claim 只在下一次 Consent 中标为新增请求，新增可选 Scope 默认不勾选，也不会被静默加入既有 Token；Redirect URI 变化、Grant/Scope/Claim 移除或访问策略变化会推进授权 revision，使 Nyauth 的授权码兑换、Access Token 校验和 Refresh Token 轮换拒绝旧版本，并要求用户重新授权。自包含 JWT 若由第三方资源服务器完全离线验签，仍只能在其原始短期 `exp` 到达后自然失效；需要即时状态的集成应调用 introspection 或使用 Nyauth 的 UserInfo。

管理员直接创建的客户端标记为 `system_managed`；用户自助创建的客户端标记为 `user_registered/unverified`，Consent 会显示发布者未验证警告。管理员在核对应用身份和回调来源后，可通过后台将用户注册客户端标记为已审核，或撤销审核；两种操作都要求近期重新认证并与审计事件同事务提交。该状态是 Nyauth 管理员的人工审核结论，不是 DNS、TLS 或域名所有权的自动证明。

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
| GET | `/api/human-verification?action=...` | 读取指定公开动作的验证挑战；不返回 Secret 或内部 revision |

自助注册默认关闭。开启前必须存在已配置的邮件能力；邀请制模式下用户、注册生命周期、邀请码预占、验证 Token、邮件 outbox 和审计事件在同一事务内提交，失败会整体回滚。邀请码在邮箱验证后才计为已使用；删除或清理待验证用户会释放预占，删除已完成用户不会返还次数。SMTP 未配置、被禁用或熔断打开时，公开配置返回 `available=false`，注册请求在创建用户前返回 `503`；熔断状态同时返回 `Retry-After: 60`。

`pending_registration_ttl` 是可热更新的注册设置，默认 `72h`、允许 `1h` 至 `720h`。创建注册时会保存绝对截止时间，后续修改设置或重发验证邮件都不会改变既有截止时间。注册、邮箱验证、邀请码预占/消耗/释放及注册过期均写入审计 outbox。

## 运行状态端点

| 方法 | 路径 | 描述 |
|---|---|---|
| GET | `/livez` | 仅表示进程仍可响应 |
| GET | `/readyz` | 检查 schema、PostgreSQL、Redis、活动 JWK 与 Provider 快照 |
| GET | `/api/service-status` | 公开的派生运行状态、暂停能力、提示与预计恢复时间；不返回内部原因或实例信息 |
| GET | `/api/service-status/events` | 同一公开状态的 SSE 实时推送；浏览器断线自动重连，并以轮询和到期刷新兜底 |
| GET | `/metrics` | 仅允许内部或可信来源访问的 Prometheus 指标 |

旧 `/health` 已删除。`/readyz` 失败返回 503，响应不会包含数据库地址、原始依赖错误或 secret。主动维护是预期运行状态，不会把 `/readyz` 改为失败；系统状态通过独立的 `operating_state` 展示。SMTP 和头像媒体存储故障也不进入 `/readyz`，避免非核心能力降级让登录与 OAuth/OIDC 整体下线；管理员通过 `/api/admin/system/status` 的 `services.mail`、`services.media` 和对应设置状态查看降级信息。媒体故障期间头像上传或读取返回 `503`；删除以 PostgreSQL 中解除当前引用为成功边界，对象删除失败会标记降级并交给后台清理重试。

## 外部身份

| 方法 | 路径 | 描述 |
|---|---|---|
| GET | `/auth/{provider}/authorize` | 兼容性外部登录入口；开启 Provider 人机验证时会返回登录页 |
| GET | `/auth/{provider}/callback` | 外部 Provider 回调 |
| POST | `/api/provider-login/{provider}` | 受同源和可选人机验证保护的外部登录启动入口 |
| POST | `/api/me/identities/{provider}/bind` | CSRF 保护的身份绑定入口 |

首次使用未绑定的外部身份登录时会创建外部账号，但不会根据 email 自动合并到已有账号。通用 OIDC Provider 的 discovery URL 必须使用 HTTPS。

Provider 不再从 YAML 或环境变量静态加载，只能由管理员写入数据库。Client secret 使用 master key envelope 加密；禁用或删除通过 PostgreSQL `LISTEN/NOTIFY` 刷新其他实例，并由 60 秒 reconciliation 修复丢失通知。Provider 配置检查只表示“配置有效”或“Discovery 可访问”，不伪称上游登录已经成功。

管理员可为 Provider 启用默认关闭的 `import_avatar`。它只在外部身份首次创建本地用户时异步导入一次，不阻塞登录、后续不持续同步，也绝不覆盖用户主动上传的头像。GitHub 和 Google 使用代码内置的严格图片主机；通用 OIDC 必须配置精确公共 DNS 主机 allowlist。远程获取只允许 HTTPS/443，对每次重定向重新检查主机和全部解析地址，并阻断私网、loopback、link-local、云元数据与 DNS rebinding。上游 URL 使用 master key 加密，完成或最终失败后清空；浏览器只会看到 Nyauth 生成的媒体地址。

## 管理与运维 API

内部管理界面继续使用 Cookie + CSRF，不是稳定的自动化 API：

- `GET /api/admin/system/status`：版本、schema、PostgreSQL/Redis/JWK/Provider、SMTP、头像媒体、人机验证与可观测性状态，以及当前运营告警。
- `GET/PUT /api/admin/settings/operations`：六类能力的运行时暂停、恢复、到期和多实例应用进度；修改要求近期重新认证，使用 revision CAS 并与审计同事务提交。
- `GET /api/admin/settings/media`、候选保存/测试、迁移及 `fallback/migrate` 接口：私有 S3 运行时配置、迁回已配置本地 fallback、真实对象测试、迁移进度和失败重试；凭据只加密保存且永不回显。
- `GET/PUT /api/admin/settings/branding`、`registration`、`security`、`protection`、`lifecycle`、`oauth`：六组运行时设置统一使用 revision CAS；写入要求近期重新认证、固定保护限流，并与 `settings.updated` 审计同事务提交。
- `GET /api/site-banner`、`GET /api/site-banner/events`：读取全站横幅并通过 SSE 接收实时状态；公开响应不包含设置 revision 或邮件模板。
- `GET/PUT /api/admin/settings/communications`、邮件模板 `preview/test`、横幅 Markdown `site-banner/preview`：动态管理结构化事务邮件模板和全站横幅。模板只接受受限纯文本字段与按字段授权的变量，动作链接和安全提示由服务端生成；测试邮件只能发往当前管理员已验证邮箱。
- `GET/PUT /api/admin/settings/observability` 及其 `otlp/candidate`、`test`、`activate`、`rollback`、`disable` 接口：动态日志级别、最长 24 小时的临时 Debug、五项固定低基数告警阈值和加密的 OTLP 版本状态机；修改要求近期重新认证、CSRF、固定限流与审计。
- `GET/PUT /api/admin/settings/human-verification` 及其 `candidate`、`candidate/test`、`activate`、`rollback`、`disable`、`enable` 接口：管理 Turnstile 不可变候选版本和注册、登录、密码恢复、验证邮件重发、Provider 登录策略；Secret 加密保存且永不回显，激活要求同一候选版本在最近十分钟内真实验证成功，禁用只关闭运行开关并保留当前配置。
- `protection` 动态控制登录、账户操作、头像和 SMTP 管理限流，以及自助客户端全局默认配额。关闭限流组需要精确危险确认；每次 revision 都使用新的 Redis key namespace，旧计数自然过期。
- `lifecycle` 动态控制浏览器会话绝对/空闲期限、每用户并发会话上限、近期认证期限、Access/Refresh Token、授权码和审计保留天数。缩短会话期限会在下一次请求时淘汰超龄会话；并发上限在下一次登录时原子淘汰最旧会话；延长不会恢复 Redis 中已经过期的会话。Token 与授权码策略只影响之后新签发或轮换的凭据，已签发凭据保持原到期时间。
- `oauth` 动态控制用户自助创建、Public Client、可新增 Grant/Scope、Scope Catalog、Claim 分配权限与回调地址数量。标准 Scope 的 Claim 语义固定；自定义 Scope 可映射受支持的内置 Claim。Scope 或 Claim 可设为仅管理员分配，普通用户的客户端目录与创建接口不会暴露这些项目，但最终 Consent 仍会如实显示。每个客户端再以 `scopes`、`optional_scopes` 和 `allowed_claims` 限制请求、用户可拒绝项与字段上限。收紧全局策略不修改或停用既有客户端；既有超限或已禁用项可以原样保留、等量替换或逐步减少，但不能继续扩大。
- `/admin/oauth/test`：管理员可在生产构建中使用真实 Authorization Code + S256 PKCE 流程检查 Scope Catalog、Consent、Token 与 UserInfo；Confidential Client Secret 只保存在当前页面内存中。测试前必须把页面显示的回调地址登记到目标客户端。
- `GET /api/admin/stats`：快照化的用户、会话、注册、邮件 backlog、24 小时失败尝试和 SMTP 熔断摘要。
- `GET /api/admin/stats/login-trend`、`registration-trend`、`mail-trend`：按 UTC 返回 7–90 天的补零趋势；注册趋势含邀请预占/消费/释放，邮件趋势区分其他失败尝试（不含永久拒收）、永久拒收与过期。
- `GET /api/admin/audit-logs/options`：返回有界、静态的事件、结果、风险和目标类型筛选目录，不扫描审计分区。
- `GET /api/admin/audit-logs`：按事件、结果、风险、Actor、模糊 Target、精确 subject user/target、IP 和时间筛选；管理员 DTO 包含 User-Agent，details 会在服务端递归脱敏。
- `GET /api/admin/audit-logs/export`：复用列表的全部筛选语义，按最多 31 天、50,000 条流式导出 NDJSON 或 CEF；CEF 可导入常见 SIEM。
- `POST /api/admin/clients/{id}/rotate-secret`：立即轮换客户端 Secret，新值仅展示一次。
- `POST/DELETE /api/admin/clients/{id}/logo`：管理员上传或删除受控应用 Logo；对象继续使用当前本地/S3 媒体存储。
- `POST/DELETE /api/admin/clients/{id}/publisher-verification`：审核或撤销用户注册客户端的发布者可信状态；系统管理客户端不适用，操作要求近期重新认证。
- `GET /api/admin/users/{id}/sessions`、`DELETE /api/admin/users/{id}/sessions`：查看或撤销用户会话。
- `GET /api/admin/users/{id}/clients`、`PUT /api/admin/users/{id}/client-quota`：查看权威客户端配额，或设置 0–1000 的用户覆盖值；`null` 恢复继承全局默认，降低配额不删除已有客户端。
- `POST /api/admin/users/{id}/avatar`、`DELETE /api/admin/users/{id}/avatar`：管理员上传或删除用户头像，受 CSRF、限流与审计保护。
- `GET/PUT /api/admin/settings/registration`：注册模式、邮箱验证要求、域名白名单、待验证期限与邀请默认值（运行时设置，免重启生效；修改要求近期重新认证）。
- `GET/PUT /api/admin/settings/security`：TOTP/Passkey 注册开关与管理员强制 MFA（运行时设置，免重启生效；修改要求近期重新认证）。开关只阻止新注册，不停用已有因素。开启强制策略前所有活动管理员必须在当前 RP 下至少配置 TOTP 或 Passkey；策略生效后，无因素用户不能被激活/晋升为管理员，活动管理员也不能删除其最后一个因素。
- `GET/POST /api/admin/invites`、`DELETE /api/admin/invites/{id}`：邀请码管理；明文 code 仅创建响应返回一次，库中只存哈希；列表分别返回已使用与待验证预占数。创建要求近期重新认证，紧急吊销不要求。
- `GET /api/admin/settings/mail`、`PUT /api/admin/settings/mail/candidate`，以及邮件设置下的 `candidate/test`、`activate`、`rollback`、`disable` POST：数据库动态 SMTP；候选必须实际测试成功并在十分钟内激活，所有读取和变更均要求近期重新认证，写操作还受 CSRF、限流和审计保护。

事务邮件模板和 SMTP 投递配置相互独立：模板保存后只影响之后新入队的邮件；已经入队的邮件正文在加密 outbox 中保持不变。模板不能注入任意 HTML、CSS、脚本或自定义动作链接，预览使用 `example.invalid` 的不可用示例 Token，真实测试不会生成账户操作 Token。

注册与邮件趋势使用业务事务内的低基数日聚合，后台快照每分钟在 PostgreSQL advisory lock 下刷新。30 日注册完成率按“最近 30 天创建的注册 cohort 中已完成的比例”计算，分母为空时返回 `null`。全新 baseline 会把 `mail_stats_available_from` / `available_from` 初始化为该数据库开始观测邮件投递的时间，不能把此前不存在的数据解释为零。邮件成功投递不会逐封写审计日志；配置、熔断和现有注册/邀请生命周期事件仍按既定审计契约记录。

未来只有版本化 `/api/v1` 会作为自动化管理契约；在 Service Account、细粒度 scope、audience、幂等键和 OpenAPI 稳定前不发布专有 Management SDK。

## 应用集成

Nyauth 不要求使用专有 SDK。服务端应用应通过 Discovery 配置成熟的 OAuth/OIDC 库，并默认采用 BFF + HttpOnly 应用会话。请求 `openid` scope 时必须同时发送随机 `nonce`，授权码流程必须使用 S256 PKCE，并完整验证 ID Token 的签名、issuer、audience、时间和 nonce。

推荐库、安全约束及管理员测试台步骤见 [标准 OAuth/OIDC 集成指南](docs/oauth-oidc-integration.md)。业务应用仍不应在浏览器中持久化 confidential client secret，也不得把 access/refresh token 写入 `localStorage`；管理测试台的 Secret 仅用于人工诊断并停留在页面内存。

单机备份、WAL/PITR、master key、local media/S3 恢复与演练见 [备份与恢复](docs/operations/backup-restore.md)；双实例拓扑、共享私有 S3 与故障语义见 [高可用部署](docs/operations/high-availability.md)；人机验证配置、故障语义和紧急禁用见 [运行时人机验证](docs/operations/human-verification.md)；头像输入、存储、Provider 导入和清理边界见 [安全头像媒体契约](docs/avatar-storage-design.md)。仓库还提供受保护环境下手动触发的 `Isolated recovery drill` 工作流，用一次性 PostgreSQL、空 Redis、带资源计数 manifest 的备份产物和只读 `nyauth verify-recovery` 命令验证 JWK、Provider、TOTP、Passkey 与邮件 envelope 并生成恢复证据；当前该自动化不恢复或抽查头像对象，媒体恢复必须按备份手册另行留证。

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
