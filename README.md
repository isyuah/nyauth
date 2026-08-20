# Nyauth

Nyauth 是一个面向自托管场景的认证与用户系统，提供 OAuth 2.0 Authorization Server、OpenID Connect Provider 和第一方管理后台。

当前开发线：`0.8.0-dev`。`0.3.0` 建立了新的破坏性基线，不兼容更早版本的数据库、配置、会话、令牌、JWK、Provider 凭据或 OAuth 客户端注册。

## 能力概览

- **标准协议**：OAuth 2.0 Authorization Code + PKCE S256、Device Authorization、Client Credentials、Refresh Token，以及 OIDC Discovery、JWKS、ID Token、UserInfo 和 RP-Initiated Logout。
- **认证安全**：HttpOnly 会话、CSRF、防重放、Refresh Token family 轮换与重复使用检测、TOTP、Passkey/WebAuthn、一次性恢复码和近期重新认证。
- **账号与身份**：密码登录、自助注册、邀请、邮箱验证、密码恢复，以及 GitHub、Google 和通用 HTTPS OIDC Provider。
- **授权体验**：Consent、Scope/Claim 白名单、OAuth 应用身份、发布者可信状态和 RFC 9470 Step-Up Authentication。
- **运营能力**：用户、OAuth 客户端、Provider、审计、登录历史、可信设备、公告与站内消息、运行时主题和品牌设置。
- **可靠性与运维**：PostgreSQL + Redis、多实例运行时协调、事务 outbox、动态限流、Prometheus 指标、可选 OTLP、媒体本地存储或私有 S3。

## 技术栈

| 层次 | 技术 |
| --- | --- |
| 服务端 | Go 1.26.6、Chi、pgx、go-redis |
| 数据 | PostgreSQL 16、Redis 7、嵌入式版本化迁移 |
| Web | SvelteKit、Svelte 5、TypeScript、Vite |
| 部署 | Docker Compose、非 root 容器、外部 TLS 反向代理 |

## 快速开始

### 前置条件

- Docker Engine 与 Compose v2
- 需要本机原生开发时：Go 1.26.6、Node.js 24+、PostgreSQL 16+、Redis 7+

### 使用开发 Compose

在仓库根目录运行：

```powershell
docker compose up -d --build
docker compose ps
curl.exe --fail http://localhost:8080/readyz
```

打开 <http://localhost:8080>。空数据库的本地 bootstrap 账号是 `admin`，默认密码是 `local-dev-only-admin`；首次登录后必须立即修改密码。这些值只适用于本机开发，不能用于公网或共享环境。

查看应用日志：

```powershell
docker compose logs --follow nyauth
```

停止开发栈使用 `docker compose down`，它会保留 PostgreSQL 和媒体 volume。不要在未确认数据和备份的情况下使用 `docker compose down -v`。

### 原生开发

前端构建产物会被嵌入 Go 二进制。先安装依赖并生成 `web/build`：

```powershell
Set-Location web
npm ci
npm run check
npm run build
Set-Location ..
```

复制 [`config.example.yaml`](config.example.yaml) 为本地配置，并通过环境变量提供数据库、Redis、master key 和 bootstrap 密码。迁移账号与运行账号应保持独立；生产环境的完整配置、代理和启动顺序见 [单机部署手册](docs/operations/single-host-deployment.md)。

## OAuth/OIDC 集成

Nyauth 不要求专有 SDK。业务服务应从 Discovery 获取端点，并在服务端使用成熟的 OAuth/OIDC 库；浏览器只持有业务应用自己的 HttpOnly 会话。

常用端点：

| 用途 | 端点 |
| --- | --- |
| OIDC Discovery | `/.well-known/openid-configuration` |
| JWKS | `/.well-known/jwks.json` |
| 授权 | `/authorize` |
| 令牌 | `/token` |
| UserInfo | `/userinfo` |
| Device Authorization | `/device_authorization` |

集成方必须生成并绑定 `state`、`nonce` 和 PKCE verifier，只使用 `S256`，并验证 ID Token 的签名、`kid`、issuer、audience、时间、nonce 和 `token_use`。不要在浏览器的 `localStorage` 中保存 access token、refresh token 或 ID Token。

详细参数、Step-Up、Scope/Claim 和推荐客户端库见 [标准 OAuth/OIDC 集成指南](docs/oauth-oidc-integration.md)。

## 部署与运维

生产环境应使用公开 HTTPS issuer、受控反向代理和不可变镜像 digest；PostgreSQL、Redis、应用端口和 `/metrics` 不应暴露到公网。代理转发头必须重建，`NYAUTH_TRUSTED_PROXY_CIDRS` 只信任实际代理地址。

- [单机部署](docs/operations/single-host-deployment.md)：Docker Compose、secret、升级、回滚和外部依赖
- [高可用部署](docs/operations/high-availability.md)：双实例、共享 Redis/S3 和运行时协调
- [备份与恢复](docs/operations/backup-restore.md)：PostgreSQL、JWK、master key、媒体和恢复演练
- [动态邮件](docs/operations/runtime-mail.md)：候选配置、真实测试、激活、回滚和熔断
- [运行时可观测性](docs/operations/runtime-observability.md)：日志、告警阈值和 OTLP
- [运行时人机验证](docs/operations/human-verification.md)：Turnstile 配置、故障语义和紧急禁用
- [公告与站内消息](docs/operations/communications-center.md)：草稿、发布、受众、已读和实时更新
- [安全头像媒体契约](docs/avatar-storage-design.md)：输入限制、重编码、本地媒体和私有 S3

生产升级前必须备份需要保留的数据，并核对目标镜像要求的 schema version。应用和迁移命令不会自动删除 volume 或清空 S3。

## 项目结构

```text
cmd/                 CLI 与服务入口
internal/             认证、授权、账户、OAuth、运行时和基础设施模块
migrations/           版本化 PostgreSQL 迁移
web/                  SvelteKit 管理后台与认证界面
docker-compose*.yml   开发、生产、HA、外部依赖和 E2E 拓扑
docs/                 集成、设计、部署、备份与运维文档
```

## 验证

服务端：

```powershell
go test -race ./...
go vet ./...
```

前端：

```powershell
Set-Location web
npm ci
npm run check
npm run test:unit
npm run build
```

首次运行浏览器 E2E 时，先执行 `npx playwright install chromium`，再执行 `npm run test:e2e`。

## 文档入口

- [变更记录](CHANGELOG.md)
- [API v1 设计](docs/api-v1-design.md)
- [OAuth/OIDC 集成](docs/oauth-oidc-integration.md)
- [媒体存储设计](docs/avatar-storage-design.md)
- [项目审查记录](docs/project-review-2026-07-28.md)

## 许可证

MIT
