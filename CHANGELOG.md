# Changelog

本文件记录 nyauth 的重要变更，格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [0.5.0] — 2026-07-31

### 新增

- 客户端级可选 Scope 声明、必需/可选权限分组 Consent、标准 OIDC Claim 明细和按用户选择收敛的授权码、Token 与授权记录
- 运行时 Scope Catalog、客户端级 Claim 白名单、Scope/Claim 管理员专属分配策略，以及生产可用的管理员 OAuth 流程测试台
- `email` Scope 在 ID Token 与 UserInfo 中返回持久化的 `email_verified`，并在 Discovery 中明确声明
- 运行时人机验证适配器，首个 Provider 为 Cloudflare Turnstile；支持候选保存、真实验证、十分钟激活门槛、回滚、禁用、加密 Secret 和多实例同步
- 人机验证未配置时使用通用保护基线：公开注册、密码恢复、验证邮件重发和 Provider 登录默认保护，密码登录采用三次失败后触发的 Adaptive 模式；已保存策略不会被覆盖
- 可独立保护自助注册、密码登录、密码恢复、验证邮件重发和 Provider 登录；密码登录支持关闭、失败次数触发或每次必须验证
- `nyauth human-verification disable -reason <text>` 紧急恢复命令、管理状态卡、低基数 Prometheus 指标和审计事件
- OAuth 客户端发布者可信状态：用户自助客户端默认未验证，管理员可在近期重新认证后审核或撤销；Consent 区分系统管理、已审核和未验证应用

### 变更

- 正式发布 `0.5.0`；新增兼容迁移 `000010_human_verification` 至 `000013_oauth_publisher_trust`，schema version 从 9 提升到 13，可从 `0.4.0-rc.1` 或正式 `v0.3.0` 依次迁移
- 禁用人机验证时保留当前验证器配置和策略，并提供语义独立的重新启用操作

### 已知限制

- `/api/v1`、Service Account、OpenAPI、事件 Webhook、自动更新和用户组不包含在本候选版本中
- 发布者可信状态是部署管理员的人工审核结论，不代表自动完成 DNS、TLS 或域名所有权验证
- issuer、签名密钥、数据库/Redis 连接、可信代理和本地媒体目录仍属于部署拓扑配置，修改后需要受控重启

## [0.4.0-rc.1] — 2026-07-31

### 新增

- Phase C1 运行时服务控制：六类固定 capability、四种维护预设、实时公开维护横幅、可选到期恢复、revision 冲突保护和独立 `operating_state`
- 多实例安全排空：进程内 gate 与 in-flight 计数、PostgreSQL 心跳和应用进度、`LISTEN/NOTIFY`、5 秒 reconciliation、15 秒失联 fail-closed 以及单 leader 到期审计
- `GET /api/service-status`、`GET /api/service-status/events` SSE、`GET/PUT /api/admin/settings/operations` 与 `nyauth service-control reset -reason <text>` 紧急解锁命令
- Phase C2 运行时运营策略：动态限流、浏览器会话和 Token 生命周期、近期认证期限、审计保留策略，以及全局和每用户 OAuth 客户端配额
- Phase C3 运行时媒体存储：私有 S3 候选测试、可续跑迁移、失败重试和迁回部署时本地存储；凭据使用 envelope encryption 且永不回显
- Phase C4 认证生命周期：动态会话空闲期限、并发会话淘汰、Access/Refresh Token 与授权码期限，并提供审计化 MFA 恢复 CLI
- Phase C5 OAuth 客户端策略：动态控制自助创建、Public Client、Grant、标准/自定义 Scope 和 Redirect URI 数量，同时保留既有客户端的收紧兼容语义
- Phase C6 沟通设置：结构化事务邮件模板、真实测试邮件，以及支持 Markdown、独立起止时间和 SSE 实时更新的全站横幅
- Phase C7 运行时可观测性：日志基线、临时 Debug、固定低基数运营告警，以及带不可变候选、真实测试、激活、回滚和禁用状态机的动态 OTLP
- 管理员可在近期重新认证后修改用户账号名；新增审计化 MFA 恢复和管理员账号恢复路径

### 变更

- 版本进入 `0.4.0-rc.1`；新增兼容迁移 `000004_runtime_service_control` 至 `000009_runtime_observability`，schema version 从 3 提升到 9，可从正式 `v0.3.0` 依次迁移
- 受控请求在能力暂停时返回稳定错误码 `service.capability_paused`、HTTP 503 和 `Retry-After`；主动维护不改变 `/readyz`

### 修复

- 系统状态和可观测性响应在没有活动告警时稳定返回空数组，避免管理页面读取 `null.length` 而崩溃
- 管理筛选输入避免密码管理器自动填充，Provider 登录入口统一显示内置或配置的品牌图标

### 已知限制

- `/api/v1`、Service Account、OpenAPI、事件 Webhook、自动更新和用户组不包含在本候选版本中
- issuer、签名密钥、数据库/Redis 连接、可信代理和本地媒体目录仍属于部署拓扑配置，修改后需要受控重启

## [0.3.0] — 2026-07-28

> [!CAUTION]
> 0.3.0 是破坏性开发基线，不提供旧数据库、配置、接口或 SDK 的兼容层。升级前请备份需要保留的数据。

### 新增

- 账户安全中心：设备会话管理、OAuth 授权管理、近期重新认证（密码 / 外部 Provider）、邮箱验证与变更、密码找回；全部邮件操作使用一次性 token，且只在用户主动确认后消费
- 邮件子系统：SMTP 发送、email outbox 与安全通知；新增 PostgreSQL 不可变候选版本、真实测试邮件、十分钟激活门槛、免重启切换/回滚/禁用、密码 envelope encryption、跨实例同步和 HA 共享熔断；outbox 领取会在同一事务校验活动 sender，永久收件人/消息拒绝进入不重试的 `rejected` 终态并清除密文；`NYAUTH_MAIL_*` 与 password file 仅作为首次 fallback/bootstrap
- 运维能力：`maintenance` 子命令（审计月分区预建、保留策略、outbox 清理）、`verify-recovery` 只读恢复校验、严格 readiness、内部 Prometheus `/metrics`、可选 OTLP 指标导出
- 审计：月分区表、审计 outbox、审计导出接口
- 数据库双角色：迁移账号执行 DDL，运行时账号最小权限；`serve` 不再执行任何 DDL
- 品牌：接入 nyauth 猫猫 logo（favicon 与 Web UI 品牌区）
- 运行时设置：`runtime_settings` 表与跨实例同步（LISTEN/NOTIFY + 定时对账）；首个消费者为品牌设置（站点名称 / Logo URL），管理后台"系统状态"页可编辑，免重启即时生效
- 每客户端访问策略：`open`（默认）/ `admins_only` / `allowlist`（用户白名单）；授权端点拒绝名单外用户（`access_denied` + 审计），refresh 与 access token 校验时复查策略——被移出名单的用户令牌在下次使用时即失效；机器流程（client_credentials）不受限；管理后台可编辑策略与访问名单
- 自助注册与邀请制：注册模式（`closed` 默认 / `invite_only` / `open`）、邮箱验证要求、域名白名单、`pending_registration_ttl` 与邀请默认值均为跨实例运行时设置；用户、注册记录、邀请码预占、验证 Token、邮件 outbox 和审计事件同事务提交；邀请码在验证后消耗，删除或自动清理 pending 用户会释放预占；公开重发接口不可枚举且不延长截止时间；服务启动后及每小时执行 HA 安全的有界清理，`maintenance` 复用同一逻辑兜底；创建邀请和修改注册策略要求近期重新认证，吊销不要求；新增 `invite.reserved`、`invite.consumed`、`invite.reservation_released` 与 `registration.expired` 审计事件
- 邮件运行状态与注册联动：`GET /api/registration` 返回 `available`；SMTP 未配置、禁用或熔断时注册在创建用户前返回 `503`，熔断附带 `Retry-After: 60`；注册事务、注册策略变更与 SMTP 禁用通过 PostgreSQL 共享/独占协调锁线性化，防止多实例旧快照越过安全约束；SMTP 降级显示在管理员系统状态中但不影响 `/readyz`、登录或 OAuth/OIDC
- TOTP 多因素认证：支持恢复码、登录与近期重新认证 challenge、重放防护、管理员强制 MFA 策略，以及认证状态变化后的会话轮换和撤销
- Passkey / WebAuthn：支持 discoverable 与 Conditional UI 登录、作为第二因素及近期重新认证、凭据注册和管理、跨实例 ceremony 单次消费，以及管理员 Passkey/MFA 策略
- 恢复验证覆盖活动 JWK、Provider、TOTP、Passkey 与邮件密文，并要求备份 manifest 独立核对 Passkey 行数
- 安全头像媒体：浏览器 1:1 裁剪，服务端签名、尺寸、像素和动画校验后重编码四种 WebP；支持本地持久 volume、私有 S3、Provider 首次异步导入、SSRF 防护和 HA 安全清理
- 路由化个人中心与管理员用户详情：资料、安全、会话、授权、身份、客户端和精确用户活动分离为可深链页面；品牌、注册、邮件和安全设置拆页
- 审计体验：静态筛选目录、单一日期时间范围选择器、1/7/14/30 天快捷范围、URL 同步、精确 subject/target 筛选、筛选 chips、详情抽屉、User-Agent、递归脱敏和筛选一致的 NDJSON/CEF 导出
- 高可用与备份恢复文档、OAuth/OIDC 集成指南（`docs/`）

### 变更（破坏性）

- 第一方后台仅使用 `HttpOnly + SameSite=Lax` 会话 Cookie，修改请求强制 CSRF 校验
- OAuth 授权码客户端强制 PKCE S256；不支持 plain、implicit、hybrid
- JWT 固定 RS256；refresh token 采用 family 轮换与重复使用检测
- 数据库迁移以嵌入式 `000001` 建立破坏性基线，并通过兼容的 `000002_provider_presentation`、`000003_security_revocation_outbox` 演进到 schema version 3；`serve` 启动只校验 schema 版本
- 配置严格解码：未知字段导致启动失败；敏感项统一支持 `*_FILE` 注入
- 环境变量统一 `NYAUTH_` 前缀与下划线层级

### 移除

- Go / TypeScript SDK（`sdk/`）：集成方式改为标准 OAuth/OIDC Discovery、成熟语言库与 BFF 会话模式
- 旧多文件开发迁移序列（000001–000010）与 `/health` 路由（由 `/livez`、`/readyz` 取代）

### 修复

- 登录趋势图表因 Svelte 5 `$state` 代理与 Chart.js 不兼容而从不渲染
- 窗口从移动断点拖宽后桌面侧边栏无法恢复展开
- 审计筛选中的主体用户 ID、目标 ID 和 IP 地址误用等宽字体，并以两个原生时间输入拆散范围选择
- Redis 暂时不可用时，用户安全世代变更对应的会话与 refresh family 撤销任务可能缺少持久重试；现由 PostgreSQL outbox、lease、revision 和有界退避保证恢复后完成
- 审计详情允许安全的 MFA 布尔/计数元数据，同时拒绝并脱敏精确的 credential、恢复码、TOTP seed 和密钥字段
- 升级 `google.golang.org/grpc` 至 `v1.82.1`，修复 `govulncheck` 确认可达的 `GO-2026-6061`
- 仓库行尾统一为 LF（CRLF 曾导致 postgres init 脚本在容器内失败）

## [0.2.0] — 2026-07

不兼容的安全基线版本：控制面迁移到会话 + CSRF 认证、OAuth 强制 S256 与 token 轮换、外部身份 Provider 加固、配置与迁移基线重建、Web SDK CI 与运维更新。

## [0.1.0] — 2026-07

初始版本：OAuth 2.0 Authorization Server（Authorization Code + PKCE、Client Credentials、Refresh Token）、OIDC Provider（Discovery、JWKS、UserInfo 等）、用户/客户端/Provider 管理后台、用户仪表盘与自助应用创建、GitHub/Google/通用 OIDC 外部登录、Docker 部署。
