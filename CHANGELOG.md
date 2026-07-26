# Changelog

本文件记录 nyauth 的重要变更，格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased] — 0.3.0-dev

> [!CAUTION]
> 0.3.0 是破坏性开发基线，不提供旧数据库、配置、接口或 SDK 的兼容层。升级前请备份需要保留的数据。

### 新增

- 账户安全中心：设备会话管理、OAuth 授权管理、近期重新认证（密码 / 外部 Provider）、邮箱验证与变更、密码找回；全部邮件操作使用一次性 token，且只在用户主动确认后消费
- 邮件子系统：SMTP 发送、email outbox、安全通知；仅通过 `NYAUTH_MAIL_*` 环境变量配置（配置文件中的 `mail.*` 会被拒绝）
- 运维能力：`maintenance` 子命令（审计月分区预建、保留策略、outbox 清理）、`verify-recovery` 只读恢复校验、严格 readiness、内部 Prometheus `/metrics`、可选 OTLP 指标导出
- 审计：月分区表、审计 outbox、审计导出接口
- 数据库双角色：迁移账号执行 DDL，运行时账号最小权限；`serve` 不再执行任何 DDL
- 品牌：接入 nyauth 猫猫 logo（favicon 与 Web UI 品牌区）
- 运行时设置：`runtime_settings` 表与跨实例同步（LISTEN/NOTIFY + 定时对账）；首个消费者为品牌设置（站点名称 / Logo URL），管理后台"系统状态"页可编辑，免重启即时生效
- 每客户端访问策略：`open`（默认）/ `admins_only` / `allowlist`（用户白名单）；授权端点拒绝名单外用户（`access_denied` + 审计），refresh 与 access token 校验时复查策略——被移出名单的用户令牌在下次使用时即失效；机器流程（client_credentials）不受限；管理后台可编辑策略与访问名单
- 高可用与备份恢复文档、OAuth/OIDC 集成指南（`docs/`）

### 变更（破坏性）

- 第一方后台仅使用 `HttpOnly + SameSite=Lax` 会话 Cookie，修改请求强制 CSRF 校验
- OAuth 授权码客户端强制 PKCE S256；不支持 plain、implicit、hybrid
- JWT 固定 RS256；refresh token 采用 family 轮换与重复使用检测
- 数据库迁移压缩为嵌入式单一 `000001` 基线；`serve` 启动只校验 schema 版本
- 配置严格解码：未知字段导致启动失败；敏感项统一支持 `*_FILE` 注入
- 环境变量统一 `NYAUTH_` 前缀与下划线层级

### 移除

- Go / TypeScript SDK（`sdk/`）：集成方式改为标准 OAuth/OIDC Discovery、成熟语言库与 BFF 会话模式
- 旧多文件迁移序列（000001–000008）与 `/health` 路由（由 `/livez`、`/readyz` 取代）

### 修复

- 登录趋势图表因 Svelte 5 `$state` 代理与 Chart.js 不兼容而从不渲染
- 窗口从移动断点拖宽后桌面侧边栏无法恢复展开
- 仓库行尾统一为 LF（CRLF 曾导致 postgres init 脚本在容器内失败）

## [0.2.0] — 2026-07

不兼容的安全基线版本：控制面迁移到会话 + CSRF 认证、OAuth 强制 S256 与 token 轮换、外部身份 Provider 加固、配置与迁移基线重建、Web SDK CI 与运维更新。

## [0.1.0] — 2026-07

初始版本：OAuth 2.0 Authorization Server（Authorization Code + PKCE、Client Credentials、Refresh Token）、OIDC Provider（Discovery、JWKS、UserInfo 等）、用户/客户端/Provider 管理后台、用户仪表盘与自助应用创建、GitHub/Google/通用 OIDC 外部登录、Docker 部署。
