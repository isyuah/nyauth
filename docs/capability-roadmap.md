# 能力路线图（0.4+ 展望）

> 状态：更新于 2026-07-29。本文档记录"网站自身能力"的增强方向与取舍结论，按优先级排序。

## 结论摘要

| 方向 | 结论 | 优先级 |
|---|---|---|
| 运行时服务控制 | Phase C1 已完成：六类能力暂停、维护预设、HA 排空、定时恢复与 CLI 紧急解锁 | 已完成 |
| 运行时设置（部分配置免重启） | Phase C2–C6 已实现运营策略、受控媒体迁移、认证生命周期、OAuth 客户端策略、事务邮件模板与全站横幅；部署拓扑配置仍需重启 | 已完成当前阶段 |
| 受控头像存储 | 已完成——本地持久化 / 私有 S3、裁剪重编码、Provider 安全导入 | 已完成 |
| 账户与后台信息架构 | 已完成——路由化个人中心、用户详情与设置拆分 | 已完成 |
| 审计体验 | 已完成——精确筛选、URL 状态、详情与一致导出 | 已完成 |
| 每客户端访问策略 | 已完成——支持 open、admins_only 和 allowlist，并在授权与用户 Token 使用时持续执行 | 已完成 |
| TOTP + 恢复码 | Phase T 已完成：登录、reauth、管理员强制策略、恢复验证 | 已完成 |
| Passkey/WebAuthn | Phase P 已完成：独立登录、Conditional UI、MFA、step-up 与安全中心管理 | 已完成 |
| 自助注册 / 邀请制 | Phase R 已完成：关闭 / 邀请制 / 开放注册、验证与邀请预占生命周期 | 已完成 |
| 事件 Webhook | 做——作为插件系统的替代品，复用审计 outbox | P2 |
| 插件系统 | **不做进程内插件**；先观察 Webhook + /api/v1 能覆盖多少扩展需求 | 推迟 |
| UI 国际化（中/英） | 视下游需求再做 | 推迟 |

## 1. 运行时服务控制（Phase C1 已完成）

- 固定控制 `self_registration`、`account_mutations`、`admin_mutations`、`auth_issuance`、`mail_delivery` 和 `media_writes` 六类能力，不以粗粒度的全站下线代替业务边界。
- 管理界面提供正常运行、只读维护、认证维护和全面暂停四个预设，也可单独组合能力；预设名不持久化，数据库只保存事实状态。
- 每个实例先关闭 gate，再排空旧 in-flight；PostgreSQL revision、心跳、`LISTEN/NOTIFY` 和 reconciliation 提供多实例一致性，失联实例 fail-closed。
- 支持 1 分钟至 30 天的到期恢复或显式无限期；CLI `service-control reset` 是不依赖管理 UI 的审计化紧急解锁路径。
- 主动维护不污染 `/readyz`。Discovery、JWKS、UserInfo、introspection、revoke、logout、安全撤销、审计和清理始终可用。

## 2. 运行时设置（P0）

**用户诉求**：改运营配置不想每次编辑文件 + 重启。

**判断**：对认证服务器，"全量配置热重载"是反目标——issuer、签名密钥、数据库/Redis 连接、可信代理这类配置的变更语义就应该是"重启生效"：重启是原子的、可审计的、可回滚的，而热重载这些项会产生半旧半新的中间态（例如 issuer 换了但已发 JWT 的 `iss` 没换）。会话都在 Redis/PG 里，重启本身零用户影响、秒级完成。

真正值得免重启的是**运营型设置**：品牌（标题/Logo）、注册策略、邮件发送配置、限流阈值、审计保留时长等——这些本质是"数据"而不是"部署形态"。当前实现：

- 通用 `runtime_settings` 已承载品牌、注册、安全、访问保护、生命周期和 OAuth 客户端策略。六组设置统一使用 revision CAS，管理变更走 CSRF、近期重新认证、固定代码级限流和事务审计。
- SMTP 因为包含加密 secret、不可变候选、真实测试门槛、回滚和共享熔断，使用专门的版本表与 singleton 状态，而不是塞入通用 JSON 设置；详见 [动态 SMTP 配置与故障处理](operations/runtime-mail.md)。
- 多实例使用 PostgreSQL `LISTEN/NOTIFY` 和定时 reconciliation；静态邮件环境变量只作为首次 fallback/bootstrap。
- 登录、账户操作、头像和 SMTP 管理限流可动态调整或按组关闭；revision 隔离 Redis 计数。全局客户端配额与用户覆盖值在数据库事务中防止并发超发。
- 浏览器会话绝对/空闲期限、每用户并发会话上限、近期认证期限、Access/Refresh Token 和授权码期限均可动态调整。空闲活动续期不会突破绝对期限；降低并发上限后在用户下一次登录时原子淘汰最旧会话。Token 策略只影响之后新签发或轮换的凭据，不批量改写或恢复现有凭据。
- 审计保留天数可动态调整；缩短只保存策略，删除仍由受控 `maintenance` 执行。
- OAuth 客户端策略可动态控制自助创建、Public Client、可新增 Grant/Scope 和 URI 上限。策略收紧只约束后续创建和扩展，不停用既有客户端；客户端写入与策略 revision 使用事务锁建立明确提交边界。
- 沟通设置可动态管理结构化事务邮件模板和一个全站横幅。模板只开放纯文本字段和按字段授权的变量，动作链接、有效期说明及 HTML 外壳固定由服务端生成；全站横幅支持开始与结束时间独立省略、严重程度、按版本关闭与 SSE 实时同步，公开 API 使用 `/api/site-banner`。

## 3. 每客户端访问策略（已完成）

OAuth 客户端已支持 `open`、`admins_only` 和 `allowlist`。策略在用户授权流程和后续用户 Token 使用时持续执行，白名单移除无需等待既有 access token 自然过期；`client_credentials` 机器流程不受用户访问策略影响。管理后台可维护策略和白名单，并对拒绝和名单变更写入审计。

## 4. 受控头像存储（已完成）

用户和管理员上传的图片会在浏览器完成 1:1 裁剪，再由服务端独立校验、解码、重编码并生成固定尺寸变体；默认使用本地持久化目录，HA/远程部署支持私有 S3 兼容对象存储。浏览器只加载 Nyauth 管理的稳定地址，Provider 头像只在首次创建账号时通过 SSRF 防护管线异步导入，不透传外部 URL。

完整威胁模型、数据模型、API、对象回收和存储边界见 [受控头像存储与对象存储设计](avatar-storage-design.md)。

## 5. MFA（Phase T/P 已完成）

- TOTP 已实现 RFC 6238、time-step 防重放、一次性恢复码、密码/Provider MFA 与 step-up、动态管理员强制策略和 HA 同步。
- Passkey 已支持 discoverable 独立登录、Conditional UI、MFA 第二因素、近期重新认证与安全中心管理；RP ID 和 origin 从公开 `auth.issuer` 固定派生。
- 完整 WebAuthn credential 加密存储，每次认证在事务中持久化 sign count、clone warning 与 backup state；Redis ceremony 使用不透明 ID，并与 MFA pending 原子消费。
- 管理员强制 MFA 接受 TOTP 或当前 RP Passkey；两个注册开关都是运行时 enrollment 开关，不会停用已有因素。

## 6. 自助注册 / 邀请（已完成）

- 邀请码/邀请链接由管理员生成，支持限次、限期、预占、验证后消费和过期释放。
- 支持关闭、邀请制和开放注册；开放注册强制邮箱验证，SMTP 不可用时注册在创建用户前返回 `503`。
- 注册策略是运行时设置，并与动态 SMTP 的 configured/available 状态做跨依赖校验。

## 7. 事件 Webhook（P2）——插件系统的替代品

**为什么不做进程内插件**：认证服务器的插件意味着第三方代码进入信任边界内——能触碰会话、密钥和用户数据，这与 0.3.0 整个安全加固方向相悖；Go 的 `plugin` 机制在 Windows 上不可用、跨版本脆弱；wasm/进程外插件的工程成本远超当前收益。

**替代路径**（覆盖插件的绝大多数真实用途）：

1. **事件出站**：审计 outbox 已经存在——加一个 Webhook 投递器（HMAC 签名、重试、死信），外部系统订阅 `user.created`、`login.failed` 等事件后可自行做通知、风控、同步
2. **管理自动化**：`/api/v1` + Service Account（已有设计草案）
3. **协议扩展**：OIDC 本身的 scope/claims 是标准扩展点，将来按需支持自定义 claim 映射（配置驱动，不是代码插件）

若未来出现三条路径都覆盖不了的需求，再评估进程外插件（gRPC 子进程模型），届时有 Webhook 的经验打底。

## 实施顺序建议

```
当前 0.4.0-dev: Phase C1 已验收，Phase C2–C6 已实现；C6 待用户验收
下一步: Phase C7 动态日志级别、告警阈值与 OTLP 运营参数
后续: 自动更新、/api/v1、用户组和事件 Webhook 继续推迟
```
