# Passkey/TOTP 与自助注册/邀请制实施状态

> 状态：Phase R、Phase S 与 Phase T 已完成；Phase P 是下一阶段（2026-07-27）。下文 Phase R 的早期数据模型草图仅保留设计背景，当前注册/邀请契约以 README 和实现为准。所有行为开关继续使用运行时设置，配置文件不新增业务开关。

## 0. 顺序建议

1. **Phase R：自助注册 + 邀请制**（先做——是接入真实应用的前置条件，且完全复用已有的邮件/token/限流基础设施，无新外部依赖）
2. **Phase T：TOTP + 恢复码**（已完成）
3. **Phase P：Passkey/WebAuthn**（下一阶段——引入 go-webauthn 库与浏览器 API，联调面最大）

三个阶段各自独立发布，中途可穿插其他工作。

## 1. Phase R：自助注册 + 邀请制

### 运行时设置（新增 `registration` 设置组，全部后台可改）

| 键 | 默认 | 说明 |
|---|---|---|
| `mode` | `closed` | `closed`（现状，仅管理员建号）/ `invite_only` / `open` |
| `require_email_verification` | `true` | 注册后必须完成邮箱验证才算 `active`（`open` 模式强制为 true，不可关） |
| `allowed_email_domains` | `[]` | 非空时仅允许这些域名的邮箱注册（如 `["corp.example.com"]`） |
| `default_role` | `user` | 固定 `user`，仅展示不可改（防呆） |
| `invite_default_ttl` | `168h` | 新建邀请的默认有效期 |
| `invite_default_max_uses` | `1` | 新建邀请的默认可用次数 |

约束校验：`mode != closed` 时要求动态邮件状态 `configured=true`（否则拒绝保存该设置并提示）；真正注册时还要求 `available=true`。SMTP 熔断打开时在创建用户前返回 `503` 和 `Retry-After: 60`。邮件配置来源与状态语义见 [动态 SMTP 配置与故障处理](operations/runtime-mail.md)。注册端点始终挂账号动作限流器（复用 `AccountActionLimiter`）。

### 数据模型（迁移 000004）

```sql
CREATE TABLE invites (
    id UUID PRIMARY KEY,
    code_hash TEXT NOT NULL UNIQUE,        -- SHA-256，明文只在创建时返回一次
    created_by UUID NOT NULL REFERENCES users(id),
    note TEXT NOT NULL DEFAULT '',
    max_uses INT NOT NULL DEFAULT 1,
    used_count INT NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- users 增加 pending_verification 场景复用现有 status='pending'（baseline 已有该枚举值）
```

### 流程

- `POST /api/register`（公开，CSRF 同源校验 + 限流）：按 mode 分支——closed 直接 403；invite_only 要求有效邀请码（原子 `used_count` 递增，防并发超用）；open 直接进入。创建 `status='pending'` 用户 → 发验证邮件（复用 account 包）→ 验证完成置 `active` 并消耗邀请
- 未验证的 pending 用户不能登录（登录处已有 status 检查，需确认 pending 分支文案）；过期未验证的 pending 用户由 `maintenance` 清理（如 72h）
- 管理端：`GET/POST/DELETE /api/admin/invites`（创建返回一次性明文 code + 可分享链接 `/register?invite=...`）；后台"邀请管理"页；注册开关放进系统状态页设置区
- 登录页在 mode != closed 时显示"注册"入口；注册页按 mode/邀请码状态渲染
- 审计事件：`user.registered`、`invite.created/revoked/consumed`

## 2. Phase T：TOTP + 恢复码（已完成）

### 运行时设置（新增 `security` 组）

| 键 | 默认 | 说明 |
|---|---|---|
| `totp_enabled` | `true` | 是否允许用户启用 TOTP |
| `require_mfa_for_admins` | `false` | 管理员登录必须完成第二因素（开启前校验所有 admin 已配置 MFA，否则拒绝保存并列出未配置者） |

### 已实现契约

- 迁移 `000007_totp_mfa` 新增 `user_totp_credentials` 与 `user_recovery_codes`。TOTP secret 使用 master key envelope encryption，AAD 绑定用户 ID；恢复码以随机 selector 定位单行，再用 Argon2id 校验完整值。
- 标准参数为 RFC 6238 / SHA-1 / 30 秒 / 6 位 / `±1` 窗口。最近成功 time-step 在 `FOR UPDATE` 事务内推进，相同或更旧 step 会作为重放拒绝。
- 启用时生成 10 枚恢复码并只返回一次；恢复码原子消费，重新生成会让旧集合全部失效。
- 密码和外部 Provider 登录都先建立独立 Redis `mfa_pending` 状态，而不是完整 session。Cookie 为 `nyauth_mfa_pending`，TTL 5 分钟，不进入用户 session set、设备列表或活跃会话统计。
- MFA pending 支持 `login` 与 `reauthentication` 两种 purpose。密码/Provider 重新认证也必须完成已绑定的第二因素，主因素本身不会刷新近期认证时间。
- MFA pending CSRF 与正式 session CSRF 完全分离；验证和取消接口显式使用 challenge CSRF，不会覆盖或清空仍有效的正式会话令牌。
- 启用/停用 TOTP 会在同一 PostgreSQL 事务中推进 `auth_version` 并写审计 outbox，随后清理旧 session/refresh family 并轮换当前会话。
- 管理员强制策略通过 PostgreSQL advisory lock 与管理员角色/状态变更、TOTP 停用协调。开启前列出所有缺少 MFA 的活动管理员；开启后不能将无 MFA 用户激活或晋升为管理员，活动管理员不能停用 TOTP。
- 动态 `security` 设置通过 `LISTEN/NOTIFY` 与一分钟 reconciliation 在多实例同步，不要求重启。
- `verify-recovery` 会只读认证所有已存 TOTP envelope；错误 master key 或被篡改密文会使恢复演练失败。

### API

- 公开：`GET/POST/DELETE /api/login/mfa`
- 当前用户：`GET /api/me/mfa`、`POST /api/me/mfa/totp/enroll`、`POST /api/me/mfa/totp/enroll/confirm`、`POST /api/me/mfa/recovery-codes`、`DELETE /api/me/mfa/totp`
- 管理：`GET/PUT /api/admin/settings/security`

### 审计与测试

- 审计：`mfa.enrolled`、`mfa.disabled`、`mfa.challenge_failed`、`recovery_code.used`、`recovery_code.regenerated`。
- 集成测试覆盖密码与 Provider 登录、密码与 Provider reauth、TOTP 防重放、恢复码一次性消费、MFA pending 不计入 session、被撤销 session 不会被 reauth 复活、管理员策略并发不变量与恢复验证。
- 前端覆盖登录 challenge、内联 reauth challenge、取消时正式 CSRF 保留，以及 TOTP 启用/恢复码替换/停用流程。

## 3. Phase P：Passkey/WebAuthn

- 库：`github.com/go-webauthn/webauthn`（Go 生态事实标准）
- RP ID/origin 取自 `auth.issuer`（又一个 issuer 必须等于公开域名的理由）
- 新迁移计划为 `000008_passkeys`：保存 credential ID、公钥、sign count、transports、AAGUID、自定义名称、backup state 与 created/last_used 时间
- 能力：① 独立登录方式（discoverable credential + 浏览器 conditional UI，登录页"使用通行密钥登录"）② 已登录用户的 step-up 重新认证手段（并入 reauth 框架，与密码/Provider reauth 并列）③ 作为 MFA 第二因素
- 运行时设置：`security.passkeys_enabled`（默认 true）
- 注册/删除通行密钥要求近期重新认证；删除最后一个凭据时校验用户还有其他登录方式（复用 identity 的"最后认证方式"检查思路）
- 审计：`passkey.registered/removed/login`

## 4. 统一原则

- 所有开关经由 runtime_settings（管理后台编辑 + LISTEN/NOTIFY 同步 + 配置默认值兜底），保存时做跨依赖校验（如动态邮件未配置不能开放注册）
- 所有敏感操作（启停 MFA、生成邀请、注册凭据）走 CSRF + mutation audit + 近期重新认证
- 每阶段交付含：迁移（发布时并入基线）、Go 单测/集成测试、Playwright e2e、CHANGELOG、README API 表更新
