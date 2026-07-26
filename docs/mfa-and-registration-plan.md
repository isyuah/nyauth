# Passkey/TOTP 与自助注册/邀请制 实施计划（草案）

> 状态：**待用户确认**（2026-07-26）。原则：所有行为开关都是**运行时设置**（`runtime_settings`，管理后台编辑、免重启、跨实例同步），配置文件不新增字段。

## 0. 顺序建议

1. **Phase R：自助注册 + 邀请制**（先做——是接入真实应用的前置条件，且完全复用已有的邮件/token/限流基础设施，无新外部依赖）
2. **Phase T：TOTP + 恢复码**（次之——纯服务端实现，简单可靠）
3. **Phase P：Passkey/WebAuthn**（最后——引入 go-webauthn 库与浏览器 API，联调面最大）

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

约束校验：`mode != closed` 时要求 `mail.enabled`（否则拒绝保存该设置并提示）；注册端点始终挂账号动作限流器（复用 `AccountActionLimiter`）。

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

## 2. Phase T：TOTP + 恢复码

### 运行时设置（新增 `security` 组）

| 键 | 默认 | 说明 |
|---|---|---|
| `totp_enabled` | `true` | 是否允许用户启用 TOTP |
| `require_mfa_for_admins` | `false` | 管理员登录必须完成第二因素（开启前校验所有 admin 已配置 MFA，否则拒绝保存并列出未配置者） |

### 设计

- 迁移 000005：`user_mfa`（TOTP secret 用 master key envelope 加密）+ `recovery_codes`（argon2id 哈希，一次性）
- 标准 TOTP（RFC 6238，30s/6 位，±1 窗口），防重放：记录最近成功的 time-step
- 登录流：密码/外部身份验证成功 → 若用户有 MFA → 会话进入 `mfa_pending` 半状态（不发全量会话）→ `POST /api/login/mfa` 校验 TOTP 或恢复码 → 升级为完整会话；`mfa_pending` 状态只能访问 MFA 校验端点
- 启用/停用 TOTP 要求近期重新认证（复用 reauth 框架）；启用时生成 10 个恢复码（一次性显示）
- 个人资料"安全"区新增 MFA 卡片：启用向导（QR + 手动密钥 + 首次校验）、恢复码重新生成、停用
- 审计：`mfa.enrolled/disabled/challenge_failed`、`recovery_code.used`

## 3. Phase P：Passkey/WebAuthn

- 库：`github.com/go-webauthn/webauthn`（Go 生态事实标准）
- RP ID/origin 取自 `auth.issuer`（又一个 issuer 必须等于公开域名的理由）
- 迁移 000006：`webauthn_credentials`（credential_id、公钥、sign_count、transports、aaguid、自定义名称、created/last_used_at）
- 能力：① 独立登录方式（discoverable credential + 浏览器 conditional UI，登录页"使用通行密钥登录"）② 已登录用户的 step-up 重新认证手段（并入 reauth 框架，与密码/Provider reauth 并列）③ 作为 MFA 第二因素
- 运行时设置：`security.passkeys_enabled`（默认 true）
- 注册/删除通行密钥要求近期重新认证；删除最后一个凭据时校验用户还有其他登录方式（复用 identity 的"最后认证方式"检查思路）
- 审计：`passkey.registered/removed/login`

## 4. 统一原则

- 所有开关经由 runtime_settings（管理后台编辑 + LISTEN/NOTIFY 同步 + 配置默认值兜底），保存时做跨依赖校验（如 mail 未启用不能开注册）
- 所有敏感操作（启停 MFA、生成邀请、注册凭据）走 CSRF + mutation audit + 近期重新认证
- 每阶段交付含：迁移（发布时并入基线）、Go 单测/集成测试、Playwright e2e、CHANGELOG、README API 表更新
