# Nyauth 运行时人机验证

Nyauth 的人机验证使用 Provider 适配器边界，当前实现 Cloudflare Turnstile。管理员可以在不重启服务的情况下保存候选、完成真实挑战测试、激活、回滚或禁用。Turnstile Secret Key 使用 `auth.master_key` 信封加密，不会通过 API、日志、指标或审计返回。

## 前置条件

1. 在 Cloudflare Turnstile 创建 Widget，将生产 `auth.issuer` 的主机名加入允许列表。Nyauth 服务器会再次校验 Siteverify 返回的 `hostname` 和 `action`。
2. 浏览器必须能访问 `https://challenges.cloudflare.com`，Nyauth 服务器必须能访问同一域名的 `/turnstile/v0/siteverify`。
3. 完成 `000010_human_verification` 迁移。缺少迁移时 `serve` 会因 schema version 不匹配而拒绝启动。

## 激活流程

1. 以管理员身份打开“设置 → 人机验证”，填写 Site Key、Secret Key，并选择与 Cloudflare 控制台一致的 Widget 模式后保存候选。
2. 页面使用候选 Site Key 渲染真实 Widget，服务端使用同一候选的 Secret Key 调用 Siteverify。
3. 只能在同一候选版本测试成功后的十分钟内激活。测试超时、替换候选或 revision 冲突都要求重新读取状态并测试。
4. 激活时一并确认保护策略。之后可单独修改策略，或回滚到上一个活动配置。

Widget 模式由 Cloudflare 控制台中的 Site Key 决定，Nyauth 后台选择的模式必须与之保持一致。Nyauth 使用显式渲染来控制验证出现在哪个业务入口，但不会替代 Cloudflare 的模式决策。页面呈现遵循以下规则：

| Cloudflare Widget 模式 | Nyauth 页面呈现 |
|---|---|
| Managed | 使用 `interaction-only`；Cloudflare 判定需要交互时才显示 Widget，不预留固定空间。 |
| Non-interactive | 使用 `always`；持续显示 Cloudflare 的非交互验证过程并预留 Widget 高度。 |
| Invisible | 不显示 Widget、普通进度文字或空白占位；失败仍通过对应表单给出错误。 |

所有管理变更都需要管理员会话、CSRF、最近十分钟重新认证、固定代码级限流和 revision CAS，并与审计 outbox 在同一 PostgreSQL 事务提交。候选配置和测试记录是追加不可变数据；删除创建者只会将 actor 引用设为空，不会删除历史。

“禁用”只关闭运行开关，当前选定的验证器版本、加密 Secret 和保护策略都会保留。管理员可直接重新启用同一配置，不需要重新填写 Secret 或再次测试；“回滚”只用于切换到更早的不可变配置版本，不承担重新启用语义。

## 策略语义

新数据库尚未保存人机验证策略时，默认采用一套适合大多数公开站点的基线：自助注册、密码重置请求、验证邮件重发和 Provider 登录保护开启；密码登录采用 Adaptive 模式，在同一用户名或 IP 的连续失败达到 3 次后要求验证。这个默认值只用于“尚未配置”的状态；管理员已经保存过的策略不会在服务重启或升级时被覆盖。验证器本身仍默认为“已禁用”，必须先配置并成功测试 Provider，再由管理员激活。

| 入口 | 策略 |
|---|---|
| 自助注册 | 开启后每次提交都要求挑战。 |
| 密码登录 | `off`、`adaptive` 或 `always`。Adaptive 只计入无效凭据，正确密码但待验证邮箱的账户不会增加次数。 |
| 密码恢复 | 保护不可枚举的邮件请求入口。 |
| 验证邮件重发 | 保护不可枚举的公开重发入口。 |
| Provider 登录 | 开启后所有外部登录在跳转上游前验证；此时还不知道上游身份，无法只对首次开户验证。 |

现有 Redis 限流始终先于外部 Siteverify 执行，防止攻击者把 Cloudflare 调用变成无上限的外部资源消耗。Adaptive 登录使用独立的用户名摘要和 IP 摘要计数；人机验证策略 revision 变化后切换 Redis key namespace，旧计数自然过期。

## 故障与恢复

当某个入口的策略要求挑战时，浏览器未提交证明会收到 `428 human_verification.required`；挑战被拒绝返回 `422`；活动配置无法加载或 Siteverify 不可用时返回 `503`。必须挑战的入口 fail closed，但人机验证降级不改变 `/readyz`，不会下线已有会话、OIDC Discovery、JWKS 或 Token 验证。

若错误配置导致无法从管理页恢复，可在任一带同版本配置的容器中执行：

```bash
docker compose run --rm nyauth human-verification disable -reason "Turnstile incident recovery"
```

命令使用运行时 PostgreSQL 配置，原子关闭验证、保留当前配置、通知其他实例并写入高风险审计事件。已处于禁用状态时只返回 `changed=false`，不重复写审计。不要直接修改候选版本表或删除历史。

## 可观测性与隐私

Prometheus 记录有界的 Provider、动作、结果、原因和验证延迟，不使用用户名、邮箱、IP、Site Key、Token 或 idempotency key 作为标签。管理状态只显示 mode、configured、available 和 Provider；候选 Secret 和验证 Token 不得进入 sessionStorage、日志或审计 details。
