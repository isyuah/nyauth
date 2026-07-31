# Nyauth 标准 OAuth/OIDC 集成指南

Nyauth 以标准协议为正式集成契约，不要求使用专有 SDK。Web 应用默认采用 Backend for Frontend（BFF）：后端完成 OAuth/OIDC 流程，浏览器只持有应用自己的 `HttpOnly + Secure + SameSite=Lax` 会话 Cookie。

## 必须遵守的安全约束

- 从 `/.well-known/openid-configuration` 读取端点并验证返回的 `issuer` 与配置完全一致。
- Authorization Code 流程必须生成不可预测的 `state`、`nonce` 和 PKCE verifier。
- PKCE 只使用 `S256`；Nyauth 不接受 `plain`。
- `state`、`nonce` 和 verifier 必须绑定到发起登录的浏览器会话，并在回调时一次性消费。
- 请求 `openid` scope 时必须发送 `nonce`。
- ID Token 必须验证 RS256、`kid`、JWKS 签名、issuer、audience、时间、nonce 和 `token_use=id`。
- return path 只允许同源相对路径。
- confidential client secret 只能保存在服务端。
- 不要把 access token、refresh token 或 ID Token 放入 `localStorage`。

## 推荐库

| 语言/平台 | 推荐实现 |
|---|---|
| Node.js / Next.js | Auth.js 或维护活跃的 OpenID Connect Client；在服务端完成 callback |
| Go | `golang.org/x/oauth2` 配合 `github.com/coreos/go-oidc/v3/oidc` |
| Python | Authlib |
| Java | Spring Security OAuth2 Client / OIDC |
| .NET | ASP.NET Core OpenID Connect handler |
| iOS / Android | AppAuth |

## 授权请求

授权请求至少包含以下参数：

```text
GET /authorize
  ?response_type=code
  &client_id=...
  &redirect_uri=...
  &scope=openid%20profile
  &state=...
  &nonce=...
  &code_challenge=...
  &code_challenge_method=S256
```

回调出现 `error` 参数时必须终止流程并消费对应 transaction，不得继续交换授权码。

## 客户端 Scope 与可选权限

客户端注册中的 `scopes` 是该客户端可请求的权限上限，授权请求出现未登记 Scope 时会返回 `invalid_scope`。管理员或客户端创建者可以把其中一部分非 `openid` Scope 声明为 `optional_scopes`：

- `openid` 始终是 OIDC 身份流程的必需权限，不能声明为可选。
- `optional_scopes` 必须是 `scopes` 的子集，并且只适用于包含 Authorization Code Grant 的客户端。
- 客户端以及每次非空授权请求都必须至少保留一个必需 Scope；现有客户端升级后默认没有可选 Scope，行为不变。
- Consent 页面允许用户逐项关闭可选权限；必需权限只能整体接受或拒绝。

当用户拒绝部分可选权限时，授权回调和 Token 响应中的 `scope` 是实际获准集合。应用必须以这个集合启用功能，不能继续按原始请求推断权限。例如用户拒绝 `offline_access` 后不会获得 Refresh Token；拒绝 `email` 后 ID Token 和 UserInfo 都不会包含邮箱字段。

全局 Scope Catalog 为每项 Scope 保存面向用户的名称、说明、风险等级、Claim 映射和分配策略。每个客户端的 `allowed_claims` 是 Catalog 映射后的第二层白名单：即使某个 Scope 理论上包含三个 Claim，管理员仍可以只让该客户端获得其中一部分。Scope 或 Claim 设为 `admin_only` 后，普通客户端所有者的目录和创建 API 不会暴露它，且伪造请求会被后端拒绝；管理员为客户端分配后，Consent 仍会把实际 Claim 完整显示给最终用户。

标准 Scope 当前对应：

| Scope | 返回或授予的能力 |
|---|---|
| `openid` | 稳定用户标识 `sub` 和 ID Token |
| `profile` | `preferred_username`、可用时的 `name` 与 `picture` |
| `email` | 可用时的 `email` 与持久化验证状态 `email_verified` |
| `offline_access` | 可轮换 Refresh Token；不直接增加用户资料 Claim |

自定义 Scope 可以映射 `preferred_username`、`name`、`picture`、`email`、`email_verified` 和 `role` 等受支持的内置 Claim；不能重新定义标准 Scope，也不能通过自定义 Scope 映射 `sub`。自由格式用户 Metadata 不会自动变成 Claim，避免把未经治理的数据意外暴露给客户端。

从全局目录移除 Scope 表示停止新分配并从 Discovery 隐藏，不会删除最后一版可信说明或 Claim 映射，也不会让已持有该 Scope 的客户端立即失效。若需要紧急收紧字段，应直接修改 Claim 映射或客户端 `allowed_claims`；既有 Access Token 仍按自身短期有效期到期，尚未兑换的授权码和后续 Refresh Token 轮换会应用收紧后的策略。

## 管理员 OAuth 测试台

管理员可从后台“OAuth 测试”进入 `/admin/oauth/test`，使用真实 Authorization Code + S256 PKCE 流程检查 Consent、Token 与 UserInfo：

1. 在目标客户端中登记测试台显示的 Redirect URI，例如 `https://issuer.example/admin/oauth/test`。
2. 输入 Client ID；Public Client 将 Secret 留空，Confidential Client 输入只展示一次的 Secret。
3. 从实时 Scope Catalog 选择 Scope 并开始授权，在 Consent 页面逐项确认实际权限。
4. 回调后检查 Token 响应和 UserInfo，确认返回的 `scope` 与 Claim 符合客户端白名单和用户选择。

测试台不会把 Client Secret、PKCE verifier 或 Token 写入 URL 或 `localStorage`；Secret 只保存在当前页面内存。它用于管理员人工诊断，不是业务 SPA 保存 Confidential Client Secret 的许可。

## Refresh Token

只有 authorization-code 请求显式申请且用户最终获准 `offline_access` 时才会返回 refresh token。调用方必须保存最新 refresh token；如果旧 token 被重复使用，Nyauth 会撤销整个 token family。

## 浏览器与原生应用

当前正式支持的是服务端/BFF 集成。纯浏览器 SPA 不得携带 client secret；在客户端级精确 CORS 与 `allowed_origins` 模型完成前，不承诺跨域 token endpoint 支持。原生应用应使用系统浏览器和 AppAuth，不使用嵌入式 WebView。
