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
- Device Authorization 的 `device_code` 与 Client Secret 同样属于 bearer secret，不得写入日志、URL、持久化浏览器存储或终端历史。

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

## RFC 9470 Step-Up Authentication

Nyauth 授权服务器支持 [RFC 9470 OAuth 2.0 Step Up Authentication Challenge Protocol](https://www.rfc-editor.org/rfc/rfc9470.html) 在授权请求侧使用的标准认证上下文参数。Discovery 会公布：

- `urn:nyauth:loa:1`：完成一个主认证因素，例如密码、外部身份或 Passkey 独立登录；
- `urn:nyauth:loa:2`：完成多因素验证或使用 Passkey 达到更高认证等级。

客户端可以在授权请求中加入 `acr_values` 和 `max_age`：

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
  &acr_values=urn%3Anyauth%3Aloa%3A2
  &max_age=300
```

当当前会话不满足要求时，Nyauth 会保留原授权 challenge，先完成登录、TOTP、恢复码或 Passkey 验证，再回到同一个 Consent 页面。未绑定任何可用 MFA 因子时不会降级授权，也不会消费请求；第一方页面会引导用户进入安全中心绑定验证方式。`max_age=0` 使用一次性、Redis 保存的重新认证续接令牌，避免用客户端可伪造的查询参数绕过强制重新认证。

成功签发的用户 Access Token 和 ID Token 会携带实际认证上下文 `acr`、认证方法 `amr` 和认证时间 `auth_time`；Refresh Token 轮换会保留这组认证上下文。资源服务器应验证这些 Claim，并在认证等级不足时按 RFC 9470 返回挑战，例如：

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="urn:nyauth:loa:2"
```

RFC 9470 规定挑战和续接参数的协议语义，不规定 MFA 的具体实现；上面的 ACR 等级是本 Nyauth 部署公开的固定词汇。资源服务器收到挑战后，应让客户端重新发起带有 `acr_values` 或 `max_age` 的授权请求，并在收到新 Token 后再次验证 Claim。当前 Step-Up 参数接入 Authorization Code 授权请求；Device Authorization 仍使用浏览器 Consent 的当前会话认证等级，不接受设备端自定义 `acr_values`。

## 客户端 Scope 与可选权限

客户端注册中的 `scopes` 是该客户端可请求的权限上限，授权请求出现未登记 Scope 时会返回 `invalid_scope`。管理员或客户端创建者可以把其中一部分非 `openid` Scope 声明为 `optional_scopes`：

- `openid` 始终是 OIDC 身份流程的必需权限，不能声明为可选。
- `optional_scopes` 必须是 `scopes` 的子集，并且只适用于包含 Authorization Code 或 Device Authorization Grant 的客户端。
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

## 发布者可信状态

Consent 会同时展示客户端注册来源、发布者可信状态和本次请求的实际回调来源：

- 管理员直接创建的客户端是“系统管理”，不显示未验证警告。
- 用户自助创建的客户端默认“发布者未验证”。
- 管理员人工核对应用身份和回调来源后，可将用户注册客户端标记为“发布者已验证”，也可随时撤销。

发布者审核是当前 Nyauth 部署管理员的人工信任结论，不代表 Nyauth 自动完成了 DNS、TLS 证书或域名所有权验证。最终用户仍应核对应用名称和回调来源；管理员也不应仅凭客户端显示名称完成审核。

## 管理员 OAuth 测试台

管理员可从后台“OAuth 测试”进入 `/admin/oauth/test`，切换真实 Authorization Code + S256 PKCE 或 Device Authorization 流程检查 Consent、Token 与 UserInfo：

1. 在目标客户端中登记测试台显示的 Redirect URI，例如 `https://issuer.example/admin/oauth/test`。
2. 输入 Client ID；Public Client 将 Secret 留空，Confidential Client 输入只展示一次的 Secret。
3. 从实时 Scope Catalog 选择 Scope 并开始授权，在 Consent 页面逐项确认实际权限。
4. 回调后检查 Token 响应和 UserInfo，确认返回的 `scope` 与 Claim 符合客户端白名单和用户选择。

测试台不会把 Client Secret、PKCE verifier 或 Token 写入 URL 或 `localStorage`；Secret 只保存在当前页面内存。它用于管理员人工诊断，不是业务 SPA 保存 Confidential Client Secret 的许可。

## 应用运营与失败诊断

客户端所有者可在“我的应用”进入应用数据页，管理员可从应用管理进入同一套管理视图。页面按 UTC 展示 7/30/90 天 OAuth 协议操作检查点、活动授权、流程趋势和失败原因，用于区分“回调地址错误”“Scope 未登记”“PKCE 无效”“Refresh Token 重用”“用户主动拒绝”等问题。

统计中的成功率是所有已记录协议阶段操作的成功占比，不是用户转化率：一次完整 Authorization Code 流程会经过授权请求、Consent 和 Token 签发等多个检查点。Device Authorization 的正常 `authorization_pending` 与节流提示 `slow_down` 不作为故障计数。

失败诊断只记录固定原因、流程、阶段、Request ID、规范化 Scope 和删除 query/fragment 后的回调来源；不会记录 Token、Client Secret、授权码、PKCE verifier、用户 ID、邮箱、上游 Claim 或原始内部错误。调用方仍应在自己的服务端日志中使用 Request ID 关联业务请求，但不得记录 Token 或 Secret。

## Device Authorization Grant

Device Authorization 适用于电视、CLI 和其他不便直接打开完整登录页的设备。客户端必须登记 `urn:ietf:params:oauth:grant-type:device_code` Grant；纯设备客户端不需要 Redirect URI。Public Client 直接发送 `client_id`，Confidential Client 仍必须使用 HTTP Basic 或表单 Secret 完成客户端认证。

先创建设备授权请求：

```http
POST /device_authorization
Content-Type: application/x-www-form-urlencoded

client_id=tv-client&scope=openid%20profile
```

成功响应示例：

```json
{
  "device_code": "opaque-high-entropy-secret",
  "user_code": "BCDF-2345",
  "verification_uri": "https://issuer.example/device",
  "verification_uri_complete": "https://issuer.example/device?user_code=BCDF-2345",
  "expires_in": 600,
  "interval": 5
}
```

设备应显示 `user_code` 和 `verification_uri`，可额外生成指向 `verification_uri_complete` 的二维码，但不能把 `device_code` 展示给用户。用户在浏览器登录后仍会看到客户端身份、发布者可信状态、必需/可选 Scope 和实际 Claim；批准或拒绝均不会跳转到第三方回调地址。

设备必须等待至少 `interval` 秒再轮询 Token：

```http
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code
&device_code=opaque-high-entropy-secret
&client_id=tv-client
```

- `authorization_pending`：用户尚未决定，继续按当前间隔轮询。
- `slow_down`：轮询过快；读取 `Retry-After`，后续间隔至少增加 5 秒。
- `access_denied`：用户拒绝，立即终止且不要自动重试。
- `expired_token`：代码已过期、已消费或绑定已失效，重新创建一轮设备授权。
- `temporarily_unavailable`：服务暂时不可用，遵循 `Retry-After` 或指数退避，不得高频重试。

设备码批准后仍会在 Token 兑换时重新检查客户端 revision、Scope/Claim 白名单、用户状态、认证版本、访问策略和授权撤销时间；只有一个并发轮询者能够完成一次性消费。请求 `openid` 时会签发 ID Token，但 Device Authorization 没有浏览器 Authorization Request 的 `nonce` 参数，调用方仍必须验证签名、issuer、audience、时间和 `token_use=id`。

## Refresh Token

只有 Authorization Code 或 Device Authorization 请求显式申请且用户最终获准 `offline_access` 时才会返回 refresh token。调用方必须保存最新 refresh token；如果旧 token 被重复使用，Nyauth 会撤销整个 token family。

## 浏览器与原生应用

当前正式支持的是服务端/BFF 集成。纯浏览器 SPA 不得携带 client secret；在客户端级精确 CORS 与 `allowed_origins` 模型完成前，不承诺跨域 token endpoint 支持。原生应用应使用系统浏览器和 AppAuth，不使用嵌入式 WebView。
