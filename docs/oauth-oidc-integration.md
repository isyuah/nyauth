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

## Refresh Token

只有 authorization-code 请求显式申请并获准 `offline_access` 时才会返回 refresh token。调用方必须保存最新 refresh token；如果旧 token 被重复使用，Nyauth 会撤销整个 token family。

## 浏览器与原生应用

当前正式支持的是服务端/BFF 集成。纯浏览器 SPA 不得携带 client secret；在客户端级精确 CORS 与 `allowed_origins` 模型完成前，不承诺跨域 token endpoint 支持。原生应用应使用系统浏览器和 AppAuth，不使用嵌入式 WebView。
