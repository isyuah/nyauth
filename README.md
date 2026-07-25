# nyauth 0.2.0

统一认证与用户系统，提供 OAuth 2.0 Authorization Server、OpenID Connect Provider、第一方管理后台和 Go/TypeScript SDK。

## 0.2.0 安全版本说明

`0.2.0` 是不兼容的安全基线版本：

- 第一方后台仅使用 `HttpOnly + SameSite=Lax` 会话 Cookie，并对修改请求强制校验 CSRF。
- OAuth 授权码客户端强制使用 PKCE S256；不支持 plain、implicit 或 hybrid 流程。
- JWT 固定使用 RS256，refresh token 采用 family 轮换与重复使用检测。
- 数据库迁移压缩为嵌入二进制的单一 `000001` 基线，服务启动只校验 schema，不再隐式迁移。
- 旧数据库、session、token、JWK、Provider 凭据和 OAuth 客户端注册均不兼容。

> [!CAUTION]
> 升级前请备份需要保留的数据。旧 PostgreSQL/Redis volume 必须在运维人员核对环境、备份和准确 volume 名称并明确批准后，才可人工删除重建。应用和迁移命令不会自动删除 volume，也不要在未经确认时执行 `docker compose down -v`。

重建后需要重新注册 OAuth 客户端和外部 Provider。首次启动只会在空用户库中创建管理员；该管理员必须在首次登录后修改密码。

## 功能

- OAuth 2.0：Authorization Code + S256、Client Credentials、Refresh Token
- OpenID Connect：Discovery、JWKS、ID Token、UserInfo、RP-Initiated Logout
- 控制面认证：HttpOnly 会话、CSRF、强制首次改密、会话与令牌即时失效
- 外部身份：GitHub、Google、通用 HTTPS OIDC Provider；不按邮箱自动合并账户
- 管理后台：用户、客户端、Provider、审计与统计
- SDK：Go、TypeScript

## 本地开发

### 前置要求

- Go 1.26+
- PostgreSQL 16+
- Redis 7+
- Node.js 20+

### 使用本机服务

```bash
cp config.example.yaml config.yaml
# 编辑 config.yaml 中的数据库、Redis 和开发配置

go run ./cmd/nyauth migrate -config config.yaml
go run ./cmd/nyauth serve -config config.yaml
```

迁移命令使用数据库锁；多个实例同时执行时只有一个实例应用迁移。`serve` 不会修改 schema，数据库未迁移或版本不匹配时会拒绝启动。

### 使用开发 Compose

```bash
docker compose up --build
```

开发 Compose 将应用、PostgreSQL 和 Redis 分别绑定到 `127.0.0.1:8080`、`127.0.0.1:5432` 和 `127.0.0.1:6379`，并通过一次性 `migrate` service 初始化空数据库。

## 生产部署

生产环境由外部反向代理终止 TLS。只有配置的可信代理 CIDR 可以提供转发头。

1. 复制生产配置模板并替换全部部署值：

   ```bash
   cp config.production.example.yaml config.production.yaml
   ```

2. 设置 `docker-compose.prod.yml` 要求的环境变量：

   - `NYAUTH_IMAGE`：建议使用不可变镜像 digest
   - `NYAUTH_DATABASE_DSN`
   - `POSTGRES_PASSWORD`
   - `NYAUTH_REDIS_PASSWORD`：至少 16 字符且不可使用示例值
   - `NYAUTH_AUTH_ISSUER`：生产 HTTPS issuer
   - `NYAUTH_AUTH_MASTER_KEY`：标准 Base64 编码的随机 32 字节 master key
   - `NYAUTH_TRUSTED_PROXY_CIDRS`：准确的反向代理 CIDR
   - 可选 `NYAUTH_BOOTSTRAP_ADMIN_USERNAME`、`NYAUTH_BOOTSTRAP_ADMIN_EMAIL`、`NYAUTH_BOOTSTRAP_ADMIN_PASSWORD`

3. 先检查 Compose 展开结果，再启动：

   ```bash
   docker compose -f docker-compose.prod.yml config
   docker compose -f docker-compose.prod.yml up -d
   ```

生产 Compose 不发布 PostgreSQL/Redis 端口，应用仅通过共享 proxy network 暴露 `8080`；应用与迁移容器使用非 root 用户、只读根文件系统、临时 `/tmp`、cap drop 和 `no-new-privileges`。

如果未提供 bootstrap 密码，空用户库会生成一次性随机管理员密码并只写入一次启动日志；如果通过环境变量提供密码，则不会回显。两种情况都要求首次登录修改密码。

## 第一方会话 API

`POST /api/login` 创建会话 Cookie，不返回 OAuth access/refresh token。

| 方法 | 路径 | 描述 |
|---|---|---|
| POST | `/api/login` | 用户名密码登录并创建会话 |
| GET | `/api/session` | 返回 `{ user, csrf_token, must_change_password }` |
| POST | `/api/logout` | 销毁当前会话 |
| GET | `/api/me` | 当前用户资料 |
| PUT | `/api/me` | 修改 email、display name、avatar |
| POST | `/api/me/password` | 使用当前密码修改密码并轮换会话 |
| GET | `/api/me/identities` | 当前用户的外部身份 |
| POST | `/api/me/identities/{provider}/bind` | 发起当前用户的身份绑定 |
| GET/POST | `/api/my/clients` | 管理当前用户拥有的 OAuth 客户端 |

除安全方法外，所有已认证 `/api` 请求都必须携带 `/api/session` 返回的 `X-CSRF-Token`。后台接口只接受会话 Cookie，不接受 OAuth Bearer token。

```typescript
const session = await fetch('/api/session', {
  credentials: 'same-origin',
}).then((response) => response.json());

await fetch('/api/me', {
  method: 'PUT',
  credentials: 'same-origin',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': session.csrf_token,
  },
  body: JSON.stringify({ display_name: 'Nya' }),
});
```

## OAuth 2.0 / OIDC 端点

| 方法 | 路径 | 描述 |
|---|---|---|
| GET | `/.well-known/openid-configuration` | OIDC Discovery |
| GET | `/.well-known/jwks.json` | 当前及仍处于验证生命周期内的公钥 |
| GET | `/authorize` | Authorization Code + S256 授权 |
| POST | `/token` | code、client credentials、refresh grant |
| GET/POST | `/userinfo` | OIDC UserInfo |
| POST | `/revoke` | 撤销属于调用客户端的 token |
| POST | `/introspect` | confidential client 查询自身 token |
| GET | `/end_session` | 清理会话并校验 post-logout redirect URI |

只有 authorization-code 请求显式申请并获准 `offline_access` 时才会签发 refresh token。Client Credentials 不会获得 refresh token。

OAuth 客户端支持 `post_logout_redirect_uris`。`/end_session` 仅允许跳转到与 ID token 客户端匹配的已注册 URI。

## 外部身份

| 方法 | 路径 | 描述 |
|---|---|---|
| GET | `/auth/{provider}/authorize` | 发起外部登录 |
| GET | `/auth/{provider}/callback` | 外部 Provider 回调 |
| POST | `/api/me/identities/{provider}/bind` | CSRF 保护的身份绑定入口 |

首次使用未绑定的外部身份登录时会创建外部账号，但不会根据 email 自动合并到已有账号。通用 OIDC Provider 的 discovery URL 必须使用 HTTPS。

## Go SDK

```go
client := nyauth.NewClient(nyauth.Config{
    Issuer:      "https://auth.example.com",
    ClientID:    "my-public-app",
    RedirectURI: "https://app.example.com/callback",
})

authURL, state, verifier, _, err := client.GetAuthorizationURL(
    []string{"openid", "profile"},
    "",
)
if err != nil {
    return err
}

// 将 state 与 verifier 绑定到发起登录的浏览器会话，然后重定向到 authURL。
_ = authURL
_ = state

token, err := client.ExchangeCodePKCE(ctx, code, verifier)
if err != nil {
    return err
}
user, err := client.GetUserInfo(ctx, token.AccessToken)
```

SDK 只生成 S256 PKCE。公共客户端的 `client_id` 会写入 form body；随机数生成失败会向调用方返回错误。

## TypeScript SDK

```typescript
import { NyAuthClient } from '@nyasharp/nyauth';

const client = new NyAuthClient({
  issuer: 'https://auth.example.com',
  clientId: 'my-public-app',
  redirectUri: 'https://app.example.com/callback',
});

const { url, state, codeVerifier } = await client.getAuthorizationURL([
  'openid',
  'profile',
]);

// 仅临时保存 PKCE state/verifier；不要把 access/refresh token 放入 localStorage。
sessionStorage.setItem('oauth_state', state);
sessionStorage.setItem('pkce_verifier', codeVerifier);
window.location.assign(url);

const token = await client.exchangeCodePKCE(code, codeVerifier);
const user = await client.getUserInfo(token.access_token);
```

浏览器应用不得配置或分发 confidential client secret。TypeScript SDK 使用 WebCrypto SHA-256，并包含 RFC 7636 S256 构建验证。

## 质量检查

```bash
go test -race ./...

cd web
npm ci
npm run check
npm run test:unit
npm run build

# 首次运行 E2E 时安装 Playwright 管理的 Chromium
npx playwright install chromium
npm run test:e2e

cd ../sdk/ts
npm ci
npm run build
```

CI 同时校验开发与生产 Compose 配置。CI 和文档中的 Compose 检查不会启动服务或删除数据。

## 许可证

MIT
