# nyauth

统一认证与用户系统 — OAuth 2.0 Authorization Server + OpenID Connect Provider

## 功能

- **OAuth 2.0 Server** — Authorization Code + PKCE, Client Credentials, Refresh Token
- **OpenID Connect** — Discovery, JWKS, ID Token, UserInfo, End Session
- **用户管理** — 用户名/密码登录 (argon2id), CRUD API
- **外部 OAuth** — GitHub, Google, 任意 OIDC Provider (静态配置 + 动态管理)
- **管理后台** — SvelteKit Web UI (嵌入式或独立部署)
- **SDK** — Go, TypeScript (Python, C# 后期)

## 快速开始

### 前置要求

- Go 1.26+
- PostgreSQL 16+
- Redis 7+
- Node.js 20+ (构建 Web UI)

### 1. 配置

```bash
cp config.example.yaml config.yaml
# 编辑 config.yaml，配置数据库和 Redis 连接
```

### 2. 数据库

创建 PostgreSQL 数据库：

```sql
CREATE DATABASE nyauth;
CREATE USER nyauth WITH PASSWORD 'nyauth';
GRANT ALL PRIVILEGES ON DATABASE nyauth TO nyauth;
```

运行迁移：

```bash
make migrate
# 或
go run ./cmd/nyauth -config config.yaml -migrate
```

### 3. 构建 & 运行

```bash
# 仅后端 (不含嵌入式 UI)
make build
./bin/nyauth.exe -config config.yaml

# 含嵌入式 Web UI
make build-all

# 开发模式
make run
```

## 项目结构

```
nyauth/
├── cmd/nyauth/          # 主入口
├── internal/
│   ├── auth/            # OAuth 2.0 + OIDC 核心
│   ├── user/            # 用户管理
│   ├── client/          # OAuth Client 管理
│   ├── provider/        # 外部 OAuth Provider
│   ├── identity/        # 外部身份绑定
│   ├── session/         # Redis Session 管理
│   ├── server/          # HTTP Server, 路由, 中间件
│   ├── config/          # 配置加载
│   ├── crypto/          # 加密工具 (argon2id, AES-GCM)
│   └── database/        # PostgreSQL + Redis 连接
├── pkg/models/          # 共享数据模型
├── web/                 # SvelteKit Web UI
├── sdk/
│   ├── go/              # Go SDK
│   └── ts/              # TypeScript SDK
├── migrations/          # SQL 迁移文件
└── config.example.yaml  # 示例配置
```

## API 端点

### OAuth 2.0 / OIDC (公开)

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | `/.well-known/openid-configuration` | OIDC Discovery |
| GET | `/.well-known/jwks.json` | JSON Web Key Set |
| GET | `/authorize` | 授权端点 |
| POST | `/token` | Token 端点 |
| GET | `/userinfo` | 用户信息 |
| POST | `/revoke` | Token 撤销 |
| POST | `/introspect` | Token 内省 |

### 用户 API

| 方法 | 路径 | 描述 |
|------|------|------|
| POST | `/api/login` | 用户名密码登录 |
| POST | `/api/logout` | 登出 |
| GET | `/api/me` | 当前用户信息 |
| PUT | `/api/me` | 更新个人信息 |
| GET | `/api/providers` | 可用外部 Provider 列表 |

### 外部 OAuth

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | `/auth/:provider/authorize` | 发起外部 OAuth |
| GET | `/auth/:provider/callback` | 外部 OAuth 回调 |

### 管理 API (需 admin 认证)

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | `/api/admin/users` | 用户列表 |
| POST | `/api/admin/users` | 创建用户 |
| GET | `/api/admin/clients` | Client 列表 |
| POST | `/api/admin/clients` | 创建 Client |
| GET | `/api/admin/providers` | Provider 列表 |
| POST | `/api/admin/providers` | 添加 Provider |

## SDK 使用

### Go

```go
import nyauth "github.com/nyasharp/nyauth/sdk/go"

client := nyauth.NewClient(nyauth.Config{
    Issuer:      "http://localhost:8080",
    ClientID:    "my-app",
    RedirectURI: "https://my-app.com/callback",
})

url, state := client.GetAuthorizationURL([]string{"openid", "profile"}, "")
token, _ := client.ExchangeCode(ctx, code)
user, _ := client.GetUserInfo(ctx, token.AccessToken)
```

### TypeScript

```typescript
import { NyAuthClient } from '@nyasharp/nyauth';

const client = new NyAuthClient({
    issuer: 'http://localhost:8080',
    clientId: 'my-app',
    redirectUri: 'https://my-app.com/callback',
});

const { url, state, codeVerifier } = client.getAuthorizationURLPKCE(['openid', 'profile']);
const token = await client.exchangeCodePKCE(code, codeVerifier);
const user = await client.getUserInfo(token.access_token);
```

## 许可证

MIT
