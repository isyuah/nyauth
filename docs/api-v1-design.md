# /api/v1 管理契约设计（草案）

> 状态：**草案**（2026-07-26），未开始实现。目标版本：0.4.0。
> 本文档定义 nyauth 面向自动化消费者的第一个稳定管理 API 契约。

## 1. 背景与目标

当前 `/api/*` 是第一方 Web UI 的私有接口：会话 Cookie + CSRF 认证，形状随 UI 迭代随时变化，README 已明确声明它不是自动化契约。任何 CI、IaC 或外部服务想管理 nyauth（创建 OAuth 客户端、管理用户、拉取审计）都只能模拟浏览器登录——这是 0.3.0 之后最大的能力缺口。

`/api/v1` 的目标：

1. **稳定**：发布后遵守语义化版本承诺，破坏性变更只出现在 `/api/v2`
2. **机器优先**：Service Account 认证，无 Cookie、无 CSRF、无强制改密流程
3. **可生成**：OpenAPI 3.1 规范是唯一真值，CI 校验实现与规范一致
4. **最小起步**：首版只覆盖已有明确自动化需求的资源，宁缺毋滥

**非目标**：不替代第一方 UI 的 `/api/*`（继续作为私有 BFF 接口存在）；不暴露 OAuth/OIDC 协议端点（那些本身就是标准契约）；首版不做 webhook/事件推送。

## 2. 认证：Service Account

复用自身的 OAuth 基础设施，不发明新机制：

- Service Account 是一种特殊的 OAuth 客户端（`client_credentials` grant），由管理员在后台创建，绑定管理 scope 集合
- 调用方以 `client_credentials` 换取 access token（RS256 JWT），`aud` 固定为 `nyauth-mgmt`
- `/api/v1` 中间件校验：签名、`aud=nyauth-mgmt`、scope 覆盖目标操作；拒绝一切用户会话 Cookie
- Token TTL 建议短（≤15 分钟）；不发 refresh token（client_credentials 每次重新获取）

### Scope 模型

`mgmt:<资源>:<动作>`，动作只有 `read` 和 `write`（首版不做更细粒度）：

| Scope | 覆盖 |
|---|---|
| `mgmt:users:read` / `mgmt:users:write` | 用户查询 / 用户增删改、封禁、角色、强制重置 |
| `mgmt:clients:read` / `mgmt:clients:write` | 客户端查询 / 增删改、owner 变更、secret 轮换 |
| `mgmt:providers:read` / `mgmt:providers:write` | Provider 查询 / 增删改、测试连接 |
| `mgmt:audit:read` | 审计日志查询与导出（无 write——审计只读） |
| `mgmt:stats:read` | 统计与系统状态 |

高危操作（删除用户、轮换 secret、删除 Provider）额外要求 Service Account 创建时显式勾选 `allow_destructive`，避免一个 `mgmt:*:write` 就能删库式操作。

## 3. 资源与端点（首版范围）

映射现有 `/api/admin/*` 能力，动词与路径规范化（复数资源、无动词路径，动作用子资源表达）：

```
GET/POST        /api/v1/users               GET/PATCH/DELETE /api/v1/users/{id}
POST            /api/v1/users/{id}/suspension        (创建=封禁, DELETE=解封)
POST            /api/v1/users/{id}/password-reset    (管理员强制重置)
GET             /api/v1/users/{id}/identities        DELETE /api/v1/users/{id}/identities/{iid}
GET/DELETE      /api/v1/users/{id}/sessions

GET/POST        /api/v1/clients             GET/PATCH/DELETE /api/v1/clients/{id}
PUT             /api/v1/clients/{id}/owner
POST            /api/v1/clients/{id}/secret-rotation

GET/POST        /api/v1/providers           GET/PATCH/DELETE /api/v1/providers/{id}
POST            /api/v1/providers/{id}/connection-test

GET             /api/v1/audit-events        GET /api/v1/audit-events/export
GET             /api/v1/stats               GET /api/v1/system/status
```

注意与 UI 接口的差异：`PUT` 全量更新改为 `PATCH` 局部更新（JSON Merge Patch, RFC 7396）；`suspend`/`activate` 动词路径改为 `suspension` 子资源。

## 4. 通用约定

- **错误**：RFC 9457 Problem Details（`application/problem+json`），`type` 使用稳定的错误码 URI；不复用 UI 接口的 `{error}` 形状
- **分页**：游标分页 `?cursor=...&limit=...`，响应含 `next_cursor`；不承诺 offset 分页（审计表是分区大表）
- **幂等**：所有 POST 支持 `Idempotency-Key` 请求头，键 + 请求体哈希在 Redis 保存 24h，重放返回首次结果（`409` 当键相同但请求体不同）
- **并发控制**：可变资源响应带 `ETag`，`PATCH`/`DELETE` 支持 `If-Match`，不匹配返回 `412`
- **限流**：按 Service Account 限流，超限返回 `429` + `Retry-After`
- **审计**：所有 v1 mutation 走现有 mutation audit 管道，actor 记录为 Service Account 身份

## 5. OpenAPI 与 CI

- 规范文件 `api/openapi.v1.yaml` 手写维护（规范先行，代码跟随），作为 PR 审查对象
- CI 增加契约测试：启动服务后用规范驱动的校验器（如 kin-openapi 的请求/响应校验中间件在测试模式下强断言）验证实现与规范一致
- 规范发布到文档站/仓库 Release 资产；SDK 由消费方用 openapi-generator 自行生成——**仍然不维护官方 SDK**，这是 0.3.0 删除 SDK 决策的延续

## 6. 稳定性策略

- `/api/v1` 发布后：只加可选字段/新端点（minor），不改语义、不删字段
- 弃用流程：响应头 `Deprecation` + `Sunset`（RFC 8594），至少保留两个 minor 版本
- `/api/*`（UI 私有接口）明确豁免于任何稳定性承诺，文档中持续如此声明

## 7. 实施阶段

1. **Phase 1（基础设施）**：Service Account 客户端类型 + `nyauth-mgmt` audience + scope 校验中间件 + Idempotency-Key 存储。此阶段无任何 v1 端点，可独立合入
2. **Phase 2（只读切片）**：`users`/`clients`/`audit-events`/`stats` 的 GET + OpenAPI + 契约测试管道——先让读路径稳定运转
3. **Phase 3（写路径）**：mutation 端点 + `allow_destructive` + ETag/If-Match
4. **Phase 4（发布）**：文档、迁移指南（从"模拟 UI 登录"迁移到 Service Account）、0.4.0 发布

每个阶段独立可发布；Phase 2 完成即可宣布 beta 契约征求反馈。

## 8. 待决问题

- [ ] Service Account 的凭据形态：沿用 client secret，还是支持 private_key_jwt（更安全，实现成本更高）？建议首版 secret，v1.1 加 private_key_jwt
- [ ] `audit-events/export` 大结果集：同步流式 CSV（现状）还是异步任务 + 下载链接？首版沿用同步流式，加 `max_range` 限制
- [ ] 是否暴露 JWK 管理（轮换触发）？倾向不暴露，保持 CLI/运维专属
