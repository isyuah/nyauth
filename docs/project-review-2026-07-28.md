# 项目整体代码审查报告（2026-07-28）

> 审查范围：全仓库（后端 Go、前端 SvelteKit、部署与运维）。基线为 `codex/release-0.3.0-rc1` 分支
> 0.3.0-rc.1 及工作区中的未提交变更（provider 展示层、审计多选过滤、单会话撤销、外部依赖 compose 拓扑）。
>
> 总评：安全意识和文档纪律显著高于平均水平。outbox 审计、envelope 加密、refresh token 家族轮换、
> PG 权威版本号 + Redis 快照的 fail-closed 设计都很严谨；前端零 `{@html}`、CSRF / 开放重定向 /
> secret 展示处理全部正确且有测试锁定。未发现可直接利用的高危漏洞，短板集中在可维护性而非安全。

---

## 一、后端（Go）

### 中危

**M1. 凭证变更后的 Redis 撤销是"尽力而为"，失败仅记日志**
- `internal/server/handlers.go:435-442`（`revokeUserSecurityState`）
- 改密、管理员重置、角色/状态变更在 PG 提交后调用 `DeleteUserSessions` / `RevokeRefreshFamiliesForUser`，Redis 故障时只 `slog.Error` 仍返回 200。缓解因素：`auth_version`/`session_version` 在 `userAuthMiddleware`（middleware.go:49-55）和 `token.go:394` 每次请求都会核对，旧会话/令牌实际会被拒绝，因此是纵深防御的降级而非绕过。
- 单会话撤销（`DeleteUserSessionByPublicID`）没有版本兜底——此处的静默吞错误已于 2026-07-28 修复（`security_center.go` 改为错误检查路径）。

**M2. `LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE` 造成全表写阻塞**
- `internal/user/store.go:291`（`UpdateAdmin`）、`store.go:515`（`Delete`）、`store.go:568`（`BootstrapAdmin`）
- SHARE ROW EXCLUSIVE 与 ROW EXCLUSIVE 冲突：任一管理员更新/删除用户期间，所有对 `users` 的普通写入（包括每次登录的 `RecordLogin`、注册插入）都会排队。事务体内还包含审计入队和邮件通知构建，持锁窗口不小。"最后一个活跃管理员"不变量可以用 `pg_advisory_xact_lock` 或对 admin 行集合 `FOR UPDATE` 实现，代价小得多。

**M3. 审计路由表与真实路由双重维护，缺省 fail-open（不审计）**
- `internal/server/mutation_audit.go:128-244`（`describeMutation` 244 行 switch）与 `server.go:298-427` 的路由注册重复。
- 新增 mutation 路由若忘记登记，middleware 层的失败/成功审计静默缺失。现状已有漏网：`DELETE /api/me/sessions/{id}`、`POST /api/me/sessions/revoke-others`、`/api/me/email/change`、`/api/me/email/verification`、`/api/me/reauth/*` 不在表内——成功路径靠 handler 内 `enqueueAuditTargetResult` 补，但**失败尝试完全没有审计**。建议在路由注册处声明审计描述符，或对未登记的 mutation 路由默认记一条通用事件。

**M4. 授权码被重放时未撤销此前基于该码签发的令牌**
- `internal/auth/handler.go:418-421`（`ConsumeAuthorizationCodeIfMatch` 失败仅记 `code_reuse` 审计并返回 400）
- OAuth Security BCP 建议：检测到 code 重放时应撤销先前用该 code 签发的令牌（可通过 `AuthorizationIssuedAt` 或 refresh family 定位）。当前只有 refresh token 重放有家族撤销（session/store.go:114-160 做得很好），code 重放没有等价处理。

**M5. 单个损坏的 provider 行会阻塞启动与全部 provider 快照刷新**
- `internal/provider/manager.go:149-152`（`loadDynamic` 解密失败即整体返回 error）、`internal/server/server.go:465-467`（启动时失败直接拒绝启动）、`internal/provider/sync.go:35`（reconciliation 同样整体失败）
- master key 轮换出错或某行 envelope 损坏时：serve 无法启动；运行中则 60s reconciliation 持续失败，其他健康 provider 的增删改无法再同步到本实例。建议按 provider 隔离失败：跳过坏行 + 高危审计/告警。

### 低危

**L1. `resolveClientIP` 对不可解析的 XFF 条目 `continue`，可能把可信代理 IP 当作客户端 IP**
- `internal/server/middleware.go:144-160`
- 从右向左遍历时遇到 `net.ParseIP` 失败的条目（如带端口的 `1.2.3.4:5678`）会跳过并保留当前 candidate；若循环耗尽，返回的可能是代理自身 IP，写入审计与限流键。该函数是安全敏感解析逻辑，但**没有任何针对它的单元测试**。

**L2. JWK 私钥/公钥无进程内缓存，签发与校验都打 DB**
- `internal/auth/jwk.go:106-133`（每次签 token 都 SELECT + envelope 解密 + PKCS1 解析）、`jwk.go:136-161`（每次校验 token 都查询 + PEM/X509 解析）
- 可按 `kid` 做带 TTL 的进程内缓存（rotation 间隔远大于任何合理 TTL）。

**L3. 用户/审计搜索的 ILIKE 未转义 `%`/`_`**
- `internal/user/store.go:596-607`、`internal/audit/store.go:166-169`
- 参数化无注入风险，但用户可控通配符可造成非预期匹配和最坏情况的 seq-scan 慢查询（管理端接口，风险有限）。

**L4. `audit.Store.Record` 绕过 outbox 的直插路径无人使用**
- `internal/audit/store.go:39-57`；全仓库无调用方（仅测试）。留着一个绕过"事务性 outbox + 幂等投递"不变量的公开方法是隐患，建议删除或降级为测试助手。

**L5. 空目录与遗留物**
- `internal/admin/`、`internal/consent/` 为空目录；根目录留有 `config.yaml.0.2.bak`（含旧格式 `encryption_key`、`admin.password: changeme`，未被 gitignore）与 `nyauth.exe`/`nyauth-dev.exe`。

**L6. 会话 TTL 硬编码且无绝对/滑动策略区分**
- `internal/server/session.go:16`（`sessionTTL = 24h` 常量）；`GetSession` 的 5 分钟节流 touch 只更新 `last_seen_at`，Redis TTL 不续期，即会话是 24h 绝对过期。行为合理但值得显式配置化并写入文档。

**L7. 客户端密钥用无盐 SHA-256 哈希**
- `internal/crypto/crypto.go:137-153`
- 对 `GenerateClientSecret()` 产生的 256-bit 随机密钥而言安全充分，前提是不存在导入低熵密钥的路径；建议在 `HashClientSecret` 注释中固化该前提。

**L8. consent 处理器重复实现会话/CSRF 校验**
- `internal/auth/consent.go:143-162` 自行读 cookie、比对 CSRF，而 `/api/consent/*` 已挂在 `userAuthMiddleware + csrfMiddleware` 组内（server.go:353-355）。校验被做了两遍且逻辑分叉，将来容易漂移。

**L9. `consumeMatchingScript` 依赖 JSON 字节级 round-trip 稳定性**
- `internal/session/store.go:99-105` + `handler.go:383/418`
- 授权码"读→校验→按值消费"的原子性依赖 `json.Marshal(Unmarshal(x)) == x`。当前 `AuthorizationData` 无 map 字段所以成立，但任何人加 `map`/浮点字段就会悄悄破坏消费逻辑。建议比对哈希或版本号。

### 测试覆盖缺口（按重要性）

1. `resolveClientIP` / trusted proxy 解析：零测试（见 L1）。
2. `/authorize` 端点本身：redirect_uri 校验顺序、open-redirect 防护、scope/PKCE 拒绝路径只被 `examples/oidc_bff` 的快乐路径间接覆盖。
3. consent handler：Deny / 用户不匹配 / AuthVersion 不匹配分支无直接测试。
4. `safeReturnPath`（provider_handlers.go:31-45）：开放重定向白名单函数无独立测试。
5. `identity.Store`：`DeleteOwned` 的"最后认证方式"不变量、并发解绑竞态值得集成测试。
6. `server/handlers_test.go` 仅 1 个测试：login 的限流/MFA 分支主要靠集成测试兜底。

### 后端架构评价

分层清晰且边界纪律很好：`server` 是纯组合根 + HTTP 适配层；领域包各自持有 store 并对外暴露语义化错误；`session`（Redis）与 `database`（PG）职责分离明确——PG 是权威状态（auth_version/session_version 世代号），Redis 只是可失效的快照，Redis 故障时安全性 fail-closed。突出优点：

- **审计 outbox 模式实现完整**：`EnqueueMutationTx` 强制审计与状态变更同事务提交、outbox ID 复用为 audit_logs ID 实现幂等重投、`DeliverAuditEvent` 先抢租约再写入防僵尸 worker、分区维护用 advisory lock + 严格解析分区名后再拼 DDL。
- **会话/令牌安全**：Redis 中一律存 SHA-256 摘要而非明文 token；refresh 轮换 + 重放检测 + 家族撤销在单个 Lua 脚本内原子完成；`AuthorizationIssueTime` 用 Redis 逻辑时钟解决跨实例撤销排序。
- **密钥体系**：统一 envelope（version:keyID:payload + purpose/AAD 绑定），JWK 私钥用 HMAC 派生子密钥加密，支持 keyring 轮换，生产配置强制拒绝示例 master key。
- **并发**：`provider.Manager` 的 `mutationMu` + `mu` + atomic revision 三层分工正确；`settings`/`mailruntime` 用 `atomic.Pointer` 快照 + revision 单调安装。
- **SQL**：全库参数化；SSRF 防护（provider/generic.go:267-306、avatar/remote_fetch.go）做了解析后按 IP 拨号，防了 DNS rebinding。

结构性风险不在设计错误而在重复维护点：路由表 vs 审计描述符（M3）、consent 双份校验（L8）、`server.New` 270 行的上帝构造函数（server.go:88-272）。

---

## 二、前端（web/）

### 中等严重度

**A1. e2e 巨型手写 mock，与后端契约漂移风险高**
- `web/tests/e2e/session-flows.spec.ts`（约 3500 行，单文件 70 个 test，`MockState` 90+ 字段）。所有 API 响应均为手工构造 fixture，后端 JSON 行为变化时 mock 不会失败，测试会"绿色通过但与真实后端不符"。建议拆分文件、抽公共 mock server 工厂，并用 Go 侧集成测试或 schema 校验兜住契约。

**A2. 错误本地化依赖后端英文文案精确匹配**
- `web/src/lib/api.ts:713-791`：`API_ERROR_TRANSLATIONS` 约 80 条英文消息 → 中文的精确匹配表，`isRecentAuthenticationError` 也用字符串比对。后端任何文案微调都会静默退化成英文裸消息。这是前后端最脆弱的耦合点，建议后端改为稳定错误码。

**A3. api.ts 单体过大、职责混杂**
- 1126 行，混合 60+ DTO、翻译表、CSRF 状态、请求引擎和 100+ 端点定义。另外 `req()` 在 401 时直接 `window.location.assign('/login...')`（838-843 行），把导航副作用埋进数据层，`redirectOnUnauthorized=false` 需逐调用手工传递，容易遗漏。

**A4. TreeMultiSelect 可访问性**（已于 2026-07-28 修复：combobox 语义 + 方向键导航 + 中文分组名）

**A5. 无组件级单测，覆盖有结构性空洞**
- `vitest.config.ts` 用 `environment: 'node'`，8 个 `*.test.ts` 只覆盖纯逻辑，所有 `.svelte` 组件行为完全依赖 e2e；vitest 未配置 coverage。`AvatarCropper`、`MailSettingsPanel` 等复杂组件没有快速反馈层。

### 低严重度

**A6. 视觉回归测试跨环境脆弱**
- `fullPage` 截图 + `maxDiffPixelRatio: 0.08` 仅 chromium；截图基线对 OS 字体渲染敏感（Windows 开发 / Linux CI 会互相打架）。`fullyParallel: false` 且 webServer 每次全量 build，e2e 反馈慢。axe 扫描只覆盖 3 个页面。

**A7. DataTable 行级 `role="button"` 的嵌套交互问题**
- `<tr role="button" tabindex="0" onclick>` 中 `actions` snippet 里的按钮点击会冒泡触发行点击，依赖各调用方自行 `stopPropagation`；屏幕阅读器语义不理想（更常见做法是行内首列放真实链接）。

**A8. branding logo_url 未做协议约束**
- `Sidebar.svelte`(86,91)、`routes/login/+page.svelte`(271) 直接 `<img src={$brandingStore.logo_url}>`。管理员可配任意外链（含 http://），登录页会向第三方泄露 Referer/IP；非 XSS，但建议限制 https 或同源。

**A9. `app.html` 无 CSP**
- 需确认由 Go 服务端下发 CSP 响应头；鉴于前端零 `{@html}`，风险低，但作为 IdP 建议显式收紧。

### 前端安全与设计亮点

- **XSS**：全仓库无任何 `{@html}`；所有跳转 sink 要么经 `safeReturnPath`（`lib/navigation.ts:24`，正确拦截 `//`、`\`、控制字符、超长、跨源），要么是服务端校验过的 `redirect_url`。
- **CSRF**：内存态 token（不落 localStorage）、仅对 `/api/` 变更请求附加、MFA pending 用独立 token、401 时清空——设计正确且有测试锁定。
- **敏感信息**：TOTP secret / recovery codes / client secret 均一次性展示；`query-secret.ts` 用 `replaceState` 从 URL 摘除 secret；有"绝不序列化 SMTP 密码"的单测。
- **状态管理**：sessionStore 用 generation 计数防竞态、区分 401/网络/服务错误三态。
- **组件库**：基于 bits-ui，Modal/Drawer/ConfirmDialog 有焦点困锁与焦点归还断言（e2e 已验证）。

---

## 三、部署与运维

### 中等严重度

**B1. prod compose 中 postgres/redis 未与应用同级加固**
- `docker-compose.prod.yml`：`nyauth`/`migrate` 有 `user: 65532`、`read_only`、`cap_drop: ALL`、`no-new-privileges`、tmpfs，但 `postgres`/`redis` 只有资源限额（redis 完全可以 read_only + tmpfs）。同一文件内加固标准不一致。

**B2. `docker-compose.external.yml` 被文档引用但尚未提交**
- 文档 `docs/operations/single-host-deployment.md` 已把它写成"仓库中的"部署物。合并前需一并提交（当前 untracked，属 WIP 时序风险）。

**B3. Makefile 与运维文档漂移**
- `docker-prod-config`/`docker-prod-up` 不带 `--env-file .env.production`，也不支持 media-s3/SMTP override 组合，而文档明确要求所有命令带同一组 `-f` 与 env-file。另：`build` 目标硬编码 `bin/nyauth.exe`（Windows 后缀），`swagger` 不在 `.PHONY`。

### 低严重度

**B4. 各拓扑间默认值/secret 策略漂移**
- `external.yml` 的 `NYAUTH_DATABASE_TLS_MODE` 默认 `disable` 而 `ha.yml` 默认 `verify-full`（有文档解释，但默认朝不安全方向）。
- bootstrap 密码策略三种拓扑三个样：prod/ha 裸透传（推荐一次性生成），external 强制 secret 文件。
- `ha.yml` 的 `nyauth-a/b` 缺 `expose: 8080` 声明（prod 有）。
- 三份高度重复的 `x-nyauth-environment` anchor 是漂移温床，每次新增 env 需手工同步多处。

**B5. Dockerfile 供应链基线与文档要求不对称**
- 文档强制 `NYAUTH_IMAGE` 用不可变 digest，但构建端 `node:20-alpine`、`golang:1.26.5-bookworm`、`debian:bookworm-slim` 均为可移动 tag；`COPY web/package-lock.json* ./` 的通配允许 lockfile 缺失时静默继续。运行时镜像本身加固到位。

**B6. 仓库根目录残留物**
- `config.yaml.0.2.bak` 未被 gitignore，存在误提交风险；`nyauth.exe`/`nyauth-dev.exe` 已被 ignore 但建议清理。

### 运维亮点

- **secret 管理高度一致**：三个生产拓扑全部用 `*_FILE` + Compose file secret，无环境变量明文 secret；dev compose 默认值全带 `local-dev-only-` 前缀且端口只绑 `127.0.0.1`。
- **postgres 初始化脚本**（`docker/postgres/init-runtime-role.sh`）用 `\getenv` + `format(%I/%L)` 防注入、校验角色名、最小权限授权。
- **文档与配置同步度非常高**：`docs/operations/` 四篇手册对 secret 权限、`down -v` 危险性、digest 固定、trusted proxy 精确 `/32`、media 后端不可迁移契约等描述与实际内容逐条吻合。

---

## 四、处理建议（优先级）

| 优先级 | 事项 | 引用 |
|---|---|---|
| P0 | 合并前提交 `docker-compose.external.yml` 等 untracked 部署物 | B2 |
| P1 | 审计路由表 fail-open：漏网路由的失败审计 | M3 |
| P1 | `LOCK TABLE users` 改 advisory lock | M2 |
| P1 | provider 行级失败隔离 | M5 |
| P1 | 后端稳定错误码，替代前端文案匹配翻译表 | A2 |
| P2 | code 重放时撤销已签发令牌 | M4 |
| P2 | `resolveClientIP` 补测试；`/authorize`、consent、`safeReturnPath` 补测试 | L1、测试缺口 |
| P2 | postgres/redis 容器加固对齐；Dockerfile 基础镜像固定 digest | B1、B5 |
| P2 | e2e mock 拆分 + 契约校验 | A1 |
| P3 | JWK 缓存、ILIKE 转义、删除 `audit.Store.Record`、`.bak` 清理、api.ts 拆分、组件级单测 | L2-L5、A3、A5 |

## 五、已修复项（2026-07-28）

- 单会话撤销吞错误：`security_center.go` 两处改为错误检查的删除路径，仅自撤销时清 cookie。
- 审计事件常量统一：新增 `models.AuditSessionOthersRevoked`，替换 3 处字面量。
- 移除 `setDynamicProvider` 与 `normalizePresentation` 重复的兜底逻辑。
- `docker-compose.external.yml` 为 bootstrap 密码透传变量补充说明注释。
- 本次变更的 9 个前端文件行首缩进统一为 2 空格。
- `TreeMultiSelect`：combobox 语义、方向键/Escape 键盘导航、分组名中文化。
