# Nyauth 双实例部署

Nyauth 的高可用形态是多个无状态应用实例共享外部 PostgreSQL、Redis 和私有 S3 兼容头像存储。内置数据容器和本地 media volume 只用于开发与小规模单机部署。

仓库中的 `docker-compose.ha.yml` 是双实例部署物，只包含一次性 `migrate`、`nyauth-a` 和 `nyauth-b`。它不创建 PostgreSQL/Redis 容器，不发布应用或数据端口；两个应用仅通过外部 proxy network 接收反向代理流量。

## 依赖要求

- PostgreSQL 提供高可用、备份、PITR 和连接上限管理。
- PostgreSQL 平台预先创建相互独立的迁移登录角色和 runtime 登录角色；迁移角色拥有目标数据库与应用 schema，runtime 角色不得拥有 superuser、createdb、createrole 或 schema CREATE 权限。
- Redis 使用认证、TLS、`noeviction` 和故障转移能力。
- 头像媒体使用所有实例共享的同一私有 S3 bucket 与 prefix；HA 不支持每个实例各自使用本地目录。
- 所有应用实例使用同一 issuer、master key、Cookie 配置和可信代理 CIDR。WebAuthn RP ID 固定取 issuer hostname；实例间不一致会直接破坏 Passkey ceremony，更换 hostname 会使旧 Passkey 不可用。
- 反向代理只向 `/readyz` 返回成功的实例发送流量。
- 迁移由独立一次性任务执行，应用启动不隐式修改 schema。

## Compose 前置条件

外部 PostgreSQL 和 Redis 必须可从同一个 backend network 访问，反向代理必须加入 proxy network。两个网络都由平台预先创建并交给 Compose 引用，Compose 不负责创建或删除它们。

必须配置：

- `NYAUTH_IMAGE`：使用不可变镜像 digest。
- `NYAUTH_DATABASE_DSN_FILE`：仅含运行账号 DSN 的文件。
- `NYAUTH_DATABASE_MIGRATION_DSN_FILE`：仅含迁移账号 DSN 的文件。
- `NYAUTH_DATABASE_RUNTIME_ROLE`：运行账号角色名，默认 `nyauth_runtime`，必须与运行 DSN 中的 PostgreSQL `current_user` 完全一致。
- `NYAUTH_REDIS_ADDR` 和 `NYAUTH_REDIS_PASSWORD_FILE`：外部 Redis 地址与密码文件。
- `NYAUTH_AUTH_MASTER_KEY_FILE`：所有实例共享的 Base64 32 字节 master key。
- `NYAUTH_AUTH_ISSUER` 和 `NYAUTH_TRUSTED_PROXY_CIDRS`：公开 HTTPS issuer 与准确的反向代理 CIDR。
- `NYAUTH_BACKEND_NETWORK` 和 `NYAUTH_PROXY_NETWORK`：预置 Docker network 名称。
- `NYAUTH_MEDIA_S3_REGION`、`NYAUTH_MEDIA_S3_BUCKET`：共享的私有 S3 兼容存储区域与 bucket。
- `NYAUTH_MEDIA_S3_ACCESS_KEY_ID_FILE`、`NYAUTH_MEDIA_S3_SECRET_ACCESS_KEY_FILE`：S3 凭据 secret 文件；两个应用和 maintenance 使用同一权限边界。
- 可选 `NYAUTH_MEDIA_S3_ENDPOINT`、`NYAUTH_MEDIA_S3_PREFIX`、`NYAUTH_MEDIA_S3_PATH_STYLE`：自定义 S3 endpoint、共享 prefix 与 path-style 行为。

Redis TLS 默认启用。使用公共 CA 时无需额外文件；使用私有 CA 时，通过部署环境的 Compose override 将只读 CA 文件挂入两个应用和迁移容器，并设置 `NYAUTH_REDIS_TLS_ROOT_CA_FILE`。只有依赖网络已经提供等效的加密隔离时，才应显式设置 `NYAUTH_REDIS_TLS_ENABLED=false`。

SMTP 的主配置保存在共享 PostgreSQL，并按 [动态 SMTP 配置与故障处理](runtime-mail.md) 通过候选、真实测试邮件和激活流程免重启切换。Nyauth 只发信，不读取邮箱，因此无需 IMAP。环境变量和 password file 仅作为数据库状态仍为 `fallback` 时的首次 bootstrap；若使用它，仓库提供的 HA override 会把同一只读 secret 挂入两个实例：

```bash
docker compose \
  -f docker-compose.ha.yml \
  -f docker/compose.ha.smtp-password-file.yml \
  config --quiet
```

SMTP 其余 `NYAUTH_MAIL_*` 参数由部署环境提供。两个实例的 fallback 必须完全一致；仍处于 `fallback` 时修改静态配置需要重建两个 `serve` 实例。管理员一旦激活数据库候选或明确禁用邮件，环境 fallback 不再参与选择，重启也不会重新启用它。

## 共享头像媒体

`docker-compose.ha.yml` 固定设置 `NYAUTH_MEDIA_BACKEND=s3`，并把同一 access key ID/secret access key 文件挂载到 `nyauth-a`、`nyauth-b` 和用于 `maintenance` 的 `migrate` service。HA 部署不得通过环境覆盖回 `local`，也不得给不同实例配置不同 bucket、prefix 或凭据范围。

当前 Compose 契约为：

```dotenv
NYAUTH_MEDIA_S3_ENDPOINT=https://s3.example.com
NYAUTH_MEDIA_S3_REGION=auto
NYAUTH_MEDIA_S3_BUCKET=nyauth-media
NYAUTH_MEDIA_S3_PREFIX=nyauth
NYAUTH_MEDIA_S3_PATH_STYLE=false
NYAUTH_MEDIA_S3_ACCESS_KEY_ID_FILE=/secure/path/media-s3-access-key-id
NYAUTH_MEDIA_S3_SECRET_ACCESS_KEY_FILE=/secure/path/media-s3-secret-access-key
```

`NYAUTH_MEDIA_S3_ENDPOINT` 可留空以使用 AWS SDK 默认 endpoint；自定义 endpoint 在生产环境必须使用 HTTPS。R2 等平台按供应商要求填写 region，MinIO 等实现需要时启用 path-style。bucket 必须 private，浏览器不会取得对象存储凭据或直接访问 bucket，而是通过任一 Nyauth 实例的同源 `/media/avatars/...` 路由读取。

凭据只授予目标 bucket 中配置 prefix 所需的读取、写入和删除权限。bucket 应启用默认静态加密、versioning、访问审计和删除告警；lifecycle 不得按年龄删除当前对象版本，只能在覆盖 PostgreSQL PITR 窗口后清理 noncurrent version 和 delete marker。完整恢复要求见 [备份与恢复手册](backup-restore.md)。

静态媒体配置只是在数据库尚未激活动态 profile 时使用的 fallback。管理员可在单机阶段通过 `/admin/settings/media` 保存并真实测试私有 S3 候选，再由系统排空 `media_writes`、逐对象复制回读校验并切换 profile；迁移完成且所有实例加载新 revision 后，才能把应用扩成 HA。失败迁移仍会阻止清理和候选替换，必须在媒体写入保持排空时重试。迁回已配置本地 fallback 只允许在单实例阶段执行；HA 不能使用各实例互不共享的本地目录。

展开配置前先确认两个 secret 文件存在且权限受控：

```bash
docker compose -f docker-compose.ha.yml config --quiet
```

日常 maintenance 也必须携带相同 S3 配置与 secret，以便清理 PostgreSQL 已解除引用的头像对象：

```bash
docker compose -f docker-compose.ha.yml run --rm migrate maintenance
```

媒体存储故障不会让 `/readyz` 失败，也不会下线登录和 OAuth/OIDC；头像上传或读取会返回 `503`。删除先解除 PostgreSQL 当前引用并返回成功，对象删除失败由共享清理任务重试。管理员系统状态的 `services.media` 会显示 degraded 和最近错误时间。反向代理不能仅依赖 `/readyz` 判断头像能力，必须另外监控媒体状态和头像存储错误指标。

外部 PostgreSQL 不会由 Compose 创建登录角色。DBA 至少要在目标数据库中先执行等价操作，并将密码只写入运行 DSN secret：

```sql
CREATE ROLE nyauth_runtime LOGIN PASSWORD '<secret>'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
```

迁移角色必须拥有目标数据库和应用 schema，或具备向 runtime 角色授予 `CONNECT`、schema `USAGE`、现有对象权限及 default privileges 的 grant option。runtime 角色不得属于任何其他 PostgreSQL 角色，以免通过 `SET ROLE` 绕过权限边界。`nyauth migrate` 在 schema 成功建立后原子授予业务表 DML、sequence、function 和 type 权限，并把 `schema_migrations` 收紧为只读；runtime 角色不存在、存在角色成员关系或迁移角色无权授权时，迁移任务会失败。生产 `serve` 启动还会验证 `current_user` 等于 `NYAUTH_DATABASE_RUNTIME_ROLE`，并拒绝高权限属性、角色成员关系、应用 schema `CREATE` 权限及 `schema_migrations` 写权限。

展开配置不会连接依赖，也不会启动容器：

```bash
docker compose -f docker-compose.ha.yml config --quiet
```

首次启动或破坏性版本切换时，先停止所有旧版本实例，再启动新栈。`migrate` 成功退出后，Compose 才会启动两个应用：

```bash
docker compose -f docker-compose.ha.yml up -d
docker compose -f docker-compose.ha.yml ps
```

反向代理 upstream 使用 `nyauth-a:8080` 和 `nyauth-b:8080`，只把 `/readyz` 成功的实例纳入流量。不要从宿主机发布 `8080`，也不需要粘性会话。

## 一致性模型

- Session、MFA pending、WebAuthn ceremony、授权码和 Token 安全状态由共享 Redis 保证；Passkey MFA 的 ceremony 与父 pending 由 Lua 原子消费，不需要粘性会话。
- JWK 轮换由 PostgreSQL advisory lock 保证单写者。
- Provider 变更通过 PostgreSQL `LISTEN/NOTIFY` 通知，并使用周期 reconciliation 修复丢失通知。
- 头像元数据和当前引用存于 PostgreSQL，四种 WebP 变体存于共享 S3。两个实例可跨节点上传和读取；Provider 导入任务使用行锁/lease 分工，孤儿清理使用 PostgreSQL advisory lock 保证每轮单执行者。
- 动态 SMTP 的活动版本、上一版本和熔断状态由 PostgreSQL 共享；变更通过 `LISTEN/NOTIFY` 同步，并每分钟 reconciliation。每 30 秒最多一个实例取得熔断探测权。
- 日志基线、临时 Debug 和运营告警阈值由通用运行时设置共享；OTLP 使用独立的不可变候选、测试证据与活动版本。变更通过 `LISTEN/NOTIFY` 同步并每分钟 reconciliation，实例只替换 exporter，不重建 Prometheus MeterProvider。collector 故障和阈值告警不改变 `/readyz`。
- 运行时服务控制状态和 revision 存于 PostgreSQL；`LISTEN/NOTIFY` 提供即时同步，5 秒 reconciliation 修复丢失通知。实例先关闭对应 gate，再等待旧 in-flight 排空并确认 applied revision。15 秒未能刷新数据库状态的实例对六类受控能力 fail-closed，但健康检查、撤销、登出、审计与清理仍可用。
- 运行时运营设置存于 PostgreSQL 并按设置组使用 revision CAS；实例通过原子快照、`LISTEN/NOTIFY` 和每分钟 reconciliation 同步。限流 revision 隔离 Redis 计数；全局客户端配额变更与客户端创建/转入使用共享/独占 advisory lock 建立明确提交边界。
- 运行时媒体 profile 和迁移状态存于 PostgreSQL；实例预加载候选私有 S3 profile 后才允许迁移。迁移使用持久化逐头像 item、对象回读哈希校验和 `media_writes` 排空，失败不会切断旧 profile 读取，也不会自动覆盖管理员后续维护状态。
- 管理员高风险变更与审计记录必须在同一数据库事务中完成。
- 审计日志按 UTC 月分区；分区预创建和保留清理由独立迁移账号运行 `nyauth maintenance`，应用实例不执行 DDL。

## 发布顺序

`0.3.0-rc.1` 是 schema version 1 的破坏性 release baseline，不支持从早期开发数据库滚动升级。正式 `0.3.0` 通过兼容迁移演进到 schema version 3；`0.4.0-dev` 再通过 `000004` 至 `000009_runtime_observability` 兼容升级到 schema version 9。必须先由迁移任务完成加法迁移，再逐个替换应用实例。首次部署仍必须使用全新 PostgreSQL/Redis；启动单个新实例完成 smoke test 后再扩容第二实例。后续版本只有在发布说明明确承诺兼容时才可滚动升级，不得让要求不同数据库契约的应用版本同时处理流量。

运行时暂停变更后，管理 API 最多等待 5 秒收集所有活动实例的排空确认；返回 `202 applying` 时设置已经生效且不会自动回滚，应轮询管理状态直至所有活动实例 applied。无限期暂停的 HA 紧急解锁可从任一相同版本服务定义执行：

```bash
docker compose --env-file .env.production -f docker-compose.ha.yml run --rm --no-deps nyauth-a \
  service-control reset -reason "HA break-glass recovery"
```

命令只需 runtime PostgreSQL DSN，不开放额外端口，默认等待在线实例 30 秒并输出 JSON 应用进度。不要在两个节点并发重复执行；revision CAS 会保持状态一致，但会制造无意义的额外审计和 revision。

## 故障验证

每次高可用发布至少验证：

- 任一应用实例终止后已有会话可通过另一实例继续使用。
- 同一授权码并发交换只有一个成功。
- 同一 refresh token 并发轮换只有一个成功，重复使用撤销整个 family。
- Provider 启停、删除和 JWK 轮换在所有实例收敛。
- SMTP 候选激活、回滚和禁用在所有实例收敛；模拟丢失通知后也能在 reconciliation 周期内一致。
- SMTP 配置/认证/TLS 故障或传输故障达到阈值后共享熔断只打开一次，注册返回 `503`，探测成功后所有实例恢复投递。
- 用户暂停、密码重置和会话撤销在所有实例立即生效。
- Passkey options 可在一个实例创建、在另一实例完成；同一 ceremony 只能成功消费一次，Passkey MFA 不会留下可单独重放的父 challenge。
- 在一个实例上传头像后，另一实例能立即读取四种尺寸；删除或替换后，旧 avatar ID 不再作为 active 媒体提供。
- 模拟 S3 读取或写入失败时，对应头像 API 返回 `503`；模拟对象删除失败时，逻辑删除仍成功且进入待清理队列。两类故障都使 `services.media` 变为 degraded，但两个实例的 `/readyz`、登录和 OAuth/OIDC 仍保持可用。
- 停止任一实例的 Provider 头像 worker 或清理任务后，另一实例能继续领取任务；并发清理不会把同一对象误确认删除两次。
- 在一个实例设置四种维护预设和单独能力暂停后，两个实例都拒绝新工作、允许旧 in-flight 完成，并在 5 秒内确认相同 revision；模拟丢失通知时 reconciliation 最终收敛。
- 模拟 PostgreSQL 状态刷新失败超过 15 秒时，失联实例对受控能力 fail-closed；恢复连接后按数据库 revision 恢复。到期恢复只能写一次 `service_control.expired` 审计，CLI reset 可在管理 UI 不可用时恢复全部能力。

CI 的真实 PostgreSQL/Redis 集成测试使用两个独立 HTTP Server、连接池和 Redis client，覆盖 Cookie 跨实例使用、用户暂停后的跨实例失效、Passkey options 跨实例完成与单次消费，以及通过 `/token` 并发交换同一授权码时只有一个请求成功。组件级测试继续覆盖 Provider 通知与 reconciliation、JWK advisory lock 和 Refresh family 并发轮换。完整部署仍应在目标反向代理和托管依赖上重复上述故障验证。
