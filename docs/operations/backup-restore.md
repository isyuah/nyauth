# Nyauth 备份与恢复手册

本手册面向生产环境运维。Nyauth 的 PostgreSQL 数据、master key、Redis 安全状态和头像媒体具有不同恢复语义，必须分别处理并在同一次恢复证据中关联。

## 恢复目标

- PostgreSQL：使用全量备份与 WAL 归档实现时间点恢复（PITR）。
- Master key：独立于数据库备份并加密保存；丢失后无法解密 Provider secret、TOTP secret、Passkey credential、动态 SMTP 密码、邮件 outbox 或 JWK 私钥。
- Redis：不恢复旧快照。Redis 丢失后启动空实例，使全部会话和 Token 失效。
- 本地头像：备份 Compose `media` volume 或 `media.local.directory`，并与 PostgreSQL 恢复点配对。
- S3 头像：使用私有 bucket、versioning 和受控 lifecycle 保留足以覆盖数据库 PITR 窗口的对象历史。

## PostgreSQL

生产环境应启用 WAL 归档，并由 PostgreSQL 或托管数据库平台执行基础备份。至少保留：

- 最近一份已验证的基础备份。
- 覆盖目标 RPO 的连续 WAL。
- 与备份对应的 PostgreSQL 主版本、扩展和配置记录。

Nyauth 不负责拉取 WAL、操作托管数据库快照或选择生产恢复点。上线验收必须记录负责这些动作的外部平台、备份策略、告警负责人、目标 RPO/RTO，以及最近一次成功恢复演练。缺少其中任一项时，生产环境不得声明具备 PITR 能力。

仅执行 `pg_dump` 可以用于小规模逻辑备份，但不能替代 PITR。恢复演练必须在隔离网络和独立数据库实例中进行，不得覆盖当前生产数据库。

恢复验证顺序：

1. 恢复到隔离 PostgreSQL。
2. 使用一次性迁移账号运行 schema 检查，不运行应用流量。
3. 将恢复后的用户、客户端、Provider、JWK、审计和邮件 outbox 数量与备份 manifest 比较；另外记录 `mail_config_versions`、`mail_runtime_state`、`user_avatars`、active 头像、待清理头像和 Provider 头像导入任务数量。当前自动化 manifest 尚未包含动态邮件和头像媒体证据。
4. 运行只读的 `nyauth verify-recovery`，验证活动 JWK、全部 Provider Secret、全部 TOTP secret、全部 Passkey credential，以及最多 100 条仍保留密文的邮件 outbox envelope。
5. 在 `serve` 和 maintenance 都停止的状态下，恢复与该数据库恢复点匹配的本地 media 备份或 S3 prefix/version。
6. 使用正确 master key 和匹配的媒体后端启动单个隔离应用实例并检查 `/readyz` 与 `/api/admin/system/status`。媒体故障不进入 `/readyz`，因此必须单独确认 `services.media`。
7. 读取 `/api/admin/settings/mail`，确认活动版本、mode 和 `password_configured` 符合恢复点。当前 `verify-recovery` 不验证动态 SMTP 密码 envelope；应在隔离环境创建继承密码的候选并向受控测试地址实际测试，或使用等价的受控 SMTP 验证流程。
8. 从恢复数据库抽取 active avatar ID，逐个抽查 64、128、256、512 四种 `/media/avatars/{id}/{size}.webp`，确认返回静态 WebP；当前 `verify-recovery` 不读取媒体对象。
9. 验证新的登录和 OAuth code 流程；不得使用备份中的旧 Redis。
10. 验证完成后才允许切换流量。

## 头像媒体

PostgreSQL 保存当前头像引用、对象 key、存储后端和清理状态，图片内容则位于本地目录或 S3。两者无法形成同一个事务快照，恢复策略必须同时处理“数据库引用存在但对象缺失”和“对象存在但数据库不再引用”两类偏差。

### 本地 media volume

开发和单机生产 Compose 的逻辑 volume 名为 `media`，容器内挂载点为 `/var/lib/nyauth/media`；实际 Docker volume 名通常带 Compose project 前缀。备份前用以下只读命令确认最终名称和挂载，不要根据目录名猜测：

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml config --volumes
docker compose --env-file .env.production -f docker-compose.prod.yml ps
docker volume ls
docker volume inspect <confirmed-project-media-volume>
```

本地备份必须满足：

- 备份工具保存完整目录树、文件名和文件内容，并保护备份介质免受未授权读取或修改。
- 为取得清晰恢复边界，短暂停止 `nyauth` 和任何 `nyauth maintenance` 任务，再在同一维护窗口记录 PostgreSQL 恢复点并快照/备份 `media` volume。PostgreSQL 自身可继续由平台执行基础备份和 WAL 归档。
- 备份 manifest 记录 Compose project、实际 volume 名、备份开始/结束时间、对应数据库恢复点、文件数量和备份校验和；不要记录用户邮箱、object key 清单或图片内容。
- 恢复时先停止 `serve` 和 maintenance，恢复 PostgreSQL，再把匹配备份恢复到确认过的 `media` volume，最后启动应用。后台清理在启动后立即运行，恢复尚未完成时不得提前启动。

媒体对象使用不可变、随机 avatar ID 路径。若恢复出的媒体比数据库稍新，多余对象会在失去引用并超过 15 分钟宽限期后由 HA 安全清理回收；若媒体比数据库旧，数据库引用的对象会永久缺失并使对应媒体请求返回 404/503，因此不能把“稍旧的 media 快照 + 较新的数据库 PITR”视为成功恢复。

### 私有 S3

S3 bucket 必须保持 private，并仅向 Nyauth 部署身份授予配置 prefix 下所需的读取、写入和删除权限。建议在对象存储平台启用：

- bucket 默认服务端加密；密钥策略和恢复权限由组织的对象存储规范管理。
- versioning，用于在误删、错误 lifecycle 或数据库回退时找回指定恢复点仍应存在的对象版本。
- 访问日志、对象变更审计和删除告警；这些日志不得公开。
- noncurrent version 与 delete marker 的 lifecycle，但保留期必须不短于 PostgreSQL 的 PITR/WAL 保留窗口、备份发现延迟和恢复审批时间之和。

不得对当前对象版本设置“创建超过 N 天即删除”的通用规则：用户可以多年不更换头像，旧对象仍可能被 active 数据库引用。生命周期只能针对 noncurrent version、已确认的 delete marker 或与 Nyauth 活跃 prefix 明确隔离的临时区域；当前实现本身不创建单独临时 prefix。

S3 恢复应按选定 PostgreSQL 恢复点确定同一时刻应存在的对象版本。恢复或移除 delete marker 后，先在隔离环境使用相同 bucket 的隔离副本/隔离 prefix 验证，不得让恢复演练直接修改生产 prefix。若平台无法按时间恢复整个 prefix，应从数据库中的 active 与尚待清理记录生成受控比对集合，再通过对象版本清单恢复缺失 key；完整 object key 清单属于内部恢复材料，不应进入普通 CI artifact。

### 恢复抽查

隔离数据库中可用以下只读 SQL 选择最近 active 头像；结果只有随机 UUID，不包含用户名或邮箱：

```sql
SELECT id
FROM user_avatars
WHERE status = 'active'
ORDER BY created_at DESC
LIMIT 10;
```

对每个 ID 抽查四种固定尺寸：

```bash
for size in 64 128 256 512; do
  curl --fail --silent --show-error \
    --output "/tmp/avatar-${size}.webp" \
    "https://recovery-auth.example.test/media/avatars/<avatar-id>/${size}.webp"
done
```

证据至少记录抽查数量、四种响应是否成功、`Content-Type: image/webp`、恢复点、媒体后端和验证时间，不保存下载图片本身。抽样通过不能替代对象清单比对；它只证明应用、数据库引用和媒体后端已经连通。

## Master key

`NYAUTH_AUTH_MASTER_KEY` 必须作为独立秘密备份：

- 使用秘密管理器、离线密钥库或双人控制的加密介质。
- 不与数据库备份放在同一存储位置。
- 不写入 Compose 文件、日志、工单或代码仓库。
- 每次恢复演练必须验证密钥可以解密恢复数据库中的活动 JWK、全部 TOTP secret、全部 Passkey credential、Provider secret 和当前动态 SMTP 密码。动态 SMTP 的候选测试、激活与恢复流程见 [动态 SMTP 配置与故障处理](runtime-mail.md)。

所有 Provider、TOTP 与 Passkey envelope 都必须通过认证；报告中的 `totp_envelopes_verified` 和 `passkey_envelopes_verified` 是实际逐条验证数量，后者必须等于 `counts.passkeys`。邮件 outbox 中仍保留密文的记录会抽样验证并报告符合条件的总数与实际抽样数。邮件发送成功或过期后会按设计清除密文，因此邮件抽样数可以为零，报告不得把零样本描述为已验证历史邮件内容。

数据库备份和 master key 任一缺失都应视为不可恢复事件。

## Redis 故障恢复

Redis 保存 session、MFA pending challenge、WebAuthn ceremony、授权码、CSRF state、access token 元数据和 refresh token family。恢复旧 RDB/AOF 可能使已撤销的安全状态重新出现，因此灾难恢复流程为：

1. 启动新的空 Redis。
2. 使用新的强密码和 `noeviction` 策略。
3. 确认应用 `/readyz` 通过。
4. 通知用户重新登录。
5. 检查登录、授权码、refresh rotation 和撤销指标。

Redis 恢复后不得导入事故前的 session/token key。

## 演练频率与证据

- 至少每季度执行一次完整恢复演练。
- 每次发布数据库基线变更后额外执行一次。
- 记录备份时间、恢复点、耗时、验证结果和负责人。
- 演练环境中的数据库、日志和临时 secret 在验证后按内部数据处置流程销毁。

## 自动化隔离演练

`.github/workflows/recovery-drill.yml` 提供手动触发的 `Isolated recovery drill`。它从指定历史 workflow run 下载受保护的数据库备份与 manifest，在 GitHub 托管 runner 上创建无持久 volume 的 PostgreSQL 16 和空 Redis 7。工作流先比较资源数量，再使用候选镜像执行只读 envelope 验证，随后启动应用并验证 `/livez`、`/readyz`、Discovery、JWKS 和 schema。可选步骤会使用受保护环境中的演练账号执行标准 code + S256 + state + nonce 流程。

当前自动化演练不下载、恢复或抽查本地 media volume/S3 对象，manifest 也没有头像计数字段。它只能证明数据库、master key 和核心协议恢复链路，不得作为头像媒体已经恢复的证据。生产演练必须在工作流之外追加本节规定的媒体恢复、对象比对和四尺寸抽查。

使用前必须建立受审批保护的 GitHub Environment `recovery-drill`，至少配置：

- `NYAUTH_RECOVERY_MASTER_KEY`：与备份匹配的 Base64 master key。
- 可选 `NYAUTH_RECOVERY_TEST_USERNAME`、`NYAUTH_RECOVERY_TEST_PASSWORD`、`NYAUTH_RECOVERY_TEST_NEW_PASSWORD`：只属于隔离演练账号。

输入 artifact 应来自专门的受控备份 workflow，或已经完成 PITR 的隔离数据库导出，不应把未经批准的生产数据上传到普通 CI artifact。触发演练时还必须从受信备份系统填写 `expected_backup_sha256`；工作流会在恢复前比较下载文件的 SHA-256，不能只信任与备份一同下载的 manifest。Artifact 必须恰好包含一个 `.dump`、`.sql` 或 `.sql.gz` 文件，以及一个 `recovery-manifest.json`：

```json
{
  "format_version": 1,
  "backup_created_at": "2026-07-26T01:00:00Z",
  "recovery_point": "2026-07-26T01:05:00Z",
  "counts": {
    "users": 42,
    "oauth_clients": 8,
    "oauth_providers": 2,
    "jwk_keys": 3,
    "audit_logs": 1200,
    "email_outbox": 15,
    "passkeys": 6
  }
}
```

Manifest 不得包含用户名、邮箱、Client Secret、Provider Secret、Token 或其他逐条数据。`recovery_point` 必须与手动触发输入一致，全部计数必须是非负整数。工作流以 `recovery_reference_time - recovery_point` 检查 RPO，并以 artifact 下载开始到应用验证完成的耗时检查应用侧 RTO；外部数据库平台恢复快照和重放 WAL 的耗时必须由该平台另行计入完整 RTO。

工作流不实现数据库平台的 WAL 拉取和时间点选择；它负责验证 PITR/恢复产物可由应用和原 master key 正确使用。每次运行上传不含 secret 的 Markdown 证据，并在 `always()` 清理固定名称的一次性容器和网络。

审计表按 UTC 月分区。`migrate` 会在迁移账号权限下执行分区维护；长期无发布的环境应至少每月使用同一迁移账号运行 `nyauth maintenance`。常驻 `serve` 进程不执行 DDL，也不得持有迁移 DSN。

## 破坏性基线提示

当前开发基线不提供旧版本数据迁移。需要重建时，运维人员必须先确认准确的 Compose project、PostgreSQL volume、media volume 或 S3 prefix，并完成必要备份。应用及迁移命令不会自动执行 `docker compose down -v`、删除任何 volume 或清空 S3；`down -v` 会同时删除本地 PostgreSQL 与 media volume，不得用于普通停止或回滚。
