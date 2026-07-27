# Nyauth 备份与恢复手册

本手册面向生产环境运维。Nyauth 的 PostgreSQL 数据、master key 和 Redis 安全状态具有不同恢复语义，必须分别处理。

## 恢复目标

- PostgreSQL：使用全量备份与 WAL 归档实现时间点恢复（PITR）。
- Master key：独立于数据库备份并加密保存；丢失后无法解密 Provider secret、TOTP secret、动态 SMTP 密码、邮件 outbox 或 JWK 私钥。
- Redis：不恢复旧快照。Redis 丢失后启动空实例，使全部会话和 Token 失效。

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
3. 将恢复后的用户、客户端、Provider、JWK、审计和邮件 outbox 数量与备份 manifest 比较；另外记录 `mail_config_versions` 数量与 `mail_runtime_state` singleton 状态。当前自动化 manifest 尚未包含这两项动态邮件证据。
4. 运行只读的 `nyauth verify-recovery`，验证活动 JWK、全部 Provider Secret、全部 TOTP secret，以及最多 100 条仍保留密文的邮件 outbox envelope。
5. 使用正确 master key 启动单个隔离应用实例并检查 `/readyz`。
6. 读取 `/api/admin/settings/mail`，确认活动版本、mode 和 `password_configured` 符合恢复点。当前 `verify-recovery` 不验证动态 SMTP 密码 envelope；应在隔离环境创建继承密码的候选并向受控测试地址实际测试，或使用等价的受控 SMTP 验证流程。
7. 验证新的登录和 OAuth code 流程；不得使用备份中的旧 Redis。
8. 验证完成后才允许切换流量。

## Master key

`NYAUTH_AUTH_MASTER_KEY` 必须作为独立秘密备份：

- 使用秘密管理器、离线密钥库或双人控制的加密介质。
- 不与数据库备份放在同一存储位置。
- 不写入 Compose 文件、日志、工单或代码仓库。
- 每次恢复演练必须验证密钥可以解密恢复数据库中的活动 JWK、全部 TOTP secret、Provider secret 和当前动态 SMTP 密码。动态 SMTP 的候选测试、激活与恢复流程见 [动态 SMTP 配置与故障处理](runtime-mail.md)。

所有 Provider 与 TOTP envelope 都必须通过认证；报告中的 `totp_envelopes_verified` 是实际逐条验证数量。邮件 outbox 中仍保留密文的记录会抽样验证并报告符合条件的总数与实际抽样数。邮件发送成功或过期后会按设计清除密文，因此邮件抽样数可以为零，报告不得把零样本描述为已验证历史邮件内容。

数据库备份和 master key 任一缺失都应视为不可恢复事件。

## Redis 故障恢复

Redis 保存 session、MFA pending challenge、授权码、CSRF state、access token 元数据和 refresh token family。恢复旧 RDB/AOF 可能使已撤销的安全状态重新出现，因此灾难恢复流程为：

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
    "email_outbox": 15
  }
}
```

Manifest 不得包含用户名、邮箱、Client Secret、Provider Secret、Token 或其他逐条数据。`recovery_point` 必须与手动触发输入一致，全部计数必须是非负整数。工作流以 `recovery_reference_time - recovery_point` 检查 RPO，并以 artifact 下载开始到应用验证完成的耗时检查应用侧 RTO；外部数据库平台恢复快照和重放 WAL 的耗时必须由该平台另行计入完整 RTO。

工作流不实现数据库平台的 WAL 拉取和时间点选择；它负责验证 PITR/恢复产物可由应用和原 master key 正确使用。每次运行上传不含 secret 的 Markdown 证据，并在 `always()` 清理固定名称的一次性容器和网络。

审计表按 UTC 月分区。`migrate` 会在迁移账号权限下执行分区维护；长期无发布的环境应至少每月使用同一迁移账号运行 `nyauth maintenance`。常驻 `serve` 进程不执行 DDL，也不得持有迁移 DSN。

## 破坏性基线提示

当前开发基线不提供旧版本数据迁移。需要重建时，运维人员必须先确认准确的 Compose project 和 volume 名称，并完成必要备份。应用及迁移命令不会自动执行 `docker compose down -v` 或删除任何 volume。
