# Nyauth 运行时可观测性

Phase C7 把日志级别、运营告警阈值和 OTLP 导出参数变成受控运行时设置。Prometheus `/metrics` 始终保留；主动禁用 OTLP、collector 故障或阈值告警都不会改变 `/readyz`，避免监控链路故障反过来下线认证服务。

## 日志与临时 Debug

日志基线只允许 `info`、`warn` 或 `error`。需要诊断时可临时启用 Debug，截止时间必须在当前时间 1 分钟至 24 小时之间；每个实例在截止时本地恢复原基线，不依赖下一次请求或额外数据库写入。新的设置 revision 会替换旧定时器，因此旧到期任务不能覆盖较新的日志策略。

Debug 日志仍遵守现有脱敏边界。不要把密码、Token、Authorization、DSN 或用户敏感数据写入日志；提高级别不是扩大可记录数据范围的授权。

## 运营告警

管理员可设置邮件 outbox 数量和最老待发年龄、审计 outbox 数量和最老待处理年龄、头像待清理数量五个阈值。服务每 30 秒读取一次固定聚合并发布原子快照，同时输出低基数 `nyauth_operational_alert_active{alert_code}` 指标。

阈值用于发现积压，不代表依赖已经不可用。活动告警显示在系统状态和可观测性设置页，但不会把 PostgreSQL、Redis、SMTP、媒体状态或 readiness 改写为失败。告警标签不会包含用户、邮箱、IP、对象 key 或任意数据库值。

## OTLP 配置生命周期

数据库状态固定为：

- `fallback`：使用启动时的 `NYAUTH_TELEMETRY_OTLP_*`；没有静态配置时仅保留 Prometheus。
- `active`：使用数据库中已测试并激活的版本，忽略静态 OTLP。
- `disabled`：明确关闭 OTLP，重启也不会回退到环境变量。

后台操作顺序：

1. 保存 endpoint、发送间隔、timeout 和可选 Authorization，生成不可变候选。
2. 对候选执行真实测试。服务会向 collector 发送一条专用测试指标，验证 URL、网络、TLS、Authorization 和 collector 接受结果。
3. 在成功测试后的十分钟内激活同一版本。超时或候选变化后必须重测。
4. 需要时回滚到上一活动版本，或显式禁用 OTLP。

Authorization 省略表示继承当前有效 secret；显式空字符串表示清除。首次没有 fallback 时不能省略，必须提供 secret 或明确选择无 Authorization。密文使用 master key envelope encryption，API、审计和日志只返回 `authorization_configured`，不会返回明文或 ciphertext。

生产 endpoint 必须是无凭据、query 和 fragment 的绝对 HTTPS URL。发送间隔范围为 10 秒至 1 小时；timeout 范围为 1–30 秒且不得超过发送间隔。所有写操作要求管理员、CSRF、近期重新认证、固定代码级限流和审计。

## 多实例与故障语义

每个实例保留同一个 Prometheus MeterProvider 和稳定的周期 reader，只原子替换其后的 OTLP exporter，因此已有指标句柄不会因切换失效。在途导出使用旧 exporter 完成，之后的周期使用新版本。PostgreSQL `LISTEN/NOTIFY` 提供即时同步，每分钟 reconciliation 修复丢失通知。

collector 导出错误只记录有界错误类别和时间，不记录不受信任的响应正文。运行中数据库同步暂时失败时保留最后有效 exporter；数据库中明确激活的版本无法解密或验证时则停止 OTLP，不静默发送到旧目的地。系统状态会显示 degraded，但登录、OAuth、Prometheus 和 readiness 继续工作。
