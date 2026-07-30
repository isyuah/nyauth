# Nyauth 动态 SMTP 配置与故障处理

Nyauth 只通过 SMTP 发送验证、密码恢复、邮箱变更和安全通知邮件，不读取任何邮箱，也不需要或支持 IMAP。运行中的 SMTP 主配置保存在 PostgreSQL；管理员可以保存候选版本、发送真实测试邮件、激活、回滚或禁用，无需重启 `serve` 实例。

事务邮件的主题、标题、正文、按钮文字和统一页脚也可以在“设置 → 沟通”中免重启修改。这里不是任意 HTML 编辑器：字段只接受纯文本和服务端按字段允许的变量；HTML 外壳、动作链接、有效期和安全提示由 Nyauth 固定生成并转义。预览使用 `example.invalid` 示例链接，真实模板测试只能发送到当前管理员已经验证的邮箱，且不会生成真实账户操作 Token。保存后的模板只影响之后新入队的邮件，已经加密写入 outbox 的邮件保持原内容。

本文中的管理端点仍属于第一方后台 API，不是稳定的 `/api/v1` 自动化契约。所有示例都使用占位值或交互式秘密输入，不要把真实 SMTP 密码写入仓库、命令历史、工单或截图。

## 配置来源与状态

`0.3.0` 的 release baseline 创建不可变配置版本、测试记录和一个共享运行状态。运行状态有三种模式：

| `mode` | 含义 |
|---|---|
| `fallback` | 尚未明确激活或禁用数据库配置；如果启动环境提供了有效的 `NYAUTH_MAIL_*`，临时使用该配置。 |
| `active` | 使用数据库中的活动版本；环境变量不再参与选择。 |
| `disabled` | 邮件被管理员明确禁用；不会自动回退到环境变量。 |

环境变量和 `NYAUTH_MAIL_SMTP_PASSWORD_FILE` 只用于首次启动的 fallback/bootstrap。数据库状态一旦进入 `active` 或 `disabled`，重启也不会重新启用环境 fallback。此后修改 SMTP 应走动态配置流程；只有仍处于 `fallback` 时修改环境配置才需要重启所有 `serve` 实例。

SMTP 密码使用 `auth.master_key` 做 envelope encryption。管理 API 不返回密码或密文，只返回 `password_configured`。保存候选时：

- 省略 `password`：从当前有效的数据库配置或环境 fallback 继承；没有可继承来源时返回 `400`。
- 传入非空 `password`：保存新的加密密码。
- 显式传入空字符串：配置无需认证的 passwordless SMTP；不要用空字符串表达“保留旧密码”。
- `disabled` 模式没有有效继承来源，重新启用前必须显式提供密码或空字符串。

数据库配置是多实例共享的事实来源。变更通过 PostgreSQL `LISTEN/NOTIFY` 通知其他实例，并每分钟对账一次以修复丢失通知。Dispatcher 在领取一个有界批次前读取原子 sender 快照，并在领取事务中对 `mode`、活动版本和熔断状态加共享行锁复核；领取提交后的邮件视为已在途，可以使用该快照完成，状态变更后不能再由旧 sender 领取新邮件。发现本地快照落后时，本轮不领取并立即刷新。

## 安全变更流程

固定管理 API 如下：

| 方法 | 路径 | 作用 |
|---|---|---|
| GET | `/api/admin/settings/mail` | 查看 mode、活动/候选/上一版本、状态 revision 与熔断状态。 |
| PUT | `/api/admin/settings/mail/candidate` | 创建新的不可变候选版本。 |
| POST | `/api/admin/settings/mail/candidate/test` | 使用指定候选向指定地址实际发送测试邮件。 |
| POST | `/api/admin/settings/mail/activate` | 激活最近十分钟内测试成功的同一候选版本。 |
| POST | `/api/admin/settings/mail/rollback` | 切回 `previous`；没有上一数据库版本时返回 `409`。 |
| POST | `/api/admin/settings/mail/disable` | 明确禁用邮件；自助注册必须先设为 `closed`。 |

读取配置和所有变更都要求管理员会话在最近十分钟内完成过认证。密码账户可调用 `POST /api/me/reauth/password`；无本地密码的账户可通过已绑定 Provider 的 `POST /api/me/reauth/{provider}` 浏览器流程完成。修改请求还必须携带会话的 `X-CSRF-Token`，并受操作限流保护。

SMTP 管理默认使用独立于公开账户操作的宽松限流：15 分钟内同一管理员与来源 IP 组合可保存 60 次候选配置，发送 30 次测试邮件，并分别执行 30 次激活、回滚或禁用；同一来源 IP 的每类操作默认聚合上限为 200 次。管理员可在“访问保护”中热更新这些阈值或显式关闭 SMTP 管理限流；变更 revision 会切换 Redis key namespace，各类操作的计数仍互不影响。超过限制时 API 返回 `429` 和 `Retry-After`；公开注册、密码恢复和邮箱验证使用独立的账户操作策略。

推荐顺序：

1. 读取当前配置，取得 `state_revision`。
2. 用该 revision 保存候选；候选保存后不可修改，继续调整会创建新版本。
3. 对候选发送真实测试邮件。HTTP `200` 仍可能返回 `result: "failure"`，必须检查 `result` 和 `error_category`。
4. 仅当同一版本测试成功后，使用测试响应中的最新 `state_revision` 在十分钟内激活。
5. 激活后再次读取状态，确认 `mode=active`、`available=true`、活动版本 ID 正确。

每次操作都使用乐观并发 revision。收到 `409 mail settings changed; reload and try again` 时，不要盲目重放旧请求；重新 GET，确认当前候选和活动版本后再决定。测试成功超过十分钟、候选已被替换或测试的是其他版本时，激活都会被拒绝。

首次从环境 fallback 激活数据库版本时还没有 `previous` 数据库版本，因此不能回滚到环境 fallback。第二次激活会保留上一活动版本；从此可通过 rollback 在两个数据库版本之间安全切换。禁用活动配置也会保留上一版本，关闭注册后可禁用，之后可回滚恢复。

配置保存、测试、激活、禁用和回滚，以及熔断打开/恢复都会写入审计事件。测试收件地址只以摘要持久化；SMTP 密码、密文和邮件正文不会进入管理响应或审计详情。

## 投递可信度与反垃圾邮件

Nyauth 会为账户操作邮件生成完整的纯文本与 HTML 两部分、与发件地址域名一致的 `Message-ID`，并标记为自动生成的事务邮件。这些格式能够减少内容过于简陋、身份头明显不一致造成的误判，但不能替代发件域名和 SMTP 基础设施的信誉配置。

生产环境至少应确认以下事项：

- `from_address` 使用你实际控制的域名，并且该地址允许通过所选 SMTP 服务发信。不要伪造公共邮箱或未授权域名的 From 地址。
- 在 DNS 中发布 SPF，授权实际投递邮件的 SMTP 服务；不要简单复制服务商示例而形成多个 SPF TXT 记录。
- 在 SMTP 服务商处启用 DKIM，并从实际收到的邮件头确认 `dkim=pass`，而不只是看到 DNS 记录存在。
- 发布 DMARC，并确保可见的 From 域与通过验证的 SPF Return-Path 或 DKIM 签名域至少有一项对齐。上线初期可先使用监控策略，再根据报告逐步收紧。
- `public_base_url` 在生产环境使用稳定的 HTTPS 域名，不要使用 IP、`localhost`、短链接或与组织无关的临时域名。验证链接域最好与发件域属于同一组织域。
- 使用自建 SMTP 时还要配置稳定的 EHLO 名称、PTR/rDNS 和 TLS 证书；使用托管 SMTP 时通常由服务商负责这些项目。

测试邮件到达后，检查原始邮件头中的 `Authentication-Results`，确认 SPF、DKIM、DMARC 均符合预期。若收件系统仍返回 `912` 或“疑似垃圾邮件”，应同时核对退信中的拒绝阶段、发件域信誉、链接域信誉和正文，而不能只反复修改 SMTP 端口或密码。模板更新只影响新入队邮件；已经加密存入 outbox 的旧邮件会保留原正文。

## 本地开发：PowerShell 操作路径

先按 README 启动开发 Compose，访问 `http://localhost:8080`，完成首次管理员密码修改。以下脚本需要 PowerShell 7+，会在内存中交互式读取管理员密码和 SMTP 密码；示例结束后变量会清空。它会登录、显式重新认证、保存候选、实际发送测试邮件并激活。

```powershell
Set-Location E:\Proj\nya

$baseUrl = 'http://localhost:8080'
$origin = $baseUrl

function Read-PlainSecret([string]$Prompt) {
    $secure = Read-Host $Prompt -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

$adminUsername = Read-Host '管理员用户名'
$adminPassword = Read-PlainSecret '管理员密码'
$smtpPassword = $null

try {
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $login = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/login" `
        -WebSession $session -Headers @{ Origin = $origin } `
        -ContentType 'application/json' `
        -Body (@{ username = $adminUsername; password = $adminPassword } | ConvertTo-Json)

    if ($login.must_change_password) {
        throw '请先在 Web UI 修改 bootstrap 管理员密码，然后重新运行本脚本。'
    }

    $csrf = $login.csrf_token
    $reauth = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/me/reauth/password" `
        -WebSession $session `
        -Headers @{ Origin = $origin; 'X-CSRF-Token' = $csrf } `
        -ContentType 'application/json' `
        -Body (@{ password = $adminPassword } | ConvertTo-Json)
    $csrf = $reauth.csrf_token

    $current = Invoke-RestMethod -Method Get -Uri "$baseUrl/api/admin/settings/mail" `
        -WebSession $session -Headers @{ Origin = $origin }
    $current | ConvertTo-Json -Depth 8

    $smtpHost = Read-Host 'SMTP 主机'
    $smtpPortText = Read-Host 'SMTP 端口 [587]'
    $smtpPort = if ([string]::IsNullOrWhiteSpace($smtpPortText)) { 587 } else { [int]$smtpPortText }
    $smtpUsername = Read-Host 'SMTP 用户名（可为空）'
    $smtpPassword = Read-PlainSecret 'SMTP 密码（passwordless SMTP 可留空）'
    $fromAddress = Read-Host '发件地址'
    $fromName = Read-Host '发件名称 [Nyauth]'
    if ([string]::IsNullOrWhiteSpace($fromName)) { $fromName = 'Nyauth' }
    $testRecipient = Read-Host '接收真实测试邮件的地址'

    $candidateBody = @{
        expected_revision = [int64]$current.state_revision
        host = $smtpHost
        port = $smtpPort
        username = $smtpUsername
        password = $smtpPassword
        tls_mode = 'starttls'
        from_address = $fromAddress
        from_name = $fromName
        public_base_url = $baseUrl
        connect_timeout = '5s'
        send_timeout = '15s'
    }
    $candidate = Invoke-RestMethod -Method Put -Uri "$baseUrl/api/admin/settings/mail/candidate" `
        -WebSession $session `
        -Headers @{ Origin = $origin; 'X-CSRF-Token' = $csrf } `
        -ContentType 'application/json' -Body ($candidateBody | ConvertTo-Json)

    $testBody = @{
        expected_revision = [int64]$candidate.state_revision
        version_id = $candidate.candidate.id
        email = $testRecipient
    }
    $test = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/admin/settings/mail/candidate/test" `
        -WebSession $session `
        -Headers @{ Origin = $origin; 'X-CSRF-Token' = $csrf } `
        -ContentType 'application/json' -Body ($testBody | ConvertTo-Json)

    if ($test.result -ne 'success') {
        throw "SMTP 测试失败，分类：$($test.error_category)。候选未激活。"
    }

    $activateBody = @{
        expected_revision = [int64]$test.state_revision
        version_id = $candidate.candidate.id
    }
    Invoke-RestMethod -Method Post -Uri "$baseUrl/api/admin/settings/mail/activate" `
        -WebSession $session `
        -Headers @{ Origin = $origin; 'X-CSRF-Token' = $csrf } `
        -ContentType 'application/json' -Body ($activateBody | ConvertTo-Json)

    Invoke-RestMethod -Method Get -Uri "$baseUrl/api/admin/settings/mail" `
        -WebSession $session -Headers @{ Origin = $origin } | ConvertTo-Json -Depth 8
}
finally {
    $adminPassword = $null
    $smtpPassword = $null
}
```

本地开发允许 `public_base_url=http://localhost:8080`。若以 `environment=production` 运行，即使是内网地址，也必须使用 HTTPS，并且 `tls_mode` 只能是 `starttls` 或 `implicit`。

## 远程部署：curl 操作路径

从受控运维工作站运行以下示例，不需要进入应用容器。前置工具为现代 `curl` 和 `jq`，公开地址必须与 `auth.issuer` 完全一致。脚本不会把密码写入命令历史或文件；Cookie jar 在退出时删除。

```bash
set -euo pipefail
umask 077

BASE_URL='https://auth.example.com'
BASE_URL="${BASE_URL%/}"
ORIGIN="$BASE_URL"
COOKIE_JAR="$(mktemp)"
trap 'rm -f "$COOKIE_JAR"; unset ADMIN_PASSWORD SMTP_PASSWORD ADMIN_USERNAME SMTP_USERNAME TEST_RECIPIENT' EXIT

read -r -p '管理员用户名: ' ADMIN_USERNAME
read -r -s -p '管理员密码: ' ADMIN_PASSWORD
printf '\n'

LOGIN_JSON="$({
  ADMIN_USERNAME="$ADMIN_USERNAME" ADMIN_PASSWORD="$ADMIN_PASSWORD" \
    jq -n '{username:env.ADMIN_USERNAME,password:env.ADMIN_PASSWORD}'
} | curl --fail-with-body --silent --show-error \
  --cookie "$COOKIE_JAR" --cookie-jar "$COOKIE_JAR" \
  --header "Origin: $ORIGIN" --header 'Content-Type: application/json' \
  --data-binary @- "$BASE_URL/api/login")"

if jq -e '.must_change_password == true' >/dev/null <<<"$LOGIN_JSON"; then
  echo '请先通过 Web UI 修改 bootstrap 管理员密码。' >&2
  exit 1
fi

CSRF="$(jq -er '.csrf_token' <<<"$LOGIN_JSON")"
REAUTH_JSON="$({
  ADMIN_PASSWORD="$ADMIN_PASSWORD" jq -n '{password:env.ADMIN_PASSWORD}'
} | curl --fail-with-body --silent --show-error \
  --cookie "$COOKIE_JAR" --cookie-jar "$COOKIE_JAR" \
  --header "Origin: $ORIGIN" --header "X-CSRF-Token: $CSRF" \
  --header 'Content-Type: application/json' \
  --data-binary @- "$BASE_URL/api/me/reauth/password")"
CSRF="$(jq -er '.csrf_token' <<<"$REAUTH_JSON")"

CURRENT_JSON="$(curl --fail-with-body --silent --show-error \
  --cookie "$COOKIE_JAR" --header "Origin: $ORIGIN" \
  "$BASE_URL/api/admin/settings/mail")"
STATE_REVISION="$(jq -er '.state_revision' <<<"$CURRENT_JSON")"
jq . <<<"$CURRENT_JSON"

read -r -p 'SMTP 主机: ' SMTP_HOST
read -r -p 'SMTP 端口 [587]: ' SMTP_PORT
SMTP_PORT="${SMTP_PORT:-587}"
read -r -p 'SMTP 用户名（可为空）: ' SMTP_USERNAME
read -r -s -p 'SMTP 密码（passwordless SMTP 可留空）: ' SMTP_PASSWORD
printf '\n'
read -r -p '发件地址: ' FROM_ADDRESS
read -r -p '发件名称 [Nyauth]: ' FROM_NAME
FROM_NAME="${FROM_NAME:-Nyauth}"
read -r -p '接收真实测试邮件的地址: ' TEST_RECIPIENT

CANDIDATE_JSON="$({
  SMTP_HOST="$SMTP_HOST" SMTP_PORT="$SMTP_PORT" SMTP_USERNAME="$SMTP_USERNAME" \
  SMTP_PASSWORD="$SMTP_PASSWORD" FROM_ADDRESS="$FROM_ADDRESS" FROM_NAME="$FROM_NAME" \
  jq -n \
    --argjson expected_revision "$STATE_REVISION" \
    --arg tls_mode 'starttls' --arg public_base_url "$BASE_URL" \
    --arg connect_timeout '5s' --arg send_timeout '15s' \
    '{expected_revision:$expected_revision,host:env.SMTP_HOST,port:(env.SMTP_PORT|tonumber),
      username:env.SMTP_USERNAME,password:env.SMTP_PASSWORD,tls_mode:$tls_mode,
      from_address:env.FROM_ADDRESS,from_name:env.FROM_NAME,
      public_base_url:$public_base_url,connect_timeout:$connect_timeout,send_timeout:$send_timeout}'
} | curl --fail-with-body --silent --show-error --request PUT \
  --cookie "$COOKIE_JAR" --header "Origin: $ORIGIN" \
  --header "X-CSRF-Token: $CSRF" --header 'Content-Type: application/json' \
  --data-binary @- "$BASE_URL/api/admin/settings/mail/candidate")"

VERSION_ID="$(jq -er '.candidate.id' <<<"$CANDIDATE_JSON")"
STATE_REVISION="$(jq -er '.state_revision' <<<"$CANDIDATE_JSON")"

TEST_JSON="$({
  TEST_RECIPIENT="$TEST_RECIPIENT" jq -n --argjson expected_revision "$STATE_REVISION" \
    --arg version_id "$VERSION_ID" \
    '{expected_revision:$expected_revision,version_id:$version_id,email:env.TEST_RECIPIENT}'
} | curl --fail-with-body --silent --show-error --request POST \
  --cookie "$COOKIE_JAR" --header "Origin: $ORIGIN" \
  --header "X-CSRF-Token: $CSRF" --header 'Content-Type: application/json' \
  --data-binary @- "$BASE_URL/api/admin/settings/mail/candidate/test")"

if ! jq -e '.result == "success"' >/dev/null <<<"$TEST_JSON"; then
  jq . <<<"$TEST_JSON" >&2
  echo 'SMTP 测试失败，候选未激活。' >&2
  exit 1
fi
STATE_REVISION="$(jq -er '.state_revision' <<<"$TEST_JSON")"

ACTIVATE_JSON="$({
  jq -n --argjson expected_revision "$STATE_REVISION" --arg version_id "$VERSION_ID" \
    '{expected_revision:$expected_revision,version_id:$version_id}'
} | curl --fail-with-body --silent --show-error --request POST \
  --cookie "$COOKIE_JAR" --header "Origin: $ORIGIN" \
  --header "X-CSRF-Token: $CSRF" --header 'Content-Type: application/json' \
  --data-binary @- "$BASE_URL/api/admin/settings/mail/activate")"
jq . <<<"$ACTIVATE_JSON"

curl --fail-with-body --silent --show-error \
  --cookie "$COOKIE_JAR" --header "Origin: $ORIGIN" \
  "$BASE_URL/api/admin/settings/mail" | jq .
```

生产候选必须使用 `starttls` 或 `implicit`，`public_base_url` 必须是无凭据、query 和 fragment 的绝对 HTTPS URL。若要继承当前有效密码，应从候选 JSON 中完全删除 `password` 字段。当前 DTO 会把 JSON `null` 解码成与省略字段相同的值，但运维脚本不应依赖这一实现细节；空字符串始终表示 passwordless SMTP，不是继承。

## 回滚与禁用

回滚和禁用请求体只包含最新 revision：

```json
{
  "expected_revision": 12
}
```

- `POST /api/admin/settings/mail/rollback`：要求响应中的 `previous` 存在。成功后熔断状态清零，后续邮件使用恢复的版本。
- `POST /api/admin/settings/mail/disable`：必须先通过 `GET/PUT /api/admin/settings/registration` 把注册模式改为 `closed`，否则返回 `409 close self-registration before disabling mail`。

禁用不会删除 email outbox。Dispatcher 在没有可用 sender 时不会领取待发送记录，但仍会在每轮清除已过期 Token 和邮件密文；重新激活或回滚成功后继续处理仍在有效期内的邮件。禁用后环境 fallback 不会自行恢复。

## 熔断、注册与服务状态

活动 SMTP 的失败按类别处理：

- 配置、认证或 TLS 永久错误：立即打开共享熔断。
- 传输错误：两分钟窗口内累计三次后打开熔断。
- SMTP `RCPT TO` 或最终 `DATA` 的永久 5xx 拒绝：该邮件进入不重试的 `rejected` 终态并立即清除密文，不影响全局熔断；临时 4xx 仍按传输故障重试。
- 熔断打开后：停止领取 outbox；每 30 秒最多由一个实例取得探测权，执行连接、TLS、认证、`MAIL FROM`、`RSET` 和 `NOOP`，但不发送邮件。探测成功后自动恢复。

SMTP 不进入公开 `/readyz`，因此邮件服务故障不会让登录、OAuth/OIDC 和已有会话整体下线。管理员可查看：

- `GET /api/admin/system/status` 的 `services.mail`：`ok`、`degraded`、`unavailable`、`disabled` 或 `not_configured`。
- `GET /api/admin/settings/mail` 的 `configured`、`available`、`circuit.state`、错误类别、打开时间和下一探测时间。
- `GET /api/admin/stats` 的 backlog、近 24 小时失败尝试和快照化熔断状态，以及 `GET /api/admin/stats/mail-trend?days=7..90` 的 UTC 入队、发送、其他失败尝试（不含永久拒收）、永久拒收和过期趋势。

邮件趋势从 release baseline 建库时开始采用事务内增量聚合。API 返回 `mail_stats_available_from` / `available_from` 作为该数据库的邮件观测起点；该时间之前没有可比较数据。Prometheus 同时导出 `nyauth_smtp_outbox_failures_total`、`nyauth_smtp_circuit_open`、`nyauth_smtp_outbox_backlog` 和 `nyauth_smtp_outbox_oldest_pending_age_seconds`。这些指标不使用邮箱、用户、邀请码、配置版本、SMTP 主机或原始错误作为标签。

注册可用性遵循以下契约：

- `GET /api/registration` 的 `available` 只有在注册模式不是 `closed` 且 SMTP 当前可用时才为 `true`。
- SMTP 未配置、被禁用或熔断打开时，`POST /api/register` 在创建用户之前返回 `503`；熔断状态还返回 `Retry-After: 60`。
- 注册事务使用共享协调锁，并在事务内复核完整注册策略及活动 mail sender；注册策略变更和 SMTP 禁用使用独占锁。因此多实例短暂持有旧内存快照时只会收到 `503/409`，不会创建违反当前策略的用户。
- 开启 `invite_only` 或 `open` 只要求存在已配置的邮件能力，不要求 SMTP 当时没有瞬时故障；这样临时故障恢复后无需再次修改注册策略。
- 熔断期间，密码恢复和公开验证邮件重发仍保持不可枚举响应，并可把匹配请求排入 outbox；实际投递等待熔断恢复。明确禁用或从未配置邮件时，这些能力返回不可用。

排障时先看候选测试的 `error_category`、管理系统状态和应用结构化日志。不要在日志中增加 SMTP 密码、完整收件地址、验证链接 Token 或邮件正文。确认配置错误后应保存并测试一个新候选；不要直接修改数据库中的不可变版本记录。
