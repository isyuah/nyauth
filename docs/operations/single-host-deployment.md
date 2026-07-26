# Nyauth 单机远程部署手册

本手册使用 `docker-compose.prod.yml` 在一台 Linux 主机上运行 Nyauth、PostgreSQL 和 Redis，并由同机或外部平台的通用反向代理终止 TLS。Compose 不发布应用或数据库端口；反向代理通过预先创建的 external Docker network 访问 `nyauth:8080`。

生产数据的备份与恢复要求见 [备份与恢复手册](backup-restore.md)。需要外部 PostgreSQL、外部 Redis 或双应用实例时，使用 [高可用部署](high-availability.md)，不要把本手册的内置数据库拓扑直接扩展成多主机部署。

## 安全边界与前置条件

- 准备一个只用于认证服务的 HTTPS 域名，例如 `auth.example.com`，并把 A/AAAA 记录指向入口地址。
- 防火墙只对公网开放反向代理需要的 `80/443`；PostgreSQL、Redis 和 Nyauth 的 `8080` 不对宿主机或公网发布。
- 安装 Docker Engine 与 Compose v2，并由受控运维账号管理部署目录。
- 从发布产物取得 `ghcr.io/nyasharp/nyauth@sha256:<64-hex-digest>`。生产环境固定 digest，不使用 `latest` 或可移动 tag。
- 在首次启动前确定 PostgreSQL runtime role 名称。内置初始化脚本只在空 PostgreSQL volume 上执行；已有数据库改名或新增角色必须由 DBA 显式处理。
- 建立 PostgreSQL、master key 和部署配置备份，明确 RPO/RTO 和回滚负责人。

`auth.issuer` 必须是浏览器唯一使用的公开 HTTPS origin，例如 `https://auth.example.com`。协议、主机名或端口任一不一致都会使同源检查、Cookie 或 OIDC 校验失败。

## 反向代理与可信代理

先创建专用 external network。示例网段只用于说明，应与主机现有 Docker 网络规划协调：

```bash
docker network create --driver bridge --subnet 172.30.0.0/24 nyauth-proxy
```

让反向代理加入该网络，并把 upstream 指向 `http://nyauth:8080`。保持实现中立，但代理必须满足以下契约：

- 在代理处终止 HTTPS，向 upstream 传递原始 `Host`。
- 把 `X-Forwarded-Proto` 固定为 `https`，并传递原始 `X-Forwarded-Host`。
- 丢弃公网请求自带的伪造转发头，再由代理追加或重建 `X-Forwarded-For`；可同时设置 `X-Real-IP`。
- 只把 `/readyz` 返回成功的实例纳入 upstream；不得把 `/metrics` 暴露到公网。
- 代理与 Nyauth 之间不得经过未列入可信范围的二级代理。存在多级代理时，必须按实际转发链逐个收紧信任边界。

最稳妥的方式是给代理容器分配固定地址，例如 `172.30.0.2`，并设置 `NYAUTH_TRUSTED_PROXY_CIDRS=172.30.0.2/32`。如果平台不能固定容器地址，可以信任专用网络的精确子网，但该网络只能加入受信代理和 Nyauth，不能接入普通工作负载。用以下命令核对实际网络，而不是猜测 CIDR：

```bash
docker network inspect nyauth-proxy
```

## 部署目录与 secret

以下示例使用 `/opt/nyauth`。把仓库中与目标镜像版本匹配的 `docker-compose.prod.yml`、`docker/postgres/init-runtime-role.sh` 和可选 SMTP override 放入该目录；不要混用不同版本的 Compose 文件和镜像。

```bash
sudo install -d -m 0750 /opt/nyauth/docker/postgres
sudo install -d -m 0700 /opt/nyauth/secrets
sudo chown -R "$USER" /opt/nyauth
cd /opt/nyauth
```

为 migrator、runtime、Redis 和 master key 生成互不相同的 secret。这里使用十六进制数据库密码，避免在 PostgreSQL URI 中再做百分号编码：

```bash
umask 077
MIGRATION_PASSWORD="$(openssl rand -hex 32)"
RUNTIME_PASSWORD="$(openssl rand -hex 32)"
REDIS_PASSWORD="$(openssl rand -hex 32)"
MASTER_KEY="$(openssl rand -base64 32 | tr -d '\n')"

printf '%s' "$MIGRATION_PASSWORD" > secrets/postgres-password
printf '%s' "$RUNTIME_PASSWORD" > secrets/database-runtime-password
printf 'postgres://nyauth_migrator:%s@postgres:5432/nyauth?sslmode=disable' "$MIGRATION_PASSWORD" > secrets/database-migration-dsn
printf 'postgres://nyauth_runtime:%s@postgres:5432/nyauth?sslmode=disable' "$RUNTIME_PASSWORD" > secrets/database-runtime-dsn
printf '%s' "$REDIS_PASSWORD" > secrets/redis-password
printf '%s' "$MASTER_KEY" > secrets/auth-master-key
chmod 0600 secrets/*
unset MIGRATION_PASSWORD RUNTIME_PASSWORD REDIS_PASSWORD MASTER_KEY
```

如果使用自定义 runtime role，把上面 runtime DSN 中的用户名和后面的 `NYAUTH_DATABASE_RUNTIME_ROLE` 同时改成同一值。内置 PostgreSQL 初始化脚本只接受 `[A-Za-z_][A-Za-z0-9_]*`、最长 63 个 ASCII 字符的角色名，并始终使用 PostgreSQL 标识符引用；runtime role 不能与 `nyauth_migrator` 相同。

创建权限为 `0600` 的 `.env.production`。其中只保存非 secret 参数和 secret 文件路径：

```dotenv
NYAUTH_IMAGE=ghcr.io/nyasharp/nyauth@sha256:<replace-with-verified-64-hex-digest>
NYAUTH_AUTH_ISSUER=https://auth.example.com
NYAUTH_TRUSTED_PROXY_CIDRS=172.30.0.2/32
NYAUTH_PROXY_NETWORK=nyauth-proxy
NYAUTH_DATABASE_RUNTIME_ROLE=nyauth_runtime
NYAUTH_DATABASE_DSN_FILE=/opt/nyauth/secrets/database-runtime-dsn
NYAUTH_DATABASE_MIGRATION_DSN_FILE=/opt/nyauth/secrets/database-migration-dsn
NYAUTH_DATABASE_RUNTIME_PASSWORD_FILE=/opt/nyauth/secrets/database-runtime-password
NYAUTH_REDIS_PASSWORD_FILE=/opt/nyauth/secrets/redis-password
NYAUTH_AUTH_MASTER_KEY_FILE=/opt/nyauth/secrets/auth-master-key
POSTGRES_PASSWORD_FILE=/opt/nyauth/secrets/postgres-password
NYAUTH_REDIS_ADDR=redis:6379
NYAUTH_BOOTSTRAP_ADMIN_USERNAME=admin
NYAUTH_BOOTSTRAP_ADMIN_EMAIL=admin@example.com
```

```bash
chmod 0600 .env.production
```

不要把 secret 值写进 `.env.production`、Compose 文件、shell history 或工单。默认不配置 bootstrap 密码：空用户库会生成一次性管理员密码，并只写入首次启动日志。需要预置时应使用受控的环境注入或单独的 Compose secret override，而不是提交明文。

## 配置展开与首次启动

先确认 external network 存在、文件路径正确，并展开最终配置。`config` 只做插值和语法检查，不会启动容器：

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml config --quiet
docker compose --env-file .env.production -f docker-compose.prod.yml pull
docker compose --env-file .env.production -f docker-compose.prod.yml up -d
docker compose --env-file .env.production -f docker-compose.prod.yml ps --all
docker compose --env-file .env.production -f docker-compose.prod.yml logs --tail 100 migrate nyauth
```

首次空 volume 启动时，PostgreSQL entrypoint 会创建配置的 runtime role；随后一次性 `migrate` 使用 migrator DSN 建表和收紧权限，只有迁移成功后才启动 Nyauth。初始化脚本不会在已有 PostgreSQL volume 上再次运行。

如果没有预置 bootstrap 密码，从只受管理员访问的日志中取得一次性值：

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml logs nyauth | grep 'BOOTSTRAP ADMIN PASSWORD'
```

只在首次创建空用户库时会出现该行。登录 `https://auth.example.com` 后立即修改密码，并确认日志访问权限和保留策略不会把该值长期暴露给无关人员。

## 验收

先从容器内部验证应用依赖，再从公网路径验证 TLS 与代理：

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml exec nyauth \
  nyauth healthcheck -url http://127.0.0.1:8080/readyz -timeout 5s

curl --fail --silent --show-error https://auth.example.com/livez
curl --fail --silent --show-error https://auth.example.com/readyz
curl --fail --silent --show-error https://auth.example.com/.well-known/openid-configuration
```

至少确认：

- HTTPS 证书链和主机名正确，HTTP 会跳转到唯一 HTTPS issuer。
- Discovery 文档的 `issuer` 与 `NYAUTH_AUTH_ISSUER` 完全一致，授权、Token、JWKS 和 UserInfo 地址均使用公开域名。
- 初始管理员可以登录、被强制修改密码，并可再次登录。
- 日志中的客户端 IP 来自受信转发链，公网伪造 `X-Forwarded-For` 不会覆盖真实地址。
- `/metrics` 无法从公网访问，PostgreSQL、Redis 和 `8080` 未出现在宿主机监听端口中。

## 动态 SMTP 与可选 bootstrap fallback

Nyauth 只通过 SMTP 发信，不读取邮箱，因此无需 IMAP。生产环境的主配置入口是 PostgreSQL 中的动态 SMTP：首次登录并修改管理员密码后，按 [动态 SMTP 配置与故障处理](runtime-mail.md) 从受控工作站保存候选、向指定地址实际发送测试邮件，并在成功后的十分钟内激活。激活、后续切换、回滚和禁用都不需要重建容器；所有操作要求最近十分钟内重新认证，并走 CSRF、限流和审计。

环境变量与 password file 仅作为可选的首次 fallback/bootstrap。例如希望应用第一次启动后、管理员尚未写入数据库配置前就具备邮件能力，可以创建 SMTP 密码文件并在 `.env.production` 中补充宿主机路径和非 secret 设置：

```bash
umask 077
printf '%s' '<smtp-password>' > secrets/smtp-password
chmod 0600 secrets/smtp-password
```

```dotenv
NYAUTH_MAIL_ENABLED=true
NYAUTH_MAIL_FROM_ADDRESS=noreply@example.com
NYAUTH_MAIL_FROM_NAME=Nyauth
NYAUTH_MAIL_PUBLIC_BASE_URL=https://auth.example.com
NYAUTH_MAIL_SMTP_HOST=smtp.example.com
NYAUTH_MAIL_SMTP_PORT=587
NYAUTH_MAIL_SMTP_USERNAME=nyauth@example.com
NYAUTH_MAIL_SMTP_TLS_MODE=starttls
NYAUTH_MAIL_SMTP_PASSWORD_FILE=/opt/nyauth/secrets/smtp-password
```

加载单机 override；只要部署仍保留该 fallback，所有 `config`、`up` 和重建命令都应使用同一组 `-f` 参数，避免不同运维命令展开出不一致的容器定义：

```bash
docker compose --env-file .env.production \
  -f docker-compose.prod.yml \
  -f docker/compose.prod.smtp-password-file.yml \
  config --quiet

docker compose --env-file .env.production \
  -f docker-compose.prod.yml \
  -f docker/compose.prod.smtp-password-file.yml \
  up -d --force-recreate nyauth
```

生产环境只能使用 `starttls` 或 `implicit`，且邮件链接基址必须是 HTTPS。数据库运行状态初始为 `fallback`；一旦管理员激活数据库候选或明确禁用邮件，环境配置即不再参与选择，重启也不会自动回退。只有仍处于 `fallback` 时修改静态 SMTP 配置才需要重建 `serve` 容器。HA bootstrap 使用 `docker/compose.ha.smtp-password-file.yml`，两个实例必须读取同一只读 secret。

不配置 SMTP fallback 也可以正常启动、登录和完成 OAuth/OIDC 服务；管理员可在启动后直接通过动态配置流程建立第一版 SMTP。数据库中没有已激活配置且候选请求省略 `password` 时没有可继承秘密，会返回 `400`，因此第一版需要显式输入密码，或显式使用 passwordless SMTP。

## 日常运维

查看状态与日志：

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml ps --all
docker compose --env-file .env.production -f docker-compose.prod.yml logs --tail 200 nyauth postgres redis
```

至少按月使用迁移账号执行维护任务：

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml run --rm migrate maintenance
```

持续监控 `/readyz`、登录失败率、PostgreSQL/Redis 容量、最老审计 outbox、磁盘空间和证书到期时间。SMTP 不属于 `/readyz`；邮件故障通过 `/api/admin/system/status` 的 `services.mail`、邮件设置中的熔断状态和受控指标观察。熔断期间注册会返回 `503`，但登录与 OAuth/OIDC 保持在线。日志不得泄露地址、凭据、验证 Token 或邮件内容。

正常停止而保留 PostgreSQL 数据：

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml down
```

不要执行 `docker compose down -v`；`-v` 会删除 PostgreSQL volume。任何数据删除都必须先核对 Compose project、volume 名称和备份，并经过独立批准。

## 升级

当前开发基线不承诺不同数据库契约的版本可以滚动混跑。升级前保存旧 digest、备份 PostgreSQL 和 master key，并阅读目标版本的迁移说明：

1. 把匹配目标版本的 Compose 和初始化脚本放入部署目录。
2. 在临时副本中把 `.env.production` 的 `NYAUTH_IMAGE` 更新为已验证的新 digest，执行 `config --quiet`，确认后再原子替换正式文件。
3. 停止旧应用流量，但保持 PostgreSQL 和 Redis 运行。
4. 使用新镜像运行一次迁移。
5. 重建应用并执行 readiness、Discovery、登录和 OAuth smoke。

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml pull
docker compose --env-file .env.production -f docker-compose.prod.yml stop nyauth
docker compose --env-file .env.production -f docker-compose.prod.yml run --rm migrate
docker compose --env-file .env.production -f docker-compose.prod.yml up -d --no-deps --force-recreate nyauth
```

保留 SMTP bootstrap override 的部署必须在上述每条 Compose 命令中追加相同的 override 文件。数据库模式已经是 `active` 或 `disabled` 时，该环境 fallback 不会覆盖数据库状态；是否移除 override 应作为一次独立、经 `config --quiet` 验证的部署配置变更处理。

## 回滚

只在旧镜像明确兼容当前 schema 时，才可以直接把 `NYAUTH_IMAGE` 改回旧 digest 并重建应用。若新版本已经执行不兼容迁移，单独回退镜像会导致启动失败或数据损坏；必须停止应用，按备份手册恢复升级前 PostgreSQL 恢复点，重新启动空 Redis 使旧会话和 Token 全部失效，再使用旧 digest 启动并验证。

回滚过程中不得运行 `down -v`。保留失败版本日志、迁移输出、digest 和恢复证据，待根因确认后再安排下一次升级。
