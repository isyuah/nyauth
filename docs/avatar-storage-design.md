# 安全头像媒体契约

> 状态：已实现；`0.4.0-rc.1` 的 `000006_runtime_media_storage` 增加版本化运行时 S3 配置与可续跑迁移，`000007_runtime_media_fallback` 补充迁回已配置本地 fallback；`0.6.0-dev` 的 `000014_oauth_application_identity` 将同一安全管线扩展到 OAuth 应用 Logo。

## 1. 结论与边界

Nyauth 不再接受、保存或直接渲染用户提供的任意头像 URL。用户和管理员只能上传图片内容，服务端校验并重新编码后，将头像保存到受控的本地目录或私有 S3 兼容对象存储。用户 DTO 中的 `avatar_url` 是只读字段，只会返回 Nyauth 生成的 `/media/avatars/{avatar_id}/256.webp`；OIDC `picture` 基于 issuer 生成对应的绝对地址。

OAuth 应用 Logo 遵循相同边界：所有者或管理员通过字段名 `logo` 上传正方形图片，服务端生成同样的四种 WebP 变体，只返回 `/media/client-logos/{logo_id}/{size}.webp`。客户端注册不接受任意 `logo_url`，因此应用 Logo 也不能变成外部追踪、动态换图或主动内容入口。

这条媒体管线解决以下可达风险：

- 外部图片主机追踪访问者 IP、User-Agent 和访问时间。
- URL 保存后内容被替换，展示结果与最初检查不一致。
- SVG、HTML、多态文件、错误 MIME 和内容嗅探造成主动内容风险。
- 超大尺寸、解压炸弹、畸形图片或动画耗尽 CPU、内存和存储。
- EXIF、GPS、ICC 和注释等元数据泄露。
- 可预测路径、路径穿越、跨用户覆盖和高频上传滥用。
- Provider 头像导入形成 SSRF、DNS 重绑定或云元数据探测。

头像不是认证秘密，但属于用户内容。对象存储凭据、内部 object key、Provider 上游完整 URL 和原始图片都不会返回给浏览器，也不得进入日志或普通审计详情。

## 2. 图片处理契约

用户和管理员上传使用 `multipart/form-data`，字段名固定为 `avatar`，请求必须恰好包含一个非空文件。当前限制为：

- 图片内容上限 8 MiB；HTTP 层另外只预留 1 MiB multipart 开销。
- 只接受真实签名为 JPEG、PNG 或静态 WebP 的内容。
- 拒绝 SVG、GIF、动画 WebP 和其他格式；WebP 解码后也必须只有一帧。
- 原图宽高都不得超过 4096，像素总数不得超过 16,777,216。
- 用户和管理员上传的图片必须已经是正方形；Provider 图片由服务端居中裁成正方形。
- 服务端解码后统一生成 64、128、256、512 四种静态 WebP，质量为 85。
- 不保存原图；重新编码会移除 EXIF、ICC、注释及其他非必要元数据。

浏览器提供固定 1:1 裁剪组件，支持拖动、缩放、90° 旋转、重置和圆形预览，输出最大 1024×1024 的正方形结果。原始选择文件只停留在浏览器内存，上传或取消后释放 Object URL、Canvas 和位图资源。浏览器裁剪是交互辅助，不能替代上述服务端校验。

头像上传和删除要求已认证会话、CSRF 与 Redis 限流。默认按目标用户与请求 IP 计数：每个目标用户 15 分钟最多 30 次，每个 IP 15 分钟最多 200 次；管理员可在“访问保护”中热更新或显式关闭该组限流。管理员代操作仍以目标用户作为限流 subject，并保留管理员 actor。

为限制 4096×4096 解码、缩放和 WebP 编码的峰值内存，每个应用实例同时只接受一个用户或管理员头像处理任务；繁忙时在读取 multipart 内容前返回 `503` 和 `Retry-After: 2`。Provider 导入 worker 本身按单任务顺序处理，因此单实例不会被认证用户用并发大图突破既定内存边界。

## 3. 存储配置

后端通过统一的 `BlobStore` 使用 `Backend`、`Put`、`Get` 和 `Delete` 操作。存储选择属于静态部署配置，修改后必须重启对应应用和 maintenance 容器。

### 3.1 本地存储

原生二进制默认使用：

```yaml
media:
  backend: local
  local:
    directory: data/media
```

开发和生产 Compose 将目录显式设置为 `/var/lib/nyauth/media`，并挂载独立的命名 volume `media`。实际 Docker volume 名通常带 Compose project 前缀，应以 `docker compose config --volumes` 和 `docker volume inspect` 的结果为准。

本地写入在目标目录内创建临时文件，完成写入、`fsync` 和关闭后再原子重命名。目录权限为 `0750`，路径解析会拒绝绝对路径、空路径、NUL 和逃逸存储根目录的 key。只读根文件系统不会承载头像数据。

本地模式只适合单应用主机。`docker compose down` 会保留 `media` volume；`docker compose down -v` 会连同 PostgreSQL 和头像 volume 一起删除，因此不得作为普通停止命令。

### 3.2 私有 S3 兼容存储

S3 配置字段与当前实现一致：

```yaml
media:
  backend: s3
  s3:
    endpoint: ""
    region: ""
    bucket: ""
    prefix: "nyauth"
    path_style: false
```

- `endpoint` 为空时使用 AWS SDK 的默认 S3 endpoint；自定义 endpoint 必须是无凭据、query 和 fragment 的绝对 HTTP(S) URL，生产环境强制 HTTPS。
- `region`、`bucket`、access key ID 和 secret access key 必填；`prefix` 可为空；MinIO 等实现需要时可启用 `path_style`。
- 凭据只能通过 `NYAUTH_MEDIA_S3_ACCESS_KEY_ID[_FILE]`、`NYAUTH_MEDIA_S3_SECRET_ACCESS_KEY[_FILE]` 和可选的 `NYAUTH_MEDIA_S3_SESSION_TOKEN[_FILE]` 注入，不能写进配置文件。
- bucket 必须保持 private。浏览器不取得 S3 凭据或预签名上传地址，Nyauth 通过同源 `/media` 路由读取对象。
- 凭据应只允许目标 bucket 中配置 prefix 下的读取、写入和删除；bucket 的默认加密、versioning、生命周期和恢复策略由对象存储平台配置。

仓库中的 `docker-compose.media-s3.yml` 为单机生产 Compose 提供 S3 override；`docker-compose.ha.yml` 则直接强制 `NYAUTH_MEDIA_BACKEND=s3`。当前 Compose override 为 access key ID 和 secret access key 提供 secret 文件挂载；需要 session token 的平台应通过部署环境自己的受控 override 挂载并设置对应 `*_FILE`。

静态 `media` 配置是数据库尚未激活动态 profile 时的 fallback。运行时配置 API 只接受私有 S3 兼容候选，不接受任意本地目录；每个候选版本不可变，access key、secret 和可选 session token 分字段使用 master key envelope encryption，响应、日志和审计只返回是否已配置。单实例可把动态 S3 中的对象迁回部署时已挂载的本地 fallback，目标路径始终来自静态部署配置。

S3 候选必须在十秒有界操作窗口内实际执行 Put、Get、字节校验和 Delete，且成功结果只有十分钟有效；迁回本地时会在创建迁移前对既有 fallback 执行同样的真实测试。迁移自动通过运行时服务控制排空 `media_writes`，头像读取、登录和 OAuth 不暂停。每条头像绑定明确的 `storage_profile_id`；迁移期间新旧 store 同时可读，单个头像的四种变体全部复制并从目标重新读取校验后，数据库才切换该头像的 profile，再删除源对象。进程在复制、切换或删除之间退出时会从持久化 item 状态继续；失败状态仍属于未解决迁移，会继续阻止对象清理和候选替换，并保持媒体写入暂停供管理员显式重试。重试前服务控制必须再次确认 `media_writes` 已排空。全部完成并由实例加载新 revision 后才尝试以 CAS 恢复迁移前的服务控制状态；若管理员期间修改了维护状态，系统不会覆盖该修改。

系统不支持通过 API 新增或修改本地目录，也不支持浏览器直传 S3。迁回本地只允许使用已挂载的静态 fallback，并要求当前只有一个活动实例；HA 仍必须使用所有实例可访问的私有 S3。

## 4. 数据与事务生命周期

`user_avatars` 保存受控图片元数据和对象变体，不保存图片二进制。为兼容已经发布并部署的 0.5.0 表与媒体迁移外键，0.6.0 通过 `media_purpose=user_avatar/client_logo` 和互斥的 `user_id/client_id` 扩展该表，而不在兼容迁移中破坏性重命名；表名属于内部实现，不进入 API。记录包含所有者、用途、来源、状态、存储后端、可空的不可变存储 profile、对象前缀、四种变体、原始媒体类型与尺寸、内容 SHA-256，以及激活、替换、删除、失败和存储清理时间。`storage_profile_id=NULL` 明确表示部署期静态 fallback，不表示“当前任意同类型 store”。

状态固定为：

- `staging`：数据库已记录，变体仍在写入或等待激活。
- `active`：当前用户正在使用；每个用户最多一条 active 记录。
- `replaced`：已被新头像替换，等待或已经完成对象清理。
- `deleted`：用户或管理员已移除，等待或已经完成对象清理。
- `failed`：处理、写入或激活失败，等待清理可能已写入的对象。

`users.current_avatar_id` 是当前头像引用，外键可延迟检查；用户删除后头像记录的 `user_id` 会变为 `NULL`，保留为可回收 orphan。历史 `users.avatar_url` 列已删除，不会抓取或迁移旧外部 URL。

上传顺序为：

1. 在 PostgreSQL 中提交 staging 记录。
2. 写入四个不可变变体对象；部分写入失败时记录 failed，并尽力删除已写对象。
3. 在新事务中锁定用户、激活新头像并把旧 active 记录标记为 replaced。
4. 激活失败时独立保留 failed 状态，旧头像引用不受影响。

PostgreSQL 与文件系统/S3 不能组成分布式事务，因此清理采用宽限期和可重试状态：

- staging、failed、replaced、deleted 或失去用户引用的对象超过 15 分钟后才有资格清理。
- `serve` 启动后立即执行一轮，之后每小时执行；`nyauth maintenance` 复用相同服务作为运维兜底。
- PostgreSQL advisory lock 保证多实例每轮只有一个清理者；有界批次和 claim 防止重复处理。
- 清理按每条记录的 `storage_profile_id` 解析静态 fallback 或历史动态 profile；存在未完成或失败待重试的媒体迁移时整轮跳过。对象删除成功后才写 `storage_deleted_at`；删除失败会释放 claim，留待下次重试。

## 5. HTTP API 与缓存

当前接口为：

```text
POST   /api/me/avatar
DELETE /api/me/avatar
POST   /api/admin/users/{id}/avatar
DELETE /api/admin/users/{id}/avatar
GET    /media/avatars/{avatar_id}/{size}.webp
```

上传和删除成功都返回更新后的用户 DTO。用户资料中的 `avatar_url` 默认指向 256 像素变体；调用方不能指定 avatar ID、object key、bucket、endpoint 或展示 URL。

媒体读取只接受 64、128、256、512 四种尺寸，只提供状态仍为 active 的头像。无效 ID、尺寸、非 active 记录或缺失对象返回 404；存储后端故障返回 503，但不影响登录、OAuth/OIDC 和全局 `/readyz`。

成功响应固定为：

```text
Content-Type: image/webp
X-Content-Type-Options: nosniff
Cache-Control: public, max-age=86400, immutable
```

对象地址包含随机 avatar ID，替换后用户 DTO 会返回新地址。最长 24 小时的公共缓存不会让旧对象重新成为当前引用；删除后的旧 URL 不再由数据库作为 active 媒体提供，但浏览器或中间缓存已经保存的副本最多可能继续存在 24 小时。

## 6. Provider 首次头像导入

每个 Provider 有 `import_avatar` 开关，默认关闭。开启后只在该外部身份第一次创建本地用户时异步导入；绑定到已有用户、后续登录和 Provider 资料变化都不会持续同步，也不会覆盖用户主动上传的头像。

允许主机规则固定为：

- GitHub：代码内置 `avatars.githubusercontent.com`，管理配置不得另传 allowlist。
- Google：代码内置 `lh3.googleusercontent.com`，管理配置不得另传 allowlist。
- 通用 OIDC：必须配置至少一个精确的公共 ASCII DNS 主机名；拒绝 IP、localhost、通配符、端口、URL、单标签名称和包含路径的值。

Provider 返回的完整上游 URL 使用 master key envelope encryption 保存，AAD 绑定 job、Provider 和用户。任务完成或最终失败后立即清空密文；日志、审计和 `last_error` 只保留有界错误类别，不记录完整 URL。

异步 worker 在多实例中使用 PostgreSQL `FOR UPDATE SKIP LOCKED` 和 processing lease 领取任务。单任务超时 20 秒，最多尝试 4 次，临时错误按 1 分钟、5 分钟、30 分钟退避。最终失败只保留首字母头像，不阻塞建号或登录。

远程获取的安全边界为：

- 仅 HTTPS，端口只能省略或为 443，不允许 URL credentials 和 fragment。
- 主机必须精确匹配 allowlist；每次跳转都重新执行 URL、主机和 DNS 检查，最多 5 次重定向。
- DNS 返回的全部地址都必须是公网地址；拒绝 loopback、私网、link-local、云元数据、文档和保留地址。
- 实际 TCP 连接固定到已经校验的 IP，TLS ServerName 仍使用原主机，阻断解析后换址的 DNS rebinding。
- 下载仍受 8 MiB、超时和同一图片处理管线限制。
- 如果任务完成前用户已有头像，Provider 结果会被拒绝激活并清理，不覆盖用户选择。

## 7. 审计与可观测性

已实现审计事件：

- `user.avatar_updated`
- `user.avatar_removed`
- `admin.user_avatar_updated`
- `admin.user_avatar_removed`
- `provider.avatar_imported`
- `provider.avatar_import_failed`

用户和管理员上传/删除事件由 mutation audit 记录 actor、目标用户、结果与风险；Provider 导入事件另外记录 Provider ID 和有界原因。所有事件都不会记录图片内容、凭据、完整 object key 或 Provider 上游 URL。

低基数指标包括头像操作结果、处理耗时、按后端和操作分类的存储错误，以及等待清理的记录数。标签不会包含用户 ID、文件名、object key、内容摘要或上游主机。管理员系统状态通过 `services.media` 返回 `backend`、`configured`、`status` 和最近错误时间。

媒体存储故障会让管理系统状态变为 degraded，并使头像上传或读取返回 503。删除以 PostgreSQL 中解除当前引用为成功边界；若同步对象删除失败，API 仍返回更新后的无头像用户，存储错误进入指标并由后台清理重试。媒体故障不会进入 `/readyz`，因此不会因为非核心头像依赖而下线登录与 OAuth/OIDC 服务。

## 8. 运维要求

- 本地模式必须备份 Compose `media` volume，并与 PostgreSQL 恢复点共同验证。
- S3 bucket 必须私有，建议启用 versioning；生命周期只能清理 noncurrent 版本和 delete marker，不得按对象年龄删除仍可能被数据库引用的当前版本。
- 恢复期间应先恢复 PostgreSQL 与匹配的本地目录或 S3 prefix，再启动 `serve`，避免后台清理在恢复尚未完成时处理对象。
- 恢复抽查必须从数据库选择 active avatar ID，并验证 64、128、256、512 四种同源地址都返回有效静态 WebP。
- HA 部署必须使用所有实例共享的同一私有 S3 bucket、prefix 和凭据边界；不得为每个实例配置独立本地目录。

具体命令、versioning/lifecycle 边界和恢复证据见 [备份与恢复手册](operations/backup-restore.md)、[单机远程部署手册](operations/single-host-deployment.md) 与 [高可用部署](operations/high-availability.md)。
