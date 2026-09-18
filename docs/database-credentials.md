# 数据库凭据与恢复

数据库服务可以从本地受限文件加载已验证的 SQLCipher 凭据。此方式用于
避免每次 bot 启动或恢复时重新扫描微信内存。它不会启动调试器或自动提权。

```yaml
database:
  key_file: /config/database_keys.json
  scan_keys: false
```

`key_file` 默认为空，未配置时保持现有 scanner 行为。配置后该文件是唯一
来源，即使 `scan_keys: true` 也不扫描。文件缺失或损坏时明确报告错误，不会
退回其他获取方式。

## 凭据文件

文件结构为 `{"version": 1, "keys": {"相对数据库路径": "96位十六进制值"}}`。
路径相对 `database.xwechat_files_root`，包含账号目录和 `db_storage`。值沿用
现有服务的 32 字节 raw key 加 16 字节 salt 格式。实际值不应粘贴到文档、
日志、命令行或聊天中。

文件必须是非符号链接的普通文件，权限为 `0600`，所有者为 bot 运行用户或
root。这是受权限保护的明文凭据，不是加密保管库。`/config` 挂载负责重启后的
持久化；Git 和 Docker 构建上下文均排除运行配置及凭据。

读取时逐条检查路径范围、当前发现的数据库、salt 和 page HMAC。无效条目不
加载；失效连接会关闭，刷新时清空旧联系人缓存。运行中的消息轮询按
`key_retry_interval` 检查文件变更并刷新，保留仍有效消息表的轮询游标。
首次启动按最新消息建立基线，不把全部历史记录作为新消息重放。

## 生成与更新

独立诊断工具的用法和限制见
[工具说明](../tools/wechat_key_probe/README.md)。其显式写入选项
`--write-key-file /config/database_keys.json` 只保存通过真实副本结构查询及
`quick_check` 的条目。写入模块先重新验证 HMAC，保留原文件中的有效条目，
再以 `0600` 临时文件原子替换目标。失败候选不能覆盖有效凭据。

普通 bot 只读取该文件。微信更换数据库 key、新增消息分库或切换账号时，
需要显式补充新的已验证凭据。无需为每个辅助数据库取得 key 才能恢复核心读取。

## 状态与验收

现有 `get_database_status` / Dashboard 状态增加：

- `key_source`：当前凭据来源。
- `key_file`：有效条目数、无效条目数和脱敏错误。
- `core_ready`：核心库能打开，联系人和消息映射已加载。
- `core_missing_databases` / `core_query_errors`：核心缺项与打开失败项。

核心库包括联系人库及当前账号所有编号消息分库。`available` 保留原来的
“存在可读消息表”语义；只有它为 true 不代表所有核心库均就绪。
`core_ready` 不替代实际接口、消息轮询和重启验收，也不表示媒体与发送链路已验证。

验收应包括联系人、最近会话、历史消息接口正常，新消息轮询无重复，以及仅
重启 bot 后仍可恢复。无需重启微信；不要通过修改加密参数处理凭据文件错误。

## 部署与回退

日常完整构建仍使用项目根目录 Dockerfile。如果只改 Python 代码而依赖不变，
可基于已部署镜像进行离线更新，避免下载不同版本的微信：

```sh
docker build --network=none -f tools/Dockerfile.bot-update \
  --build-arg BASE_IMAGE=本地保留的原镜像标签 -t wechat-ai:core-recovery .
```

此路径要求原镜像使用当前依赖和 `/app/src` 的 editable 安装；不适用于依赖
变更。验证后再将候选镜像设置为部署使用的标签。构建不包含凭据文件。
保留原镜像标签和运行配置备份；回退时恢复对应代码和原配置，凭据文件可保留，
但旧代码不会使用它。
