# QQNT 媒体修复

这是一个仅在本地运行、面向批量处理的工具和 Codex skill，用于在本地原件仍存在时，修复范围有限且明确的旧版 QQNT 文件卡片媒体记录。

它不是通用 QQ 媒体恢复工具，也不承诺所有过期或缺失项目都能恢复。当前初始支持范围仅限 skill 中[兼容性说明](skills/qqnt-media-repair/references/compatibility.md)所述的旧版 `FILE` 卡片布局。

## 工作流

工具旨在确认当前数据根目录、清点单聊与群聊、生成 dry-run 计划、处理获授权的整批合格记录，并支持验证或回滚。它会对实际原始字节计算哈希、保留加密的受影响行回滚包，并要求在发布前取得稳定的本地数据库状态。详见[批量工作流](skills/qqnt-media-repair/references/workflow.md)。

需要 Windows x64、Python 3.13 和已核验的 `sqlcipher3==0.6.4`。数据库适配器会检查模块指纹，不匹配时停止。先关闭 QQ，准备匹配当前数据库的本地密钥文件；本项目不附带密钥提取器。

```powershell
# 在仓库根目录运行。变量填写自己的路径；运行目录放在空间充足的盘上。
$script = '.\skills\qqnt-media-repair\scripts\qqnt_repair.py'
$account = 'D:\QQ\YOUR_ACCOUNT'
$run = 'D:\QQRepairRuns\run-001'
$key = 'D:\Private\qq.key'
uv run --python 3.13 --with sqlcipher3==0.6.4 -- python $script scan --db "$account\nt_qq\nt_db\nt_msg.db" --account $account --qq-build 'YOUR_QQ_BUILD' --run $run --key-file $key
uv run --python 3.13 --with sqlcipher3==0.6.4 -- python $script apply --run $run --key-file $key --sample 2
# 打开 QQ，确认这两条原始聊天卡片能预览、双击打开，然后再次退出 QQ。
uv run --python 3.13 --with sqlcipher3==0.6.4 -- python $script confirm-ui --run $run --key-file $key --sample-count 2 --evidence '已在原聊天验证预览和双击打开'
uv run --python 3.13 --with sqlcipher3==0.6.4 -- python $script apply --run $run --key-file $key
uv run --python 3.13 --with sqlcipher3==0.6.4 -- python $script status --run $run --key-file $key
# 需要回滚时，退出 QQ 后执行。只逆向恢复仍符合修复后内容的行。
uv run --python 3.13 --with sqlcipher3==0.6.4 -- python $script rollback --run $run --key-file $key
```

`scan` 可加 `--extra-root` 纳入其他本地下载目录；`--existing-index` 可复用兼容的文件清单，但选中的文件仍会核对实际内容。`confirm-ui` 是操作者对原生 QQ 界面结果的确认，不是工具自动验证界面的证明。此前已在同一数据库和版本验证过相同规则时，可用 `--existing-cases` 记录已有验证。

每个操作至多建立一份临时数据库副本，结束后自动清理；原始媒体文件不复制。运行目录保留加密的受影响行计划及回滚数据、私有索引和报告。不要在仓库内创建运行目录。

在 QQ 中用 1–2 条原始文件卡片确认配置文件后，工作流应继续处理全部合格记录。样本检查不是停下等待逐条授权的理由，只要用户已授权本次修复任务。报告应分别统计已修复并经 UI 验证的记录、跳过、失败和未处理媒体。

## 安装 Codex skill

将 `skills/qqnt-media-repair` 目录复制到本地 Codex skills 目录，常见位置为 `~/.codex/skills/qqnt-media-repair`，然后使用 `$qqnt-media-repair` 调用。Skill 可指导工作流；实际执行仍需安装仓库工具并查阅其当前帮助信息。

## 隐私

数据库、WAL/SHM 文件、密钥/密钥文件、账号标识、消息内容、原文件名、哈希、快照、回滚包和运行报告都是本地私有产物，不得提交或上传。示例只使用通用路径。初始支持范围不包含密钥提取工具。

## 许可

本项目按 MIT License 发布，详见 [LICENSE](LICENSE)。许可仅覆盖项目原创内容，不授予第三方软件或数据的权利。
