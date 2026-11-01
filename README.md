# QQNT 媒体修复

这是一个仅在本地运行、面向批量处理的工具和 Codex skill，用于在本地原件仍存在时，修复符合已验证规则的 QQNT 媒体引用或缺失路径。

当前支持旧版 `FILE` 卡片引用修正，以及普通图片原件仍在、明确引用路径缺失时的文件补回；具体边界见[兼容性说明](skills/qqnt-media-repair/references/compatibility.md)。其他图片、视频、语音可清点，但不承诺所有过期或缺失项目都能恢复。

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

每个数据库操作至多建立一份临时数据库副本，结束后自动清理。文件卡片引用修正不复制原始媒体；下述路径补回会按计划创建缺失文件，并报告新增空间。运行目录保留加密的受影响行计划及回滚数据、私有索引和报告。不要在仓库内创建运行目录。

在 QQ 中用 1–2 条原始文件卡片确认配置文件后，工作流应继续处理全部合格记录。样本检查不是停下等待逐条授权的理由，只要用户已授权本次修复任务。报告应分别统计已修复并经 UI 验证的记录、跳过、失败和未处理媒体。

### Profile 2：按明确本地路径补回已验证图片

`restore_media_paths.py` 是独立的路径补回辅助工具，不改消息数据库。它只处理元数据快照中明确缺失的图片原件路径，并从已验证本地来源逐次核验大小、MD5 和 SHA256 后原字节复制。默认仅生成 dry-run 清单；`--apply` 才创建目标文件，默认新增总量上限为 2 GiB，目标已存在时不会覆盖。预览缓存必须显式启用，且只接受原件也明确缺失的同一图片记录和元数据声明路径；使用 `--include-declared-previews` 时需安装 Pillow 以验证图片可解码。预览仍按原件字节复制，不做转码。工具结果不代表 QQ 界面已验证。

```powershell
$scan = '.\skills\qqnt-media-repair\scripts\broad_media_scan.py'
$restore = '.\skills\qqnt-media-repair\scripts\restore_media_paths.py'
$account = 'D:\QQ\YOUR_ACCOUNT'
$run = 'D:\QQRepairRuns\broad-001'
$key = 'D:\Private\qq.key'
# 退出 QQ 后清点所有普通图片、文件、语音和视频。未知类别只报告，不自动修改。
uv run --python 3.13 --with sqlcipher3==0.6.4 -- python $scan --account $account --key-file $key --run $run --qq-stopped --timeout-seconds 0
$metadata = "$run\media-metadata.private.sqlite"
$out = 'D:\Private\restore-plan.private.json'
uv run --python 3.13 -- python $restore --metadata-db $metadata --account $account --out $out
# 核实一两个原聊天案例后，对同类目标批量执行：
uv run --python 3.13 -- python $restore --metadata-db $metadata --account $account --out $out --apply
# 显式补回同一批记录声明的缺失预览；已有预览保留原字节。
uv run --python 3.13 --with pillow -- python $restore --metadata-db $metadata --account $account --out $out --include-declared-previews --apply
```

输入是只读 metadata snapshot，至少包含 `restore_targets`、`verified_sources`、`verified_refs`、`blocked_restore_paths` 和 `restore_target_conflicts` 表。完整预览清单可通过 `declared_restoration_previews(path,source_id,field,table_code,msg_id,segment_path)` 提供；若无此表，工具只使用明确标记原件缺失的受限 examples 回退集。不要把数据库快照或清单提交到仓库。

扫描过总消息数不代表每种媒体都已验证可用。第一条规则仅处理旧 FILE 卡片，不能用它的“零新增”推断普通图片、视频、语音也没有问题；应使用广域清点并分别报告覆盖范围、补回路径、保留或跳过的项目及实际 QQ 抽查结果。

## 安装 Codex skill

将 `skills/qqnt-media-repair` 目录复制到本地 Codex skills 目录，常见位置为 `~/.codex/skills/qqnt-media-repair`，然后使用 `$qqnt-media-repair` 调用。Skill 可指导工作流；实际执行仍需安装仓库工具并查阅其当前帮助信息。

## 隐私

数据库、WAL/SHM 文件、密钥/密钥文件、账号标识、消息内容、原文件名、哈希、快照、回滚包和运行报告都是本地私有产物，不得提交或上传。示例只使用通用路径。初始支持范围不包含密钥提取工具。

## 许可

本项目按 MIT License 发布，详见 [LICENSE](LICENSE)。许可仅覆盖项目原创内容，不授予第三方软件或数据的权利。
