# QQNT 媒体修复

这是一个仅在本地运行、面向批量处理的工具和 Codex skill，用于在本地原件仍存在时，修复符合已验证规则的 QQNT 媒体引用或缺失路径。

修复分为三类，不能相互替代：旧版 `FILE` 卡片的特定配置会修改对应消息记录；原件路径补回只新建记录明确指向的缺失文件，不修改数据库；视频封面重建则从已核验的本地 MP4 派生首帧 PNG，补回记录字段 `45404` 明确声明的缺失缓存路径。图片路径补回已完成 QQ 原聊天和原生查看器验证。视频封面流程已在 QQ 9.9.31-49738 的代表案例中验证原聊天封面和播放按钮恢复，且可启动原生播放器；该验证不代表所有视频布局都兼容。文件路径补回仍为 opt-in 实验流程。详见[兼容性说明](skills/qqnt-media-repair/references/compatibility.md)。

## 工作流

工具旨在确认当前数据根目录、清点单聊与群聊、生成 dry-run 计划、处理获授权的整批合格记录，并支持验证或回滚。它会对实际原始字节计算哈希、保留加密的受影响行回滚包，并要求在发布前取得稳定的本地数据库状态。详见[批量工作流](skills/qqnt-media-repair/references/workflow.md)。

数据库修复默认使用已验证的 `legacy-file-subtype1-ascii-md5-failed-v1` 配置。`legacy-file-subtype7-v1` 是独立的显式 opt-in 配置，扫描时传入 `--profile legacy-file-subtype7-v1`；默认不会启用，也不能把 subtype 1 的结果套用到 subtype 7。Subtype 7 已通过数据库完整性检查，原聊天代表案例成功打开本地 PDF；本地文档解析与渲染通过。该证据不代表所有文件格式都可用。

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

扫描 subtype 7 必须显式选择配置，并为该配置单独生成计划：

```powershell
$profile = 'legacy-file-subtype7-v1'
uv run --python 3.13 --with sqlcipher3==0.6.4 -- python $script scan --db "$account\nt_qq\nt_db\nt_msg.db" --account $account --qq-build 'YOUR_QQ_BUILD' --run $run --key-file $key --profile $profile
```

其后仍须走样本 apply、原聊天 UI 确认，再 bulk apply 的流程。profile 写入加密计划；不能用 subtype 1 计划执行 subtype 7，也不要复用其他 profile 的计划。

`scan` 可加 `--extra-root` 纳入其他本地下载目录；`--existing-index` 可复用兼容的文件清单，但选中的文件仍会核对实际内容。`confirm-ui` 是操作者对原生 QQ 界面结果的确认，不是工具自动验证界面的证明。此前已在同一数据库和版本验证过相同规则时，可用 `--existing-cases` 记录已有验证。

每个数据库操作至多建立一份临时数据库副本，结束后自动清理。文件卡片引用修正不复制原始媒体；下述路径补回会按计划创建缺失文件，并报告新增空间。运行目录保留加密的受影响行计划及回滚数据、私有索引和报告。不要在仓库内创建运行目录。

在 QQ 中用 1–2 条原始文件卡片确认配置文件后，工作流应继续处理全部合格记录。样本检查不是停下等待逐条授权的理由，只要用户已授权本次修复任务。报告应分别统计已修复并经 UI 验证的记录、跳过、失败和未处理媒体。

### 明确原件路径补回：图片、视频和文件

路径补回只针对消息中明确写出的 `Ori` 原件路径确实缺失、来源字节经大小、MD5 和 SHA-256 核验，并且记录与来源身份无歧义的目标。候选扫描不等于恢复结论；`not_in_fast_index` 只表示当前索引没有快速命中，不代表文件丢失。详细边界和验证状态见[兼容性说明](skills/qqnt-media-repair/references/compatibility.md)。

原件路径补回先生成 dry-run 清单；只有显式 apply 才会创建目标文件。它只补不存在的路径，不覆盖已有文件、不修改消息数据库，也不清除未知失败标记。默认按图片路径补回；视频和文件必须 opt-in。`--media-kinds image,video,file` 用于明确指定候选类别。视频原件路径补回不一定能让聊天卡片恢复；当记录声明的封面缓存路径也缺失时，可再使用下方的封面派生流程。图片预览路径是独立选项。

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
uv run --python 3.13 -- python $restore --metadata-db $metadata --account $account --out $out --media-kinds image,video,file
# 核实代表案例、审阅目标路径及来源字节，并确认本次批量操作已获授权后，再应用符合该验证配置的目标。
uv run --python 3.13 -- python $restore --metadata-db $metadata --account $account --out $out --media-kinds image,video,file --apply
# 显式补回同一批记录声明的缺失预览；已有预览保留原字节。
uv run --python 3.13 --with pillow -- python $restore --metadata-db $metadata --account $account --out $out --media-kinds image --include-declared-previews --apply
```

### 从本地视频生成缺失封面

`video_cover_repair.py` 只处理只读清点保存到 `video_cover_targets` 的目标。每个封面路径都必须直接来自消息字段 `45404`；不得按常见目录布局自行推算，也不要在扫描器未提供明确路径时应用修复。工具会重新校验本地 MP4 来源字节，再解码首帧并生成派生 PNG。生成图是本地预览缓存，不是云端原封面；原视频字节和消息数据库均不修改。默认 dry-run；只创建缺失目标，已有封面保留。需要安装 PyAV（`av`）和 Pillow。

```powershell
$cover = '.\skills\qqnt-media-repair\scripts\video_cover_repair.py'
$coverOut = 'D:\Private\video-cover-plan.private.json'
uv run --python 3.13 --with av --with pillow -- python $cover --metadata-db $metadata --account $account --out $coverOut --qq-build '9.9.31-49738'
# 先核验一条原聊天卡片；仅在本机确认后，再对同一已验证布局应用：
uv run --python 3.13 --with av --with pillow -- python $cover --metadata-db $metadata --account $account --out $coverOut --qq-build '9.9.31-49738' --apply
```

在 QQ 9.9.31-49738 的代表案例中，只补回 MP4 原件后聊天卡片仍显示过期；再补回消息明确指向的派生封面缓存后，原聊天恢复封面和播放按钮，并可启动 QQ 原生播放器。该观察适用于此处验证过的路径布局，不保证其他版本或布局。封面工具生成的 PNG 和视频原件路径数都不是照片、视频或聊天数。

输入是只读 metadata snapshot，至少包含 `restore_targets`、`verified_sources`、`verified_refs`、`blocked_restore_paths` 和 `restore_target_conflicts` 表。完整预览清单可通过 `declared_restoration_previews(path,source_id,field,table_code,msg_id,segment_path)` 提供；若无此表，工具只使用明确标记原件缺失的受限 examples 回退集。不要把数据库快照或清单提交到仓库。

扫描过的消息总数不代表每种媒体都已验证可用。旧 `FILE` 卡片规则和原件路径补回是不同配置，不能用其中一种的“零新增”推断其他媒体没有问题。应分别报告扫描覆盖范围、按路径创建的文件数、保留或跳过项目，以及实际 QQ 抽查结果；路径数不等于独立媒体、照片或聊天数。

面向社区分享的通用流程见[社区说明稿](docs/community-post.zh-CN.md)。该稿不包含账号、聊天内容、私有文件名、哈希、截图或运行统计。

## 安装 Codex skill

将 `skills/qqnt-media-repair` 目录复制到本地 Codex skills 目录，常见位置为 `~/.codex/skills/qqnt-media-repair`，然后使用 `$qqnt-media-repair` 调用。Skill 可指导工作流；实际执行仍需安装仓库工具并查阅其当前帮助信息。

## 隐私

数据库、WAL/SHM 文件、密钥/密钥文件、账号标识、消息内容、原文件名、哈希、快照、回滚包和运行报告都是本地私有产物，不得提交或上传。示例只使用通用路径。初始支持范围不包含密钥提取工具。

## 许可

本项目按 MIT License 发布，详见 [LICENSE](LICENSE)。许可仅覆盖项目原创内容，不授予第三方软件或数据的权利。
