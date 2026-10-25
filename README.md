# 移动端广告过滤规则

协助 iOS 上的 Shadowrocket 屏蔽广告，保留日常网站分流，并支持自定义规则与每周更新。配置不包含代理节点、账号或节点订阅信息；所有 `PROXY` 规则统一使用手机当前选中的代理。

Android Clash Meta 版本提供独立的远程规则集合和单 `PROXY` 配置模板，详见 [安卓使用说明](Docs/Android.md)。安卓的节点订阅需保留在设备或私有文件中，不能把 iOS 的 `.conf` 链接直接作为安卓配置导入。

## 配置地址

```text
https://raw.githubusercontent.com/QmQsun/Shadowrocket-Rules/main/sr_ios_adblock.conf
```

在 Shadowrocket 中打开「配置」，点右上角「+」，粘贴此地址下载，然后选择「使用配置」。全局路由选择「配置」。先导出原配置留作备份，确认新配置可以正常使用后再切换日常使用。

「更新配置」会从上述地址覆盖本机这份配置。需要手机定期拉取时，在 Shadowrocket「设置 → 自动更新 → 配置」中打开自动更新，并按需设置间隔。GitHub 的周更与手机的拉取是两个独立步骤。

## 更新与维护

- GitHub Actions 每周一 04:17（Asia/Shanghai，UTC+8）检查上游；实际触发可能延迟。
- 在仓库 Actions 中选择 `Update mobile ad-blocking rules → Run workflow` 可手动更新。
- 修改 `Rules/Overrides.list`、`Config/Local.conf` 或构建相关文件后，推送到 `main` 也会触发更新。
- 每次先解析上游提交 SHA，再下载该固定提交。`Build-info.json` 记录来源、输入及输出 SHA256 和规则数量。
- 校验不通过时，工作流失败并保留远端已有配置。没有内容变化时不产生新提交。
- 公开仓库长期没有活动时，GitHub 可能停用定时工作流；届时在 Actions 中重新启用。每周检查不代表上游一定有新的规则。

本机更新远端版本：

```powershell
git pull --ff-only
```

本地测试和联网构建（Python 3.12 或更新版本，无第三方依赖）：

```powershell
python Tests/run.py
python Scripts/build.py
python Scripts/build_android.py
```

原始快照的离线构建：

```powershell
python Scripts/build.py --upstream-file Upstream/Original-20261026.conf --upstream-commit cc14d9db68bf81aafccb26f99e8ae6badf31937f
```

## 文件及合并规则

| 文件 | 用途 |
|---|---|
| `sr_ios_adblock.conf` | 手机下载的完整配置 |
| `Config/Local.conf` | 固定通用设置、更新地址和 URL Rewrite |
| `Rules/Overrides.list` | 优先于上游的本地规则 |
| `Scripts/build.py` | 固定版本下载、合并及验证 |
| `Tests/` | 真实快照、路由边界及失败保留测试 |
| `Upstream/Original-20261026.*` | 首次下载的原始快照及来源记录 |
| `Build-info.json` | 当前产物的校验信息 |

通用设置和 URL Rewrite 只从本地配置读取，周更不采用上游的对应设置。本地规则排在上游前面；只删除与本地规则类型、目标完全相同的上游条目，其余保留原顺序。`FINAL,DIRECT` 必须唯一且位于规则末尾。

上游结构、规则类型、策略或数量出现异常会中止构建。当前数量范围为 50,000–80,000，相比上次构建变化超过 10% 也需要人工审阅，不能直接放宽验证绕过失败。

## 验证与回滚

静态检查覆盖域名例外的优先级、后缀边界、IPv4/IPv6 兜底、指定域名及接入网段的 UDP 443 行为、FINAL 位置及失败保留。它不模拟 Shadowrocket 内核。定向 UDP 443 规则在指定域名或两个接入网段条件命中时拒绝；网段内的 TCP 和其他 UDP 端口仍走代理，不构成全面 UDP/STUN 或 DNS 防泄漏保证。

手机上还需检查：配置可导入和编译、当前使用的是这份配置、路由模式为「配置」、节点连接正常，以及连接日志中的规则命中。添加 IPv6 规则不会自动改变应用的 IPv6 开关。

回滚单次自动更新提交：在工作目录干净时运行以下命令，用实际提交 SHA 替换占位符。两份产物会一起恢复。

```powershell
git pull --ff-only
git revert <更新提交SHA>
git push origin main
```

手机随后执行「更新配置」。如故障来自持续变化的上游，在 GitHub Actions 暂时停用工作流，审阅修复后再启用，避免下次周更重新引入问题。手动修改了输入文件时，应同时回滚对应输入改动。

## 来源与许可证

上游：[nthack/Shadowrocket-ADBlock-Rules-Easy](https://github.com/nthack/Shadowrocket-ADBlock-Rules-Easy)，原配置 `sr_banlist_ad.conf`。感谢上游及其引用的广告过滤和分流规则维护者。

本项目在上游基础上合并本地优先规则、固定通用设置，并增加构建校验及自动更新流程，沿用 [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)；许可证原文见 `LICENSE`。具体技术依据见 [Docs/Validation.md](Docs/Validation.md)。
