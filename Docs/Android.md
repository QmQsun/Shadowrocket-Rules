# Android Clash Meta 使用说明

安卓版本默认使用全局模式，`GLOBAL` 组固定指向手动选择的 `PROXY` 组，两种模式共用同一个节点选择。公开仓库只包含规则和占位模板，不包含可用的节点账号或订阅凭据。

## 导入与首次连接

1. 将为自己生成的私有 `Android-PandaFan.yaml` 传到安卓手机，在 Clash Meta「配置」中从文件导入并启用。无需删除原来的配置。
2. 在代理页面进入 `PROXY`，手动选择一个订阅节点。首次默认选项 `REJECT` 表示暂不代理，选好节点后才能正常代理连接。
3. 首次尚未选择节点时，远程规则下载可能失败。选好节点后重启应用内连接，检查规则集合更新；这不会修改系统或电脑的 Clash 配置。
4. 默认是全局模式。需要分流及广告过滤时，在「代理页 → 菜单 → 模式」选择「规则模式」；需要恢复全局时在同一菜单切换。

全局模式将进入内核的普通连接交给 `GLOBAL → PROXY`，跳过规则表，因此广告过滤、国内直连和定向 UDP 443 拦截仅在规则模式下生效。应用的分应用代理或 VPN 排除设置仍可能使部分流量不进入内核。

客户端的模式覆写优先于文件中的默认值。更新配置后若仍显示旧模式，将「设置 → 覆写 → 模式」及代理页模式菜单恢复为「不修改」，再重新启用配置以遵循文件默认值；也可以直接在模式菜单选择想使用的模式。

私有 YAML 中的订阅会独立刷新，规则集合每日检查一次；仓库每周一 04:17（UTC+8）构建上游更新。以后通常无需重新导入整个 YAML。需要改动 DNS、组结构或兜底策略时，仍需更新本机配置文件。

公开的 `Android/Profile-template.yaml` 使用 `example.invalid` 占位订阅，不能直接连接。其余 `.yaml` 是 `classical` 规则集合，也不是可以单独导入的完整配置。

## 规则模式的顺序与适配范围

| 顺序 | 规则 | 策略 |
|---|---|---|
| 1 | 明确的本机、局域网地址 | DIRECT |
| 2 | 共享的定向 UDP 443 条件 | REJECT |
| 3 | 共享优先域名及接入网段 | PROXY |
| 4 | 上游广告过滤 | REJECT |
| 5 | 桌面配置提取的 56 条通用服务域名 | PROXY |
| 6 | 桌面配置提取的 4 条通用直连域名 | DIRECT |
| 7 | GeoIP 中国地址 | DIRECT |
| 8 | 其他流量 | PROXY |

优先规则与 iOS 共用 `Rules/Overrides.list`。安卓按 Mihomo 语法生成 `NETWORK,udp`、`IP-CIDR6` 及 `REJECT`，不照搬 iOS 的关键字。服务分流分别保存在 `Rules/Android-services.list` 和 `Rules/Android-direct.list`。Google 组中的广告域名仍先经过广告过滤，不会因通用服务规则而被整体放行。

手机版不复制 Windows 进程、RDP 私有地址、Bloomberg 端口、Wind 桌面规则或 HOME 专用组；这些不是单出口手机配置的组成部分。政务及其他国内服务由中国地址直连规则处理，不保留电脑的 HOME 出口语义。通用 UDP 443 拒绝未带入手机版，仅保留共享的定向条件。

DNS 沿用桌面配置的主要方向：默认使用经 `PROXY` 的 Google/Cloudflare DoH，IPv6 关闭。节点及订阅主机使用独立的启动解析器，以免尚未取得节点时无法下载订阅。这不是所有 DNS 请求都经过代理的保证。Android 的 VPN 接管由客户端处理，本配置不复制 Windows TUN 设置。

## 维护

```powershell
python Tests/run.py
python Scripts/build.py
python Scripts/build_android.py
```

`Android/Build-info.json` 记录每份规则集合的规则数量、SHA256 和上游提交。两种客户端全部构建成功后，工作流才以一个提交发布更新。

需要从自己的桌面 YAML 重新生成私有配置时，运行（此步骤需要本机已有 PyYAML）：

```powershell
python Scripts/make_android_profile.py <自己的桌面配置路径>
```

输出限定在 Git 忽略的 `Output/Private/` 中，默认拒绝覆盖已有文件。更新时使用 `--output Output/Private/Android-PandaFan-v2.yaml` 等新文件名，保留旧版本。

## 验证范围

2026-10-26：已用本机 Mihomo Meta v1.19.32 对规则集合形式及展开后的完整规则执行 `-t` 原生语法验证。验证使用独立目录和测试节点，没有启动新代理服务，也没有修改电脑正在使用的配置。手机上的具体内核版本、首次订阅下载、规则更新和连接出口仍需实机验证。

依据：[Mihomo 规则集合格式](https://wiki.metacubex.one/config/rule-providers/content/)、[规则集合更新设置](https://wiki.metacubex.one/config/rule-providers/)、[节点集合设置](https://wiki.metacubex.one/config/proxy-providers/)。
