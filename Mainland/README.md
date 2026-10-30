# 大陆线路配置

独立配置地址：

```text
https://raw.githubusercontent.com/QmQsun/Shadowrocket-Rules/main/sr_mainland.conf
```

**必须使用 Shadowrocket「全局路由 → 配置」。选「代理」时不能依赖这份黑名单。**

本配置拒绝已审阅清单中的目标，其余被 Shadowrocket 接管的流量通过 `FINAL,PROXY` 使用首页选定的节点。节点需要自己选择，并不会自动识别或自动切换到大陆线路。此文件不含账号、订阅或节点信息。

## 导入和切换

1. 关闭需要限制联网的应用，停止 Shadowrocket 连接，保留原有日常配置。
2. 在「配置 → +」导入上述地址，选择「使用配置」。
3. 首页选择所需的大陆节点，例如自己的 Home 线路。
4. 将「全局路由」设为「配置」，再启动连接。不要切成「代理」。
5. 检查新连接日志：清单内目标应为 REJECT，未被列入清单的普通网站应使用所选代理。域名测试匹配不能代替实际连接检查。
6. 恢复日常使用时，先停止连接，切回日常配置和适当节点，再重新连接。

不要用 `ip.net.coffee` 做这份配置的出口测试，它本身在用户提供的拒绝清单中。

## 范围及影响

`Deny.list` 来自用户于 2026-10-30 提供的桌面策略清单：29 条域名或关键词条件，加 2 个 IP 网段。Windows 进程条件没有移植到 iOS。对清单中的域名和 IP，拒绝不限于 UDP 443，也覆盖匹配的 TCP 和其他端口。

清单包含共享服务，例如 Cloudflare、Stripe、Sentry、Intercom、Segment。这些目标全部拒绝时，其他网站的验证、支付、客服或统计功能也可能受影响。当前按用户确认的整份清单执行，没有把共享域名误称为某个服务独占。

本配置不载入日常广告规则或任何其他放行规则。DNS 使用系统设置作为本地解析入口，代理域名的实际解析由应用及所选代理处理；没有承诺所有 DNS、系统或不受 VPN 接管的流量都经过同一出口。保留局域网及特殊地址的绕过设置，普通公开网站不在 `skip-proxy` 例外中。

这是一份已知目标清单，不是对某个 iOS App 的独立联网权限控制，也不能保证自动覆盖未来新增域名或所有第三方基础设施。实际域名可见性、IPv6、既有连接和设备版本均需要实机确认。

## 自动更新

- 独立工作流 `Update mainland routing profile` 每周一 04:27（Asia/Shanghai，UTC+8）校验并重建。GitHub 调度可能延迟。
- 手机在 Shadowrocket「设置 → 自动更新 → 配置」中启用更新，或手动执行「更新配置」。
- 没有输入变化就不会生成新版本。校验失败不发布、不替换现有产物。
- 当前数据源是已确认的个人规则清单；周更不等于自动发现新增服务域名。需要补充时维护 `Mainland/Deny.list` 并审阅校验限制。
- 这条工作流只提交 `sr_mainland.conf` 和 `Mainland/Build-info.json`，不重建或修改日常 iOS、Android 配置。

本地维护：

```powershell
python -m unittest discover -s Mainland -p 'test_*.py' -v
python Mainland/build.py
```

`Build-info.json` 记录输入、输出 SHA256、规则数量及“只支持配置模式”的边界。此处验证为静态测试及构建检查，不代表 iPhone 已完成实机验收。
