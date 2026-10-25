# 构建与验证依据

核对日期：2026-10-26（UTC+8）。本文件记录构建依据，不代表 iPhone 实机验收。

## 上游来源

- 仓库：<https://github.com/nthack/Shadowrocket-ADBlock-Rules-Easy>
- 分支：`master`
- 首次固定提交：`cc14d9db68bf81aafccb26f99e8ae6badf31937f`
- 提交时间：2026-10-25 21:01:28（UTC+8）
- 原文件：[sr_banlist_ad.conf](https://raw.githubusercontent.com/nthack/Shadowrocket-ADBlock-Rules-Easy/cc14d9db68bf81aafccb26f99e8ae6badf31937f/sr_banlist_ad.conf)
- SHA256：`b8b5f2f87ad23fdfa564dba8c18971f7a5a47fc427a0a4ec5ffcb968e637925d`
- 结构：`General`、`Rule`、`URL Rewrite`；62,653 条规则。
- 首次合并：62,653 + 64 - 5 = 62,712 条规则。

原始快照逐字节保存。注释中存在上游原有的乱码，不影响规则正文，也未据此重写上游内容。

## 语法依据

参考 [Shadowrocket 使用手册原维护仓库](https://github.com/LOWERTOP/Shadowrocket/wiki)，该手册基于官方群组关键词和更新日志维护：

- `PROTOCOL` 是逻辑规则的子条件，使用 `PROTOCOL,UDP`。
- `AND` 组合协议、端口及域名条件；`REJECT-NO-DROP` 返回 ICMP 端口不可达。
- `IP-CIDR` 同时用于 IPv4 和 IPv6，`no-resolve` 避免该规则主动触发域名解析。
- UDP 匹配到不支持 UDP 的代理时，`udp-policy-not-supported-behaviour = REJECT` 拒绝转发。

保留已有通用设置不代表 DNS 已强制经过代理。静态匹配器只覆盖本项目已审阅的语法，不模拟 DNS、SNI 识别、内核优先级或真实出口。实际设备行为仍需连接日志验证。

## 工作流依据

已通过 GitHub API 核对以下标签在 2026-10-26 指向的提交，工作流使用固定 SHA：

- [actions/checkout v4](https://github.com/actions/checkout/tree/11d5960a326750d5838078e36cf38b85af677262)
- [actions/setup-python v5](https://github.com/actions/setup-python/tree/a26af69be951a213d495a4c3e4e4022e16d87065)

更新前执行 `Tests/run.py`，零测试、测试失败或构建失败均阻止发布。两份正式产物以同一 Git 提交发布。本地文件替换对普通 I/O 异常实施回滚，不能承诺突然断电时的跨文件原子性。

GitHub cron 使用 UTC；`17 20 * * 0` 对应 UTC+8 周一 04:17。调度延迟及公开仓库长期无活动的停用行为参见 [GitHub schedule 文档](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)。
