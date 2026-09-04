<p align="center">
  <img src="https://github.com/xzxxzzzz000/impacket-programming-manual/assets/24671887/2c9fd1fb-98f8-46c3-ad70-8d083e0a082b" alt="impacket-programming-manual" width="220" />
</p>

<h1 align="center">impacket-programming-manual</h1>

<h3 align="center">impacket 编程手册 · 域渗透脚本开发（The impacket Programming Manual）</h3>

<p align="center"><em style="font-family: Georgia, serif; font-size: 1.1em; color: #777;">不止会用 impacket 的示例脚本——学会基于 Kerberos / RPC / DCOM 协议栈编写自己的 PoC。</em></p>

<p align="center">
  <a href="https://github.com/lupingQAQ/impacket-programming-manual/releases"><img src="https://img.shields.io/badge/release-v2.0-blue" alt="release v2.0"></a>
  <a href="https://github.com/lupingQAQ/impacket-programming-manual/stargazers"><img src="https://img.shields.io/github/stars/lupingQAQ/impacket-programming-manual?style=flat&logo=github" alt="stars"></a>
  <a href="https://github.com/lupingQAQ/impacket-programming-manual/forks"><img src="https://img.shields.io/github/forks/lupingQAQ/impacket-programming-manual?style=flat&logo=github" alt="forks"></a>
  <a href="https://github.com/lupingQAQ/impacket-programming-manual/issues"><img src="https://img.shields.io/github/issues/lupingQAQ/impacket-programming-manual?style=flat&logo=github" alt="issues"></a>
  <a href="impacket_programming_manual_EN.pdf"><img src="https://img.shields.io/badge/PDF-English%20Edition-red" alt="PDF EN"></a>
  <a href="impacket编程手册.pdf"><img src="https://img.shields.io/badge/PDF-中文版-red" alt="PDF ZH"></a>
</p>

<br/>

<p align="center">
  <a href="#about">简介</a> ·
  <a href="#whats-inside">内容</a> ·
  <a href="#highlights">特色</a> ·
  <a href="#getting-started">快速开始</a> ·
  <a href="#repository-layout">仓库结构</a> ·
  <a href="#contributing">参与贡献</a> ·
  <a href="#disclaimer">免责声明</a>
</p>

<p align="center">
  🌐 <a href="README.md">English</a>
</p>

<br/>

<a id="about"></a>

## 简介

**impacket-programming-manual** 是一本以 impacket 源码为线索、面向**域渗透脚本开发**的中文编程手册——不是又一篇 `secretsdump.py` / `psexec.py` 参数用法教程。

近年来几乎每个 Active Directory 域漏洞的公开利用脚本都直接基于 impacket 模块开发——`sam-the-admin`、`CVE-2022-33679`、`noPac`、Zerologon 工具链、`PetitPotam` 类中继攻击……但网上文章几乎都只在讲怎么**运行**这些示例脚本。本手册反其道而行：逐模块拆解 impacket 源码树，让下次域漏洞爆发时，你能直接拿起 impacket **快速写出自己的 PoC**。

- **作者：** 鲁平 · 微信公众号：`Security丨Art`
- **篇幅：** 约 5600 行，五部分七章；英文版与修订后的中文第二版同步维护
- **覆盖：** LDAP · Kerberos（krb5）· GSS-API/SPNEGO · DCE/RPC（NDR、EPM、transport）· 20+ 个 MS 协议模块（SAMR、NRPC、LSAD、RRP、SRVS、RPRN/PAR、TSCH、BKRP、DRSUAPI…）· DCOM 与 WMI（dcomrt、oaut、comev、scmp、vds、wmi）· common 基础库

<a id="whats-inside"></a>

## 内容

| 部分 | 章节 | 内容 | 前置知识 |
| :--- | :--- | :--- | :--- |
| 第一部分 预备与基础 | 第 1 章 impacket 总览与目录结构 | 各模块在源码树中的位置 | 无 |
| | 第 2 章 structure.py 通用序列化基类 | 所有协议包结构的公共基类 | 无 |
| 第二部分 认证与目录服务 | 第 3 章 LDAP（ldap） | 域内目录查询、ACL 结构、全局编录 | 第 2 章 |
| | 第 4 章 Kerberos（krb5） | 票据、ccache/keytab、PAC、GSS-API 与 SPNEGO | 第 2 章 |
| 第三部分 DCE/RPC | 第 5 章 dcerpc | RPC 基础（NDR、rpcrt、EPM、transport）+ 按功能分五组的 20+ 接口模块 | 第 2、4 章 |
| 第四部分 DCOM 与 WMI | 第 6 章 MS-DCOM | COM/DCOM 编程、dcomrt、oaut/comev/scmp/vds/wmi 子模块 | 第 5 章 |
| 第五部分 基础库 | 第 7 章 common | SMB2/3、DPAPI、NTDS（ese）、TDS 等 | 按需 |

穿插的实战案例分析：nrpc 中的 **Zerologon（CVE-2020-1472）**、rprn/par 中的 **PrinterBug / PrintNightmare**、gssapi 中的 **CVE-2019-1040 NTLM MIC 绕过**、**Exchange RPC over HTTP 中继**（rpcmap / ProxyRelay）、Akamai 的 **Cold Hard Cache** RPC 安全回调缓存滥用、**WMI 事件持久化**（wmipersist）、黄金 PAC 构造等。

<a id="highlights"></a>

## 特色

- **源码级讲解，而非示例级** —— 每一章都在读 impacket 真实源码：`getKerberosTGT`/`getKerberosTGS` 内部流程、ccache/keytab 二进制布局、`DCERPCTransportFactory` 分发逻辑、`DCOMConnection`/`INTERFACE`/`IRemUnknown` 对象模型、`IWbemServices` 方法表。
- **引用代码与上游逐条核对** —— 全部代码引用已与 fortra/impacket 最新 master 比对；上游自身的历史笔误（par.py opnum 39 元组、`hept_map` 拼写、`MimiUnbind` 与 `MiniUnbind` 的分歧）按源码原样保留并加注说明，而非"顺手改掉"。
- **教科书式结构（第二版）** —— 五部分七章、阅读指南与前置知识表、术语全书统一（封送/marshaling、注册表项/registry key）、表格与微软协议文档（[MS-KILE]、[MS-NRPC]、[MS-DCOM]、[MS-WMI]…）对齐。
- **中英双语双版本** —— 修订版中文与完整英文版并行维护，144 个代码清单两版逐字节一致。
- **随附 PDF** —— 两种语言的印刷版由同一 Markdown 源生成。

<a id="getting-started"></a>

## 快速开始

```bash
git clone https://github.com/lupingQAQ/impacket-programming-manual.git
```

- 在线阅读：[`impacket编程手册.md`](impacket编程手册.md)（中文）/ [`impacket_programming_manual_EN.md`](impacket_programming_manual_EN.md)（English）
- 离线阅读：下载 [`impacket编程手册.pdf`](impacket编程手册.pdf) 或 [`impacket_programming_manual_EN.pdf`](impacket_programming_manual_EN.pdf)
- 推荐路线：按手册开头的**阅读指南**表格推进——基础（第 1–2 章）→ Kerberos（第 4 章）→ 按功能组选读 RPC 接口模块（第 5 章）
- 实验环境：一套 Windows AD 实验（两台虚拟机 + `pip install impacket`），跟着案例逐模块复现

<a id="repository-layout"></a>

## 仓库结构

```
.
├── README.md                         # 项目说明（English，默认展示）
├── README.zh-CN.md                   # 本文件（中文说明）
├── impacket编程手册.md                # 中文版手册（内容源头）
├── impacket编程手册.pdf               # 中文印刷版
├── impacket_programming_manual_EN.md # 英文版手册
└── impacket_programming_manual_EN.pdf# 英文印刷版
```

<a id="contributing"></a>

## 参与贡献

欢迎纠错，尤其欢迎：

1. 对照 impacket / 微软协议文档做技术审校（函数名、认证流程、加解密描述）
2. 补充新章节素材（如 ADCS、`ntlmrelayx` 内部实现、`smbconnection` 深入解析）
3. 英文版翻译改进

Fork → 分支 → PR。错别字与引用补充同样感谢。

**联系方式：** 微信公众号 `Security丨Art` · [GitHub Issues](https://github.com/lupingQAQ/impacket-programming-manual/issues)

<a id="disclaimer"></a>

## 免责声明

本手册**仅用于合法的安全研究、教学以及获得明确授权的渗透测试**。书中讨论的所有技术均以实验室环境或已获授权评估的系统为目标。作者与贡献者不对滥用行为承担任何责任。

<p align="right">(<a href="#about">回到顶部</a>)</p>
