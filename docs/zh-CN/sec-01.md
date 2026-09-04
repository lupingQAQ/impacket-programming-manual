# 阅读指南

本手册按「基础 → 认证与目录 → RPC 接口 → DCOM/WMI → 基础库」的顺序组织，建议的阅读路线如下：

| 部分 | 章节 | 内容 | 前置知识 |
| :--- | :--- | :--- | :--- |
| 第一部分 预备与基础 | 第 1 章 impacket 总览与目录结构 | 各模块在源码树中的位置 | 无 |
| | 第 2 章 structure.py 通用序列化基类 | 所有协议包结构的公共基类 | 无 |
| 第二部分 认证与目录服务 | 第 3 章 LDAP（ldap） | 域内目录查询、ACL 结构 | 第 2 章 |
| | 第 4 章 Kerberos（krb5） | 域认证核心：票据、凭据缓存、PAC、GSS-API/SPNEGO | 第 2 章 |
| 第三部分 DCE/RPC | 第 5 章 dcerpc | 先读 RPC 编程基础（NDR、rpcrt、epm、transport），再按功能组选读各接口模块 | 第 2、4 章 |
| 第四部分 DCOM 与 WMI | 第 6 章 MS-DCOM | DCOM 编程、dcomrt、oaut/wmi 等子模块 | 第 5 章 |
| 第五部分 基础库 | 第 7 章 common | SMB、DPAPI、NTDS 等基础支撑模块速览 | 按需 |

第三部分中，dcerpc 的接口模块按功能可分为五组（正文大体按此组织，可按组选读）：

1. **基础与传输**：ndr、dtypes、rpcrt、enum、epm、transport；
2. **安全策略与域认证**：lsad、lsat、mgmt、mimilib、nrpc（Zerologon）、samr；
3. **系统与运维**：even6、iphlp、rrp（注册表）、rprn / par（打印）、srvs（共享）、wkst、tsts、MS-TSCH（计划任务）、dhcpm；
4. **Exchange 相关**：nspi、oxabref、rpch；
5. **凭据与目录复制**：bkrp、drsuapi（DCSync）、dssp。

[TOC]
