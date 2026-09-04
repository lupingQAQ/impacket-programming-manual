<p align="center">
  <img src="https://github.com/xzxxzzzz000/impacket-programming-manual/assets/24671887/2c9fd1fb-98f8-46c3-ad70-8d083e0a082b" alt="impacket-programming-manual" width="220" />
</p>

<h1 align="center">impacket-programming-manual</h1>

<h3 align="center">The impacket Programming Manual · impacket 编程手册（域渗透脚本开发）</h3>

<p align="center"><em style="font-family: Georgia, serif; font-size: 1.1em; color: #777;">Stop copy-pasting impacket examples — learn to write your own PoC against the Kerberos / RPC / DCOM stack.</em></p>

<p align="center">
  <a href="https://github.com/lupingQAQ/impacket-programming-manual/releases"><img src="https://img.shields.io/badge/release-v2.1-blue" alt="release v2.1"></a>
  <a href="https://github.com/lupingQAQ/impacket-programming-manual/stargazers"><img src="https://img.shields.io/github/stars/lupingQAQ/impacket-programming-manual?style=flat&logo=github" alt="stars"></a>
  <a href="https://github.com/lupingQAQ/impacket-programming-manual/forks"><img src="https://img.shields.io/github/forks/lupingQAQ/impacket-programming-manual?style=flat&logo=github" alt="forks"></a>
  <a href="https://github.com/lupingQAQ/impacket-programming-manual/issues"><img src="https://img.shields.io/github/issues/lupingQAQ/impacket-programming-manual?style=flat&logo=github" alt="issues"></a>
  <a href="impacket_programming_manual_EN.pdf"><img src="https://img.shields.io/badge/PDF-English%20Edition-red" alt="PDF EN"></a>
  <a href="impacket编程手册.pdf"><img src="https://img.shields.io/badge/PDF-中文版-red" alt="PDF ZH"></a>
</p>

<br/>

<p align="center">
  <a href="#about">About</a> ·
  <a href="#whats-inside">What's inside</a> ·
  <a href="#highlights">Highlights</a> ·
  <a href="#getting-started">Getting started</a> ·
  <a href="#repository-layout">Repo layout</a> ·
  <a href="#contributing">Contributing</a> ·
  <a href="#disclaimer">Disclaimer</a>
</p>

<p align="center">
  🌐 <a href="README.zh-CN.md">中文版</a>
</p>

<br/>

<a id="about"></a>

## About

**impacket-programming-manual** is a book-length, source-code-driven guide to **developing your own domain-penetration scripts on top of [impacket](https://github.com/fortra/impacket)** — not another walkthrough of `secretsdump.py` / `psexec.py` flags.

Almost every public exploit for recent Active Directory vulnerabilities was built directly on impacket modules — `sam-the-admin`, `CVE-2022-33679`, `noPac`, `Zerologon` tooling, `PetitPotam`-style relay chains… Yet nearly all existing articles only explain how to *run* the example scripts. This manual fills the gap the other way around: it walks module by module through the impacket source tree, so when the next domain vulnerability drops you can grab impacket and **write your own PoC fast**.

- **Author:** Lu Ping (鲁平) · WeChat blog: `Security丨Art`
- **Length:** ~5,600 lines, 7 chapters, 5 parts — with an English edition translated from the revised Chinese 2nd edition
- **Covers:** LDAP · Kerberos (krb5) · GSS-API/SPNEGO · DCE/RPC (NDR, EPM, transport) · 20+ MS protocol modules (SAMR, NRPC, LSAD, RRP, SRVS, RPRN/PAR, TSCH, BKRP, DRSUAPI…) · DCOM & WMI (dcomrt, oaut, comev, scmp, vds, wmi) · the common support libraries

<a id="whats-inside"></a>

## What's inside

| Part | Chapter | Content | Prerequisites |
| :--- | :--- | :--- | :--- |
| I. Preliminaries | Ch.1 impacket overview & directory layout | Where every module lives in the source tree | none |
| | Ch.2 `structure.py` — universal serialization base | The base class behind every protocol packet structure | none |
| II. Authentication & Directory | Ch.3 LDAP (`ldap`) | Directory queries, ACL structures, Global Catalog | Ch.2 |
| | Ch.4 Kerberos (`krb5`) | Tickets, ccache/keytab, PAC, GSS-API & SPNEGO | Ch.2 |
| III. DCE/RPC | Ch.5 `dcerpc` | RPC basics (NDR, rpcrt, EPM, transport) + 20+ interface modules in 5 functional groups | Ch.2, 4 |
| IV. DCOM & WMI | Ch.6 MS-DCOM | COM/DCOM programming, dcomrt, oaut/comev/scmp/vds/wmi submodules | Ch.5 |
| V. Support libraries | Ch.7 `common` | SMB2/3, DPAPI, NTDS (ese), TDS and friends | as needed |

Case studies woven through the chapters: **Zerologon (CVE-2020-1472)** in nrpc, **PrinterBug / PrintNightmare** in rprn/par, **CVE-2019-1040 NTLM MIC bypass** in gssapi, **Exchange RPC-over-HTTP relay** (rpcmap / ProxyRelay), Akamai's **Cold Hard Cache** RPC security-callback bypass, **WMI persistence** (wmipersist), golden PAC forging and more.

<a id="highlights"></a>

## Highlights

- **Source-level, not example-level** — every chapter reads the actual impacket source: `getKerberosTGT`/`getKerberosTGS` internals, ccache/keytab binary layouts, `DCERPCTransportFactory` dispatch, `DCOMConnection`/`INTERFACE`/`IRemUnknown` object model, `IWbemServices` method tables.
- **Annotated code excerpts** — long listings are compressed to key code paths with step-numbered annotations (`① ② ③…` in Chinese, `(1) (2) (3)…` in English), so you see the flow at a glance instead of scrolling through hundreds of lines of boilerplate.
- **Upstream-verified quotes** — all cited code was checked against the current fortra/impacket master; known upstream quirks (the `par.py` opnum 39 tuple, `hept_map` spelling, `MimiUnbind` vs `MiniUnbind`) are preserved and annotated instead of silently "fixed".
- **Descriptive TOC** — every module heading carries a content summary (`### nrpc.py — Netlogon Authentication & Zerologon (CVE-2020-1472)`), not just a bare filename.
- **Fully bilingual** — the English edition's code blocks carry zero CJK characters; all annotations and method descriptions are translated.

<a id="getting-started"></a>

## Getting started

```bash
git clone https://github.com/lupingQAQ/impacket-programming-manual.git
```

- Read online: [`impacket编程手册.md`](impacket编程手册.md) (中文) / [`impacket_programming_manual_EN.md`](impacket_programming_manual_EN.md) (English)
- Offline reading: grab [`impacket编程手册.pdf`](impacket编程手册.pdf) or [`impacket_programming_manual_EN.pdf`](impacket_programming_manual_EN.pdf)
- Recommended path: follow the **Reading Guide** table at the top of the manual — foundations (Ch.1–2) → Kerberos (Ch.4) → pick RPC interface modules by functional group (Ch.5)
- Practice environment: a Windows AD lab (e.g. two VMs + `pip install impacket`), then re-implement the case studies module by module

<a id="repository-layout"></a>

## Repository layout

```
.
├── README.md                         # This file (English, default)
├── README.zh-CN.md                   # 中文版说明
├── impacket编程手册.md                # Chinese edition (source of truth)
├── impacket编程手册.pdf               # Chinese print edition
├── impacket_programming_manual_EN.md # English edition
└── impacket_programming_manual_EN.pdf# English print edition
```

<a id="contributing"></a>

## Contributing

Corrections are very welcome — especially:

1. Technical review against impacket / Microsoft protocol documentation (function names, flows, crypto descriptions)
2. New chapter material (e.g. ADCS, `ntlmrelayx` internals, `smbconnection` deep-dive)
3. Translation improvements for the English edition

Fork → branch → PR. Typos and citation fixes are just as appreciated.

**Contact:** WeChat blog `Security丨Art` · [GitHub Issues](https://github.com/lupingQAQ/impacket-programming-manual/issues)

<a id="disclaimer"></a>

## Disclaimer

This manual is provided for **lawful security research, education, and authorized penetration testing only**. All techniques discussed target protocols and systems in lab environments you own or are explicitly authorized to assess. The author and contributors accept no liability for misuse.

<p align="right">(<a href="#about">back to top</a>)</p>
