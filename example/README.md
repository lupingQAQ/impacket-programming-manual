# example/ - impacket latest-feature PoCs

Runnable examples for the interfaces in **Part VI** of the manual that impacket's own
`examples/` folder does **not** already demonstrate. We deliberately avoid
re-implementing what upstream already ships (see "Already covered upstream" below).

> ⚠️ For **lawful security research and authorized penetration testing only.**
> Run them only against lab systems you own or are explicitly authorized to test.

## Scripts

| Script | Manual | Module / interface | What it does |
| :--- | :--- | :--- | :--- |
| `icpr_enroll_cert.py` | 8.1 | `dcerpc/v5/icpr.py` ([MS-ICPR]) | Submit a PKCS#10 CSR to an enterprise CA over the ICertPassage RPC interface and save the result as PKCS#12. Upstream only uses ICPR *inside* `ntlmrelayx`, never as a standalone enrollment demo. |
| `gkdi_get_key.py` | 8.2 | `dcerpc/v5/gkdi.py` ([MS-GKDI]) | Fetch a Group Key Envelope (GKE) from the domain KDS in isolation. |
| `negoex_parse_token.py` | 8.3 | `negoex.py` ([MS-NEGOEX]) | Build / parse NEGOEX messages and print advertised auth-scheme GUIDs. No upstream example exists. |
| `raa_enum_permissions.py` | 8.4 | `dcerpc/v5/raa.py` ([MS-RAA]) | Ask the server whether a SID has a given access on an object's security descriptor. No upstream example exists. |

## Already covered upstream - use these instead

Do not re-implement these locally; impacket already ships a working example:

| Topic | Upstream example |
| :--- | :--- |
| Service control ([MS-SCMR]) | [`examples/services.py`](https://github.com/fortra/impacket/blob/master/examples/services.py) |
| SMB / NTFS ACLs (`impacket.acl`) | [`examples/smbclient.py`](https://github.com/fortra/impacket/blob/master/examples/smbclient.py) (ACL commands) |
| DPAPI-NG / GKDI decryption | [`examples/GetLAPSPassword.py`](https://github.com/fortra/impacket/blob/master/examples/GetLAPSPassword.py) |
| BadSuccessor (dMSA) | [`examples/badsuccessor.py`](https://github.com/fortra/impacket/blob/master/examples/badsuccessor.py) |

## Requirements

```bash
pip install impacket            # >= 0.13.1
# negoex_parse_token.py + raa_enum_permissions.py additionally need impacket master (0.14.0.dev):
#   pip install git+https://github.com/fortra/impacket.git
```

Most scripts accept the usual impacket identity form
`[domain/]username[:password]` plus `-hashes`, `-k` and `-dc-host`.

## A note on versions

- `icpr.py`, `gkdi.py`: available since impacket **0.13.0 / 0.12.0**.
- `negoex.py`, `raa.py`: on **master (0.14.0.dev)** at the time of writing; verify they are present in your installed version.

中文：本目录只补充手册**第六部分**中、impacket 自带 `examples/` **尚未提供独立示例**的接口
——证书注册（ICPR）、GKDI 取密钥、NEGOEX 解析、RAA 权限枚举。SCMR、SMB ACL、DPAPI-NG、
BadSuccessor 请直接用 impacket 自带的 `examples/services.py` / `smbclient.py` /
`GetLAPSPassword.py` / `badsuccessor.py`，不在本地重复实现。
**仅限合法的安全研究与获得明确授权的渗透测试。**
