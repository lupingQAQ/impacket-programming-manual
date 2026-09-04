# Reading Guide

The manual is organized as "Foundations → Authentication & Directory → RPC interfaces → DCOM/WMI → Support libraries". The recommended reading path:

| Part | Chapter | Content | Prerequisites |
| :--- | :--- | :--- | :--- |
| Part I Preliminaries | Ch. 1 impacket overview & directory layout | Where each module lives in the source tree | none |
| | Ch. 2 structure.py, the universal serialization base | Common base class of every protocol packet structure | none |
| Part II Authentication & Directory | Ch. 3 LDAP (ldap) | In-domain directory queries, ACL structures | Ch. 2 |
| | Ch. 4 Kerberos (krb5) | Core of domain authentication: tickets, credential cache, PAC, GSS-API/SPNEGO | Ch. 2 |
| Part III DCE/RPC | Ch. 5 dcerpc | Read the RPC basics first (NDR, rpcrt, epm, transport), then pick interface modules by functional group | Ch. 2, 4 |
| Part IV DCOM & WMI | Ch. 6 MS-DCOM | DCOM programming, dcomrt, oaut/wmi submodules | Ch. 5 |
| Part V Support libraries | Ch. 7 common | Quick tour of SMB, DPAPI, NTDS support modules | as needed |

Within Part III, the dcerpc interface modules fall into five functional groups (the text roughly follows this grouping, so you can read by group):

1. **Foundations & transport**: ndr, dtypes, rpcrt, enum, epm, transport;
2. **Security policy & domain authentication**: lsad, lsat, mgmt, mimilib, nrpc (Zerologon), samr;
3. **System & operations**: even6, iphlp, rrp (registry), rprn / par (printing), srvs (shares), wkst, tsts, MS-TSCH (scheduled tasks), dhcpm;
4. **Exchange-related**: nspi, oxabref, rpch;
5. **Credentials & directory replication**: bkrp, drsuapi (DCSync), dssp.

[TOC].
