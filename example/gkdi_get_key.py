#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Impacket Programming Manual - supporting example
#
# [MS-GKDI] Group Key Distribution: fetch a Group Key Envelope (GKE).
#
# GKDI is the first half of the "managed password" story: it returns the group
# key material (L1Key/L2Key + KDF parameters) that DPAPI-NG needs to unprotect
# gMSA/dMSA msDS-ManagedPassword and Windows LAPS v2 msLAPS-EncryptedPassword.
#
# The server authorizes the caller against a target security descriptor, so the
# caller must be allowed to read the key (e.g. be in msDS-GroupMSAMembership).
#
# Companion section: Chapter 8.2
# For LAB / authorized security testing only.

import argparse
import sys

from impacket import version
from impacket.examples import logger
from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc.v5.gkdi import MSRPC_UUID_GKDI, GkdiGetKey, GroupKeyEnvelope
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dpapi_ng import create_sd


def connect_gkdi(target, username, password, domain, lmhash, nthash, do_kerberos=False, kdc_host=None):
    string_binding = epm.hept_map(destHost=target, remoteIf=MSRPC_UUID_GKDI, protocol="ncacn_ip_tcp")
    rpctransport = transport.DCERPCTransportFactory(string_binding)
    if hasattr(rpctransport, "set_credentials"):
        rpctransport.set_credentials(username, password, domain, lmhash, nthash)
    if do_kerberos:
        rpctransport.set_kerberos(do_kerberos, kdcHost=kdc_host)

    dce = rpctransport.get_dce_rpc()
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.connect()
    dce.bind(MSRPC_UUID_GKDI)
    return dce


def main():
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True,
        description="Fetch a Group Key Envelope from the domain KDS over [MS-GKDI].")
    parser.add_argument("target", action="store", help="DC host (IP or FQDN)")
    parser.add_argument("account", action="store", metavar="[domain/]username[:password]", help="account used to authenticate")
    parser.add_argument("-sid", action="store", required=True,
                        help="SID the target security descriptor should authorize (e.g. the gMSA/dMSA computer SID)")
    parser.add_argument("-root-key-id", action="store", default=None, help="RootKeyId as a GUID (default: zero GUID)")
    parser.add_argument("-hashes", action="store", metavar="LMHASH:NTHASH", help="NTLM hashes")
    parser.add_argument("-k", action="store_true", help="use Kerberos authentication")
    parser.add_argument("-dc-host", action="store", default=None, help="hostname of the DC/KDC")
    parser.add_argument("-debug", action="store_true", help="turn DEBUG output ON")
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    options = parser.parse_args()

    logger.init(False, options.debug)

    from impacket.examples.utils import parse_identity
    from impacket.dcerpc.v5.dtypes import NULL
    from impacket.uuid import string_to_bin

    domain, username, password, lmhash, nthash, do_kerberos = parse_identity(
        options.account, options.hashes, False, None, options.k
    )

    # Build the target security descriptor: owner/group = SYSTEM, an ALLOW ACE
    # for the requested SID (mask 3) plus Everyone (mask 2). This must match the
    # descriptor the server uses to authorize the key request.
    target_sd = create_sd(options.sid)

    root_key_id = NULL
    if options.root_key_id:
        root_key_id = string_to_bin(options.root_key_id)

    dce = connect_gkdi(options.target, username, password, domain, lmhash, nthash, do_kerberos, options.dc_host)
    try:
        print("[*] Calling MS-GKDI GetKey (l0=-1, l1=-1, l2=-1)...")
        resp = GkdiGetKey(dce, target_sd=target_sd, l0=-1, l1=-1, l2=-1, root_key_id=root_key_id)
    finally:
        dce.disconnect()

    gke = GroupKeyEnvelope(b"".join(resp["pbbOut"]))
    print("[+] Group Key Envelope received (%d bytes)" % len(b"".join(resp["pbbOut"])))
    gke.dump()
    print("[*] Hand this GKE to impacket.dpapi_ng.compute_kek() to derive the KEK (see example/dpapi_ng_decrypt.py)")


if __name__ == "__main__":
    main()
