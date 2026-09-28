#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Impacket Programming Manual - supporting example
#
# [MS-RAA] Remote Authorization API: ask the server what an identity may do.
#
# Given a target object's security descriptor (read from LDAP) and a SID, RAA
# computes - server-side, with inheritance and policy handling - whether that
# identity holds the requested access. This is the precise way to confirm a
# permission such as CreateChild (0x1) before an attack like BadSuccessor.
#
# Companion section: Chapter 8.4
# For LAB / authorized security testing only.

import argparse
import sys

from impacket import version
from impacket.examples import logger
from impacket.dcerpc.v5 import transport, epm, raa
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.examples.utils import (parse_identity, ldap_login, search_entries,
                                     ldap_value_to_bytes)
from impacket.ldap import ldap, ldapasn1
from impacket.ldap.ldap import get_entry_dn, get_entry_value

# Common access masks worth checking on an AD object
INTERESTING = {
    "CreateChild": 0x00000001,
    "DeleteChild": 0x00000002,
    "GenericAll": 0x10000000,
    "WriteDACL": 0x00040000,
    "WriteOwner": 0x00080000,
    "ExtendedRight": 0x00000100,
}


def connect_raa(target, username, password, domain, lmhash, nthash, do_kerberos=False, kdc_host=None):
    string_binding = epm.hept_map(destHost=target, remoteIf=raa.MSRPC_UUID_RAA, protocol="ncacn_ip_tcp")
    rpctransport = transport.DCERPCTransportFactory(string_binding)
    if hasattr(rpctransport, "set_credentials"):
        rpctransport.set_credentials(username, password, domain, lmhash, nthash)
    if do_kerberos:
        rpctransport.set_kerberos(do_kerberos, kdcHost=kdc_host)

    dce = rpctransport.get_dce_rpc()
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.connect()
    dce.bind(raa.MSRPC_UUID_RAA)
    return dce


def main():
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True,
        description="Use [MS-RAA] to ask the server whether a SID has a given access on an object.")
    parser.add_argument("account", action="store", metavar="[domain/]username[:password]", help="account used to authenticate")
    parser.add_argument("-dc-host", action="store", required=True, help="DC hostname (used for LDAP and RAA)")
    parser.add_argument("-dc-ip", action="store", default=None, help="DC IP (optional)")
    parser.add_argument("-baseDN", action="store", default=None, help="base DN for LDAP")
    parser.add_argument("-dn", action="store", required=True, help="DN of the object whose security descriptor is tested")
    parser.add_argument("-sid", action="store", required=True, help="SID to test (e.g. S-1-5-21-...-1108)")
    parser.add_argument("-hashes", action="store", metavar="LMHASH:NTHASH", help="NTLM hashes")
    parser.add_argument("-k", action="store_true", help="use Kerberos authentication")
    parser.add_argument("-debug", action="store_true", help="turn DEBUG output ON")
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    options = parser.parse_args()

    logger.init(False, options.debug)

    domain, username, password, lmhash, nthash, do_kerberos = parse_identity(
        options.account, options.hashes, False, None, options.k
    )
    if options.baseDN is None:
        options.baseDN = ",".join("dc=%s" % p for p in domain.split("."))

    # 1. Read the object's nTSecurityDescriptor from LDAP
    ldap_connection = ldap_login(options.dc_host, options.baseDN, options.dc_ip, options.dc_host,
                                 do_kerberos, username, password, domain, lmhash, nthash, None)
    try:
        entries = search_entries(ldap_connection, "(objectClass=*)", options.dn,
                                 search_scope=ldap.Scope('baseObject'), attributes=["nTSecurityDescriptor"])
    finally:
        ldap_connection.close()

    if not entries:
        print("[!] Object not found: %s" % options.dn)
        sys.exit(2)
    sd_bytes = ldap_value_to_bytes(get_entry_value(entries[0], "nTSecurityDescriptor"))
    if not sd_bytes:
        print("[!] Could not read nTSecurityDescriptor (need read rights on the object)")
        sys.exit(2)
    print("[*] Loaded security descriptor for %s (%d bytes)" % (get_entry_dn(entries[0]), len(sd_bytes)))

    # 2. Ask the server via RAA
    dce = connect_raa(options.dc_host, username, password, domain, lmhash, nthash, do_kerberos, options.dc_host)
    try:
        ctx = raa.hAuthzrInitializeContextFromSid(dce, options.sid, flags=raa.AUTHZ_COMPUTE_PRIVILEGES)
        handle = ctx["ContextHandle"]
        print("[*] Initialized authz context for %s" % options.sid)
        for label, mask in INTERESTING.items():
            resp = raa.hAuthzrAccessCheck(dce, handle, sd_bytes, mask, objectTypeList=[], resultListLength=1)
            granted = resp["pReply"]["GrantedAccessMask"][0] & 0xFFFFFFFF
            verdict = "GRANTED" if (granted & mask) == mask else "denied"
            print("    %-14s (0x%08x): %s" % (label, mask, verdict))
        raa.hAuthzrFreeContext(dce, handle)
    finally:
        dce.disconnect()


if __name__ == "__main__":
    main()
