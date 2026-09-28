#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Impacket Programming Manual - supporting example
#
# [MS-ICPR] ICertPassage: enroll a certificate from an enterprise CA over RPC.
#
# Instead of the HTTP enrollment endpoint (the classic ESC8 target), this uses
# the ICertPassage RPC interface (impacket.dcerpc.v5.icpr). It builds a PKCS#10
# CSR with `cryptography`, submits it with icpr.hCertServerRequest(), and saves
# the issued certificate as a password-less PKCS#12 (.pfx) file.
#
# Companion section: Chapter 8.1 / 8.1 (见 impacket 编程手册)
# For LAB / authorized security testing only.

import argparse
import sys

from impacket import version
from impacket.examples import logger
from impacket.dcerpc.v5 import transport, epm, icpr
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY


def build_csr(common_name, key_size=2048):
    """Return (private_key, der_encoded_csr)."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return key, csr.public_bytes(serialization.Encoding.DER)


def connect_icpr(target, username, password, domain, lmhash, nthash, do_kerberos=False, kdc_host=None):
    # Resolve the ICertPassage dynamic endpoint through the Endpoint Mapper.
    string_binding = epm.hept_map(destHost=target, remoteIf=icpr.MSRPC_UUID_ICPR, protocol="ncacn_ip_tcp")
    rpctransport = transport.DCERPCTransportFactory(string_binding)
    if hasattr(rpctransport, "set_credentials"):
        rpctransport.set_credentials(username, password, domain, lmhash, nthash)
    if do_kerberos:
        rpctransport.set_kerberos(do_kerberos, kdcHost=kdc_host)

    dce = rpctransport.get_dce_rpc()
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.connect()
    dce.bind(icpr.MSRPC_UUID_ICPR)
    return dce


def save_pfx(path, key, cert_der, password=None):
    from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
    from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, NoEncryption
    from cryptography.x509 import load_der_x509_certificate

    cert = load_der_x509_certificate(cert_der)
    encryption = BestAvailableEncryption(password.encode()) if password else NoEncryption()
    pfx = serialize_key_and_certificates(name=None, key=key, cert=cert, cas=None, encryption_algorithm=encryption)
    with open(path, "wb") as f:
        f.write(pfx)


def main():
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True,
        description="Request a certificate from an enterprise CA over [MS-ICPR] (ICertPassage).")
    parser.add_argument("target", action="store", help="DC/CA host (IP or FQDN)")
    parser.add_argument("account", action="store", metavar="[domain/]username[:password]", help="account used to authenticate")
    parser.add_argument("-ca", action="store", default="", help="CA name (netbios\\CAName or CA name); empty = server default")
    parser.add_argument("-template", action="store", default="User", help="certificate template name (default: User)")
    parser.add_argument("-subject", action="store", default=None, help="CSR subject CN (default: username)")
    parser.add_argument("-out", action="store", default="enrolled.pfx", help="output PKCS#12 file")
    parser.add_argument("-pfx-password", action="store", default=None, help="password for the output PKCS#12")
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
    domain, username, password, lmhash, nthash, do_kerberos = parse_identity(
        options.account, options.hashes, False, None, options.k
    )
    if domain == "":
        # allow "domain/user:pass"; parse_identity already splits it
        domain = "."

    subject = options.subject or username or "impacket"

    # 1. Build the CSR
    key, csr_der = build_csr(subject)
    print("[*] Generated %d-bit key and CSR for CN=%s" % (2048, subject))

    # 2. Submit over ICertPassage
    dce = connect_icpr(options.target, username, password, domain, lmhash, nthash, do_kerberos, options.dc_host)
    try:
        print("[*] Requesting template '%s' from CA '%s'..." % (options.template, options.ca or "<default>"))
        cert_der = icpr.hCertServerRequest(
            dce, csr_der, ["CertificateTemplate:%s" % options.template], ca=options.ca
        )
    finally:
        dce.disconnect()

    if not cert_der:
        print("[!] No certificate returned (request may be pending approval)")
        sys.exit(2)

    # 3. Save as PKCS#12
    save_pfx(options.out, key, cert_der, options.pfx_password)
    print("[+] Certificate written to %s (%d bytes DER)" % (options.out, len(cert_der)))


if __name__ == "__main__":
    main()
