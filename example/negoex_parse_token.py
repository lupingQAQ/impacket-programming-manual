#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Impacket Programming Manual - supporting example
#
# [MS-NEGOEX] SPNEGO Extended Negotiation: parse / build NEGOEX messages.
#
# NEGOEX (magic "NEGOEXTS") is the part of SPNEGO that can carry multiple
# authentication mechanisms and metadata. This script shows the two things you
# actually need for research:
#   1. build an INITIATOR_NEGO token and an EXCHANGE_MESSAGE (AP_REQUEST);
#   2. split a concatenated token back into its messages and print the auth
#      scheme GUIDs it advertises.
#
# You can also feed a token captured from the wire (hex) with -hex.
#
# NOTE: negoex.py currently lives on impacket master (0.14.0.dev), not in a
# release. Companion section: Chapter 8.3.
# For LAB / authorized security testing only.

import argparse
import binascii
import sys

from impacket import version
from impacket.examples import logger
from impacket.negoex import (
    MESSAGE_TYPE,
    AUTH_SCHEME_PKU2U,
    createNegoMessage,
    createExchangeMessage,
    parseNegoExToken,
)

try:
    from impacket.negoex import _normalizeGuid  # internal, best-effort
except ImportError:  # pragma: no cover
    _normalizeGuid = None


def describe(token):
    messages = parseNegoExToken(token)
    print("[+] token is %d bytes, %d message(s)" % (len(token), len(messages)))
    for idx, pm in enumerate(messages):
        name = pm.getMessageType().name if hasattr(pm.getMessageType(), "name") else pm.getMessageType()
        print("    [%d] type=%-18s offset=0x%04x len=%d" % (idx, name, pm.offset, len(pm.raw_data)))
        msg = pm.message
        if msg is None:
            continue
        if pm.getMessageType() in (MESSAGE_TYPE.INITIATOR_NEGO, MESSAGE_TYPE.ACCEPTOR_NEGO):
            for scheme in msg.getAuthSchemeList():
                print("         auth-scheme=%s" % binascii.hexlify(scheme).decode())
        if pm.getMessageType() in (MESSAGE_TYPE.CHALLENGE, MESSAGE_TYPE.AP_REQUEST):
            print("         exchange-auth-scheme=%s" % binascii.hexlify(msg.getAuthScheme()).decode())
            print("         exchange-data=%d bytes" % len(msg.getExchangeData()))


def demo():
    import uuid

    conversation_id = uuid.uuid4()
    # INITIATOR_NEGO advertising a single scheme, then an AP_REQUEST carrying
    # an "optimistic token" (the initiator's first message to the mechanism).
    nego = createNegoMessage(MESSAGE_TYPE.INITIATOR_NEGO, 0, conversation_id, [AUTH_SCHEME_PKU2U])
    ap_request = createExchangeMessage(MESSAGE_TYPE.AP_REQUEST, 1, conversation_id, AUTH_SCHEME_PKU2U, b"\x60\x01\x02\x03")
    token = nego + ap_request
    print("[*] Built a demo NEGOEX token with 2 messages")
    describe(token)


def main():
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True,
        description="Parse or build NEGOEX (MS-NEGOEX) messages.")
    parser.add_argument("-hex", action="store", default=None, help="hex-encoded NEGOEX token to parse")
    parser.add_argument("-file", action="store", default=None, help="file containing a raw NEGOEX token")
    parser.add_argument("-debug", action="store_true", help="turn DEBUG output ON")
    options = parser.parse_args()

    logger.init(False, options.debug)

    if options.hex:
        describe(binascii.unhexlify(options.hex.replace(" ", "").replace(":", "")))
    elif options.file:
        with open(options.file, "rb") as f:
            describe(f.read())
    else:
        demo()


if __name__ == "__main__":
    main()
