#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Find uncommon SMB shares on remote machines
#
# Author:
#   Remi GASCOU (@podalirius_)
#


import argparse
import sys
import traceback
import logging
from impacket import version
from impacket.examples import logger, utils
from impacket.smbconnection import SMBConnection, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError

COMMON_SHARES = [
    "ADMIN$", "IPC$", "C$", "NETLOGON", "SYSVOL"
]

def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Find uncommon SMB shares on remote machines')
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials '
                            'cannot be found, it will use the ones specified in the command '
                            'line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def parse_target(args):
    domain, username, password, address = utils.parse_target(args.target)

    if args.target_ip is None:
        args.target_ip = address

    if domain is None:
        domain = ''

    if password == '' and username != '' and args.hashes is None and args.no_pass is False and args.aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    if args.aesKey is not None:
        args.k = True

    if args.hashes is not None:
        lmhash, nthash = args.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    return domain, username, password, address, lmhash, nthash


def init_logger(args):
    # Init the example's logger theme and debug level
    logger.init(args.ts)
    if args.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger('impacket.smbserver').setLevel(logging.ERROR)


def init_smb_session(args, domain, username, password, address, lmhash, nthash):
    smbClient = SMBConnection(address, args.target_ip, sess_port=int(args.port))
    dialect = smbClient.getDialect()
    if dialect == SMB_DIALECT:
        logging.debug("SMBv1 dialect used")
    elif dialect == SMB2_DIALECT_002:
        logging.debug("SMBv2.0 dialect used")
    elif dialect == SMB2_DIALECT_21:
        logging.debug("SMBv2.1 dialect used")
    else:
        logging.debug("SMBv3.0 dialect used")
    if args.k is True:
        smbClient.kerberosLogin(username, password, domain, lmhash, nthash, args.aesKey, args.dc_ip)
    else:
        smbClient.login(username, password, domain, lmhash, nthash)
    if smbClient.isGuestSession() > 0:
        logging.debug("GUEST Session Granted")
    else:
        logging.debug("USER Session Granted")
    return smbClient


if __name__ == '__main__':
    print(version.BANNER)
    args = parse_args()
    init_logger(args)

    domain, username, password, address, lmhash, nthash = parse_target(args)
    try:
        smbClient = init_smb_session(args, domain, username, password, address, lmhash, nthash)

        resp = smbClient.listShares()
        found_uncommon_shares = False
        for share in resp:
            sharename = share['shi1_netname'][:-1]
            if sharename not in COMMON_SHARES:
                if not found_uncommon_shares:
                    print("[>] Found uncommon shares!")
                found_uncommon_shares = True
                print(" - '%s'" % sharename)
        if found_uncommon_shares == False:
            logging.error("No uncommon shares found.")

    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        logging.error(str(e))
