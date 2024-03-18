#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : FindUncommonShares.py
# Author             : Podalirius (@podalirius_)
# Date created       : 30 Jan 2022


from concurrent.futures import ThreadPoolExecutor
from impacket.smbconnection import SMBConnection, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError
from sectools.windows.ldap import raw_ldap_query, init_ldap_session
from sectools.windows.crypto import parse_lm_nt_hashes
import argparse
import dns.resolver
import dns.exception
import json
import ntpath
import os
import random
import re
import sqlite3
import socket
import sys
import threading
import traceback
import xlsxwriter


VERSION = "3.1"


COMMON_SHARES = [
    "C$",
    "ADMIN$", "IPC$",
    "PRINT$", "print$",
    "fax$", "FAX$",
    "SYSVOL", "NETLOGON"
]


class MicrosoftDNS(object):
    """
    Class to interact with Microsoft DNS servers for resolving domain names to IP addresses.
    
    Attributes:
        dnsserver (str): The IP address of the DNS server.
        verbose (bool): Flag to enable verbose mode.
        auth_domain (str): The authentication domain.
        auth_username (str): The authentication username.
        auth_password (str): The authentication password.
        auth_dc_ip (str): The IP address of the domain controller.
        auth_lm_hash (str): The LM hash for authentication.
        auth_nt_hash (str): The NT hash for authentication.
    """

    __wildcard_dns_cache = {}

    def __init__(self, dnsserver, auth_domain, auth_username, auth_password, auth_dc_ip, auth_lm_hash, auth_nt_hash, use_ldaps=False, verbose=False):
        super(MicrosoftDNS, self).__init__()
        self.dnsserver = dnsserver
        self.verbose = verbose
        self.auth_domain = auth_domain
        self.auth_username = auth_username
        self.auth_password = auth_password
        self.auth_dc_ip = auth_dc_ip
        self.auth_lm_hash = auth_lm_hash
        self.auth_nt_hash = auth_nt_hash
        self.use_ldaps = use_ldaps

    def resolve(self, target_name):
        """
        Documentation for class MicrosoftDNS
        
        Attributes:
            dnsserver (str): The IP address of the DNS server.
            verbose (bool): Flag to enable verbose mode.
            auth_domain (str): The authentication domain.
            auth_username (str): The authentication username.
            auth_password (str): The authentication password.
            auth_dc_ip (str): The IP address of the domain controller.
            auth_lm_hash (str): The LM hash for authentication.
            auth_nt_hash (str): The NT hash for authentication.
        """
        target_ips = []
        for rdtype in ["A", "AAAA"]:
            dns_answer = self.get_record(value=target_name, rdtype=rdtype)
            if dns_answer is not None:
                for record in dns_answer:
                    target_ips.append(record.address)
        if self.verbose and len(target_ips) == 0:
            print("[debug] No records found for %s." % target_name)
        return target_ips

    def get_record(self, rdtype, value):
        """
        Retrieves DNS records for a specified value and record type using UDP and TCP protocols.

        Parameters:
            rdtype (str): The type of DNS record to retrieve.
            value (str): The value for which the DNS record is to be retrieved.

        Returns:
            dns.resolver.Answer: The DNS answer containing the resolved records.

        Raises:
            dns.resolver.NXDOMAIN: If the domain does not exist.
            dns.resolver.NoAnswer: If the domain exists but does not have the specified record type.
            dns.resolver.NoNameservers: If no nameservers are found for the domain.
            dns.exception.DNSException: For any other DNS-related exceptions.
        """
        dns_resolver = dns.resolver.Resolver()
        dns_resolver.nameservers = [self.dnsserver]
        dns_answer = None
        # Try UDP
        try:
            dns_answer = dns_resolver.resolve(value, rdtype=rdtype, tcp=False)
        except dns.resolver.NXDOMAIN:
            # the domain does not exist so dns resolutions remain empty
            pass
        except dns.resolver.NoAnswer as e:
            # domains existing but not having AAAA records is common
            pass
        except dns.resolver.NoNameservers as e:
            pass
        except dns.exception.DNSException as e:
            pass

        if dns_answer is None:
            # Try TCP
            try:
                dns_answer = dns_resolver.resolve(value, rdtype=rdtype, tcp=True)
            except dns.resolver.NXDOMAIN:
                # the domain does not exist so dns resolutions remain empty
                pass
            except dns.resolver.NoAnswer as e:
                # domains existing but not having AAAA records is common
                pass
            except dns.resolver.NoNameservers as e:
                pass
            except dns.exception.DNSException as e:
                pass

        if self.verbose and dns_answer is not None:
            for record in dns_answer:
                print("[debug] '%s' record found for %s: %s" % (rdtype, value, record.address))

        return dns_answer

    def check_presence_of_wildcard_dns(self):
        """
        Check the presence of wildcard DNS entries in the Microsoft DNS server.

        This function queries the Microsoft DNS server to find wildcard DNS entries in the DomainDnsZones of the specified domain.
        It retrieves information about wildcard DNS entries and prints a warning message if any are found.

        Returns:
            dict: A dictionary containing information about wildcard DNS entries found in the Microsoft DNS server.
        """
        
        ldap_server, ldap_session = init_ldap_session(
            auth_domain=self.auth_domain,
            auth_dc_ip=self.auth_dc_ip,
            auth_username=self.auth_username,
            auth_password=self.auth_password,
            auth_lm_hash=self.auth_lm_hash,
            auth_nt_hash=self.auth_nt_hash,
            use_ldaps=self.use_ldaps
        )

        target_dn = "CN=MicrosoftDNS,DC=DomainDnsZones," + ldap_server.info.other["rootDomainNamingContext"][0]

        ldapresults = list(ldap_session.extend.standard.paged_search(target_dn, "(&(objectClass=dnsNode)(dc=\\2A))", attributes=["distinguishedName", "dNSTombstoned"]))

        results = {}
        for entry in ldapresults:
            if entry['type'] != 'searchResEntry':
                continue
            results[entry['dn']] = entry["attributes"]

        if len(results.keys()) != 0:
            print("[!] WARNING! Wildcard DNS entries found, dns resolution will not be consistent.")
            for dn, data in results.items():
                fqdn = re.sub(',CN=MicrosoftDNS,DC=DomainDnsZones,DC=DOMAIN,DC=local$', '', dn)
                fqdn = '.'.join([dc.split('=')[1] for dc in fqdn.split(',')])

                ips = self.resolve(fqdn)

                if data["dNSTombstoned"]:
                    print("  | %s ──> %s (set to be removed)" % (dn, ips))
                else:
                    print("  | %s ──> %s" % (dn, ips))

                # Cache found wildcard dns
                for ip in ips:
                    if fqdn not in self.__wildcard_dns_cache.keys():
                        self.__wildcard_dns_cache[fqdn] = {}
                    if ip not in self.__wildcard_dns_cache[fqdn].keys():
                        self.__wildcard_dns_cache[fqdn][ip] = []
                    self.__wildcard_dns_cache[fqdn][ip].append(data)
            print()
        return results


def STYPE_MASK(stype_value):
    known_flags = {
        ## One of the following values may be specified. You can isolate these values by using the STYPE_MASK value.
        # Disk drive.
        "STYPE_DISKTREE": 0x0,

        # Print queue.
        "STYPE_PRINTQ": 0x1,

        # Communication device.
        "STYPE_DEVICE": 0x2,

        # Interprocess communication (IPC).
        "STYPE_IPC": 0x3,

        ## In addition, one or both of the following values may be specified.
        # Special share reserved for interprocess communication (IPC$) or remote administration of the server (ADMIN$).
        # Can also refer to administrative shares such as C$, D$, E$, and so forth. For more information, see Network Share Functions.
        "STYPE_SPECIAL": 0x80000000,

        # A temporary share.
        "STYPE_TEMPORARY": 0x40000000
    }
    flags = []
    if (stype_value & 0b11) == known_flags["STYPE_DISKTREE"]:
        flags.append("STYPE_DISKTREE")
    elif (stype_value & 0b11) == known_flags["STYPE_PRINTQ"]:
        flags.append("STYPE_PRINTQ")
    elif (stype_value & 0b11) == known_flags["STYPE_DEVICE"]:
        flags.append("STYPE_DEVICE")
    elif (stype_value & 0b11) == known_flags["STYPE_IPC"]:
        flags.append("STYPE_IPC")
    if (stype_value & known_flags["STYPE_SPECIAL"]) == 0:
        flags.append("STYPE_SPECIAL")
    if (stype_value & known_flags["STYPE_TEMPORARY"]) == 0:
        flags.append("STYPE_TEMPORARY")
    return flags


def export_json(options, results):
    print("[>] Exporting results to %s ... " % options.export_json, end="")
    sys.stdout.flush()
    basepath = os.path.dirname(options.export_json)
    filename = os.path.basename(options.export_json)
    if basepath not in [".", ""]:
        if not os.path.exists(basepath):
            os.makedirs(basepath)
        path_to_file = basepath + os.path.sep + filename
    else:
        path_to_file = filename
    f = open(path_to_file, "w")
    f.write(json.dumps(results, indent=4) + "\n")
    f.close()
    print("done.")


def export_xlsx(options, results):
    print("[>] Exporting results to %s ... " % options.export_xlsx, end="")
    sys.stdout.flush()
    basepath = os.path.dirname(options.export_xlsx)
    filename = os.path.basename(options.export_xlsx)
    if basepath not in [".", ""]:
        if not os.path.exists(basepath):
            os.makedirs(basepath)
        path_to_file = basepath + os.path.sep + filename
    else:
        path_to_file = filename
    workbook = xlsxwriter.Workbook(path_to_file)
    worksheet = workbook.add_worksheet()

    if options.check_user_access:
        # Checking access rights
        header_format = workbook.add_format({'bold': 1})
        header_fields = ["Computer FQDN", "Computer IP", "Share name", "Share comment", "Is hidden", "UNC Path", "Readable", "Writable"]
        for k in range(len(header_fields)):
            worksheet.set_column(k, k + 1, len(header_fields[k]) + 3)
        worksheet.set_row(0, 20, header_format)
        worksheet.write_row(0, 0, header_fields)

        row_id = 1
        for computername in results.keys():
            computer = results[computername]
            for share in computer:
                data = [
                    share["computer"]["fqdn"],
                    share["computer"]["ip"],
                    share["share"]["name"],
                    share["share"]["comment"],
                    share["share"]["hidden"],
                    share["share"]["uncpath"],
                    share["share"]["access_rights"]["readable"],
                    share["share"]["access_rights"]["writable"]
                ]
                worksheet.write_row(row_id, 0, data)
                row_id += 1
        worksheet.autofilter(0, 0, row_id, len(header_fields) - 1)
        workbook.close()
    else:
        # Not checking access rights
        header_format = workbook.add_format({'bold': 1})
        header_fields = ["Computer FQDN", "Computer IP", "Share name", "Share comment", "Is hidden", "UNC Path"]
        for k in range(len(header_fields)):
            worksheet.set_column(k, k + 1, len(header_fields[k]) + 3)
        worksheet.set_row(0, 20, header_format)
        worksheet.write_row(0, 0, header_fields)

        row_id = 1
        for computername in results.keys():
            computer = results[computername]
            for share in computer:
                data = [
                    share["computer"]["fqdn"],
                    share["computer"]["ip"],
                    share["share"]["name"],
                    share["share"]["comment"],
                    share["share"]["hidden"],
                    share["share"]["uncpath"],
                ]
                worksheet.write_row(row_id, 0, data)
                row_id += 1
        worksheet.autofilter(0, 0, row_id, len(header_fields) - 1)
        workbook.close()
    print("done.")


def export_sqlite(options, results):
    print("[>] Exporting results to %s ... " % options.export_sqlite, end="")
    sys.stdout.flush()
    basepath = os.path.dirname(options.export_sqlite)
    filename = os.path.basename(options.export_sqlite)
    if basepath not in [".", ""]:
        if not os.path.exists(basepath):
            os.makedirs(basepath)
        path_to_file = basepath + os.path.sep + filename
    else:
        path_to_file = filename

    conn = sqlite3.connect(path_to_file)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS shares(fqdn VARCHAR(255), ip VARCHAR(255), shi1_netname VARCHAR(255), shi1_remark VARCHAR(255), shi1_type INTEGER, hidden INTEGER);")
    for computername in results.keys():
        for share in results[computername]:
            cursor.execute("INSERT INTO shares VALUES (?, ?, ?, ?, ?, ?)", (
                    share["computer"]["fqdn"],
                    share["computer"]["ip"],
                    share["share"]["name"],
                    share["share"]["comment"],
                    share["share"]["type"]["stype_value"],
                    share["share"]["hidden"]
                )
            )
    conn.commit()
    conn.close()
    print("done.")


def is_port_open(target, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        # Non-existant domains cause a lot of errors, added error handling
        try:
            return s.connect_ex((target, port)) == 0
        except Exception as e:
            return False


def dns_resolve(options, target_name):
    dns_resolver = dns.resolver.Resolver()
    if options.nameserver is not None:
        dns_resolver.nameservers = [options.nameserver]
    else:
        dns_resolver.nameservers = [options.dc_ip]
    dns_answer = None

    # Try UDP
    try:
        dns_answer = dns_resolver.resolve(target_name, rdtype="A", tcp=False)
    except dns.resolver.NXDOMAIN:
        # the domain does not exist so dns resolutions remain empty
        pass
    except dns.resolver.NoAnswer as e:
        # domains existing but not having AAAA records is common
        pass
    except dns.resolver.NoNameservers as e:
        pass
    except dns.exception.DNSException as e:
        pass

    if dns_answer is None:
        # Try TCP
        try:
            dns_answer = dns_resolver.resolve(target_name, rdtype="A", tcp=True)
        except dns.resolver.NXDOMAIN:
            # the domain does not exist so dns resolutions remain empty
            pass
        except dns.resolver.NoAnswer as e:
            # domains existing but not having AAAA records is common
            pass
        except dns.resolver.NoNameservers as e:
            pass
        except dns.exception.DNSException as e:
            pass

    target_ip = []
    if dns_answer is not None:
        target_ip = [ip.address for ip in dns_answer]

    if len(target_ip) != 0:
        return target_ip[0]
    else:
        return None


def parseArgs():
    print("FindUncommonShares v%s - by @podalirius_\n" % VERSION)

    parser = argparse.ArgumentParser(add_help=True, description="Find uncommon SMB shares on remote machines.")

    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode. (default: False).")

    parser.add_argument("--use-ldaps", default=False, action="store_true", help="Use LDAPS instead of LDAP.")
    parser.add_argument("-q", "--quiet", dest="quiet", action="store_true", default=False, help="Show no information at all.")
    parser.add_argument("--debug", dest="debug", action="store_true", default=False, help="Debug mode. (default: False).")
    parser.add_argument("-no-colors", dest="colors", action="store_false", default=True, help="Disables colored output mode.")
    parser.add_argument("-t", "--threads", dest="threads", action="store", type=int, default=20, required=False, help="Number of threads (default: 20).")
    parser.add_argument("-l", "--ldap-query", dest="ldap_query", type=str, default="(objectCategory=computer)", required=False, help="LDAP query to use to extract computers from the domain.")
    parser.add_argument("-ns", "--nameserver", dest="nameserver", default=None, required=False, help="IP of the DNS server to use, instead of the --dc-ip.")

    # Shares
    shares = parser.add_argument_group("Shares")
    shares.add_argument("--check-user-access", default=False, action="store_true", help="Check if current user can access the share.")
    shares.add_argument("--readable", default=False, action="store_true", help="Only list shares that current user has READ access to.")
    shares.add_argument("--writable", default=False, action="store_true", help="Only list shares that current user has WRITE access to.")
    shares.add_argument("-iH", "--ignore-hidden-shares", dest="ignore_hidden_shares", action="store_true", default=False, help="Ignores hidden shares (shares ending with $)")
    shares.add_argument("-iP", "--ignore-print-queues", dest="ignore_print_queues", action="store_true", default=False, help="Ignores print queues (shares of STYPE_PRINTQ)")
    shares.add_argument("-i", "--ignore-share", default=[], dest="ignored_shares", action="append", required=False, help="Specify shares to ignore explicitly. (e.g., --ignore-share \"C$\" --ignore-share \"Backup\")")
    shares.add_argument("-s", "--show-share", default=[], dest="accepted_shares", action="append", required=False, help="Specify shares to show explicitly. (e.g., --show-share \"C$\" --show-share \"Backup\")")

    output = parser.add_argument_group("Output files")
    output.add_argument("--export-xlsx", dest="export_xlsx", type=str, default=None, required=False, help="Output XLSX file to store the results in.")
    output.add_argument("--export-json", dest="export_json", type=str, default=None, required=False, help="Output JSON file to store the results in.")
    output.add_argument("--export-sqlite", dest="export_sqlite", type=str, default=None, required=False, help="Output SQLITE3 file to store the results in.")

    authconn = parser.add_argument_group("Authentication & connection")
    authconn.add_argument("--dc-ip", required=True, action="store", metavar="ip address", help="IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter")
    authconn.add_argument("-d", "--domain", dest="auth_domain", metavar="DOMAIN", action="store", default="", help="(FQDN) domain to authenticate to")
    authconn.add_argument("-u", "--user", dest="auth_username", metavar="USER", action="store", default="", help="user to authenticate with")

    secret = parser.add_argument_group("Credentials")
    cred = secret.add_mutually_exclusive_group()
    cred.add_argument("--no-pass", default=False, action="store_true", help="Don't ask for password (useful for -k)")
    cred.add_argument("-p", "--password", dest="auth_password", metavar="PASSWORD", action="store", default=None, help="Password to authenticate with")
    cred.add_argument("-H", "--hashes", dest="auth_hashes", action="store", metavar="[LMHASH:]NTHASH", help="NT/LM hashes, format is LMhash:NThash")
    cred.add_argument("--aes-key", dest="auth_key", action="store", metavar="hex key", help="AES key to use for Kerberos Authentication (128 or 256 bits)")
    secret.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help="Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.auth_password is None and options.no_pass == False and options.auth_hashes is None:
        print("[+] No password of hashes provided and --no-pass is '%s'" % options.no_pass)
        from getpass import getpass
        if options.auth_domain is not None:
            options.auth_password = getpass("  | Provide a password for '%s\\%s':" % (options.auth_domain, options.auth_username))
        else:
            options.auth_password = getpass("  | Provide a password for '%s':" % options.auth_username)

    if options.readable == True or options.writable == True:
        options.check_user_access = True

    return options


def print_results(options, shareData):
    str_access_readable, str_colored_access_readable = "", ""
    str_access_writable, str_colored_access_writable = "", ""
    str_access, str_colored_access = "", ""
    if options.check_user_access:
        if shareData["share"]["access_rights"]["readable"] == True:
            str_access_readable = "READ"
            str_colored_access_readable = "\x1b[1;92mREAD\x1b[0m"
        if shareData["share"]["access_rights"]["writable"] == True:
            str_access_writable = "WRITE"
            str_colored_access_writable = "\x1b[1;92mWRITE\x1b[0m"
        if shareData["share"]["access_rights"]["readable"] == False and shareData["share"]["access_rights"]["writable"] == False:
            str_access = "access: DENIED"
            str_colored_access = "access: \x1b[1;91mDENIED\x1b[0m"
        elif shareData["share"]["access_rights"]["readable"] == True and shareData["share"]["access_rights"]["writable"] == True:
            str_access = "access: %s, %s" % (str_access_readable, str_access_writable)
            str_colored_access = "access: %s, %s" % (str_colored_access_readable, str_colored_access_writable)
        elif shareData["share"]["access_rights"]["readable"] == False and shareData["share"]["access_rights"]["writable"] == True:
            str_access = "access: %s" % str_access_writable
            str_colored_access = "access: %s" % str_colored_access_writable
        elif shareData["share"]["access_rights"]["readable"] == True and shareData["share"]["access_rights"]["writable"] == False:
            str_access = "access: %s" % str_access_readable
            str_colored_access = "access: %s" % str_colored_access_readable


    do_print_results = False
    # Print all results
    if options.readable == False and options.writable == False:
        do_print_results = True
    # Print results for readable shares
    if options.readable == True:
        if shareData["share"]["access_rights"]["readable"] == True:
            do_print_results = True
        else:
            do_print_results = False
    # Print results for writable shares
    if options.writable == True:
        if shareData["share"]["access_rights"]["writable"] == True:
            do_print_results = True
        else:
            do_print_results = False

    if (shareData["share"]["name"] in COMMON_SHARES):
        # Ignore this common share
        do_print_results = False
    if shareData["share"]["name"].endswith('$') and options.ignore_hidden_shares:
        # Do not print hidden shares
        do_print_results = False
    if ("STYPE_PRINTQ" in shareData["share"]["stype_flags"]) and options.ignore_hidden_shares:
        # Do not print hidden shares
        do_print_results = False
    if (shareData["share"]["name"] in options.ignored_shares):
        # Ignore this specific share from the deny list
        do_print_results = False
    if (shareData["share"]["name"] in options.accepted_shares):
        # Accept this specific share from the deny list
        do_print_results = True

    if do_print_results:
        if not options.quiet:
            # Share has a comment
            if len(shareData["share"]["comment"]) != 0:
                if options.colors:
                    # Hidden share
                    if shareData["share"]["name"].endswith('$') and not options.ignore_hidden_shares:
                        print("[>] Found '\x1b[94m%s\x1b[0m' on '\x1b[96m%s\x1b[0m' (comment: '\x1b[95m%s\x1b[0m') %s" % (shareData["share"]["name"], shareData["computer"]["fqdn"], shareData["share"]["comment"], str_colored_access))
                    # Not hidden share
                    else:
                        print("[>] Found '\x1b[93m%s\x1b[0m' on '\x1b[96m%s\x1b[0m' (comment: '\x1b[95m%s\x1b[0m') %s" % (shareData["share"]["name"], shareData["computer"]["fqdn"], shareData["share"]["comment"], str_colored_access))
                else:
                    # Default uncolored print 
                    print("[>] Found '%s' on '%s' (comment: '%s') %s" % (shareData["share"]["name"], shareData["computer"]["fqdn"], shareData["share"]["comment"], str_access))
            
            # Share has no comment
            else:
                if options.colors:
                    # Hidden share
                    if shareData["share"]["name"].endswith('$') and not options.ignore_hidden_shares:
                        print("[>] Found '\x1b[94m%s\x1b[0m' on '\x1b[96m%s\x1b[0m' %s" % (shareData["share"]["name"], shareData["computer"]["fqdn"], str_colored_access))
                    # Not hidden share
                    else:
                        # Default uncolored print 
                        print("[>] Found '\x1b[93m%s\x1b[0m' on '\x1b[96m%s\x1b[0m' %s" % (shareData["share"]["name"], shareData["computer"]["fqdn"], str_colored_access))
                else:
                    # Hidden share
                    if shareData["share"]["name"].endswith('$') and not options.ignore_hidden_shares:
                        print("[>] Found '%s' on '%s' %s" % (shareData["share"]["name"], shareData["computer"]["fqdn"], str_access))
                    # Not hidden share
                    else:
                        # Default uncolored print 
                        print("[>] Found '%s' on '%s' %s" % (shareData["share"]["name"], shareData["computer"]["fqdn"], str_access))
        else:
            # Quiet mode, do not print anything
            pass
    
    # Debug mode in case of a common share
    elif options.debug and not options.quiet:
        # Share has a comment
        if len(shareData["share"]["comment"]) != 0:
            # Colored output
            if options.colors:
                # Hidden share
                if shareData["share"]["name"].endswith('$') and not options.ignore_hidden_shares:
                    print("[>] Skipping common share '\x1b[94m%s\x1b[0m' on '\x1b[96m%s\x1b[0m' (comment: '\x1b[95m%s\x1b[0m') %s" % (shareData["share"]["name"], shareData["computer"]["fqdn"], shareData["share"]["comment"], str_colored_access))
                # Not hidden share
                else:
                    # Default uncolored print 
                    print("[>] Skipping common share '\x1b[93m%s\x1b[0m' on '\x1b[96m%s\x1b[0m' (comment: '\x1b[95m%s\x1b[0m') %s" % (shareData["share"]["name"], shareData["computer"]["fqdn"], shareData["share"]["comment"], str_colored_access))
            # Not colored output
            else:
                # Default uncolored print 
                print("[>] Skipping common share '%s' on '%s' (comment: '%s') %s" % (shareData["share"]["name"], shareData["computer"]["fqdn"], shareData["share"]["comment"], str_access))

        # Share has no comment
        else:
            # Colored output
            if options.colors:
                # Hidden share
                if shareData["share"]["name"].endswith('$') and not options.ignore_hidden_shares:
                    print("[>] Skipping hidden share '\x1b[94m%s\x1b[0m' on '\x1b[96m%s\x1b[0m' %s" % (shareData["share"]["name"], shareData["computer"]["fqdn"], str_colored_access))
                # Not hidden share
                else:
                    # Default uncolored print 
                    print("[>] Skipping common share '\x1b[93m%s\x1b[0m' on '\x1b[96m%s\x1b[0m' %s" % (shareData["share"]["name"], shareData["computer"]["fqdn"], str_colored_access))

            # Not colored output
            else:
                # Hidden share
                if shareData["share"]["name"].endswith('$') and not options.ignore_hidden_shares:
                    print("[>] Skipping hidden share '%s' on '%s' %s" % (shareData["share"]["name"], shareData["computer"]["fqdn"], str_access))
                # Not hidden share
                else:
                    # Default uncolored print 
                    print("[>] Skipping common share '%s' on '%s' %s" % (shareData["share"]["name"], shareData["computer"]["fqdn"], str_access))


def get_machine_name(options, domain):
    if options.dc_ip is not None:
        s = SMBConnection(options.dc_ip, options.dc_ip)
    else:
        s = SMBConnection(domain, domain)
    try:
        s.login('', '')
    except Exception:
        if s.getServerName() == '':
            raise Exception('Error while anonymous logging into %s' % domain)
    else:
        s.logoff()
    return s.getServerName()


def get_access_rights(smbclient, sharename):
    access_rights = {"readable": False, "writable": False}
    try:
        smbclient.listPath(sharename, '*', password=None)
        access_rights["readable"] = True
    except SessionError as e:
        access_rights["readable"] = False

    try:
        temp_dir = ntpath.normpath("\\" + ''.join([random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPRSTUVWXYZ0123456759") for k in range(16)]))
        smbclient.createDirectory(sharename, temp_dir)
        smbclient.deleteDirectory(sharename, temp_dir)
        access_rights["writable"] = True
    except SessionError as e:
        access_rights["writable"] = False

    return access_rights


def init_smb_session(options, target_ip, domain, username, password, address, lmhash, nthash, port=445, debug=False):
    smbClient = SMBConnection(address, target_ip, sess_port=int(port))
    dialect = smbClient.getDialect()
    if dialect == SMB_DIALECT:
        if debug:
            print("[debug] SMBv1 dialect used")
    elif dialect == SMB2_DIALECT_002:
        if debug:
            print("[debug] SMBv2.0 dialect used")
    elif dialect == SMB2_DIALECT_21:
        if debug:
            print("[debug] SMBv2.1 dialect used")
    else:
        if debug:
            print("[debug] SMBv3.0 dialect used")
    if options.use_kerberos is True:
        smbClient.kerberosLogin(username, password, domain, lmhash, nthash, options.aesKey, options.dc_ip)
    else:
        smbClient.login(username, password, domain, lmhash, nthash)
    if smbClient.isGuestSession() > 0:
        if debug:
            print("[debug] GUEST Session Granted")
    else:
        if debug:
            print("[debug] USER Session Granted")
    return smbClient


def worker(options, target_name, domain, username, password, address, lmhash, nthash, results, lock):
    target_ip = dns_resolve(options, target_name)
    if target_ip is not None:
        if is_port_open(target_ip, 445):
            try:
                smbClient = init_smb_session(options, target_ip, domain, username, password, address, lmhash, nthash)
                resp = smbClient.listShares()
                for share in resp:
                    # SHARE_INFO_1 structure (lmshare.h)
                    # https://docs.microsoft.com/en-us/windows/win32/api/lmshare/ns-lmshare-share_info_1
                    sharename = share['shi1_netname'][:-1]
                    sharecomment = share['shi1_remark'][:-1]
                    sharetype = share['shi1_type']

                    access_rights = {"readable": False, "writable": False}
                    if options.check_user_access:
                        access_rights = get_access_rights(smbClient, sharename)

                    lock.acquire()
                    if target_name not in results.keys():
                        results[target_name] = []
                    
                    shareData = {
                        "computer": {
                            "fqdn": target_name,
                            "ip": target_ip
                        },
                        "share": {
                            "name": sharename,
                            "comment": sharecomment,
                            "hidden": (True if sharename.endswith('$') else False),
                            "uncpath": "\\".join(['', '', target_ip, sharename, '']),
                            "type": {
                                "stype_value": sharetype,
                                "stype_flags": STYPE_MASK(sharetype)
                            },
                            "access_rights": access_rights
                        }
                    }

                    results[target_name].append(shareData)

                    print_results(options=options, shareData=shareData)

                    lock.release()

            except Exception as err:
                if options.debug:
                    lock.acquire()
                    print(err)
                    lock.release()

    # DNS Resolution failed
    else:
        if options.debug:
            lock.acquire()
            print("[!] Could not resolve '%s'" % target_name)
            lock.release()


if __name__ == '__main__':
    options = parseArgs()

    # Parse hashes
    if options.auth_hashes is not None:
        if ":" not in options.auth_hashes:
            options.auth_hashes = ":" + options.auth_hashes
    auth_lm_hash, auth_nt_hash = parse_lm_nt_hashes(options.auth_hashes)
    
    # Use AES Authentication key if available
    if options.auth_key is not None:
        options.use_kerberos = True
    if options.use_kerberos is True and options.kdcHost is None:
        print("[!] Specify KDC's Hostname of FQDN using the argument --kdcHost")
        exit()

    try:
        mdns = MicrosoftDNS(
            dnsserver=options.dc_ip,
            auth_domain=options.auth_domain,
            auth_username=options.auth_username,
            auth_password=options.auth_password,
            auth_dc_ip=options.dc_ip,
            auth_lm_hash=auth_lm_hash,
            auth_nt_hash=auth_nt_hash,
            use_ldaps=options.use_ldaps,
            verbose=options.verbose
        )
        mdns.check_presence_of_wildcard_dns()

        if not options.quiet:
            print("[>] Extracting all computers ...")

        computers = raw_ldap_query(
            auth_domain=options.auth_domain,
            auth_dc_ip=options.dc_ip,
            auth_username=options.auth_username,
            auth_password=options.auth_password,
            auth_hashes=options.auth_hashes,
            query=options.ldap_query,
            use_ldaps=options.use_ldaps,
            attributes=["dNSHostName", "sAMAccountName"]
        )

        if not options.quiet:
            print("[+] Found %d computers in the domain. \n" % len(computers.keys()))
            print("[>] Enumerating shares ...")

        results = {}

        if len(computers.keys()) != 0:
            # Setup thread lock to properly write in the file
            lock = threading.Lock()
            # Waits for all the threads to be completed
            with ThreadPoolExecutor(max_workers=min(options.threads, len(computers.keys()))) as tp:
                for ck in computers.keys():
                    computer = computers[ck]
                    tp.submit(
                        worker,
                        options,
                        computer['dNSHostName'],
                        options.auth_domain,
                        options.auth_username,
                        options.auth_password,
                        computer['dNSHostName'],
                        auth_lm_hash,
                        auth_nt_hash,
                        results,
                        lock
                    )

            if options.export_json is not None:
                export_json(options, results)

            if options.export_xlsx is not None:
                export_xlsx(options, results)

            if options.export_sqlite is not None:
                export_sqlite(options, results)
        else:
            print("[!] No computers in the domain found matching filter '%s'" % options.ldap_query)
        print("[+] Bye Bye!")

    except Exception as e:
        if options.debug:
            traceback.print_exc()
        print("[!] Error: %s" % str(e))
