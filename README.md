![](.github/banner.png)

<p align="center">
    The script <a href="https://github.com/p0dalirius/FindUncommonShares/blob/main/FindUncommonShares.py">FindUncommonShares.py</a> is a Python equivalent of <a href="https://github.com/darkoperator/Veil-PowerView/">PowerView</a>'s <a href="https://github.com/darkoperator/Veil-PowerView/blob/master/PowerView/functions/Invoke-ShareFinder.ps1">Invoke-ShareFinder.ps1</a> allowing to quickly find uncommon shares in vast Windows Active Directory Domains.
    <br>
    <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/p0dalirius/FindUncommonShares">
    <a href="https://twitter.com/intent/follow?screen_name=podalirius_" title="Follow"><img src="https://img.shields.io/twitter/follow/podalirius_?label=Podalirius&style=social"></a>
    <a href="https://www.youtube.com/c/Podalirius_?sub_confirmation=1" title="Subscribe"><img alt="YouTube Channel Subscribers" src="https://img.shields.io/youtube/channel/subscribers/UCF_x5O7CSfr82AfNVTKOv_A?style=social"></a>
    <br>
</p>


## Features

 - [x] Only requires a **low privileges domain user account**.
 - [x] Automatically gets the list of all computers from the domain controller's LDAP.
 - [x] Ignore the hidden shares (ending with `$`) with `--ignore-hidden-shares`.
 - [x] Multithreaded connections to discover SMB shares.
 - [x] Export results in JSON with IP, name, comment, flags and UNC path with `--export-json <file.json>`.
 - [x] Export results in XLSX with IP, name, comment, flags and UNC path with `--export-xlsx <file.xlsx>`.
 - [x] Export results in SQLITE3 with IP, name, comment, flags and UNC path with `--export-sqlite <file.db>`.
 - [x] Iterate on LDAP result pages to get every computer of the domain, no matter the size.

## Usage

```              
$ ./FindUncommonShares.py -h
FindUncommonShares v2.6 - by @podalirius_

usage: FindUncommonShares.py [-h] [-v] [--use-ldaps] [-q] [--debug] [-no-colors] [-t THREADS] [-l LDAP_QUERY] [-ns NAMESERVER] [-I] [-i IGNORED_SHARES] [-s ACCEPTED_SHARES] [--export-xlsx EXPORT_XLSX] [--export-json EXPORT_JSON]
                             [--export-sqlite EXPORT_SQLITE] --dc-ip ip address [-d DOMAIN] [-u USER] [--no-pass | -p PASSWORD | -H [LMHASH:]NTHASH | --aes-key hex key] [-k]

Find uncommon SMB shares on remote machines.

options:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose mode. (default: False)
  --use-ldaps           Use LDAPS instead of LDAP
  -q, --quiet           Show no information at all.
  --debug               Debug mode. (default: False)
  -no-colors            Disables colored output mode
  -t THREADS, --threads THREADS
                        Number of threads (default: 20)
  -l LDAP_QUERY, --ldap-query LDAP_QUERY
                        LDAP query to use to extract computers from the domain.
  -ns NAMESERVER, --nameserver NAMESERVER
                        IP of the DNS server to use, instead of the --dc-ip.
  -I, --ignore-hidden-shares
                        Ignores hidden shares (shares ending with $)
  -i IGNORED_SHARES, --ignore-share IGNORED_SHARES
                        Specify shares to ignore explicitly. (e.g., --ignore-share 'C$' --ignore-share 'Backup')
  -s ACCEPTED_SHARES, --show-share ACCEPTED_SHARES
                        Specify shares to show explicitly. (e.g., --show-share 'C$' --show-share 'Backup')

Output files:
  --export-xlsx EXPORT_XLSX
                        Output XLSX file to store the results in.
  --export-json EXPORT_JSON
                        Output JSON file to store the results in.
  --export-sqlite EXPORT_SQLITE
                        Output SQLITE3 file to store the results in.

Authentication & connection:
  --dc-ip ip address    IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter
  -d DOMAIN, --domain DOMAIN
                        (FQDN) domain to authenticate to
  -u USER, --user USER  user to authenticate with

Credentials:
  --no-pass             Don't ask for password (useful for -k)
  -p PASSWORD, --password PASSWORD
                        Password to authenticate with
  -H [LMHASH:]NTHASH, --hashes [LMHASH:]NTHASH
                        NT/LM hashes, format is LMhash:NThash
  --aes-key hex key     AES key to use for Kerberos Authentication (128 or 256 bits)
  -k, --kerberos        Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line
```

## Examples :

```
$ ./FindUncommonShares.py -u 'user1' -d 'LAB.local' -p 'P@ssw0rd!' --dc-ip 192.168.2.1
FindUncommonShares v2.5 - by @podalirius_

[>] Extracting all computers ...
[+] Found 2 computers.

[>] Enumerating shares ...
[>] Found 'Users' on 'DC01.LAB.local'
[>] Found 'WeirdShare' on 'DC01.LAB.local' (comment: 'Test comment')
[>] Found 'AnotherShare' on 'PC01.LAB.local'
[>] Found 'Users' on 'PC01.LAB.local
$
```


Each JSON entry looks like this:

```json
{
    "computer": {
        "fqdn": "DC01.LAB.local",
        "ip": "192.168.1.1"
    },
    "share": {
        "name": "ADMIN$",
        "comment": "Remote Admin",
        "hidden": true,
        "uncpath": "\\\\192.168.1.46\\ADMIN$\\",
        "type": {
            "stype_value": 2147483648,
            "stype_flags": [
                "STYPE_DISKTREE",
                "STYPE_TEMPORARY"
            ]
        }
    }
}
```

## Demonstration

![](./.github/example.png)

## Credits

 - Feature suggested in [impacket issue #1176](https://github.com/SecureAuthCorp/impacket/issues/1176) by [@CaledoniaProject](https://github.com/CaledoniaProject)
