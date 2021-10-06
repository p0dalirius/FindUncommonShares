# FindUncommonShares

![](.github/example.png)

The script [FindUncommonShares.py](https://github.com/p0dalirius/FindUncommonShares/FindUncommonShares.py) is a Python equivalent of [PowerView](https://github.com/darkoperator/Veil-PowerView/)'s [Invoke-ShareFinder.ps1](https://github.com/darkoperator/Veil-PowerView/blob/master/PowerView/functions/Invoke-ShareFinder.ps1)

## Usage

```
$ ./FindUncommonShares.py                                     
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

usage: FindUncommonShares.py [-h] [-xmlfile XMLFILE] [-share SHARE]
                             [-base-dir BASE_DIR] [-ts] [-debug]
                             [-hashes LMHASH:NTHASH] [-no-pass] [-k]
                             [-aesKey hex key] [-dc-ip ip address]
                             [-target-ip ip address]
                             [-port [destination port]]
                             target

Find uncommon SMB shares on remote machines

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

optional arguments:
  -h, --help            show this help message and exit
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters.
                        If valid credentials cannot be found, it will use the
                        ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)

connection:
  -dc-ip ip address     IP Address of the domain controller. If omitted it
                        will use the domain part (FQDN) specified in the
                        target parameter
  -target-ip ip address
                        IP Address of the target machine. If omitted it will
                        use whatever was specified as target. This is useful
                        when target is the NetBIOS name and you cannot resolve
                        it
  -port [destination port]
                        Destination port to connect to SMB Server
```

## Examples :

```
[]$ ./FindUncommonShares.py 'LAB.local/user1:PR123!@192.168.2.1' 
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

[>] Found uncommon shares!
 - 'Users'
 - 'WeirdShare'
[]$
```

## Credits

 - Feature suggested in [impacket issue #1176](https://github.com/SecureAuthCorp/impacket/issues/1176) by [@CaledoniaProject](https://github.com/CaledoniaProject)