# krbHash
Script to calculate Active Directory Kerberos keys (AES256 and AES128 'ekeys') and NT hash for an account, using its plaintext password (as printable string or hex string). 

Much of the original logic is based on [Get-KerberosAESKey.ps1](https://gist.github.com/Kevin-Robertson/9e0f8bfdbf4c1e694e6ff4197f0a4372)

## Usage
```bash
usage: krbHash.py [-h] --domain DOMAIN --user USER (--pass PASSWORD | --hex-pass HEX_PASS) [--is-machine]
                  [--iterations ITERATIONS]

Generate NT and AES128/256 Kerberos keys (ekeys) for an AD account using a plaintext password

options:
  -h, --help            show this help message and exit
  --domain DOMAIN, -d DOMAIN
                        FQDN of the domain
  --user USER, -u USER  sAMAccountName - this is case sensitive for user accounts (usually all lowercase). Do not
                        include $ for machine accounts.
  --pass PASSWORD, -p PASSWORD
                        Cleartext account password
  --hex-pass HEX_PASS, -x HEX_PASS
                        Password as a hex string, in UTF-16LE format (probably default if you got this from a dump)
  --is-machine, -m      Target is a machine account, not a user account
  --iterations ITERATIONS, -i ITERATIONS
                        Iterations to perform for PBKDF2; only used for testing against reference examples
```

## Examples
*AD user account names (sAMAccountName) are case sensitive, usually all lowercase.* Machine account names are not, and will be auto-converted to all lowercase. 

Calculate keys for a AD user account:
```
./krbHash.py -d domain.local -u matt -p Password1
```

Calculate keys for an AD computer (machine) account using the plaintext hex password:
```
./krbHash.py -d domain.local -u laptop123 -m -x 0a2b3c...
```

Use Impacket's `getTGT.py` with a resulting AES key to obtain a TGT:
```
getTGT.py domain.local/matt -aesKey <AES256/128 key>
```