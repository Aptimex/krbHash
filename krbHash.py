#!/usr/bin/env python3

# Modified from https://github.com/Tw1sm/aesKrbKeyGen
# Useful references:
# https://gist.github.com/mgeeky/852032f9736384466db40fe1ae27d4e3 (reference implementation)
# https://datatracker.ietf.org/doc/html/rfc3962 (section B contains test cases)

#pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Protocol import KDF
from Crypto.Hash import MD4
from binascii import unhexlify
import argparse


# Constants
AES256_CONSTANT = [0x6B,0x65,0x72,0x62,0x65,0x72,0x6F,0x73,0x7B,0x9B,0x5B,0x2B,0x93,0x13,0x2B,0x93,0x5C,0x9B,0xDC,0xDA,0xD9,0x5C,0x98,0x99,0xC4,0xCA,0xE4,0xDE,0xE6,0xD6,0xCA,0xE4]
AES128_CONSTANT = AES256_CONSTANT[:16]
IV = bytearray([0x00] * 16)


def do_aes_256(aes_256_pbkdf2):
    cipher = AES.new(aes_256_pbkdf2, AES.MODE_CBC, bytes(IV))
    key_1 = cipher.encrypt(bytes(AES256_CONSTANT))

    cipher = AES.new(aes_256_pbkdf2, AES.MODE_CBC, bytes(IV))
    key_2 = cipher.encrypt(bytearray(key_1))

    aes_256_raw = key_1[:16] + key_2[:16]
    return aes_256_raw.hex().upper()


def do_aes_128(aes_128_pbkdf2):
    cipher = AES.new(aes_128_pbkdf2, AES.MODE_CBC, bytes(IV))
    aes_128_raw = cipher.encrypt(bytes(AES128_CONSTANT))
    return aes_128_raw.hex().upper()

def  do_nt_hash(data):
    cipher = MD4.new()
    cipher.update(data)
    return cipher.hexdigest().upper()


def main(args):
    domain = args.domain.upper()
    if args.is_machine:
        host = args.user.replace('$', '') # ensure $ is not present in hostname
        salt = f'{domain}host{host.lower()}.{domain.lower()}'
    else:
        salt = f'{domain}{args.user}'

    print(f'[*] Salt: {salt}')

    if args.hex_pass:
        print("Parsing password as hex string")
        try:
            password_bytes8 = unhexlify(args.hex_pass).decode('utf-16-le', 'replace').encode('utf-8', 'replace')
            password_bytes16 = unhexlify(args.hex_pass)
        except Exception as e:
            print(f"Unable to parse supplied password as hex: {e}")
            return
        
    else:
        print("Parsing password as plaintext string")
        password_bytes8 = args.password.encode('utf-8')
        password_bytes16 = args.password.encode('utf-16-le')

    salt_bytes = salt.encode('utf-8')

    aes_256_pbkdf2 = KDF.PBKDF2(password_bytes8, salt_bytes, 32, args.iterations)
    aes_128_pbkdf2 = aes_256_pbkdf2[:16]


    nt_hash = do_nt_hash(password_bytes16)
    aes_256_key = do_aes_256(aes_256_pbkdf2)
    aes_128_key = do_aes_128(aes_128_pbkdf2)

    print()
    print(f'[+] NT Hash: {nt_hash}')
    print(f'[+] AES128 Key: {aes_128_key}')
    print(f'[+] AES256 Key: {aes_256_key}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate NT and AES128/256 Kerberos keys (ekeys) for an AD account using a plaintext password', formatter_class=argparse.RawDescriptionHelpFormatter)
    pwGroup = parser.add_mutually_exclusive_group(required=True)

    parser.add_argument('--domain', "-d", type=str, help='FQDN of the domain', required=True)
    parser.add_argument('--user', "-u", type=str, help='sAMAccountName - this is case sensitive for user accounts (usually all lowercase). Do not include $ for machine accounts.', required=True)
    pwGroup.add_argument('--pass', "-p", type=str, dest='password', help='Cleartext account password')
    pwGroup.add_argument('--hex-pass', "-x", type=str, help='Password as a hex string, in UTF-16LE format (probably default if you got this from a dump)')
    parser.add_argument('--is-machine', "-m", action='store_true', help='Target is a machine account, not a user account')
    parser.add_argument('--iterations', "-i", type=int, help='Iterations to perform for PBKDF2; only used for testing against reference examples', default=4096)

    args = parser.parse_args()
    main(args)
