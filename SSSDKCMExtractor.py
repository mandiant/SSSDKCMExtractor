"""
   SSSD Kerberos Database Decryption Tool
   Trevor Haskell <trevor.haskell@mandiant.com>
   Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
"""
import argparse
import base64
import hashlib
import hmac
import logging
import sys

from Crypto.Cipher import AES
import tdb

__version__ = '0.4.0'
_LOGGER = logging.getLogger('KCMKerbDecryptor.{}'.format(__version__))

AES_BLOCK_SIZE = 16
HMAC_LENGTH = 32


def decrypt_database(args):
    """Decrypt KCM Databases"""
    _LOGGER.debug("[*] Opening TDB database...")
    tdb_db = tdb.open(args.database[0])
    _LOGGER.debug("[*] Loading master key...")
    with open(args.key[0], 'rb') as f:
        tdb_db_key = f.read()
    _LOGGER.debug("[*] Printing TDB key values...")
    lookup_table = list()
    for key in tdb_db.keys():
        if key.decode('ascii', errors='ignore').startswith(('DN=CN=DEFAULT', 'DN=@BASEINFO', 'DN=CN=CCACHE')) is False:
            _LOGGER.debug(key)
            lookup_table.append(key)
    for key in lookup_table:
        _LOGGER.debug("[*] Currently processing key: %s", str(key))
        raw_key = tdb_db.get(key)
        secret = raw_key.decode('utf-8', errors='ignore').split('secret')[1].rsplit('\x00', 1)[0].rsplit('\x00', 1)[1]
        _LOGGER.debug("Stripped base64 payload: %s", secret)
        encrypted_secret = base64.b64decode(secret)
        signature = encrypted_secret[-HMAC_LENGTH:]
        hmac_input = encrypted_secret[:-HMAC_LENGTH]
        if hmac.new(tdb_db_key, hmac_input, hashlib.sha256).digest() != signature:
            _LOGGER.debug("HMAC Authentication Failed")
        else:
            _LOGGER.debug("HMAC Authentication Succeeded")
        iv_bytes = encrypted_secret[:AES_BLOCK_SIZE]
        encrypted_secret = encrypted_secret[AES_BLOCK_SIZE:]
        cipher_op = AES.new(tdb_db_key, AES.MODE_CBC, iv_bytes)
        decrypted_secret = cipher_op.decrypt(encrypted_secret)
        # This strips out characters that are not needed
        strip_length = len(decrypted_secret) - 33
        b64_kerberos_ticket = decrypted_secret[:strip_length]
        kerberos_ticket_json = base64.b64decode(b64_kerberos_ticket)
        print(kerberos_ticket_json.decode('utf-8'))


def parse_args():
    """Parses CLI Flags"""
    # pylint: disable=I0011,C0301
    parser = argparse.ArgumentParser(description="Decrypt SSSD Kerberos Databases.")
    parser.add_argument('--database', nargs=1, help='<Required> Specify path to SSSD Database File', required=True)
    parser.add_argument('--key', nargs=1, help='<Required> Specify path to SSSD Secret Key', required=True)
    parser.add_argument('--logging', default='info', action='store', required=False, help='Set logging verbosity')

    return parser.parse_args()


def main():
    """Initial Function"""
    args = parse_args()

    log_levels = {
        'debug': logging.DEBUG,
        'warn': logging.WARN,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'critical': logging.CRITICAL
    }
    log_fmt = '%(levelname) -8s %(asctime)s [%(filename)s %(lineno)d] %(funcName)s: %(message)s'
    _LOGGER.setLevel(log_levels.get(args.logging, logging.INFO))
    log_fh = logging.StreamHandler(stream=sys.stdout)
    log_fh.setFormatter(logging.Formatter(log_fmt))
    _LOGGER.addHandler(log_fh)
    decrypt_database(args)


if __name__ == '__main__':
    main()
