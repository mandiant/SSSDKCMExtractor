# SSSDKCMExtractor

This tool will decrypt Kerberos Cache Manager (KCM) databases used by the System Security
Services Daemon (SSSD). Although older Red Hat Enterprise Linux distributions stored Kerberos caches in the /tmp directory, newer installations use the SSSD Kerberos Cache Manager instead.

The Kerberos caches are maintained in a TDB database (Samba Trivial Database).
By default, the database file is located at the path: 
/var/lib/sss/secrets/secrets.ldb

The database is parsable with the python-tdb or python3-tdb TDB library.

Kerberos payloads are encrypted with AES_256_CBC. The key used to encrypt
values in the database is present at:
/var/lib/sss/secrets/.secrets.mkey

(NOTE: Both files require root access to read. The secret key is marked
as hidden on the filesystem via the dot prefix).

## Requirements

Install the python-tdb or python3-tdb library using your distribution's package manager. 

Next, install pycrypto. pip install -r requirements.txt or pip install pycrypto

You must possess both the secrets.ldb TDB database and the master key
(.secrets.mkey) to use this tool.

## Usage
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey

Once the tool finishes parsing and decrypting the relevant database entries,
the raw Kerberos JSON payloads from the KCM are displayed.

We leave it as an exercise to the reader to convert these into a usable ticket file for pass-the-cache and pass-the-ticket operations.
