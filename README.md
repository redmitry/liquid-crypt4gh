# Liquid Crypt4GH

Liquid Crypt4GH is a Java implementation of the GA4GH File Encryption Standard in a form of pluggable JSR-203 NIO.2 File System.

## Branches:

- TAG 0.0.1   - initial commit
- master      - latest releases (0.0.1) + changes that don't affect code (e.g. docs)
- dev         - next version snapshot (0.0.2-SNAPSHOT)

## Command-line tool usage

The library may be used as a command-line tool providng a simple functionality to encrypt / decrypt files.

### Key generation

The tool provides Ed25519 keys generation, similar to the OpenSSL command:  
`openssl genpkey -algorithm ED25519 -aes256 -pass pass:12345 -out alice.p8`

Generate EdDSA (ed25519) keys pair **alce.p8** and **alice.pem** in PKCS#8 and X.509 formats:  
`java -jar liquid-crypt4gh.jar -k -o alice`  
or which is the same:  
`java -jar liquid-crypt4gh.jar -k -sk alice.p8 -pk alice.pem`

Generate **alice.p8** private key protected with a password ('12345'):  
`java -jar liquid-crypt4gh.jar -k -o alice -p 12345`

Generate **alice.pem** public key from the **alce.p8** private key:  
`java -jar liquid-crypt4gh.jar -k pub -sk alice.p8`

### Key conversion

The tool allows conversion from ed25519/x25519 PKCS8 to the Crypt4GH private and from X.509 to Crypt4GH public key formats:

Convert **alice.p8** private key to the Crypt4GH format:  
`java -jar liquid-crypt4gh.jar -c alice.p8`  

Convert **alice.pem** public key to the Crypt4GH format:  
`java -jar liquid-crypt4gh.jar -c alice.pem -o alice.pub`  

### Files encryption and decryption

To encrypt or decrypt files users must provide at least the private key in either PKCS8 or Crypt4GH format.

Encrypt **crypt4gh.pdf** file using **alice.p8** private key:  
`java -jar liquid-crypt4gh.jar -e crypt4gh.pdf -sk alice.p8`  

Encrypt **crypt4gh.pdf** file for **bob** using **alice.p8** private key and **bob.pem** public key:  
`java -jar liquid-crypt4gh.jar -e crypt4gh.pdf -sk alice.p8 -pk bob.pem`  

Decrypt **crypt4gh.pdf.c4gh** file encrypted for **bob** with **bob.p8** private key:  
`java -jar liquid-crypt4gh.jar -d crypt4gh.pdf.c4gh -sk bob.p8 -o decrypted.pdf`

## Liquid Crypt4GH File System

The Liquid Crypt4GH may be integrated either as a default file system or as a pluggable one.  
The file system security keys are passed either via environment variables or as parameters passed to the java virtual machine.  

- CRYPT4GH_PRIVATE_KEY_FILE - mandatory property for the path to a private key used for encryption / decryption.
- CRYPT4GH_PUBLIC_KEY_FILE  - optional property for the path to a public key of the encryption destination user (no property means no files will be encrypted).
- CRYPT4GH_PASSPHRASE       - private key password (if private key itself is encrypted). only passed as an vm parameter.

To enable the Liquid Crypt4GH as default filesystem:  
`-Djava.nio.file.spi.DefaultFileSystemProvider=es.bsc.inb.ga4gh.jcrypt4gh.fs.Crypt4ghFileSystemProvider`

To include the Liquid Crypt4GH filesystem in the project the `META-INF/services/` directory must contain `java.nio.file.spi.FileSystemProvider` file with `es.bsc.inb.ga4gh.jcrypt4gh.fs.Crypt4ghFileSystemProvider` content.

##  Crypt4GH Keys

Crypt4GH uses Edwards Curve 25519 (x25519) keys for encryption / decryption its header keys.  
Liquid Crypt4GH supports either the proprietary Crypt4GH or standard PKCS8 keys (x25519 or ed25519).
The python Crypt4GH tool supports either the proprietary Crypt4GH or the old proprietary OpenSSH key formats.

### Key generation

#### Crypt4GH Key generator

Python Crypt4GH distribution comes with Crypt4GH key generator utility that generates x25519 ( Curve 25519) private and public pair of keys:
```bash
crypt4gh-keygen --sk alice.sec --pk alice.pub
```
The generated keys are in proprietary [Crypt4GH Key Format](https://crypt4gh.readthedocs.io/en/latest/keys.html).

```text
-----BEGIN CRYPT4GH PRIVATE KEY-----
BASE64 encoded Crypt4GH private key
-----END CRYPT4GH PRIVATE KEY-----
```
```text
-----BEGIN CRYPT4GH PUBLIC KEY-----
BASE64 encoded raw x25519 (256 bits) public key
-----END CRYPT4GH PUBLIC KEY-----
```

#### OpenSSH Key generator

Python Crypt4GH encryption utility also supports OpenSSH custom format keys that are in ed25519 format.


```bash
ssh-keygen -t ed25519 -f alice
```

```text
-----BEGIN OPENSSH PRIVATE KEY-----
BASE64 encoded proprietary OPEN
-----END OPENSSH PRIVATE KEY-----
```

#### OpenSSL Key generator

OpenSSL tool also allows Edwards Curve 25519 keys generation in various formats:

Generating ed25519 encrypted (AES-256) private key in PKCS8 format (password: 'alice'):
```bash
openssl genpkey -algorithm ED25519 -aes256 -pass pass:12345 -out alice.p8
```

```text
-----BEGIN ENCRYPTED PRIVATE KEY-----
BASE64 encoded private key in PKCS8 (ASN.1 DER) format encrypted with AES-256 (password protected)
-----END ENCRYPTED PRIVATE KEY-----
```

Generating ed25519 PKCS8 public key from the private key:
```bash
openssl pkey -in alice.p8 -passin pass:12345 -pubout -out alice.pem
```

```text
-----BEGIN PUBLIC KEY-----
BASE64 encoded public key in PKCS8 (ASN.1 DER) format
-----END PUBLIC KEY-----
```

Note that because OpenSSL ED25519 keys are in fact EdDSA keys (the public key is generated from the SHA256/512 private key hash), The conversion from Crypt4GH into the OpenSSL keys is impossible. Nethertheless, ED25519 keys may be converted to the Crypt4GH ones.
