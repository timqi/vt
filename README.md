# Vault, a simple KMS solution based on macOS keychain

this program will have several subcommands as below:

- serve: start a https server which will interact with system keychain for encryption/decryption
- init: initialize a gpg keypair, a passphrase which will be used by server
- encrypt: will read plain text and output encrypted message for you
- run: replace encrypted environment variables as plaintext and run program

# Secret management

It'll create two secrets when do initialize, called `passcode` and `passphrase`. The `passcode` is a random string which will derive a secret used for encrypting the `passphrase`. The `passphrase` is the real cipher key used in production to do the encryption and decryption. The plain `passcode` and encrypted `passphrase` will be created and saved in macOS keychain when run `vt init`. The `auth_token` is also created when run `vt init`. `VT_AUTH` environment variable as auth_token will be read by `vt` and set in http header for authorization and body encrypt usage.

The `vt` command is managing user interface which provide encrypt/decrypt and run command. The process do the real work is a server run by `vt serve`. `vt` command is communicating with this server to provide vault abilities. Vault server has restrict permission limitations, you should ensure these environment to keep vault server running well.

1. run `vt serve` from the same user which do the `vt init`
2. keep `vt` executable binary located in the same absolute path when do the `vt init`

# vt protocol

`vt://{location}/{data}?t={type}`

- location: mac/1p/yubikey which location will the secrets be stored, only mac supported for mac
- data: encrypted data
- type: raw(default), totp which will decrypt as a totp token