# Vault, a simple KMS solution based on macOS keychain

this program will have several subcommands as below:

- serve: start a https server which will interact with system keychain for encryption/decryption
- init: initialize a gpg keypair, a passphrase which will be used by server
- encrypt: will read plain text and output encrypted message for you
- run: replace encrypted environment variables as plaintext and run program
- inject: replace encrypted string in a file with plaintext

