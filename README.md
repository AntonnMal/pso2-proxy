# PSO2 Proxy

Simple proxy for capturing PSO2 packets. Currently, it only works for the global version due to the hardcoded IP address.

## Usage

1) Compile.
```
cargo build
```
2) Transform Sega's key to PEM format:
```
openssl rsa -pubin -inform MS\ PUBLICKEYBLOB -in SEGAKey1.blob -outform PEM -out server_pubkey.pem
```
3) Run proxy once to generate private key or supply your own as `client_privkey.pem`.
4) Transform your private key to injector's compatible format.
```
# if using my rsa injector
openssl rsa -in client_privkey.pem -outform MS\ PUBLICKEYBLOB -pubout -out publicKey.blob
```
5) Run.

## Capturing traffic

Moved [here](https://github.com/PhantasyServer/pso2-protocol-lib/blob/master/ppac.md).
