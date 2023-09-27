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
5) Run

## Capturing traffic

All packets are logged and saved in the ".pak" format. Here's what it looks like:


Header for version 3 (current):

| Field   | Type      | Notes                                                                    |
|---------|-----------|--------------------------------------------------------------------------|
| Header  | char[4]   | Always `PPAK`                                                            |
| Version | byte      | = 3                                                                      |
| Client  | byte      | 0 - Classic (generic) <br> 1 - NGS <br> 2 - NA <br> 3 - JP <br> 4 - Vita |
| Packets | Packet[_] | Format in the next table                                                 |

Header for version 2:

| Field   | Type      | Notes                    |
|---------|-----------|--------------------------|
| Header  | char[4]   | Always `PPAK`            |
| Version | byte      | = 2                      |
| Packets | Packet[_] | Format in the next table |

Packet format: 

| Field     | Type    | Notes                                          |
|-----------|---------|------------------------------------------------|
| Timestamp | u128    | Nanosecond since Unix epoch                    |
| Direction | byte    | 0 - Client -> Server <br> 1 - Server -> Client |
| Data size | u64     | Length of the following data                   |
| Data      | byte[_] | Full decrypted packet                          |

For hex viewing i recommend using ImHex and included here `packets.hexpat` pattern. Also you can break this archive into smaller ( and unknown ) packets using incuded `ppak_reader` ( but keep in mind that it was written very simply and might panic ): 

```
cargo run -- {packet_file_name}
```