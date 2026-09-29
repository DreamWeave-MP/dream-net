+++
title = "Keys and tokens"
description = "generate_key, generate_connect_token, Key, UserData and their sizes, re-exported from netcode."
weight = 50

[extra]
kind = "api"
+++

netcode's items that dream-net's API mentions, re-exported from the root so a trusted backend can
mint keys and connect tokens with dream-net alone. Token minting belongs in trusted Rust tooling,
never in a client or a script.

{{ api_signature(value="type Key = [u8; KEY_BYTES]") }}

{{ api_signature(value="const KEY_BYTES: usize = 32") }}

A server's private key: 256 bits, which signs and encrypts connect tokens. `Server::new` borrows
it; nothing in dream-net hands it back.

{{ api_signature(value="fn generate_key() -> Key") }}

A new key from the operating system's secure random number generator. It panics only if that
generator fails.

{{ api_signature(value="type UserData = [u8; USER_DATA_BYTES]") }}

{{ api_signature(value="const USER_DATA_BYTES: usize = 256") }}

Opaque bytes a token carries to the server, readable there with `Server::client_user_data`: a
session id, an account id, whatever the backend wants the server to trust.

{{ api_signature(value="const CONNECT_TOKEN_BYTES: usize = 2048") }}

The size of a connect token, as `Client::connect` takes it.

{{ api_signature(value="fn generate_connect_token(public_server_addresses: &[SocketAddr], internal_server_addresses: &[SocketAddr], expire_seconds: i32, timeout_seconds: i32, client_id: u64, protocol_id: u64, private_key: &Key, user_data: &UserData) -> Result<[u8; CONNECT_TOKEN_BYTES], netcode::Error>") }}

Mints a connect token for one client, to be handed to it over a secure channel such as HTTPS.

| Argument | Meaning |
|---|---|
| `public_server_addresses` | The servers the client tries, in order: 1 to 32 |
| `internal_server_addresses` | What each server checks its own address against, inside the encrypted part. The same length; they differ from the public ones behind NAT or a load balancer |
| `expire_seconds` | How long the token is valid after it is made. Negative never expires, for development only |
| `timeout_seconds` | How long a connection may go without a packet before it is dropped. Negative never times out, for development only |
| `client_id` | The id the server reports in `Connected` and `client_id(peer)` |
| `protocol_id` | Must match the server's `ServerConfig::protocol_id` |
| `private_key` | The server's key |
| `user_data` | 256 bytes for the server |

The error is netcode's own `Error`: `InvalidServerAddresses` when the address lists are empty,
longer than 32, or of different lengths, and `EncryptFailed` if sealing the private part fails.
The same type appears inside dream-net's [`Error::Netcode`](@/docs/api/errors.md#error); to match
on its variants, depend on `netcode-official` at the version dream-net pins.
