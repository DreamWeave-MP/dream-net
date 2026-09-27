# dream-net

The networking substrate of the DreamWeave engine: secure client/server UDP, reliable-ordered
and unreliable-unordered event channels, and schema handshakes, built on the Más Bandwidth
[netcode](https://github.com/mas-bandwidth/netcode.rs),
[reliable](https://github.com/mas-bandwidth/reliable.rs) and
[serialize](https://github.com/mas-bandwidth/serialize.rs) crates.

**Transport truth in Rust. Network behaviour in Luau.** dream-net answers who is connected,
which authenticated peer sent which bytes, whether they arrived reliably and in order, and what
the connection statistics are. It never knows what an event means.

## Credits

Networking built on netcode, reliable and serialize by Más Bandwidth LLC
(<https://mas-bandwidth.com>). Their license notices are in [`NOTICE.md`](NOTICE.md) and must
travel with any product that ships dream-net.

## License

dream-net is licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT](LICENSE-MIT) at your option.
