+++
title = "Documentation"
description = "How dream-net carries events between authenticated peers, how to host a server and a client, the limits that bound its memory, and its complete Rust API."
template = "docs/section.html"
page_template = "docs/page.html"
sort_by = "weight"

[extra]
docs_root = true
docs_project_name = "dream-net"
docs_short_title = "dream-net docs"
docs_project_path = "@/home/index.md"
docs_repository_url = "https://github.com/DreamWeave-MP/dream-net/tree/main/content/docs"
docs_sidebar_label = "Documentation"
hide_child_cards = true
kind = "guide"
+++

dream-net carries events between a server and its clients: opaque payloads, each with an event id
from a shared schema, on a channel that is either reliable and ordered or neither. A host drives it
once per frame and polls what arrived. Everything else, from what an event means to who may send
it, belongs to the engine above.

## Learn it

- **[Start here](@/docs/start-here.md)**: a server and a client in one program, from the schema to
  the first reply.
- **[How it fits together](@/docs/how-it-works.md)**: the layers, one frame, the handshake, and
  what each delivery class promises.

## Use it

- **[Schemas and events](@/docs/schemas.md)**: declaring channels and events, how ids and the
  fingerprint are made, and what both ends must agree on.
- **[Channels and packets](@/docs/channels.md)**: windows, resends, overflow policies, packet
  budgets, aggregation and large events.
- **[Servers and clients](@/docs/hosts.md)**: keys and connect tokens, the frame loop, lifecycle
  events, peers, sending and disconnecting.
- **[Memory and backpressure](@/docs/memory.md)**: the limits on every queue, what happens when
  one is full, and what a connection can be made to hold.
- **[Protocol captures](@/docs/captures.md)**: recording what crossed the host boundary, and
  reading it back.
- **[Connections and the simulator](@/docs/simulator.md)**: driving a `Connection` without
  sockets, over seeded lossy links.

## Look it up

- **[Wire format](@/docs/wire.md)**: the bits of a connection packet, and what the decoder refuses.
- **[Compatibility and performance](@/docs/compatibility.md)**: versions, the supported Rust, the
  license, what is tested, and benchmark numbers.
- **[Rust API](@/docs/api/_index.md)**: every public type, function and constant.
