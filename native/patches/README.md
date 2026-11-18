# Local patches to vendored C

Every change dream-net makes to upstream C lives here as one git-style unified diff per
concern, never as an untracked edit under `vendor/`. Every vendored file not named by a patch
is byte-identical to upstream at its pin.

| Patch | File | Why |
| --- | --- | --- |
| `0001-netcode-server-port-zero-public-address.patch` | `netcode/netcode.c` | A server created on port 0 kept port 0 as its public address, so tokens naming the bound port failed the server-address check. Approved by the campaign director; not yet sent upstream. |

A patch:

- is named `NNNN-short-description.patch` and applied in the order `vendor/PROVENANCE.toml`
  lists it;
- uses paths relative to `native/vendor/` (`a/netcode/netcode.c`, `b/netcode/netcode.c`), so
  `git apply` run inside a pristine copy of the vendored tree reproduces `vendor/`;
- has a `[[patch]]` entry in `vendor/PROVENANCE.toml` with its `file`, `sha256`, `applies_to`
  and `reason`, and the `sha256` of every file it touches is updated there;
- names the upstream issue or pull request it was sent to, when it was.

`native/tools/verify-vendor --fetch` re-derives `vendor/` from upstream plus these patches and
fails on any difference.
