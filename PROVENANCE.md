# Provenance

This repository is a personal fork of
[`JonTheNiceGuy/bwenv`](https://github.com/JonTheNiceGuy/bwenv).

- Upstream revision: `88a1cdcc2791f2570794bce51f682d15f573f3b5`
- Upstream license: Unlicense (`UNLICENSE`)
- Upstream remote: `https://github.com/JonTheNiceGuy/bwenv.git`

This fork replaces the previous resolver path with a fail-closed,
Vaultwarden-oriented implementation. It removes debug output containing command
output, item metadata, value previews, session characteristics, and raw
Bitwarden errors. Resolved values are only emitted by the explicit `read`,
`run`, or `inject` operation requested by the operator.
