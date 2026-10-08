<!-- retired-notice:start -->
> **Retired experiment, kept for reference.** The living project is [kody-w/RAPP](https://github.com/kody-w/RAPP).
<!-- retired-notice:end -->

# dogg-planet — a federated node of the global tick network

<!-- rapp1:network-header:start -->
[![RAPP/1](https://kody-w.github.io/rapp-hive-public/portfolio/badges/dogg-planet.svg)](https://github.com/kody-w/rapp-hive-public/blob/main/portfolio/repos/dogg-planet.md) · **New to RAPP?** [Start here: get your Brainstem →](https://github.com/kody-w/rapp-installer#start-here)
<!-- rapp1:network-header:end -->

**The planet, per tick: earthquakes, space weather, the GB grid's carbon intensity, the ISS, and the temperature in four world cities.**

This repo keeps its own append-only chain of rapp/1 frames in `planet/`. Every half
hour a GitHub Action reads the current tick anchor from the spine at
[kody-w/dogg](https://github.com/kody-w/dogg) and appends one frame of this node's
outlook, referencing that tick — so this chain joins every other node's data on the
same clock. "Right now" APIs only serve the present; the network keeps every present.

**Verify it yourself:** `python3 tools/verify_thread.py` re-checks every frame with the
reference implementation from [kody-w/rapp-1](https://github.com/kody-w/rapp-1). CI runs
the same oracle on every push.

## Signed RAPP/1 projection

[`dogg-rapp1-bridge/2`](BRIDGE2.md) defines a forward-only continuous
`memory.save` projection of the unchanged native `planet/` chain. Each signed
frame binds exact immutable planet provenance here and exact tick provenance
from a separately supplied canonical
[`kody-w/dogg`](https://github.com/kody-w/dogg) commit. No signing schedule is
enabled until the owner configures external key custody, persistent state, a
protected-main registry checkpoint, and an out-of-band trust anchor.

**Start your own node:** fork this repo, edit `THEME` / `STREAM` / `SOURCES` at the top
of `tools/collect.py` (keyless https APIs, small factual payloads, numbers as strings),
and enable the scheduled workflow. Your chain, your outlook, same clock — announce it on
the spine's registry ([kody-w/dogg](https://github.com/kody-w/dogg) issues) so agents
can find it.

## Trust

<!--trust-->
No ratings yet — used this chain? [Rate it](../../issues/new?template=rate.yml): valid ratings publish automatically as verifiable frames.
<!--/trust-->
