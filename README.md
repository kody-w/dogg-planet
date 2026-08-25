# dogg-planet — a federated node of the global tick network

**The planet, per tick: earthquakes, space weather, the GB grid's carbon intensity, the ISS, and the temperature in four world cities.**

This repo keeps its own append-only chain of rapp/1 frames in `planet/`. Every half
hour a GitHub Action reads the current tick anchor from the spine at
[kody-w/dogg](https://github.com/kody-w/dogg) and appends one frame of this node's
outlook, referencing that tick — so this chain joins every other node's data on the
same clock. "Right now" APIs only serve the present; the network keeps every present.

**Verify it yourself:** `python3 tools/verify_thread.py` re-checks every frame with the
reference implementation from [kody-w/rapp-1](https://github.com/kody-w/rapp-1). CI runs
the same oracle on every push.

**Start your own node:** fork this repo, edit `THEME` / `STREAM` / `SOURCES` at the top
of `tools/collect.py` (keyless https APIs, small factual payloads, numbers as strings),
and enable the scheduled workflow. Your chain, your outlook, same clock — announce it on
the spine's registry ([kody-w/dogg](https://github.com/kody-w/dogg) issues) so agents
can find it.

## Trust

<!--trust-->
No ratings yet — used this chain? [Rate it](../../issues/new?template=rate.yml): valid ratings publish automatically as verifiable frames.
<!--/trust-->
