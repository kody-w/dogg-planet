# Native `planet:@kody-w/dogg-planet` → RAPP/1

`dogg-rapp1-bridge/2` is a subordinate operational profile over frozen RAPP/1.
It continuously projects the existing native DOGG/0 `planet/` chain into a
keyed, signed RAPP/1 memory stream. It does not modify, rewrite, relabel, or
replace native DOGG/0. It defines neither DOGG/1 nor a delivery endpoint.

## Two immutable native authorities

The bridge accepts two separate exact Git repositories:

| Purpose | Exact origin | Chain |
|---|---|---|
| Planet records | `https://github.com/kody-w/dogg-planet.git` | `planet/` |
| Tick anchors | `https://github.com/kody-w/dogg.git` | `ticks/` |

Both roots must be exact Git top-level directories. Both explicit commits must
equal their checkout's `HEAD`, resolve as SHA-1 commits, and be on
`refs/remotes/origin/main`. Every Git command disables replacement objects.
Replacement refs, grafts, shallow history, Git repository overrides, and Git
ancestry-override environment are refused in either repository.

Before minting a frame, the bridge reads both complete chains from the selected
immutable commit trees. It applies the existing `tools/chainio.py` storage
contract and verifies every native record with the unchanged native
`tools/rapp.py` oracle. `HEAD.json`, flat records, and sealed epochs must be
ordinary `100644` blobs. Mutable worktree bytes are never provenance.

Native records are bounded at 1 MiB. `epoch_size` is bounded to `1..288`.
Sealed epoch blobs are streamed with a bound of
`epoch_size * (1 MiB + 1)`: exactly the declared number of nonempty,
LF-terminated, UTF-8 JSON records, each no larger than 1 MiB. Flat records use
the 1 MiB whole-blob bound.

Every planet frame's actual `payload.tick_frame` must resolve at
`payload.tick` in the separately verified tick chain. The anchor must have
stream `tick:@kody-w/global`, kind `tick.anchor`, and `payload.tick == seq`.
The bridge never substitutes a newer anchor or treats similarly named data in
the planet repository as tick authority.

## Exact signed projection

Each output is an ordinary RAPP/1 frame with exactly the frozen eleven keys:

- `spec: "rapp/1"` and exact kind `memory.save`;
- `stream_id: "<keyed-estate-owner-rappid>:dogg-bridge"`;
- contiguous RAPP and native sequence numbers beginning at zero;
- ordinary particle/wave links, `prev_wave: null`;
- a non-null detached, unencoded owner JWS in `sig`; and
- a payload with exactly `profile`, `native_source`, `tick_frame`, and
  `tick_source`.

`profile` is exactly `dogg-rapp1-bridge/2`. `native_source` and `tick_source`
each have exactly:

| Member | Meaning |
|---|---|
| `repository` | Exact repository URL from the table above |
| `commit` | Immutable full SHA-1 commit containing that record |
| `chain_path` | Exact native chain directory |
| `storage_path` / `storage_line` | Flat file and `null`, or sealed bundle and one-based line |
| `raw_sha256` / `raw_bytes` | Digest and size of exact native record octets |
| `native_stream_id` | Original native stream, unchanged |
| `native_genesis_frame_hash` | Verified native chain genesis |
| `native_seq` / `native_frame_hash` / `native_utc` | Exact verified record tuple |

Flat raw octets include original formatting and terminator. Sealed raw octets
exclude the bundle's LF delimiter. For every planet projection `tick_frame` is
the exact native value and `tick_source` is non-null, repository-bound tick
provenance from the separately supplied tick commit.

RAPP sequence `N` projects planet sequence `N`. Cold start projects genesis
through the verified planet head; later runs append only the missing suffix.
Before any further minting, every retained frame reverifies both its historical
planet commit and its historical tick commit, both complete native chains,
exact storage locations/raw bytes, oracle results, and retention in the current
canonical-main descendants.

## Registry and trust root

The owner-signed canonical JCS registry has exact profile
`dogg-rapp1-bridge-registry/1`. Its `canonical_source` is exactly:

```json
{"path":"<safe relative path>","ref":"refs/remotes/origin/main","repository":"https://github.com/kody-w/dogg-planet.git"}
```

The initial registry binds:

1. the keyed estate owner and public SPKI;
2. canonical `rapp/1` and its normative SPEC digest;
3. this exact profile path and raw digest in the planet repository;
4. `memory.save` to the `memory` family; and
5. the bridge stream's registered genesis.

The whole registry is owner-signed. Registry sequences begin at zero and are
contiguous. Rollback, same-sequence fork, gap, removed/rewritten entry prefix,
changed registered genesis, and changed native genesis refuse.

The registry bytes must be read from the configured path at an immutable
protected-main checkpoint in the planet repository. The checkpoint and planet
source commit must both be on canonical main, and the checkpoint must be an
ancestor of that planet source commit. The estate-owner RAPPID must arrive
independently through `--trust-anchor` or
`DOGG_RAPP1_BRIDGE_TRUST_ANCHOR`.

The canonical RAPP implementation is vendored byte-for-byte under
`tools/rapp1_bridge_v2_vendor/` from
`kody-w/rapp-1@dda32d741c7218f41443a5bd17eebfe0eae82cb7`.
`PROVENANCE.json` pins every imported file. The bridge imports that
canonicalizer and registry checker rather than retyping JCS.

## Owner initialization

Requirements are Git, Python 3.12+, and OpenSSL with P-256. No network call is
made. State, outputs, registry candidates, and the private key must be outside
both repositories and pairwise disjoint. The private key's parent must be
owner-held mode `0700`; the key is create-only, owner-held `0600`, regular,
single-link, and no-follow. Only `generate-key` creates a key.

```sh
PLANET_COMMIT=$(GIT_NO_REPLACE_OBJECTS=1 git --no-replace-objects rev-parse HEAD)
TICK_ROOT=/exact/path/to/dogg
TICK_COMMIT=$(GIT_NO_REPLACE_OBJECTS=1 git -C "$TICK_ROOT" --no-replace-objects rev-parse HEAD)

python3 tools/rapp1_bridge_v2.py generate-key \
  --source-root . --tick-source-root "$TICK_ROOT" \
  --out "$HOME/.dogg-private/dogg-planet-rapp1-bridge.pem"

python3 tools/rapp1_bridge_v2.py init \
  --source-root . --source-revision "$PLANET_COMMIT" \
  --tick-source-root "$TICK_ROOT" --tick-source-commit "$TICK_COMMIT" \
  --main-ref refs/remotes/origin/main --chain planet \
  --owner kody-w --slug dogg-planet-rapp1-bridge \
  --canonical-registry-path rapp1-bridge-v2/registry.json \
  --state "$HOME/.dogg-private/planet-bridge-v2-state" \
  --registry-out "$HOME/.dogg-private/planet-registry-0.json" \
  --signing-key "$HOME/.dogg-private/dogg-planet-rapp1-bridge.pem"
```

Initialization creates one candidate genesis and registry once; it grants no
authority. The owner must separately:

1. publish the exact registry candidate bytes at the declared path on protected
   planet `main`;
2. retain that immutable commit as the registry checkpoint;
3. custody the private key and persistent controller/output state externally;
4. distribute the printed trust-anchor RAPPID out of band; and
5. choose and monitor immutable canonical-main planet and tick commits for each
   append.

## Continuous append and verification

No signing schedule is enabled by this change. Do not enable one until owner
key, trust anchor, protected-main checkpoint, both exact source checkouts, and
persistent state/output are configured.

```sh
test -n "${DOGG_RAPP1_BRIDGE_SIGNING_KEY:-}"
test -n "${DOGG_RAPP1_BRIDGE_TRUST_ANCHOR:-}"
test -n "${DOGG_RAPP1_BRIDGE_REGISTRY_CHECKPOINT:-}"

python3 tools/rapp1_bridge_v2.py append \
  --source-root . --source-revision "$PLANET_COMMIT" \
  --tick-source-root "$TICK_ROOT" --tick-source-commit "$TICK_COMMIT" \
  --main-ref refs/remotes/origin/main \
  --registry-checkpoint "$DOGG_RAPP1_BRIDGE_REGISTRY_CHECKPOINT" \
  --state "$DOGG_RAPP1_BRIDGE_STATE" --out "$DOGG_RAPP1_BRIDGE_OUTPUT"

python3 tools/rapp1_bridge_v2.py verify \
  --source-root . --source-revision "$PLANET_COMMIT" \
  --tick-source-root "$TICK_ROOT" --tick-source-commit "$TICK_COMMIT" \
  --main-ref refs/remotes/origin/main \
  --registry-checkpoint "$DOGG_RAPP1_BRIDGE_REGISTRY_CHECKPOINT" \
  --state "$DOGG_RAPP1_BRIDGE_STATE" --out "$DOGG_RAPP1_BRIDGE_OUTPUT"
```

One exclusive controller lock covers recovery, all validation, candidate
creation, every delivery, and head commit. State/output/key path checks include
inode, ancestor/descendant, symlink/mount-like, and supported case/Unicode
aliases across both source repositories.

Frames, registries, and content-addressed opaque blobs are crash-durable,
atomic, create-only objects. Unique temporary inodes are fsynced, linked
without replacement, and followed by directory fsync. Exact bytes are
idempotent; different bytes refuse. Durable pending heads recover only when all
bounded dependencies verify. Partial/conflicting evidence is preserved and
refused. Missing layout can be completed only before any accepted or pending
authority exists.

All head sequences are uint53 and additionally bounded to retained contiguous
object counts before recovery resolves references. Every accepted output object
must equal controller state byte-for-byte. Lagging outputs can catch up across
multiple registry sequences only after the complete registry prefix verifies.
Rollback, fork, gaps, stale or mismatched cross-repository tick commits,
non-fast-forward history, bad native paths/modes/raw bytes, wrong signatures or
signers, and high-water races all refuse.

## Integrity is not authenticity

Native hashes and Git object IDs prove byte integrity and history linkage, not
native writer identity or the truth of planet observations. Bridge signatures
authenticate the projection key, not DOGG authorship. Authenticity requires
both the signed protected-main registry checkpoint and the out-of-band owner
RAPPID. Registry and source freshness remain explicit owner policy.
