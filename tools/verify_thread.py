#!/usr/bin/env python3
"""CI oracle: re-verify EVERY frame chain in this repo (any dir with a HEAD.json)."""
import json, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import rapp as R
root = pathlib.Path(__file__).parent.parent
fail = False
for headf in sorted(root.glob("*/HEAD.json")):
    d = headf.parent
    meta = json.loads(headf.read_text())
    head = None
    for i in range(meta["count"]):
        f = json.loads((d/f"{i}.json").read_text())
        ok, step, why = R.verify_frame(f, head=head, stream_id_of_record=meta["stream_id"])
        if not ok:
            print(f"FAIL {d.name}/{i}: {step}: {why}"); fail = True; break
        head = f
    else:
        assert head["frame_hash"] == meta["head_frame"], f"{d.name} HEAD mismatch"
        print(f"OK: {d.name} — {meta['count']} frames verify on {meta['stream_id'][:44]}…")
sys.exit(1 if fail else 0)
