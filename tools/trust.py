#!/usr/bin/env python3
"""The trust chain: accessor feedback, published as verifiable frames.

An agent that used this node's data rates how reliable it was FOR ITS PROBLEM via the
'Rate this node' issue form. This tool (run by the trust workflow) parses the form,
appends one frame to trust/, and refreshes the score shown in the README — so good
chains earn standing on the network and weak ones read as noise. Fail closed: a body
that doesn't match the shape publishes nothing.

Env: ISSUE_NUMBER, ISSUE_AUTHOR, ISSUE_BODY, GITHUB_REPOSITORY.
"""
import json, os, re, sys, pathlib, datetime

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import rapp as R

ROOT = pathlib.Path(__file__).resolve().parent.parent
TRUST = ROOT / "trust"

def utc():
    n = datetime.datetime.now(datetime.timezone.utc)
    return n.strftime("%Y-%m-%dT%H:%M:%S.") + f"{n.microsecond // 1000:03d}Z"

def parse(body):
    """Issue-form bodies render as '### <Label>\\n\\n<value>' sections."""
    fields = {}
    for m in re.finditer(r"### ([^\n]+)\n+([^\n#][^\n]*(?:\n(?!###)[^\n]*)*)", body):
        fields[m.group(1).strip().lower()] = m.group(2).strip()
    out = {"accessor": fields.get("accessor"), "ticks": fields.get("ticks used"),
           "problem": fields.get("problem it was solving"),
           "note": (fields.get("note (optional)") or "").replace("_No response_", "")[:400]}
    score = fields.get("reliability score", "")
    if not (out["accessor"] and out["ticks"] and out["problem"] and score in {"1","2","3","4","5"}):
        return None
    out["score"] = int(score)
    return out

def load_chain(d):
    if not (d / "HEAD.json").exists():
        return []
    count = json.loads((d / "HEAD.json").read_text())["count"]
    return [json.loads((d / f"{i}.json").read_text()) for i in range(count)]

def refresh_readme(chain):
    scores = [f["payload"]["score"] for f in chain]
    avg = sum(scores) / len(scores)
    recent = [f["payload"] for f in chain[-3:]][::-1]
    lines = [f"**{avg:.1f} / 5** across {len(scores)} rating(s) — every rating is a "
             f"verifiable frame in [`trust/`](trust/).", ""]
    for p in recent:
        note = f" — “{p['note']}”" if p.get("note") else ""
        lines.append(f"- {p['score']}/5 by `{p['rated_by']}` for *{p['problem']}* (ticks {p['ticks']}){note}")
    block = "\n".join(lines)
    rd = ROOT / "README.md"
    t = rd.read_text()
    t = re.sub(r"<!--trust-->.*?<!--/trust-->", f"<!--trust-->\n{block}\n<!--/trust-->",
               t, flags=re.S)
    rd.write_text(t)

def main():
    rating = parse(os.environ.get("ISSUE_BODY", ""))
    if rating is None:
        print("SHAPE FAIL: body does not match the rating form — publishing nothing")
        sys.exit(78)   # neutral: workflow comments and stops
    TRUST.mkdir(exist_ok=True)
    chain = load_chain(TRUST)
    head = chain[-1] if chain else None
    repo = os.environ.get("GITHUB_REPOSITORY", "kody-w/" + ROOT.name)
    owner, name = repo.split("/", 1)
    stream = f"trust:@{owner}/{name}"
    payload = {"rated_by": os.environ.get("ISSUE_AUTHOR", "?"),
               "issue": int(os.environ.get("ISSUE_NUMBER", "0")),
               "accessor": rating["accessor"], "ticks": rating["ticks"],
               "problem": rating["problem"], "score": rating["score"],
               "note": rating["note"], "at": utc()}
    f = R.build_frame("trust.rating", stream, (head["seq"] + 1) if head else 0,
                      utc(), payload, prev=(head["payload_hash"] if head else None))
    ok, step, why = R.verify_frame(f, head=head, stream_id_of_record=stream)
    if not ok:
        raise ValueError(f"refusing invalid trust frame: {step}: {why}")
    (TRUST / f"{f['seq']}.json").write_text(json.dumps(f, indent=2, ensure_ascii=False) + "\n")
    (TRUST / "HEAD.json").write_text(json.dumps({"count": f["seq"] + 1, "stream_id": stream,
        "head_frame": f["frame_hash"], "updated": utc()}, indent=2) + "\n")
    refresh_readme(chain + [f])
    print(f"trust frame {f['seq']}: {payload['score']}/5 from {payload['rated_by']} "
          f"for '{payload['problem']}'")

if __name__ == "__main__":
    main()
