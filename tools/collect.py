#!/usr/bin/env python3
"""A federated tick-network node: this repo's own append-only chain, keyed to the
global tick spine at kody-w/dogg.

Every run reads the spine's current tick anchor, takes this node's themed snapshot of
keyless public APIs, and appends one frame referencing that tick. Different repos, run
by different people, each with their own outlook — all joinable on the tick key. To
start your own node: fork this repo, edit THEME/STREAM/SOURCES below, enable the
scheduled workflow. Frames verify with the reference implementation (tools/rapp.py,
from kody-w/rapp-1); CI re-verifies the whole chain on every push.
"""
import json, sys, pathlib, datetime, urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import rapp as R

ROOT = pathlib.Path(__file__).resolve().parent.parent
SPINE_HEAD = "https://raw.githubusercontent.com/kody-w/dogg/main/ticks/HEAD.json"
TIMEOUT = 8

# ---- edit these three for your node -------------------------------------------------
THEME = "planet"                     # also the data directory name
STREAM = "planet:@kody-w/dogg-planet"                   # your stream id (your repo, your name)
# SOURCES: name -> zero-arg callable returning a SMALL dict of facts.
# rapp/1 canonical hashing forbids floats: numeric facts ride as strings or ints.
# -------------------------------------------------------------------------------------

def utc():
    n = datetime.datetime.now(datetime.timezone.utc)
    return n.strftime("%Y-%m-%dT%H:%M:%S.") + f"{n.microsecond // 1000:03d}Z"

def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": f"tick-node-{THEME}"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode())

CITIES = {"tokyo": ("35.68","139.69"), "london": ("51.51","-0.13"),
          "new_york": ("40.71","-74.01"), "sydney": ("-33.87","151.21")}

def _temp(lat, lon):
    d = get(f"https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}&current=temperature_2m")
    return f"{d['current']['temperature_2m']:.1f}"

SOURCES = {
    "earthquakes_past_day": lambda: (lambda g: {"count": len(g["features"]),
        "max_mag": (lambda m: f"{max(m):.1f}" if m else None)(
            [f["properties"]["mag"] for f in g["features"] if f["properties"]["mag"] is not None])})(
        get("https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_day.geojson")),
    "space_weather": lambda: (lambda last: {"kp": str(last["Kp"] if isinstance(last, dict) else last[1])})(
        get("https://services.swpc.noaa.gov/products/noaa-planetary-k-index.json")[-1]),
    "grid_carbon_gb": lambda: (lambda i: {"gco2_kwh": int(i["actual"] or i["forecast"]), "index": i["index"]})(
        get("https://api.carbonintensity.org.uk/intensity")["data"][0]["intensity"]),
    "iss": lambda: (lambda d: {"lat": f"{float(d['latitude']):.3f}", "lon": f"{float(d['longitude']):.3f}"})(
        get("https://api.wheretheiss.at/v1/satellites/25544")),
    "city_temps_c": lambda: {name: _temp(*ll) for name, ll in CITIES.items()},
}

def load_chain(d):
    if not (d / "HEAD.json").exists():
        return []
    count = json.loads((d / "HEAD.json").read_text())["count"]
    return [json.loads((d / f"{i}.json").read_text()) for i in range(count)]

def main():
    spine = get(SPINE_HEAD)
    tick_n, tick_hash = spine["count"] - 1, spine["head_frame"]
    d = ROOT / THEME
    d.mkdir(exist_ok=True)
    chain = load_chain(d)
    head = chain[-1] if chain else None
    if head is not None and head["payload"].get("tick") == tick_n:
        print(f"{THEME}: tick {tick_n} already recorded — nothing to do")
        return
    data, failed = {}, []
    for name, fn in SOURCES.items():
        try:
            data[name] = fn()
        except Exception:
            failed.append(name)
    payload = {"tick": tick_n, "tick_frame": tick_hash, "spine": "kody-w/dogg",
               "fetched_utc": utc(), THEME: data, "sources_failed": failed}
    if head is None:
        payload["about"] = (f"A federated node of the global tick network: this repo's "
                            f"own {THEME} outlook, one frame per observed tick, keyed to "
                            "the spine's tick anchors so it joins every other node's "
                            "data on the same clock.")
    f = R.build_frame(f"{THEME}.snapshot", STREAM, (head["seq"] + 1) if head else 0,
                      utc(), payload, prev=(head["payload_hash"] if head else None))
    ok, step, why = R.verify_frame(f, head=head, stream_id_of_record=STREAM)
    if not ok:
        raise ValueError(f"refusing invalid frame: {step}: {why}")
    (d / f"{f['seq']}.json").write_text(json.dumps(f, indent=2, ensure_ascii=False) + "\n")
    (d / "HEAD.json").write_text(json.dumps({"count": f["seq"] + 1, "stream_id": STREAM,
        "head_frame": f["frame_hash"], "updated": utc()}, indent=2) + "\n")
    print(f"{THEME} frame {f['seq']} @ spine tick {tick_n}: {', '.join(data) or 'nothing'}"
          + (f" (failed: {', '.join(failed)})" if failed else ""))

if __name__ == "__main__":
    main()
