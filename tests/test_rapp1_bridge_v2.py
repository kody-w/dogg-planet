#!/usr/bin/env python3
"""Signed continuous bridge/2 contracts; all native sources and keys are disposable."""
import copy
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
import unittest
from unittest import mock
import uuid


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import rapp1_bridge_v2 as B

WORK = ROOT.parent / ".dogg-planet-rapp1-v2-test-work"
NATIVE_PINS = {
    "tools/rapp.py": "c945ee85f01af5cd374490b40721d07f2aca7c8bd6d209e0d2933420f55db284",
    "tools/chainio.py": "9f9aec689112fcf0408dcd564ac0af4f974b0f6ce8aca18b0df3ec3ffd41e46d",
    "tools/verify_thread.py": "4a61d4091081f86b8afac0326221d77f6e4b8778c7c2f73bdb6c66a8281df2b0",
    "tools/collect.py": "b9364c8c5d2a6462d2b75fe7aa3828de98812f3f6bcb7345309016bb0988c6c8",
    "tools/trust.py": "8946811f8022b2c8a9924b001f85f8583c39a036fa127d34e27e112d53625610",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def concurrent_append_worker(arguments, entered, release, results):
    original = B.check_git_source
    first = True

    def gated(*args, **kwargs):
        nonlocal first
        if first:
            first = False
            entered.set()
            if not release.wait(15):
                raise RuntimeError("concurrency test gate timed out")
        return original(*args, **kwargs)

    try:
        with mock.patch.object(B, "check_git_source", side_effect=gated):
            report = B.append(*arguments)
        results.put(("ok", report))
    except (OSError, RuntimeError, TypeError, ValueError, subprocess.SubprocessError) as exc:
        results.put(("error", f"{type(exc).__name__}: {exc}"))


def crash_before_publish_worker(path):
    B.os.link = lambda *args, **kwargs: os._exit(73)
    B.write_new_or_equal(path, b"candidate-that-must-not-be-authoritative")


class Bridge2(unittest.TestCase):
    def setUp(self):
        WORK.mkdir(exist_ok=True)
        self.case = WORK / (self._testMethodName + "-" + uuid.uuid4().hex)
        self.case.mkdir(mode=0o700)
        self.repo = self.case / "repo"
        self.repo.mkdir()
        self.tick_repo = self.case / "tick-repo"
        self.tick_repo.mkdir()
        self.state = self.case / "state"
        self.output = self.case / "output"
        self.second_output = self.case / "output-2"
        self.key = self.case / "owner.pem"
        self.registry_candidate = self.case / "registry-0.json"
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Bridge Test")
        self.git("config", "user.email", "bridge@example.invalid")
        self.git("remote", "add", "origin", B.SOURCE_REPOSITORY)
        self.tick_git("init", "-b", "main")
        self.tick_git("config", "user.name", "Bridge Test")
        self.tick_git("config", "user.email", "bridge@example.invalid")
        self.tick_git("remote", "add", "origin", B.TICK_SOURCE_REPOSITORY)
        self.ticks = self.make_ticks(3)
        self.planet = self.make_planet(self.ticks)
        self.write_chain("ticks", self.ticks, repo=self.tick_repo)
        self.tick_commit("tick genesis through head")
        self.initial_tick_commit = self.tick_revision
        self.write_chain("planet", self.planet)
        self.commit("native genesis through head")
        self.initial_native_commit = self.revision
        B.generate_key(self.key, self.repo, self.tick_repo)
        initialized = B.initialize(
            self.repo, self.revision, self.tick_repo, self.tick_revision,
            "planet", B.CANONICAL_REF, "local", "dogg-planet-bridge",
            "rapp1-bridge-v2/registry.json", self.state,
            self.registry_candidate, self.key,
        )
        self.anchor = initialized["trust_anchor"]
        self.stream_id = initialized["stream_id"]
        (self.repo / "rapp1-bridge-v2").mkdir()
        shutil.copyfile(
            self.registry_candidate,
            self.repo / "rapp1-bridge-v2" / "registry.json",
        )
        self.commit("publish signed registry")
        self.registry_checkpoint = self.revision

    def tearDown(self):
        shutil.rmtree(self.case)
        if WORK.exists() and not any(WORK.iterdir()):
            WORK.rmdir()

    def git(self, *args, check=True):
        result = subprocess.run(
            ["git", *args], cwd=self.repo, capture_output=True, text=True
        )
        if check and result.returncode:
            self.fail(result.stderr)
        return result.stdout.strip()

    def tick_git(self, *args, check=True):
        result = subprocess.run(
            ["git", *args], cwd=self.tick_repo, capture_output=True, text=True
        )
        if check and result.returncode:
            self.fail(result.stderr)
        return result.stdout.strip()

    def commit(self, message):
        self.git("add", ".")
        self.git("commit", "-m", message)
        self.revision = self.git("rev-parse", "HEAD")
        self.git("update-ref", B.CANONICAL_REF, self.revision)
        return self.revision

    def tick_commit(self, message):
        self.tick_git("add", ".")
        self.tick_git("commit", "-m", message)
        self.tick_revision = self.tick_git("rev-parse", "HEAD")
        self.tick_git("update-ref", B.CANONICAL_REF, self.tick_revision)
        return self.tick_revision

    def make_ticks(self, count, first_payload=None):
        frames = []
        for seq in range(count):
            payload = {"tick": seq, "note": f"tick-{seq}"}
            if seq == 0 and first_payload is not None:
                payload = first_payload
            head = frames[-1] if frames else None
            frames.append(B.NATIVE_RAPP.build_frame(
                "tick.anchor", "tick:@kody-w/global", seq,
                f"2026-09-17T00:00:{seq:02d}.000Z", payload,
                None if head is None else head["payload_hash"],
            ))
        return frames

    def make_planet(self, ticks, note="planet"):
        frames = []
        for seq, tick in enumerate(ticks):
            payload = {
                "tick": seq,
                "tick_frame": tick["frame_hash"],
                "note": f"{note}-{seq}",
            }
            head = frames[-1] if frames else None
            frames.append(B.NATIVE_RAPP.build_frame(
                "planet.snapshot", "planet:@kody-w/dogg-planet", seq,
                f"2026-09-17T00:01:{seq:02d}.000Z", payload,
                None if head is None else head["payload_hash"],
            ))
        return frames

    def write_chain(self, name, frames, epoch_size=288, sealed_epochs=0,
                    repo=None):
        path = (repo or self.repo) / name
        if path.exists():
            shutil.rmtree(path)
        path.mkdir()
        sealed_count = epoch_size * sealed_epochs
        if sealed_epochs:
            (path / "epochs").mkdir()
        for epoch in range(sealed_epochs):
            values = frames[epoch * epoch_size:(epoch + 1) * epoch_size]
            raw = b"\n".join(
                json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
                for value in values
            ) + b"\n"
            (path / "epochs" / f"{epoch}.jsonl").write_bytes(raw)
        for seq in range(sealed_count, len(frames)):
            (path / f"{seq}.json").write_text(
                json.dumps(frames[seq], ensure_ascii=False, indent=2) + "\n"
            )
        (path / "HEAD.json").write_text(json.dumps({
            "count": len(frames),
            "stream_id": frames[-1]["stream_id"],
            "head_frame": frames[-1]["frame_hash"],
            "updated": frames[-1]["utc"],
            "epoch_size": epoch_size,
            "sealed_epochs": sealed_epochs,
        }, indent=2) + "\n")

    def append(self, outputs=None, revision=None, checkpoint=None,
               key=None, anchor=None, tick_revision=None):
        return B.append(
            self.repo, revision or self.revision, self.tick_repo,
            tick_revision or self.tick_revision, B.CANONICAL_REF,
            checkpoint or self.registry_checkpoint, self.state, outputs or [self.output],
            key or self.key,
            self.anchor if anchor is None else anchor,
        )

    def verify(self, output=None, revision=None, checkpoint=None, anchor=None,
               tick_revision=None):
        return B.verify_command(
            self.repo, revision or self.revision, self.tick_repo,
            tick_revision or self.tick_revision, B.CANONICAL_REF,
            checkpoint or self.registry_checkpoint, self.state, output or self.output,
            self.anchor if anchor is None else anchor,
        )

    def registry(self):
        return json.loads(
            (self.repo / "rapp1-bridge-v2" / "registry.json").read_bytes()
        )

    def publish_registry(self, doc, message):
        raw = B.canonical(doc)
        (self.repo / "rapp1-bridge-v2" / "registry.json").write_bytes(raw)
        checkpoint = self.commit(message)
        return checkpoint, raw

    def signed_registry(self, seq):
        prior = self.registry()
        spki = B.public_spki(self.key)
        return B.make_registry(
            prior["canonical_source"], self.anchor, spki, self.stream_id,
            prior["entries"][-1]["frame_hash"], self.key,
            registry_seq=seq, entries=prior["entries"],
        )

    def snapshot(self, path):
        return {
            item.relative_to(path).as_posix(): item.read_bytes()
            for item in path.rglob("*") if item.is_file()
        }

    @staticmethod
    def source_tuple(frame, chain_path, raw, repository):
        return {
            "repository": repository,
            "commit": "1" * 40,
            "chain_path": chain_path,
            "storage_path": f"{chain_path}/{frame['seq']}.json",
            "storage_line": None,
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "raw_bytes": len(raw),
            "native_stream_id": frame["stream_id"],
            "native_genesis_frame_hash": frame["frame_hash"],
            "native_seq": frame["seq"],
            "native_frame_hash": frame["frame_hash"],
            "native_utc": frame["utc"],
        }

    def extend_native(self):
        seq = len(self.ticks)
        tick = self.make_ticks(seq + 1)[-1]
        self.ticks.append(tick)
        head = self.planet[-1]
        self.planet.append(B.NATIVE_RAPP.build_frame(
            "planet.snapshot", "planet:@kody-w/dogg-planet", seq,
            f"2026-09-17T00:01:{seq:02d}.000Z",
            {"tick": seq, "tick_frame": tick["frame_hash"], "note": f"planet-{seq}"},
            head["payload_hash"],
        ))
        self.write_chain("ticks", self.ticks, repo=self.tick_repo)
        self.tick_commit(f"tick append {seq}")
        self.write_chain("planet", self.planet)
        return self.commit(f"native append {seq}")

    def restore_output(self, snapshot):
        if self.output.exists():
            shutil.rmtree(self.output)
        self.output.mkdir()
        for relative, raw in snapshot.items():
            path = self.output / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    def rewrite_signed_suffix(self, start, mutate):
        previous = (
            None if start == 0 else
            json.loads((self.state / "frames" / f"{start - 1}.json").read_bytes())
        )
        last = max(int(path.stem) for path in (self.state / "frames").iterdir())
        replacements = {}
        for seq in range(start, last + 1):
            original = json.loads(
                (self.state / "frames" / f"{seq}.json").read_bytes()
            )
            kind = original["kind"]
            payload = copy.deepcopy(original["payload"])
            if seq == start:
                kind, payload = mutate(kind, payload)
            frame = B.R.build_frame(
                kind, self.stream_id, seq, original["utc"], payload,
                None if previous is None else previous["payload_hash"],
                prev_wave=None,
            )
            unsigned = {key: value for key, value in frame.items() if key != "sig"}
            frame["sig"] = B.sign_detached(unsigned, self.key, self.anchor)
            replacements[seq] = frame
            previous = frame
        for root in (self.state, self.output):
            for seq, frame in replacements.items():
                (root / "frames" / f"{seq}.json").write_bytes(B.canonical(frame))
            head = json.loads((root / "HEAD.json").read_bytes())
            final = replacements[last]
            head.update({
                "rapp_frame_hash": final["frame_hash"],
                "rapp_payload_hash": final["payload_hash"],
                "rapp_utc": final["utc"],
            })
            (root / "HEAD.json").write_bytes(B.canonical(head))

    def test_exact_jcs_signature_registry_genesis_and_cold_start(self):
        report = self.append([self.output, self.second_output])
        self.assertEqual(report["frames_verified"], 3)
        registry_raw = (
            self.output / "registries" / "0.json"
        ).read_bytes()
        registry = B.R._strict_json(registry_raw)
        self.assertEqual(set(registry), B.REGISTRY_KEYS)
        self.assertEqual(registry_raw, B.canonical(registry))
        self.assertEqual(registry["profile"], B.REGISTRY_PROFILE)
        self.assertEqual(registry["canonical_source"], {
            "repository": B.SOURCE_REPOSITORY,
            "ref": B.CANONICAL_REF,
            "path": "rapp1-bridge-v2/registry.json",
        })
        with B.registry_crypto(self.state):
            status, loaded, why = B.REG.load_document(
                registry, entries_member="entries", trust_anchor=self.anchor
            )
        self.assertEqual(status, "verified", why)
        self.assertEqual(loaded.family("memory.save"), "memory")
        self.assertEqual(B.protocol_entry(loaded, B.PROFILE), {
            "type": "protocol",
            "name": B.PROFILE,
            "spec_repo": B.SOURCE_REPOSITORY,
            "spec_path": B.BRIDGE2_SPEC_PATH,
            "spec_hash": B.BRIDGE2_SPEC_SHA256,
            "deprecated": False,
        })
        genesis = loaded.registered_genesis(self.stream_id)
        self.assertEqual(
            genesis["frame_hash"],
            json.loads((self.output / "frames" / "0.json").read_bytes())["frame_hash"],
        )
        head = None
        verifier = B.registry_signature_verifier(loaded, self.state)
        for seq in range(3):
            raw = (self.output / "frames" / f"{seq}.json").read_bytes()
            frame = B.R._strict_json(raw)
            self.assertEqual(set(frame), B.R.FRAME_KEYS)
            self.assertEqual(raw, B.canonical(frame))
            self.assertEqual(frame["kind"], "memory.save")
            self.assertEqual(frame["stream_id"], self.stream_id)
            self.assertIsNone(frame["prev_wave"])
            self.assertIsNotNone(frame["sig"])
            header = B.R.parse_detached_jws(frame["sig"])[0]
            self.assertEqual(header, {
                "alg": "ES256", "b64": False, "crit": ["b64"], "kid": self.anchor,
            })
            ok, step, why = B.R.verify_frame(
                frame, head=head, stream_id_of_record=self.stream_id,
                signature_verifier=verifier,
            )
            self.assertTrue(ok, (step, why))
            self.assertEqual(frame["payload"]["tick_frame"], self.ticks[seq]["frame_hash"])
            self.assertEqual(
                frame["payload"]["native_source"]["repository"],
                B.SOURCE_REPOSITORY,
            )
            self.assertEqual(
                frame["payload"]["tick_source"]["repository"],
                B.TICK_SOURCE_REPOSITORY,
            )
            self.assertEqual(
                frame["payload"]["tick_source"]["commit"],
                self.initial_tick_commit,
            )
            self.assertEqual(
                frame["payload"]["tick_source"]["native_frame_hash"],
                self.ticks[seq]["frame_hash"],
            )
            head = frame
        for seq in range(3):
            self.assertEqual(
                (self.output / "frames" / f"{seq}.json").read_bytes(),
                (self.second_output / "frames" / f"{seq}.json").read_bytes(),
            )
        self.assertEqual(self.verify()["status"], "verified")
        persistent_head = json.loads((self.output / "HEAD.json").read_bytes())
        self.assertEqual(
            persistent_head["tick_source_commit"], self.initial_tick_commit
        )
        self.assertEqual(persistent_head["tick_native_seq"], 2)
        self.assertEqual(
            persistent_head["tick_native_frame_hash"], self.ticks[2]["frame_hash"]
        )

    def test_signed_profile_refuses_null_wrong_kid_and_wrong_key_algorithm(self):
        self.append()
        state, config = B.load_config(self.state)
        registry_raw = B.real_file(state / "registries" / "0.json")
        frame0, _ = B.read_frame(state / "frames" / "0.json")
        _, registry = B.verify_registry_raw(
            registry_raw, self.anchor, config["canonical_source"],
            frame0["frame_hash"], self.stream_id, state,
        )
        self.assertEqual(
            B.spki_jws_algorithm(registry.spki_der(self.anchor)), "ES256"
        )
        for seq in range(3):
            with self.subTest(unsigned_seq=seq):
                path = state / "frames" / f"{seq}.json"
                raw = path.read_bytes()
                frame = json.loads(raw)
                frame["sig"] = None
                path.write_bytes(B.canonical(frame))
                with self.assertRaisesRegex(ValueError, "non-null detached JWS"):
                    B.verify_frame_chain(state, config, registry, state)
                path.write_bytes(raw)

        unsigned = {key: value for key, value in frame0.items() if key != "sig"}
        wrong_algorithm = B.b64url(B.canonical({
            "alg": "EdDSA", "b64": False, "crit": ["b64"], "kid": self.anchor,
        })) + ".." + B.b64url(b"\0" * 64)
        verifier = B.registry_signature_verifier(registry, state)
        with mock.patch.object(
                B, "verify_detached", return_value=(True, "permissive verifier")):
            ok, why = verifier(unsigned, wrong_algorithm)
        self.assertFalse(ok)
        self.assertRegex(why, "expected ES256")

        other_key = self.case / "wrong-kid.pem"
        B.generate_key(other_key, self.repo, self.tick_repo)
        other_kid, _ = B.keyed_rappid("local", "wrong-kid", other_key)
        wrong_kid = B.sign_detached(unsigned, other_key, other_kid)
        ok, why = verifier(unsigned, wrong_kid)
        self.assertFalse(ok)
        self.assertRegex(why, "estate owner")

    def test_git_history_is_canonical_and_rejects_ancestry_overrides(self):
        observed = []
        original_run = B.subprocess.run

        def observe_run(args, *positional, **kwargs):
            if os.fspath(args[0]) == "git":
                observed.append((list(args), kwargs.get("env")))
            return original_run(args, *positional, **kwargs)

        with mock.patch.dict(os.environ, {"GIT_NO_REPLACE_OBJECTS": "0"}), \
                mock.patch.object(B.subprocess, "run", side_effect=observe_run):
            self.append()
        self.assertTrue(observed)
        for args, env in observed:
            self.assertEqual(args[1], "--no-replace-objects")
            self.assertEqual(env["GIT_NO_REPLACE_OBJECTS"], "1")

        self.git("replace", self.revision, self.initial_native_commit)
        try:
            with self.assertRaisesRegex(ValueError, "replacement state"):
                B.check_git_source(self.repo, self.revision, B.CANONICAL_REF)
        finally:
            self.git("replace", "-d", self.revision)

        grafts = B.git_internal_path(self.repo, "info/grafts")
        grafts.parent.mkdir(parents=True, exist_ok=True)
        grafts.write_text(f"{self.revision}\n")
        try:
            with self.assertRaisesRegex(ValueError, "graft state"):
                B.check_git_source(self.repo, self.revision, B.CANONICAL_REF)
        finally:
            grafts.unlink()

        shallow = B.git_internal_path(self.repo, "shallow")
        shallow.write_text(f"{self.revision}\n")
        try:
            with self.assertRaisesRegex(ValueError, "shallow Git history"):
                B.check_git_source(self.repo, self.revision, B.CANONICAL_REF)
        finally:
            shallow.unlink()

        for name in ("GIT_REPLACE_REF_BASE", "GIT_GRAFT_FILE", "GIT_SHALLOW_FILE"):
            with self.subTest(environment=name), \
                    mock.patch.dict(os.environ, {name: "caller-controlled"}):
                with self.assertRaisesRegex(ValueError, "ancestry override environment"):
                    B.check_git_source(self.repo, self.revision, B.CANONICAL_REF)
        with mock.patch.dict(os.environ, {"GIT_DIR": str(self.repo / ".git")}):
            with self.assertRaisesRegex(ValueError, "repository override environment"):
                B.check_git_source(self.repo, self.revision, B.CANONICAL_REF)

    def test_cli_ref_feature_branch_and_origin_alias_refuse(self):
        _, config = B.load_config(self.state)
        self.assertEqual(config["canonical_source"]["ref"], B.CANONICAL_REF)
        with self.assertRaisesRegex(ValueError, "exact Git top-level"):
            B.check_git_source(
                self.repo / "planet", self.revision, B.CANONICAL_REF
            )
        with self.assertRaisesRegex(ValueError, "exact Git top-level"):
            B.append_paths(
                self.repo / "planet", self.tick_repo, self.state,
                [self.repo / "output"],
            )
        with self.assertRaisesRegex(ValueError, "CLI main ref differs"):
            B.check_git_source(self.repo, self.revision, "refs/heads/main")

        self.git("remote", "set-url", "origin", B.SOURCE_REPOSITORY + ".git")
        try:
            with self.assertRaisesRegex(ValueError, "origin does not exactly match"):
                B.check_git_source(self.repo, self.revision, B.CANONICAL_REF)
        finally:
            self.git("remote", "set-url", "origin", B.SOURCE_REPOSITORY)

        self.git("checkout", "-b", "feature/not-canonical")
        (self.repo / "feature-only.txt").write_text("not canonical\n")
        self.git("add", "feature-only.txt")
        self.git("commit", "-m", "feature-only source")
        feature_revision = self.git("rev-parse", "HEAD")
        with self.assertRaisesRegex(ValueError, "canonical main history"):
            B.check_git_source(self.repo, feature_revision, B.CANONICAL_REF)
        with self.assertRaisesRegex(ValueError, "CLI main ref differs"):
            B.check_git_source(
                self.repo, feature_revision, "refs/heads/feature/not-canonical"
            )

    def test_tick_source_root_origin_main_and_cli_arguments_are_exact(self):
        self.assertEqual(
            B.check_git_source(
                self.tick_repo, self.tick_revision, B.CANONICAL_REF,
                B.TICK_SOURCE_REPOSITORY,
            ),
            self.tick_repo,
        )
        with self.assertRaisesRegex(ValueError, "exact Git top-level"):
            B.check_git_source(
                self.tick_repo / "ticks", self.tick_revision, B.CANONICAL_REF,
                B.TICK_SOURCE_REPOSITORY,
            )
        with self.assertRaisesRegex(ValueError, "CLI main ref differs"):
            B.check_git_source(
                self.tick_repo, self.tick_revision, "refs/heads/main",
                B.TICK_SOURCE_REPOSITORY,
            )

        self.tick_git(
            "remote", "set-url", "origin",
            B.TICK_SOURCE_REPOSITORY.removesuffix(".git"),
        )
        try:
            with self.assertRaisesRegex(ValueError, "origin does not exactly match"):
                self.append()
        finally:
            self.tick_git(
                "remote", "set-url", "origin", B.TICK_SOURCE_REPOSITORY
            )

        result = subprocess.run(
            [
                sys.executable, str(ROOT / "tools" / "rapp1_bridge_v2.py"),
                "verify", "--source-root", str(self.repo),
                "--source-revision", self.revision,
                "--registry-checkpoint", self.registry_checkpoint,
                "--state", str(self.state), "--out", str(self.output),
            ],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("--tick-source-root", result.stderr)
        self.assertIn("--tick-source-commit", result.stderr)

    def test_tick_repository_replace_graft_and_shallow_state_refuse(self):
        marker = self.tick_repo / "marker"
        marker.write_text("canonical tick history marker\n")
        current = self.tick_commit("tick history marker")

        self.tick_git("replace", current, self.initial_tick_commit)
        try:
            with self.assertRaisesRegex(ValueError, "replacement state"):
                self.append()
        finally:
            self.tick_git("replace", "-d", current)

        grafts = B.git_internal_path(self.tick_repo, "info/grafts")
        grafts.parent.mkdir(parents=True, exist_ok=True)
        grafts.write_text(f"{current}\n")
        try:
            with self.assertRaisesRegex(ValueError, "graft state"):
                self.append()
        finally:
            grafts.unlink()

        shallow = B.git_internal_path(self.tick_repo, "shallow")
        shallow.write_text(f"{current}\n")
        try:
            with self.assertRaisesRegex(ValueError, "shallow Git history"):
                self.append()
        finally:
            shallow.unlink()

    def test_cross_repository_tick_staleness_and_fork_refuse(self):
        stale_tick_repo = self.case / "stale-tick-source"
        shutil.copytree(self.tick_repo, stale_tick_repo)
        stale_tick_commit = self.tick_revision
        self.append()
        self.extend_native()

        with self.assertRaisesRegex(ValueError, "beyond the verified spine"):
            B.append(
                self.repo, self.revision, stale_tick_repo, stale_tick_commit,
                B.CANONICAL_REF, self.registry_checkpoint, self.state,
                [self.output], self.key, self.anchor,
            )
        self.assertEqual(self.append()["native_seq"], 3)
        accepted_tick_commit = self.tick_revision

        self.tick_git("checkout", "--detach", self.initial_tick_commit)
        self.write_chain("ticks", self.ticks, repo=self.tick_repo)
        fork_commit = self.tick_commit("forked tick history")
        self.assertNotEqual(fork_commit, accepted_tick_commit)
        with self.assertRaisesRegex(ValueError, "non-fast-forward tick source"):
            self.append(tick_revision=fork_commit)

    def test_every_historical_frame_rechecks_planet_and_tick_commits(self):
        self.append()
        expected = []
        for seq in range(3):
            frame = json.loads(
                (self.state / "frames" / f"{seq}.json").read_bytes()
            )
            expected.extend([
                (
                    frame["payload"]["native_source"]["repository"],
                    frame["payload"]["native_source"]["commit"],
                    "planet",
                ),
                (
                    frame["payload"]["tick_source"]["repository"],
                    frame["payload"]["tick_source"]["commit"],
                    "ticks",
                ),
            ])
        observed = []
        original = B.verify_native_chain

        def observe(root, revision, chain_path, main_ref,
                    repository=B.SOURCE_REPOSITORY, cache=None):
            observed.append((repository, revision, chain_path))
            return original(
                root, revision, chain_path, main_ref, repository, cache
            )

        with mock.patch.object(B, "verify_native_chain", side_effect=observe):
            self.assertEqual(self.verify()["status"], "verified")
        for item in expected:
            self.assertIn(item, observed)

    def test_append_idempotent_retry_and_candidate_bytes_reused(self):
        native_before = {
            (root.name, path.relative_to(root).as_posix()): path.read_bytes()
            for root, chain in ((self.repo, "planet"), (self.tick_repo, "ticks"))
            for path in (root / chain).rglob("*") if path.is_file()
        }
        self.append()
        first = self.snapshot(self.state / "frames")
        with mock.patch.object(B, "sign_detached", side_effect=AssertionError("retry signed")):
            repeated = self.append()
        self.assertEqual(repeated["status"], "unchanged")
        self.assertEqual(first, self.snapshot(self.state / "frames"))
        tick = self.make_ticks(4)[-1]
        self.ticks.append(tick)
        head = self.planet[-1]
        planet = B.NATIVE_RAPP.build_frame(
            "planet.snapshot", "planet:@kody-w/dogg-planet", 3,
            "2026-09-17T00:01:03.000Z",
            {"tick": 3, "tick_frame": tick["frame_hash"], "note": "planet-3"},
            head["payload_hash"],
        )
        self.planet.append(planet)
        self.write_chain("ticks", self.ticks, repo=self.tick_repo)
        self.tick_commit("tick append")
        self.write_chain("planet", self.planet)
        self.commit("native append")
        report = self.append([self.output, self.second_output])
        self.assertEqual(report["frames_verified"], 4)
        for seq in range(3):
            self.assertEqual(
                first[f"{seq}.json"],
                (self.state / "frames" / f"{seq}.json").read_bytes(),
            )
        for seq in range(4):
            self.assertEqual(
                (self.output / "frames" / f"{seq}.json").read_bytes(),
                (self.second_output / "frames" / f"{seq}.json").read_bytes(),
            )
        roots = {self.repo.name: self.repo, self.tick_repo.name: self.tick_repo}
        for (root_name, relative), raw in native_before.items():
            if relative.endswith("HEAD.json") or relative.endswith("2.json"):
                continue
            self.assertEqual((roots[root_name] / relative).read_bytes(), raw)

    def test_concurrent_stale_append_is_serialized_and_refused(self):
        self.append()
        old_revision = self.extend_native()
        old_tick_revision = self.tick_revision
        self.extend_native()
        old_repo = self.case / "stale-repo"
        old_tick_repo = self.case / "stale-tick-repo"
        shutil.copytree(self.repo, old_repo)
        shutil.copytree(self.tick_repo, old_tick_repo)
        result = subprocess.run(
            ["git", "checkout", "--detach", old_revision],
            cwd=old_repo, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(
            ["git", "checkout", "--detach", old_tick_revision],
            cwd=old_tick_repo, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        context = multiprocessing.get_context("fork")
        newer_entered = context.Event()
        newer_release = context.Event()
        stale_entered = context.Event()
        stale_release = context.Event()
        stale_release.set()
        results = context.Queue()
        newer_args = (
            self.repo, self.revision, self.tick_repo, self.tick_revision,
            B.CANONICAL_REF, self.registry_checkpoint, self.state,
            [self.output], self.key, self.anchor,
        )
        stale_args = (
            old_repo, old_revision, old_tick_repo, old_tick_revision,
            B.CANONICAL_REF, self.registry_checkpoint, self.state,
            [self.output], self.key, self.anchor,
        )
        newer = context.Process(
            target=concurrent_append_worker,
            args=(newer_args, newer_entered, newer_release, results),
        )
        stale = context.Process(
            target=concurrent_append_worker,
            args=(stale_args, stale_entered, stale_release, results),
        )
        newer.start()
        self.assertTrue(newer_entered.wait(10), "newer append did not enter validation")
        stale.start()
        time.sleep(0.5)
        self.assertFalse(stale_entered.is_set(), "stale append bypassed controller lock")
        newer_release.set()
        newer.join(20)
        self.assertEqual(newer.exitcode, 0)
        stale.join(20)
        self.assertEqual(stale.exitcode, 0)
        outcomes = [results.get(timeout=5), results.get(timeout=5)]
        self.assertEqual(sum(status == "ok" for status, _ in outcomes), 1, outcomes)
        refusal = next(value for status, value in outcomes if status == "error")
        self.assertRegex(refusal, "non-fast-forward Git source|native source rollback")
        self.assertEqual(
            json.loads((self.output / "HEAD.json").read_bytes())["native_seq"], 4
        )
        self.assertEqual(
            json.loads((self.state / "HEAD.json").read_bytes())["native_seq"], 4
        )

    def test_immediate_high_water_revalidation_catches_external_change(self):
        self.append()
        self.extend_native()
        old_head = json.loads((self.output / "HEAD.json").read_bytes())
        changed_head = {**old_head, "source_commit": "0" * 40}
        original = B.write_new_or_equal
        changed = False

        def mutate_before_commit(path, raw):
            nonlocal changed
            result = original(path, raw)
            if B.absolute(path) == self.output / "frames" / "3.json" and not changed:
                changed = True
                (self.output / "HEAD.json").write_bytes(B.canonical(changed_head))
            return result

        with mock.patch.object(B, "write_new_or_equal", side_effect=mutate_before_commit):
            with self.assertRaisesRegex(ValueError, "high-water changed"):
                self.append()
        self.assertEqual(
            json.loads((self.output / "HEAD.json").read_bytes()), changed_head
        )
        self.assertEqual(
            json.loads((self.state / "HEAD.json").read_bytes())["native_seq"], 2
        )

    def test_accepted_controller_frame_and_source_metadata_are_immutable(self):
        self.append()
        accepted_raw = (self.state / "frames" / "2.json").read_bytes()
        accepted_head_raw = (self.state / "HEAD.json").read_bytes()
        (self.state / "frames" / "2.json").unlink()
        self.extend_native()
        with mock.patch.object(
                B, "sign_detached", side_effect=AssertionError("generated before rollback gate")):
            with self.assertRaisesRegex(ValueError, "retained frame chain is behind accepted head"):
                self.append()
        (self.state / "frames" / "2.json").write_bytes(accepted_raw)

        accepted = json.loads(accepted_raw)
        frame1 = json.loads((self.state / "frames" / "1.json").read_bytes())
        changed_payload = copy.deepcopy(accepted["payload"])
        changed_payload["native_source"]["storage_path"] = "planet/1.json"
        fork = B.build_signed_frame(
            self.stream_id, 2, accepted["utc"], changed_payload,
            frame1, self.key, self.anchor,
        )
        (self.state / "frames" / "2.json").write_bytes(B.canonical(fork))
        with self.assertRaisesRegex(ValueError, "same-sequence controller RAPP fork"):
            self.append()
        (self.state / "frames" / "2.json").write_bytes(accepted_raw)

        changed_head = json.loads(accepted_head_raw)
        changed_head["source_commit"] = self.initial_native_commit
        (self.state / "HEAD.json").write_bytes(B.canonical(changed_head))
        with self.assertRaisesRegex(ValueError, "controller source metadata mismatch"):
            self.append()
        (self.state / "HEAD.json").write_bytes(accepted_head_raw)

        changed_head = json.loads(accepted_head_raw)
        changed_head["rapp_frame_hash"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "same-sequence persistent head RAPP fork"):
            B.commit_head(
                self.state / "HEAD.json", changed_head,
                json.loads(accepted_head_raw),
            )
        self.assertEqual((self.state / "HEAD.json").read_bytes(), accepted_head_raw)
        self.assertFalse((self.state / ".HEAD.json.pending").exists())

    def test_wrong_anchor_and_private_key_refuse(self):
        with mock.patch.dict(os.environ, {
            "DOGG_RAPP1_BRIDGE_SIGNING_KEY": "",
            "DOGG_RAPP1_BRIDGE_TRUST_ANCHOR": self.anchor,
        }):
            with self.assertRaisesRegex(ValueError, "signing configuration absent"):
                B.append(
                    self.repo, self.revision, self.tick_repo, self.tick_revision,
                    B.CANONICAL_REF, self.registry_checkpoint, self.state,
                    [self.output], None, self.anchor,
                )
        other_key = self.case / "other.pem"
        B.generate_key(other_key, self.repo, self.tick_repo)
        other, _ = B.keyed_rappid("local", "other", other_key)
        with self.assertRaisesRegex(ValueError, "untrusted anchor"):
            self.append(anchor=other)
        with self.assertRaisesRegex(ValueError, "signing key does not match"):
            self.append(key=other_key)
        self.assertFalse(self.output.exists())

    def test_private_key_creation_and_every_use_are_hardened(self):
        info = self.key.lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(info.st_uid, os.getuid())
        self.assertEqual(info.st_nlink, 1)

        generated = self.case / "generated.pem"
        opened = []
        original_open = B.os.open
        original_run = B.run
        keygen_commands = []

        def observe_open(path, flags, *args, **kwargs):
            if os.fspath(path) == generated.name and kwargs.get("dir_fd") is not None:
                opened.append(flags)
            return original_open(path, flags, *args, **kwargs)

        def observe_run(args, *positional, **kwargs):
            if list(args[:2]) == ["openssl", "ecparam"]:
                keygen_commands.append(list(args))
            return original_run(args, *positional, **kwargs)

        with mock.patch.object(B.os, "open", side_effect=observe_open), \
                mock.patch.object(B, "run", side_effect=observe_run):
            B.generate_key(generated, self.repo, self.tick_repo)
        self.assertEqual(len(keygen_commands), 1)
        self.assertNotIn("-out", keygen_commands[0])
        create_flags = next(flags for flags in opened if flags & os.O_CREAT)
        self.assertTrue(create_flags & os.O_EXCL)
        if hasattr(os, "O_NOFOLLOW"):
            self.assertTrue(create_flags & os.O_NOFOLLOW)

        os.chmod(self.key, 0o644)
        with self.assertRaisesRegex(ValueError, "exactly 0600"):
            B.public_spki(self.key)
        os.chmod(self.key, 0o600)

        hardlink = self.case / "owner-link.pem"
        os.link(self.key, hardlink)
        with self.assertRaisesRegex(ValueError, "one link"):
            B.public_spki(self.key)
        hardlink.unlink()

        symlink = self.case / "owner-symlink.pem"
        symlink.symlink_to(self.key)
        with self.assertRaisesRegex(ValueError, "not regular"):
            B.public_spki(symlink)
        symlink.unlink()

        with mock.patch.object(B.os, "getuid", return_value=os.getuid() + 1), \
                mock.patch.object(B, "validate_private_directory_info"):
            with self.assertRaisesRegex(ValueError, "signing key has wrong owner"):
                B.public_spki(self.key)

        os.chmod(self.case, 0o755)
        try:
            with self.assertRaisesRegex(ValueError, "exactly 0700"):
                B.public_spki(self.key)
        finally:
            os.chmod(self.case, 0o700)

    def test_registry_rollback_fork_and_gap_refuse(self):
        self.append()
        accepted_commit = self.revision
        accepted_registry_commit = self.registry_checkpoint
        invalid = self.signed_registry(0)
        invalid["sig"] = invalid["sig"][:-1] + (
            "A" if invalid["sig"][-1] != "A" else "B"
        )
        invalid_commit, _ = self.publish_registry(invalid, "invalid registry signature")
        with self.assertRaisesRegex(ValueError, "registry refused"):
            self.append(revision=invalid_commit, checkpoint=invalid_commit)
        self.git("reset", "--hard", accepted_commit)
        self.revision = accepted_commit
        fork = self.signed_registry(0)
        fork_commit, _ = self.publish_registry(fork, "same sequence registry fork")
        with self.assertRaisesRegex(ValueError, "same-sequence registry fork"):
            self.append(revision=fork_commit, checkpoint=fork_commit)
        self.git("reset", "--hard", accepted_commit)
        self.revision = accepted_commit
        gap = self.signed_registry(2)
        gap_commit, _ = self.publish_registry(gap, "registry sequence gap")
        with self.assertRaisesRegex(ValueError, "sequence gap"):
            self.append(revision=gap_commit, checkpoint=gap_commit)
        self.git("reset", "--hard", accepted_commit)
        self.revision = accepted_commit
        next_registry = self.signed_registry(1)
        next_commit, _ = self.publish_registry(next_registry, "registry sequence one")
        advanced = self.append(revision=next_commit, checkpoint=next_commit)
        self.assertEqual(advanced["registry_seq"], 1)
        self.registry_checkpoint = next_commit
        with self.assertRaisesRegex(ValueError, "rollback"):
            self.append(revision=next_commit, checkpoint=accepted_registry_commit)

    def test_output_frame_rollback_fork_and_gap_refuse(self):
        self.append()
        clean = self.snapshot(self.output)
        (self.output / "frames" / "1.json").unlink()
        with self.assertRaisesRegex(ValueError, "frame gap"):
            self.verify()
        self.restore_output(clean)
        frame1 = json.loads((self.output / "frames" / "1.json").read_bytes())
        frame2 = json.loads((self.output / "frames" / "2.json").read_bytes())
        fork = B.build_signed_frame(
            self.stream_id, 2, "9999-12-31T23:59:59.999Z",
            frame2["payload"],
            frame1, self.key, self.anchor,
        )
        (self.output / "frames" / "2.json").write_bytes(B.canonical(fork))
        with self.assertRaisesRegex(ValueError, "differs from controller candidate"):
            self.verify()
        self.restore_output(clean)
        invalid = copy.deepcopy(frame2)
        invalid["sig"] = invalid["sig"][:-1] + (
            "A" if invalid["sig"][-1] != "A" else "B"
        )
        (self.output / "frames" / "2.json").write_bytes(B.canonical(invalid))
        with self.assertRaisesRegex(ValueError, "differs from controller candidate"):
            self.verify()
        self.restore_output(clean)
        head = json.loads((self.output / "HEAD.json").read_bytes())
        one = json.loads((self.output / "frames" / "1.json").read_bytes())
        head.update({
            "rapp_seq": 1,
            "rapp_frame_hash": one["frame_hash"],
            "rapp_payload_hash": one["payload_hash"],
            "rapp_utc": one["utc"],
            "native_seq": 1,
            "native_frame_hash": one["payload"]["native_source"]["native_frame_hash"],
            "tick_source_commit": one["payload"]["tick_source"]["commit"],
            "tick_native_seq": one["payload"]["tick_source"]["native_seq"],
            "tick_native_frame_hash":
                one["payload"]["tick_source"]["native_frame_hash"],
            "tick_native_genesis_frame_hash":
                one["payload"]["tick_source"]["native_genesis_frame_hash"],
        })
        (self.output / "frames" / "2.json").unlink()
        (self.output / "HEAD.json").write_bytes(B.canonical(head))
        with self.assertRaisesRegex(ValueError, "persistent head"):
            self.verify()

    def test_output_objects_are_exact_controller_bytes(self):
        self.append()
        original = (self.state / "frames" / "0.json").read_bytes()
        frame = json.loads(original)
        unsigned = {key: value for key, value in frame.items() if key != "sig"}
        frame["sig"] = B.sign_detached(unsigned, self.key, self.anchor)
        substituted = B.canonical(frame)
        self.assertNotEqual(substituted, original)
        self.assertEqual(json.loads(substituted)["payload"], json.loads(original)["payload"])
        self.assertEqual(
            json.loads(substituted)["frame_hash"], json.loads(original)["frame_hash"]
        )
        (self.output / "frames" / "0.json").write_bytes(substituted)
        with self.assertRaisesRegex(ValueError, "differs from controller candidate"):
            self.verify()
        (self.output / "frames" / "0.json").write_bytes(original)

        next_registry = self.signed_registry(1)
        checkpoint, _ = self.publish_registry(next_registry, "registry sequence one")
        self.registry_checkpoint = checkpoint
        self.append(revision=checkpoint, checkpoint=checkpoint)
        (self.output / "registries" / "0.json").write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "registry differs from controller candidate"):
            self.verify(revision=checkpoint, checkpoint=checkpoint)

    def test_bridge_frame_kind_is_exactly_memory_save(self):
        self.append()
        state, config = B.load_config(self.state)
        doc = json.loads((state / "registries" / "0.json").read_bytes())
        registry = B.REG.Registry(doc["entries"] + [{
            "type": "kind", "kind": "memory.note",
            "family": "memory", "deprecated": False,
        }])
        self.rewrite_signed_suffix(
            1, lambda _kind, payload: ("memory.note", payload)
        )
        self.assertEqual(registry.family("memory.note"), "memory")
        with self.assertRaisesRegex(ValueError, "exactly memory.save"):
            B.verify_frame_chain(state, config, registry, state)

    def test_output_frame_zero_must_equal_signed_registry_genesis(self):
        self.append()
        state, config = B.load_config(self.state)
        head = B.load_head(state / "HEAD.json")
        original, _ = B.read_frame(state / "frames" / "0.json")
        registry_raw = B.real_file(state / "registries" / "0.json")
        _, registry = B.verify_registry_raw(
            registry_raw, self.anchor, config["canonical_source"],
            original["frame_hash"], self.stream_id, state,
        )
        replacement = B.build_signed_frame(
            self.stream_id, 0, "2026-09-17T23:59:59.999Z",
            original["payload"], None, self.key, self.anchor,
        )
        self.assertEqual(replacement["payload"], original["payload"])
        self.assertNotEqual(replacement["frame_hash"], original["frame_hash"])
        replacement_raw = B.canonical(replacement)
        (state / "frames" / "0.json").write_bytes(replacement_raw)
        (self.output / "frames" / "0.json").write_bytes(replacement_raw)
        with self.assertRaisesRegex(ValueError, "frame zero differs.*registry genesis"):
            B.verify_output(
                self.output, config, registry, registry_raw, head, state
            )

    def test_outputs_are_disjoint_before_any_write(self):
        lock = self.state / ".append.lock"
        for outputs in ([self.state], [self.state / "nested-output"]):
            with self.subTest(outputs=outputs):
                with self.assertRaisesRegex(ValueError, "controller state"):
                    B.append(
                        self.repo, self.revision, self.tick_repo,
                        self.tick_revision, B.CANONICAL_REF,
                        self.registry_checkpoint, self.state, outputs, self.key,
                        self.anchor,
                    )
                self.assertFalse(lock.exists())

        alias = self.case / "state-alias"
        alias.symlink_to(self.state, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "controller state|symlinks forbidden"):
            B.append(
                self.repo, self.revision, self.tick_repo, self.tick_revision,
                B.CANONICAL_REF, self.registry_checkpoint, self.state, [alias],
                self.key, self.anchor,
            )
        self.assertFalse(lock.exists())
        alias.unlink()

        layout = self.case / "path-layout"
        source = layout / "source"
        state = layout / "controller" / "state"
        source.mkdir(parents=True)
        state.mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "controller state"):
            B.append_paths(self.repo, self.tick_repo, state, [state.parent])
        with self.assertRaisesRegex(ValueError, "pairwise disjoint"):
            B.append_paths(
                self.repo, self.tick_repo, state,
                [layout / "one", layout / "one" / "nested"],
            )
        with self.assertRaisesRegex(ValueError, "pairwise disjoint"):
            B.append_paths(
                self.repo, self.tick_repo, state,
                [layout / "one", layout / "one"],
            )

        nested_state = self.case / "new-state"
        nested_registry = nested_state / "registry.json"
        with self.assertRaisesRegex(ValueError, "state and registry output"):
            B.initialize(
                self.repo, self.revision, self.tick_repo, self.tick_revision,
                "planet", B.CANONICAL_REF, "local", "overlap",
                "registry.json", nested_state, nested_registry, self.key,
            )
        self.assertFalse(nested_state.exists())

    def test_case_unicode_and_symlink_directory_aliases_refuse(self):
        layout = self.case / "aliases"
        source = layout / "source"
        state = layout / "backing" / "state"
        source.mkdir(parents=True)
        state.mkdir(parents=True)
        alias = layout / "mount-like-alias"
        alias.symlink_to(state.parent, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "controller state"):
            B.append_paths(
                self.repo, self.tick_repo, state, [alias / "state" / "future"]
            )

        case_probe = layout / "CaseProbe"
        case_probe.mkdir()
        case_alias = layout / "caseprobe"
        if case_alias.exists() and os.path.samefile(case_probe, case_alias):
            with self.assertRaisesRegex(ValueError, "pairwise disjoint"):
                B.append_paths(
                    self.repo, self.tick_repo, state,
                    [layout / "FutureOutput", layout / "futureoutput" / "nested"],
                )

        composed_probe = layout / "Caf\u00e9Probe"
        decomposed_probe = layout / "Cafe\u0301Probe"
        composed_probe.mkdir()
        if decomposed_probe.exists() and os.path.samefile(composed_probe, decomposed_probe):
            with self.assertRaisesRegex(ValueError, "pairwise disjoint"):
                B.append_paths(
                    self.repo, self.tick_repo, state,
                    [layout / "out-\u00e9", layout / "out-e\u0301" / "nested"],
                )

    def test_fsync_dependency_order_and_interrupted_append_recovery(self):
        probe_directory = self.case / "durability-probe"
        probe_directory.mkdir(mode=0o700)
        fsync_kinds = []
        original_fsync = B.os.fsync

        def observe_fsync(fd):
            fsync_kinds.append(
                "directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file"
            )
            return original_fsync(fd)

        with mock.patch.object(B.os, "fsync", side_effect=observe_fsync):
            B.write_new(probe_directory / "object.bin", b"durable")
        self.assertEqual(fsync_kinds, ["file", "directory"])

        original_replace = B.os.replace

        def interrupt_output(source, destination):
            if B.absolute(destination) == self.output / "HEAD.json":
                raise OSError("simulated output interruption")
            return original_replace(source, destination)

        with mock.patch.object(B.os, "replace", side_effect=interrupt_output):
            with self.assertRaisesRegex(OSError, "simulated output interruption"):
                self.append()
        self.assertFalse((self.output / "HEAD.json").exists())
        self.assertTrue((self.output / ".HEAD.json.pending").exists())
        self.assertFalse((self.state / "HEAD.json").exists())
        self.assertEqual(
            {path.name for path in (self.output / "frames").iterdir()},
            {"0.json", "1.json", "2.json"},
        )
        self.assertEqual(
            {path.name for path in (self.output / "registries").iterdir()},
            {"0.json"},
        )
        for frame_path in (self.output / "frames").iterdir():
            frame = json.loads(frame_path.read_bytes())
            for source in (
                frame["payload"]["native_source"],
                frame["payload"]["tick_source"],
            ):
                if source is not None:
                    self.assertTrue(
                        (self.output / "blobs" / f"{source['raw_sha256']}.bin").exists()
                    )
        self.assertEqual(self.append()["status"], "advanced")
        self.assertEqual(self.verify()["status"], "verified")

        self.extend_native()

        def interrupt_state(source, destination):
            if B.absolute(destination) == self.state / "HEAD.json":
                raise OSError("simulated controller interruption")
            return original_replace(source, destination)

        with mock.patch.object(B.os, "replace", side_effect=interrupt_state):
            with self.assertRaisesRegex(OSError, "simulated controller interruption"):
                self.append()
        self.assertEqual(
            json.loads((self.output / "HEAD.json").read_bytes())["native_seq"], 3
        )
        self.assertEqual(
            json.loads((self.state / "HEAD.json").read_bytes())["native_seq"], 2
        )
        self.assertTrue((self.state / ".HEAD.json.pending").exists())
        self.assertEqual(self.append()["status"], "advanced")
        self.assertEqual(self.verify()["status"], "verified")

    def test_unsigned_output_heads_cannot_expand_unretained_ranges(self):
        self.append()
        current = json.loads((self.output / "HEAD.json").read_bytes())
        retained_frames = len(list((self.state / "frames").iterdir()))

        def guarded_range(*arguments):
            value = range(*arguments)
            if len(value) > 128:
                raise AssertionError("head recovery expanded an unbounded numeric range")
            return value

        for label, seq in (
            ("max-uint53", B.UINT53_MAX),
            ("moderately-oversized", retained_frames + 4096),
        ):
            with self.subTest(label=label):
                pending = {**current, "rapp_seq": seq, "native_seq": seq}
                pending_path = self.output / ".HEAD.json.pending"
                pending_path.write_bytes(B.canonical(pending))
                with mock.patch.object(B, "range", guarded_range, create=True):
                    references = B._head_object_references(
                        self.output, [current, pending]
                    )
                    self.assertEqual(references["frame_max"], seq)
                    self.assertTrue(references["blobs_incomplete"])
                    with self.assertRaisesRegex(
                            ValueError,
                            "pending output head sequence is ahead of retained frame objects"):
                        B.recover_output_pending(
                            self.repo, self.revision, self.tick_repo,
                            self.tick_revision, B.CANONICAL_REF, self.state,
                            self.output, B.load_config(self.state)[1],
                        )
                pending_path.unlink()

    def test_partial_output_layout_recovers_only_without_authority(self):
        original_mkdir = B.mkdir_durable
        interrupted = False

        def interrupt_layout(path, *args, **kwargs):
            nonlocal interrupted
            result = original_mkdir(path, *args, **kwargs)
            if B.absolute(path) == self.output / "frames" and not interrupted:
                interrupted = True
                raise OSError("simulated output layout interruption")
            return result

        with mock.patch.object(B, "mkdir_durable", side_effect=interrupt_layout):
            with self.assertRaisesRegex(OSError, "layout interruption"):
                self.append()
        self.assertEqual({entry.name for entry in self.output.iterdir()}, {"frames"})
        self.assertFalse((self.output / "HEAD.json").exists())
        self.assertFalse((self.output / ".HEAD.json.pending").exists())
        self.assertEqual(self.append()["status"], "advanced")
        self.assertEqual(self.verify()["status"], "verified")

        self.second_output.mkdir()
        self.assertEqual(
            {entry.name for entry in self.second_output.iterdir()}, set()
        )
        self.assertEqual(
            self.append(outputs=[self.second_output])["status"], "unchanged"
        )
        self.assertEqual(
            self.verify(output=self.second_output)["status"], "verified"
        )

        shutil.rmtree(self.output / "blobs")
        with self.assertRaisesRegex(ValueError, "recovery forbidden after HEAD"):
            self.append()
        self.assertFalse((self.output / "blobs").exists())

        pending = self.case / "pending-authority-output"
        pending.mkdir()
        (pending / ".HEAD.json.pending").write_bytes(b"pending authority")
        with self.assertRaisesRegex(ValueError, "recovery forbidden after HEAD/pending"):
            B.output_layout(pending)
        self.assertEqual(
            {entry.name for entry in pending.iterdir()}, {".HEAD.json.pending"}
        )

    def test_partial_output_layout_refuses_unexpected_files_and_symlinks(self):
        unexpected = self.case / "unexpected-output"
        unexpected.mkdir()
        (unexpected / "surprise").write_bytes(b"unexpected")
        with self.assertRaisesRegex(ValueError, "unexpected bridge output entries"):
            B.recover_output_pending(
                self.repo, self.revision, self.tick_repo, self.tick_revision,
                B.CANONICAL_REF, self.state, unexpected,
                B.load_config(self.state)[1],
            )
        self.assertEqual({entry.name for entry in unexpected.iterdir()}, {"surprise"})

        wrong_type = self.case / "wrong-type-output"
        wrong_type.mkdir()
        (wrong_type / "frames").write_bytes(b"not a directory")
        with self.assertRaisesRegex(ValueError, "not a real directory"):
            B.recover_output_pending(
                self.repo, self.revision, self.tick_repo, self.tick_revision,
                B.CANONICAL_REF, self.state, wrong_type,
                B.load_config(self.state)[1],
            )
        self.assertEqual({entry.name for entry in wrong_type.iterdir()}, {"frames"})

        linked = self.case / "linked-output"
        linked.mkdir()
        target = self.case / "linked-target"
        target.mkdir()
        (linked / "frames").symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlinks forbidden"):
            B.recover_output_pending(
                self.repo, self.revision, self.tick_repo, self.tick_revision,
                B.CANONICAL_REF, self.state, linked,
                B.load_config(self.state)[1],
            )
        self.assertEqual({entry.name for entry in linked.iterdir()}, {"frames"})

        unknown_object = self.case / "unknown-object-output"
        for name in ("frames", "blobs", "registries"):
            (unknown_object / name).mkdir(parents=True, exist_ok=True)
        (unknown_object / "frames" / "future.json").write_bytes(b"unexpected")
        with self.assertRaisesRegex(ValueError, "unexpected output object entry"):
            B.output_layout(unknown_object, {
                "frames": set(), "blobs": set(), "registries": set(),
            })

    def test_lagging_output_pending_head_validates_full_registry_prefix(self):
        missing_output = self.case / "missing-intermediate-output"
        malformed_output = self.case / "malformed-intermediate-output"
        lagging = [self.output, missing_output, malformed_output]
        self.append([self.second_output, *lagging])

        for seq in (1, 2):
            checkpoint, _ = self.publish_registry(
                self.signed_registry(seq), f"registry sequence {seq}"
            )
            self.registry_checkpoint = checkpoint
            advanced = self.append(outputs=[self.second_output])
            self.assertEqual(advanced["registry_seq"], seq)

        original_replace = B.os.replace

        def leave_pending(output):
            def interrupt(source, destination):
                if B.absolute(destination) == output / "HEAD.json":
                    raise OSError("simulated lagging output interruption")
                return original_replace(source, destination)

            with mock.patch.object(B.os, "replace", side_effect=interrupt):
                with self.assertRaisesRegex(
                        OSError, "simulated lagging output interruption"):
                    self.append(outputs=[output])
            pending = json.loads(
                (output / ".HEAD.json.pending").read_bytes()
            )
            self.assertEqual(pending["registry_seq"], 2)
            self.assertEqual(
                json.loads((output / "HEAD.json").read_bytes())["registry_seq"], 0
            )

        for output in lagging:
            leave_pending(output)

        recovered = self.append(outputs=[self.output])
        self.assertEqual(recovered["status"], "advanced")
        self.assertFalse((self.output / ".HEAD.json.pending").exists())
        self.assertEqual(
            json.loads((self.output / "HEAD.json").read_bytes())["registry_seq"], 2
        )
        self.assertEqual(self.verify()["status"], "verified")

        missing_output_registry = missing_output / "registries" / "1.json"
        missing_output_raw = missing_output_registry.read_bytes()
        missing_output_registry.unlink()
        with self.assertRaisesRegex(ValueError, "registries object sequence gap"):
            self.append(outputs=[missing_output])
        self.assertTrue((missing_output / ".HEAD.json.pending").exists())
        missing_output_registry.write_bytes(missing_output_raw)

        controller_registry = self.state / "registries" / "1.json"
        controller_raw = controller_registry.read_bytes()
        controller_registry.unlink()
        with self.assertRaisesRegex(ValueError, "registries object sequence gap"):
            self.append(outputs=[missing_output])
        self.assertTrue((missing_output / ".HEAD.json.pending").exists())
        controller_registry.write_bytes(controller_raw)

        malformed_registry = malformed_output / "registries" / "1.json"
        malformed_raw = B.canonical({"registry_seq": 1})
        malformed_registry.write_bytes(malformed_raw)
        controller_registry.write_bytes(malformed_raw)
        with self.assertRaisesRegex(ValueError, "registry top-level key set"):
            self.append(outputs=[malformed_output])
        self.assertTrue((malformed_output / ".HEAD.json.pending").exists())

    def test_pending_recovery_survives_new_source_and_removes_abandoned_head(self):
        self.append()
        self.extend_native()
        original_replace = B.os.replace

        def interrupt_state(source, destination):
            if B.absolute(destination) == self.state / "HEAD.json":
                raise OSError("simulated controller interruption")
            return original_replace(source, destination)

        with mock.patch.object(B.os, "replace", side_effect=interrupt_state):
            with self.assertRaisesRegex(OSError, "simulated controller interruption"):
                self.append()
        interrupted = json.loads((self.state / ".HEAD.json.pending").read_bytes())
        self.assertEqual(interrupted["rapp_seq"], 3)

        self.extend_native()
        recovered = self.append()
        self.assertEqual(recovered["rapp_seq"], 4)
        self.assertFalse((self.state / ".HEAD.json.pending").exists())
        self.assertEqual(
            json.loads((self.state / "HEAD.json").read_bytes())["rapp_seq"], 4
        )

        self.extend_native()
        current = json.loads((self.state / "HEAD.json").read_bytes())
        abandoned = {
            **current,
            "source_commit": self.revision,
            "native_seq": 5,
            "native_frame_hash": self.planet[5]["frame_hash"],
            "tick_source_commit": self.tick_revision,
            "tick_native_seq": 5,
            "tick_native_frame_hash": self.ticks[5]["frame_hash"],
            "rapp_seq": 5,
            "rapp_frame_hash": "a" * 64,
            "rapp_payload_hash": "b" * 64,
            "rapp_utc": "2026-09-17T00:02:05.000Z",
        }
        (self.state / ".HEAD.json.pending").write_bytes(B.canonical(abandoned))
        self.assertFalse((self.state / "frames" / "5.json").exists())
        report = self.append()
        self.assertEqual(report["rapp_seq"], 5)
        self.assertNotEqual(report["rapp_frame_hash"], abandoned["rapp_frame_hash"])
        self.assertFalse((self.state / ".HEAD.json.pending").exists())
        self.assertEqual(self.verify()["status"], "verified")

    def test_ambiguous_pending_dependency_is_preserved_and_refused(self):
        self.append()
        self.extend_native()
        original_replace = B.os.replace

        def interrupt_state(source, destination):
            if B.absolute(destination) == self.state / "HEAD.json":
                raise OSError("simulated controller interruption")
            return original_replace(source, destination)

        with mock.patch.object(B.os, "replace", side_effect=interrupt_state):
            with self.assertRaisesRegex(OSError, "simulated controller interruption"):
                self.append()
        pending = self.state / ".HEAD.json.pending"
        frame = json.loads((self.state / "frames" / "3.json").read_bytes())
        source = frame["payload"]["native_source"]
        (self.state / "blobs" / f"{source['raw_sha256']}.bin").unlink()
        with self.assertRaises(OSError):
            self.append()
        self.assertTrue(pending.exists())

    def test_create_only_publication_never_exposes_partial_authority(self):
        publication = self.case / "publication"
        frames = publication / "frames"
        frames.mkdir(parents=True)
        target = frames / "0.json"
        context = multiprocessing.get_context("fork")
        process = context.Process(target=crash_before_publish_worker, args=(target,))
        process.start()
        process.join(10)
        self.assertEqual(process.exitcode, 73)
        self.assertFalse(target.exists())
        temporaries = [
            path for path in frames.iterdir() if B.TEMP_NAME.fullmatch(path.name)
        ]
        self.assertEqual(len(temporaries), 1)
        B.cleanup_object_temporaries(publication, None, None)
        self.assertEqual(list(frames.iterdir()), [])

        self.assertTrue(B.write_new_or_equal(target, b"authoritative"))
        before = target.stat()
        self.assertFalse(B.write_new_or_equal(target, b"authoritative"))
        with self.assertRaisesRegex(ValueError, "create-only object fork"):
            B.write_new_or_equal(target, b"different")
        after = target.stat()
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        self.assertEqual(target.read_bytes(), b"authoritative")

        self.append()
        head = json.loads((self.state / "HEAD.json").read_bytes())
        accepted = self.state / "frames" / "2.json"
        referenced_temp = accepted.parent / (
            f".{accepted.name}.bridge2-tmp-{'1' * 32}"
        )
        accepted.rename(referenced_temp)
        with self.assertRaisesRegex(ValueError, "references missing object"):
            B.cleanup_object_temporaries(self.state, head, None)
        self.assertTrue(referenced_temp.exists())
        self.assertFalse(accepted.exists())

    def test_native_commit_path_raw_rollback_fork_and_genesis_refuse(self):
        self.append()
        accepted = self.revision
        planet2 = self.repo / "planet" / "2.json"
        original = planet2.read_bytes()
        planet2.write_bytes(original.replace(b"planet-2", b"changed"))
        self.assertEqual(self.append()["status"], "unchanged")
        projected = json.loads((self.output / "frames" / "2.json").read_bytes())
        source = projected["payload"]["native_source"]
        self.assertEqual(
            (self.output / "blobs" / f"{source['raw_sha256']}.bin").read_bytes(),
            original,
        )
        planet2.write_bytes(original)
        with self.assertRaisesRegex(ValueError, "checked-out HEAD"):
            self.append(revision=self.initial_native_commit)
        config_path = self.state / "config.json"
        config_raw = config_path.read_bytes()
        config = json.loads(config_raw)
        config["chain_path"] = "ticks"
        config_path.write_bytes(B.canonical(config))
        with self.assertRaisesRegex(ValueError, "state source chain mismatch"):
            self.append()
        config_path.write_bytes(config_raw)

        self.write_chain("planet", self.planet[:2])
        rollback = self.commit("native chain rollback")
        with self.assertRaisesRegex(ValueError, "native source rollback"):
            self.append(revision=rollback)
        self.git("reset", "--hard", accepted)
        self.revision = accepted

        forked = copy.deepcopy(self.planet)
        forked[2] = B.NATIVE_RAPP.build_frame(
            "planet.snapshot", "planet:@kody-w/dogg-planet", 2, forked[2]["utc"],
            {**forked[2]["payload"], "note": "fork"},
            forked[1]["payload_hash"],
        )
        self.write_chain("planet", forked)
        fork_commit = self.commit("native same-sequence fork")
        with self.assertRaisesRegex(ValueError, "same-sequence native source fork"):
            self.append(revision=fork_commit)
        self.git("reset", "--hard", accepted)
        self.revision = accepted

        changed = self.make_planet(self.ticks, note="new-genesis")
        self.write_chain("planet", changed)
        changed_commit = self.commit("changed native genesis")
        with self.assertRaisesRegex(ValueError, "native genesis changed"):
            self.append(revision=changed_commit)

    def test_every_accepted_frame_has_exact_historical_native_provenance(self):
        copied = self.repo / "planet" / "historical-copy.json"
        copied.write_bytes((self.repo / "planet" / "1.json").read_bytes())
        self.commit("add misleading historical native copy")
        self.append()

        def use_copy(kind, payload):
            payload["native_source"]["storage_path"] = "planet/historical-copy.json"
            return kind, payload

        self.rewrite_signed_suffix(1, use_copy)
        with self.assertRaisesRegex(
                ValueError, "exact historical Git/native provenance"):
            self.verify()

    def test_every_accepted_frame_has_exact_historical_tick_provenance(self):
        copied = self.tick_repo / "ticks" / "historical-copy.json"
        copied.write_bytes((self.tick_repo / "ticks" / "1.json").read_bytes())
        self.tick_commit("add misleading historical tick copy")
        self.append()

        def use_copy(kind, payload):
            payload["tick_source"]["storage_path"] = "ticks/historical-copy.json"
            return kind, payload

        self.rewrite_signed_suffix(1, use_copy)
        with self.assertRaisesRegex(
                ValueError, "exact historical Git/native provenance"):
            self.verify()

    def test_source_bytes_and_modes_are_bound_to_the_commit_tree(self):
        self.write_chain("planet", self.planet, epoch_size=2, sealed_epochs=1)
        committed = self.commit("seal source for immutable tree test")
        committed_epoch = B.git_blob(
            self.repo, committed, "planet/epochs/0.jsonl"
        )
        original_check = B.check_git_source
        mutated = False

        def mutate_after_git_check(*args, **kwargs):
            nonlocal mutated
            result = original_check(*args, **kwargs)
            if not mutated:
                mutated = True
                epoch = self.repo / "planet" / "epochs" / "0.jsonl"
                epoch.write_bytes(epoch.read_bytes().replace(b"planet-1", b"mutable"))
                (self.repo / "planet" / "2.json").write_bytes(b"not native JSON\n")
            return result

        with mock.patch.object(B, "check_git_source", side_effect=mutate_after_git_check):
            self.assertEqual(self.append()["frames_verified"], 3)
        frame1 = json.loads((self.output / "frames" / "1.json").read_bytes())
        source = frame1["payload"]["native_source"]
        expected_line = committed_epoch[:-1].split(b"\n")[1]
        self.assertEqual(
            (self.output / "blobs" / f"{source['raw_sha256']}.bin").read_bytes(),
            expected_line,
        )
        self.git("checkout", "--", "planet")
        os.chmod(self.repo / "planet" / "2.json", 0o755)
        mode_commit = self.commit("make native source executable")
        self.assertIn(
            "100755",
            self.git("ls-tree", mode_commit, "planet/2.json"),
        )
        with self.assertRaisesRegex(ValueError, "mode/type is not regular 100644"):
            self.append(revision=mode_commit)

    def test_sealed_epoch_source_is_exact_opaque_line(self):
        self.write_chain("planet", self.planet, epoch_size=2, sealed_epochs=1)
        self.commit("seal native planet epoch")
        report = self.append()
        self.assertEqual(report["frames_verified"], 3)
        frame1 = json.loads((self.output / "frames" / "1.json").read_bytes())
        source = frame1["payload"]["native_source"]
        self.assertEqual(source["storage_path"], "planet/epochs/0.jsonl")
        self.assertEqual(source["storage_line"], 2)
        line = (self.repo / source["storage_path"]).read_bytes()[:-1].split(b"\n")[1]
        blob = self.output / "blobs" / f"{source['raw_sha256']}.bin"
        self.assertEqual(blob.read_bytes(), line)
        self.assertNotEqual(blob.read_bytes(), json.dumps(json.loads(line), indent=2).encode())

    def test_sealed_epoch_over_one_mib_is_valid_when_each_record_is_bounded(self):
        frames = [self.planet[0]]
        note = "x" * (600 * 1024)
        for seq in range(1, 3):
            tick = self.ticks[seq]
            frames.append(B.NATIVE_RAPP.build_frame(
                "planet.snapshot", "planet:@kody-w/dogg-planet", seq,
                f"2026-09-17T00:01:{seq:02d}.000Z",
                {"tick": seq, "tick_frame": tick["frame_hash"], "note": note},
                frames[-1]["payload_hash"],
            ))
        self.write_chain("planet", frames, epoch_size=3, sealed_epochs=1)
        epoch = self.repo / "planet" / "epochs" / "0.jsonl"
        self.assertGreater(epoch.stat().st_size, B.NATIVE_RECORD_MAX_BYTES)
        self.assertTrue(all(
            len(line) <= B.NATIVE_RECORD_MAX_BYTES
            for line in epoch.read_bytes()[:-1].split(b"\n")
        ))
        self.commit("seal valid large native epoch")

        report = self.append()
        self.assertEqual(report["frames_verified"], 3)
        self.assertEqual(self.verify()["frames_verified"], 3)

    def test_sealed_epoch_aggregate_and_record_bounds_refuse(self):
        accepted = self.revision
        cases = ("aggregate", "record", "epoch-size")
        for case in cases:
            with self.subTest(case=case):
                self.write_chain("planet", self.planet, epoch_size=2, sealed_epochs=1)
                epoch = self.repo / "planet" / "epochs" / "0.jsonl"
                lines = epoch.read_bytes()[:-1].split(b"\n")
                if case == "aggregate":
                    aggregate_limit = 2 * (B.NATIVE_RECORD_MAX_BYTES + 1)
                    epoch.write_bytes(b"{}\n" * (aggregate_limit // 3 + 1))
                    reason = "sealed epoch Git blob size outside"
                elif case == "record":
                    epoch.write_bytes(
                        b" " * (B.NATIVE_RECORD_MAX_BYTES + 1) + b"\n" +
                        lines[1] + b"\n"
                    )
                    reason = "sealed epoch record exceeds"
                else:
                    head_path = self.repo / "planet" / "HEAD.json"
                    head = json.loads(head_path.read_bytes())
                    head["epoch_size"] = B.MAX_NATIVE_EPOCH_SIZE + 1
                    head["sealed_epochs"] = 0
                    head_path.write_text(json.dumps(head, indent=2) + "\n")
                    shutil.rmtree(self.repo / "planet" / "epochs")
                    for seq, frame in enumerate(self.planet):
                        (self.repo / "planet" / f"{seq}.json").write_text(
                            json.dumps(frame, ensure_ascii=False, indent=2) + "\n"
                        )
                    reason = "native HEAD epoch_size must be in"
                invalid = self.commit(f"invalid native epoch {case}")
                with self.assertRaisesRegex(ValueError, reason):
                    self.append(revision=invalid)
                self.assertFalse(self.output.exists())
                self.git("reset", "--hard", accepted)
                self.revision = accepted

    def test_sealed_epoch_structure_and_encoding_refuse(self):
        accepted = self.revision
        cases = {
            "short": ("sealed epoch line count/gap", lambda lines: lines[:1]),
            "extra": ("sealed epoch line count/gap", lambda lines: lines + [b"{}"]),
            "order": ("native seq gap at planet/0", lambda lines: list(reversed(lines))),
            "utf8": ("native record is not valid UTF-8",
                     lambda lines: [b"\xff", lines[1]]),
            "json": ("native record is not valid JSON",
                     lambda lines: [b'{"seq":', lines[1]]),
        }
        for case, (reason, mutate) in cases.items():
            with self.subTest(case=case):
                self.write_chain("planet", self.planet, epoch_size=2, sealed_epochs=1)
                epoch = self.repo / "planet" / "epochs" / "0.jsonl"
                lines = epoch.read_bytes()[:-1].split(b"\n")
                epoch.write_bytes(b"\n".join(mutate(lines)) + b"\n")
                invalid = self.commit(f"invalid native epoch {case}")
                with self.assertRaisesRegex(ValueError, reason):
                    self.append(revision=invalid)
                self.assertFalse(self.output.exists())
                self.git("reset", "--hard", accepted)
                self.revision = accepted

    def test_wrong_or_stale_native_tick_frame_refuses(self):
        changed = copy.deepcopy(self.planet)
        changed[1] = B.NATIVE_RAPP.build_frame(
            "planet.snapshot", "planet:@kody-w/dogg-planet", 1, changed[1]["utc"],
            {"tick": 1, "tick_frame": self.ticks[0]["frame_hash"], "note": "stale"},
            changed[0]["payload_hash"],
        )
        changed[2] = B.NATIVE_RAPP.build_frame(
            "planet.snapshot", "planet:@kody-w/dogg-planet", 2, changed[2]["utc"],
            changed[2]["payload"], changed[1]["payload_hash"],
        )
        self.write_chain("planet", changed)
        self.commit("native stale tick reference")
        with self.assertRaisesRegex(ValueError, "wrong or stale native tick_frame"):
            self.append()
        self.assertFalse(self.output.exists())

    def test_tick_anchor_stream_kind_and_payload_are_exact_everywhere(self):
        accepted = self.revision
        cases = (
            ("stream", "tick:wrong/global", "tick.anchor", {"tick": 0}, "wrong stream"),
            ("kind", "tick:@kody-w/global", "planet.snapshot", {"tick": 0}, "wrong kind"),
            ("payload", "tick:@kody-w/global", "tick.anchor", {"tick": 1},
             "payload.tick must equal seq"),
        )
        for label, stream_id, kind, first_payload, reason in cases:
            with self.subTest(label=label):
                frames = []
                for seq in range(3):
                    head = frames[-1] if frames else None
                    frames.append(B.NATIVE_RAPP.build_frame(
                        kind if seq == 0 else "tick.anchor",
                        stream_id if seq == 0 else "tick:@kody-w/global",
                        seq, f"2026-09-17T00:00:{seq:02d}.000Z",
                        first_payload if seq == 0 else {"tick": seq},
                        None if head is None else head["payload_hash"],
                    ))
                self.write_chain("ticks", frames, repo=self.tick_repo)
                invalid = self.tick_commit(f"invalid tick {label}")
                with self.assertRaisesRegex(ValueError, reason):
                    self.append(tick_revision=invalid)
                self.assertFalse(self.output.exists())
                self.tick_git("reset", "--hard", self.initial_tick_commit)
                self.tick_revision = self.initial_tick_commit

        bad_tick = B.NATIVE_RAPP.build_frame(
            "planet.snapshot", "tick:@kody-w/global", 0,
            "2026-09-17T00:00:00.000Z", {"tick": 0}, None,
        )
        bad_tick_raw = B.canonical(bad_tick)
        native = B.NATIVE_RAPP.build_frame(
            "planet.snapshot", "planet:@kody-w/dogg-planet", 0,
            "2026-09-17T00:01:00.000Z",
            {"tick": 0, "tick_frame": bad_tick["frame_hash"]}, None,
        )
        native_raw = B.canonical(native)
        native_source = self.source_tuple(
            native, "planet", native_raw, B.SOURCE_REPOSITORY
        )
        tick_source = self.source_tuple(
            bad_tick, "ticks", bad_tick_raw, B.TICK_SOURCE_REPOSITORY
        )
        blobs = self.case / "opaque-blobs"
        blobs.mkdir(mode=0o700)
        (blobs / f"{native_source['raw_sha256']}.bin").write_bytes(native_raw)
        (blobs / f"{tick_source['raw_sha256']}.bin").write_bytes(bad_tick_raw)
        payload = B.frame_payload(
            native_source, bad_tick["frame_hash"], tick_source
        )
        with self.assertRaisesRegex(ValueError, "tick opaque anchor has wrong kind"):
            B.verify_opaque_payload(payload, blobs)

    def test_private_key_never_enters_repository_state_or_outputs(self):
        native_before = {
            (root.name, path.relative_to(root).as_posix()): digest(path)
            for root, chain in ((self.repo, "planet"), (self.tick_repo, "ticks"))
            for path in (root / chain).rglob("*") if path.is_file()
        }
        self.append([self.output, self.second_output])
        for root in (
                self.repo, self.tick_repo, self.state, self.output,
                self.second_output):
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                raw = path.read_bytes()
                self.assertNotIn(b"PRIVATE KEY", raw, path)
                self.assertNotEqual(path.suffix, ".pem", path)
        self.assertTrue(self.key.exists())
        self.assertNotEqual(self.key.stat().st_mode & 0o777, 0o644)
        native_after = {
            (root.name, path.relative_to(root).as_posix()): digest(path)
            for root, chain in ((self.repo, "planet"), (self.tick_repo, "ticks"))
            for path in (root / chain).rglob("*") if path.is_file()
        }
        self.assertEqual(native_before, native_after)

    def test_native_tools_and_vendor_provenance_are_immutable(self):
        for relative, expected in NATIVE_PINS.items():
            self.assertEqual(digest(ROOT / relative), expected, relative)
        provenance_path = ROOT / "tools" / "rapp1_bridge_v2_vendor" / "PROVENANCE.json"
        raw = provenance_path.read_bytes()
        provenance = json.loads(raw)
        self.assertEqual(raw, B.canonical(provenance) + b"\n")
        self.assertEqual(provenance["commit"], B.RAPP1_REFERENCE["commit"])
        for relative, vendor_name in (
            ("rapp.py", "rapp.py"),
            ("rapp_registry.py", "rapp_registry.py"),
            ("anchor/orient.json", "orient.json"),
            ("LICENSE", "LICENSE"),
        ):
            pin = provenance["files"][relative]
            vendor = ROOT / "tools" / "rapp1_bridge_v2_vendor" / vendor_name
            self.assertEqual(digest(vendor), pin["sha256"])
            self.assertEqual(vendor.stat().st_size, pin["bytes"])
        self.assertEqual(digest(ROOT / "BRIDGE2.md"), B.BRIDGE2_SPEC_SHA256)


if __name__ == "__main__":
    unittest.main()
