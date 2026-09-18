#!/usr/bin/env python3
"""Forward-only signed native DOGG/0 projection on a registered RAPP/1 memory stream."""
import argparse
import base64
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import types
import unicodedata


PROFILE = "dogg-rapp1-bridge/2"
REGISTRY_PROFILE = "dogg-rapp1-bridge-registry/1"
STATE_SCHEMA = "dogg-rapp1-bridge-state/2"
HEAD_SCHEMA = "dogg-rapp1-bridge-head/2"
SOURCE_REPOSITORY = "https://github.com/kody-w/dogg-planet.git"
TICK_SOURCE_REPOSITORY = "https://github.com/kody-w/dogg.git"
CANONICAL_REF = "refs/remotes/origin/main"
NATIVE_CHAIN_PATH = "planet"
TICK_CHAIN_PATH = "ticks"
NATIVE_RECORD_MAX_BYTES = 1024 * 1024
UINT53_MAX = 2**53 - 1
RAPP1_REFERENCE = {
    "repository": "https://github.com/kody-w/rapp-1",
    "commit": "dda32d741c7218f41443a5bd17eebfe0eae82cb7",
    "spec_path": "SPEC.md",
    "spec_sha256": "348e7d5baa94aaf2ce4c5354f3cb261f389298a04af65e271a686d3b62f7c384",
    "spec_bytes": 79692,
    "rapp_path": "rapp.py",
    "rapp_sha256": "1a04362b02f14c1e37b70c6b4f72d79e92df1cc9c2b5b394e8e1b141fc0b6050",
    "registry_path": "rapp_registry.py",
    "registry_sha256": "eec22844a32874cdb21772fc804db29220d2e2f052be9ca8a8049f2162ce95d2",
    "orient_path": "anchor/orient.json",
    "orient_sha256": "0e0356ef28ff7dae8f28fd363b6234665202110f3328c1ef8962a358527ec954",
}
# Updated only when BRIDGE2.md moves to a new subordinate-profile token.
BRIDGE2_SPEC_SHA256 = "8a8e19b08c584500e459c4cc90d1156e22740d0550af45d476ca9d21b0f3deb6"
BRIDGE2_SPEC_PATH = "BRIDGE2.md"
VENDOR = Path(__file__).resolve().parent / "rapp1_bridge_v2_vendor"
NATIVE_TOOLS = Path(__file__).resolve().parent
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX40 = re.compile(r"[0-9a-f]{40}")
SAFE_PATH = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*")
TEMP_NAME = re.compile(r"\.(?P<target>.+)\.bridge2-tmp-(?P<nonce>[0-9a-f]{32})")
SOURCE_KEYS = {
    "repository", "commit", "chain_path", "storage_path", "storage_line",
    "raw_sha256", "raw_bytes", "native_stream_id", "native_genesis_frame_hash",
    "native_seq", "native_frame_hash", "native_utc",
}
PAYLOAD_KEYS = {"profile", "native_source", "tick_frame", "tick_source"}
REGISTRY_KEYS = {
    "schema", "profile", "canonical_source", "registry_seq", "entries", "sig",
}
CONFIG_KEYS = {
    "schema", "profile", "canonical_source", "source_repository", "chain_path",
    "tick_source_repository", "tick_chain_path", "stream_id", "trust_anchor",
    "rapp1_reference", "bridge2_spec_sha256",
}
HEAD_KEYS = {
    "schema", "profile", "registry_seq", "registry_sha256", "registry_checkpoint",
    "source_commit", "chain_path", "native_seq", "native_frame_hash",
    "native_genesis_frame_hash", "tick_source_commit", "tick_native_seq",
    "tick_native_frame_hash", "tick_native_genesis_frame_hash", "rapp_seq",
    "rapp_frame_hash", "rapp_payload_hash", "rapp_utc", "stream_id",
}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def absolute(path):
    return Path(os.path.abspath(os.fspath(path)))


def real_directory(path):
    path = absolute(path)
    for component in reversed((path, *path.parents)):
        require(stat.S_ISDIR(component.lstat().st_mode),
                f"not a real directory (symlinks forbidden): {component}")
    return path


def real_file(path, limit=1024 * 1024):
    path = absolute(path)
    real_directory(path.parent)
    require(stat.S_ISREG(path.lstat().st_mode), f"not a regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        require(stat.S_ISREG(info.st_mode), f"not a regular file: {path}")
        require(0 < info.st_size <= limit, f"file size outside 1..{limit}: {path}")
        raw = handle.read(limit + 1)
    require(0 < len(raw) <= limit, f"file size outside 1..{limit}: {path}")
    return raw


def path_within(path, root):
    return _path_relation(path, root) in {"equal", "descendant"}


def paths_overlap(left, right):
    return _path_relation(left, right) != "disjoint"


def _path_walk(path):
    path = absolute(path)
    parts = path.parts
    require(parts and path.anchor, f"path has no absolute anchor: {path}")
    current = Path(path.anchor)
    prefixes = []
    info = os.stat(current)
    prefixes.append(((info.st_dev, info.st_ino), 0, current))
    for consumed, part in enumerate(parts[1:], 1):
        current = current / part
        try:
            info = os.stat(current)
        except FileNotFoundError:
            break
        except NotADirectoryError as exc:
            raise ValueError(f"path crosses a non-directory: {current}") from exc
        prefixes.append(((info.st_dev, info.st_ino), consumed, current))
    return {
        "path": path,
        "parts": parts[1:],
        "prefixes": prefixes,
        "complete": prefixes[-1][1] == len(parts) - 1,
    }


def _alternate_case(name):
    for index, char in enumerate(name):
        if char.isalpha() and char.lower() != char.upper():
            changed = char.upper() if char != char.upper() else char.lower()
            return name[:index] + changed + name[index + 1:]
    return None


def _filesystem_alias_support(directory, need_case, need_unicode):
    support_case = not need_case
    support_unicode = not need_unicode
    determined_case = not need_case
    determined_unicode = not need_unicode
    directory = absolute(directory)
    device = os.stat(directory).st_dev
    inspected = set()
    while True:
        identity = (os.stat(directory).st_dev, os.stat(directory).st_ino)
        if identity in inspected or identity[0] != device:
            break
        inspected.add(identity)
        try:
            entries = list(os.scandir(directory))
        except OSError:
            return True, True
        for entry in entries:
            candidates = []
            if not support_case:
                candidate = _alternate_case(entry.name)
                if candidate is not None:
                    candidates.append(("case", candidate))
            if not support_unicode:
                for form in ("NFC", "NFD"):
                    candidate = unicodedata.normalize(form, entry.name)
                    if candidate != entry.name:
                        candidates.append(("unicode", candidate))
            for kind, candidate in candidates:
                try:
                    alternate = os.stat(directory / candidate)
                    original = os.stat(directory / entry.name)
                except (FileNotFoundError, NotADirectoryError):
                    if kind == "case":
                        determined_case = True
                    else:
                        determined_unicode = True
                    continue
                except OSError:
                    return True, True
                if (alternate.st_dev, alternate.st_ino) == (original.st_dev, original.st_ino):
                    if kind == "case":
                        support_case = True
                    else:
                        support_unicode = True
                elif kind == "case":
                    determined_case = True
                else:
                    determined_unicode = True
            if support_case and support_unicode:
                return support_case, support_unicode
        parent = directory.parent
        if parent == directory:
            break
        try:
            if os.stat(parent).st_dev != device:
                break
        except OSError:
            return True, True
        directory = parent
    if need_case and not determined_case:
        support_case = True
    if need_unicode and not determined_unicode:
        support_unicode = True
    return support_case, support_unicode


def _components_alias(directory, left, right):
    if left == right:
        return True
    left_nfc = unicodedata.normalize("NFC", left)
    right_nfc = unicodedata.normalize("NFC", right)
    if left_nfc.casefold() != right_nfc.casefold():
        return False
    need_case = left_nfc != right_nfc and left_nfc.casefold() == right_nfc.casefold()
    need_unicode = left != left_nfc or right != right_nfc
    case_alias, unicode_alias = _filesystem_alias_support(
        directory, need_case, need_unicode
    )
    return case_alias and unicode_alias


def _path_relation(left, right):
    left_walk = _path_walk(left)
    right_walk = _path_walk(right)
    relations = []
    for left_identity, left_consumed, left_directory in left_walk["prefixes"]:
        for right_identity, right_consumed, _ in right_walk["prefixes"]:
            if left_identity != right_identity:
                continue
            left_tail = left_walk["parts"][left_consumed:]
            right_tail = right_walk["parts"][right_consumed:]
            matched = 0
            for left_part, right_part in zip(left_tail, right_tail):
                if not _components_alias(left_directory, left_part, right_part):
                    break
                matched += 1
            else:
                if matched == len(left_tail) == len(right_tail):
                    relations.append("equal")
                elif matched == len(left_tail):
                    relations.append("ancestor")
                elif matched == len(right_tail):
                    relations.append("descendant")
    if "equal" in relations:
        return "equal"
    if "ancestor" in relations:
        return "ancestor"
    if "descendant" in relations:
        return "descendant"
    return "disjoint"


def safe_relative(value, label):
    require(isinstance(value, str) and SAFE_PATH.fullmatch(value), f"unsafe {label}")
    require(all(part not in ("", ".", "..") for part in value.split("/")), f"unsafe {label}")
    return value


def run(args, cwd=None, data=None, timeout=30, pass_fds=(), env=None):
    result = subprocess.run(
        [os.fspath(a) for a in args],
        cwd=os.fspath(cwd) if cwd is not None else None,
        input=data,
        capture_output=True,
        timeout=timeout,
        pass_fds=pass_fds,
        env=env,
    )
    require(result.returncode == 0,
            f"{Path(os.fspath(args[0])).name} refused ({result.returncode})")
    return result.stdout


def git_environment():
    for name in ("GIT_REPLACE_REF_BASE", "GIT_GRAFT_FILE", "GIT_SHALLOW_FILE"):
        require(not os.environ.get(name), f"Git ancestry override environment is forbidden: {name}")
    repository_overrides = (
        "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    )
    for name in repository_overrides:
        require(not os.environ.get(name), f"Git repository override environment is forbidden: {name}")
    env = os.environ.copy()
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    for name in (
        "GIT_REPLACE_REF_BASE", "GIT_GRAFT_FILE", "GIT_SHALLOW_FILE",
        *repository_overrides,
    ):
        env.pop(name, None)
    env.pop("GIT_CONFIG_COUNT", None)
    for name in tuple(env):
        if name.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
            env.pop(name)
    return env


def git(root, *args):
    return run(
        ["git", "--no-replace-objects", *args],
        cwd=root,
        env=git_environment(),
    ).decode("utf-8").strip()


def git_blob(root, revision, path):
    safe_relative(path, "Git object path")
    return run(
        ["git", "--no-replace-objects", "cat-file", "blob", f"{revision}:{path}"],
        cwd=root,
        env=git_environment(),
    )


def git_tree_files(root, revision, path):
    safe_relative(path, "Git tree path")
    raw = run(
        ["git", "--no-replace-objects", "ls-tree", "-rz", "--full-tree", revision, "--", path],
        cwd=root,
        env=git_environment(),
    )
    entries = {}
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        metadata, separator, encoded_path = encoded.partition(b"\t")
        require(separator == b"\t", "malformed Git tree entry")
        fields = metadata.split()
        require(len(fields) == 3, "malformed Git tree metadata")
        mode, kind, oid = (field.decode("ascii") for field in fields)
        tree_path = encoded_path.decode("utf-8")
        safe_relative(tree_path, "Git tree entry path")
        require(tree_path == path or tree_path.startswith(path + "/"),
                "Git tree entry escaped selected chain")
        require(tree_path not in entries, "duplicate Git tree path")
        entries[tree_path] = {"mode": mode, "kind": kind, "oid": oid}
    return entries


def git_tree_blob_entry(root, tree, path):
    safe_relative(path, "Git object path")
    entry = tree.get(path)
    require(entry is not None, f"native Git object is absent: {path}")
    require(entry["kind"] == "blob" and entry["mode"] == "100644",
            f"native Git mode/type is not regular 100644: {path}")
    require(HEX40.fullmatch(entry["oid"]), f"invalid native Git blob oid: {path}")
    size_raw = run(
        ["git", "--no-replace-objects", "cat-file", "-s", entry["oid"]],
        cwd=root,
        env=git_environment(),
    )
    require(re.fullmatch(rb"[0-9]+\n?", size_raw) is not None,
            f"invalid native Git blob size: {path}")
    return entry, int(size_raw)


def git_tree_blob(root, tree, path, limit=NATIVE_RECORD_MAX_BYTES):
    entry, size = git_tree_blob_entry(root, tree, path)
    require(0 < size <= limit, f"Git blob size outside 1..{limit}: {path}")
    raw = run(
        ["git", "--no-replace-objects", "cat-file", "blob", entry["oid"]],
        cwd=root,
        env=git_environment(),
    )
    require(len(raw) == size, f"Git blob size/output mismatch: {path}")
    return raw


def git_tree_epoch_lines(root, tree, path, epoch_size):
    limit = epoch_size * (NATIVE_RECORD_MAX_BYTES + 1)
    entry, size = git_tree_blob_entry(root, tree, path)
    require(0 < size <= limit,
            f"sealed epoch Git blob size outside 1..{limit}: {path}")
    process = subprocess.Popen(
        ["git", "--no-replace-objects", "cat-file", "blob", entry["oid"]],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=git_environment(),
    )
    lines = []
    consumed = 0
    try:
        require(process.stdout is not None, "Git blob stream unavailable")
        for line_number in range(1, epoch_size + 1):
            raw = process.stdout.readline(NATIVE_RECORD_MAX_BYTES + 2)
            require(raw, f"sealed epoch line count/gap: {path}")
            if not raw.endswith(b"\n"):
                require(
                    len(raw) <= NATIVE_RECORD_MAX_BYTES,
                    f"sealed epoch record exceeds {NATIVE_RECORD_MAX_BYTES} bytes "
                    f"at line {line_number}: {path}",
                )
                raise ValueError(f"sealed epoch lacks final LF: {path}")
            value = raw[:-1]
            require(value, f"sealed epoch line count/gap: {path}")
            require(
                len(value) <= NATIVE_RECORD_MAX_BYTES,
                f"sealed epoch record exceeds {NATIVE_RECORD_MAX_BYTES} bytes "
                f"at line {line_number}: {path}",
            )
            consumed += len(raw)
            lines.append(value)
        require(process.stdout.read(1) == b"",
                f"sealed epoch line count/gap: {path}")
        require(process.wait(timeout=30) == 0, "git refused while streaming epoch")
        require(consumed == size, f"Git blob size/output mismatch: {path}")
        return lines
    except BaseException:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        raise
    finally:
        if process.stdout is not None:
            process.stdout.close()


def git_ancestor(root, older, newer, reason):
    result = subprocess.run(
        ["git", "--no-replace-objects", "merge-base", "--is-ancestor", older, newer],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=git_environment(),
    )
    require(result.returncode == 0, reason)


def git_internal_path(root, name):
    value = git(root, "rev-parse", "--git-path", name)
    path = Path(value)
    return absolute(path if path.is_absolute() else absolute(root) / path)


def source_repository_root(root):
    supplied = real_directory(root)
    value = git(supplied, "rev-parse", "--show-toplevel")
    require(value and "\n" not in value, "Git returned an invalid top-level path")
    top = Path(value)
    require(top.is_absolute(), "Git top-level is not absolute")
    top = real_directory(top)
    supplied_info = supplied.stat()
    top_info = top.stat()
    require(
        (supplied_info.st_dev, supplied_info.st_ino) ==
        (top_info.st_dev, top_info.st_ino),
        "source_root must be the exact Git top-level directory",
    )
    return top


def reject_git_ancestry_overrides(root):
    require(
        git(root, "rev-parse", "--is-shallow-repository") == "false",
        "shallow Git history is forbidden",
    )
    require(
        not os.path.lexists(git_internal_path(root, "info/grafts")),
        "Git graft state is forbidden",
    )
    replacements = git(
        root, "for-each-ref", "--format=%(refname)", "refs/replace"
    ).splitlines()
    require(not replacements, "Git replacement state is forbidden")


def check_git_commit(root, revision, main_ref, repository=SOURCE_REPOSITORY):
    root = source_repository_root(root)
    require(
        main_ref == CANONICAL_REF,
        "CLI main ref differs from the configured canonical source ref",
    )
    reject_git_ancestry_overrides(root)
    require(HEX40.fullmatch(revision or ""), "source revision must be a full SHA-1 commit")
    require(git(root, "rev-parse", "--show-object-format") == "sha1", "unsupported Git object format")
    require(git(root, "rev-parse", "--verify", f"{revision}^{{commit}}") == revision,
            "source revision is not an immutable commit")
    remotes = git(
        root, "config", "--local", "--get-all", "remote.origin.url"
    ).splitlines()
    require(remotes == [repository],
            "origin does not exactly match the configured native repository")
    require(
        HEX40.fullmatch(
            git(root, "rev-parse", "--verify", f"{CANONICAL_REF}^{{commit}}")
        ),
        "configured canonical source ref is not a commit",
    )
    git_ancestor(root, revision, main_ref,
                 "source revision is not on the configured canonical main history")
    return root


def check_git_source(root, revision, main_ref, repository=SOURCE_REPOSITORY):
    root = check_git_commit(root, revision, main_ref, repository)
    require(git(root, "rev-parse", "HEAD") == revision,
            "source revision must equal the checked-out HEAD")
    return root


def load_module(path, name):
    raw = real_file(path, 512 * 1024)
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def load_references():
    pins = {
        "rapp.py": RAPP1_REFERENCE["rapp_sha256"],
        "rapp_registry.py": RAPP1_REFERENCE["registry_sha256"],
        "orient.json": RAPP1_REFERENCE["orient_sha256"],
    }
    for name, digest in pins.items():
        require(sha256(real_file(VENDOR / name, 512 * 1024)) == digest,
                f"canonical RAPP/1 {name} pin mismatch")
    rapp = load_module(VENDOR / "rapp.py", "_dogg_bridge_v2_rapp")
    prior = sys.modules.get("rapp")
    sys.modules["rapp"] = rapp
    try:
        registry = load_module(VENDOR / "rapp_registry.py", "_dogg_bridge_v2_registry")
    finally:
        if prior is None:
            del sys.modules["rapp"]
        else:
            sys.modules["rapp"] = prior
    return rapp, registry


R, REG = load_references()
REFERENCE_VERIFY_JWS = R.verify_detached_jws
NATIVE_RAPP = load_module(NATIVE_TOOLS / "rapp.py", "_dogg_native_rapp")
CHAINIO = load_module(NATIVE_TOOLS / "chainio.py", "_dogg_native_chainio")
MAX_NATIVE_EPOCH_SIZE = CHAINIO.EPOCH_SIZE


def canonical(value):
    return R.canonical(value).encode("utf-8")


def read_canonical(path, keys=None, limit=1024 * 1024):
    raw = real_file(path, limit)
    value = R._strict_json(raw)
    require(raw == canonical(value), f"non-canonical JSON: {path}")
    if keys is not None:
        require(isinstance(value, dict) and set(value) == keys, f"wrong key set: {path}")
    return value, raw


def fsync_directory(path):
    path = real_directory(path)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        require(stat.S_ISDIR(os.fstat(fd).st_mode), f"not a real directory: {path}")
        os.fsync(fd)
    finally:
        os.close(fd)


def mkdir_durable(path, mode=0o700):
    path = absolute(path)
    real_directory(path.parent)
    os.mkdir(path, mode)
    fsync_directory(path)
    fsync_directory(path.parent)
    return path


def _publish_new(path, raw, mode=0o600, equal_ok=False):
    path = absolute(path)
    real_directory(path.parent)
    temp = path.parent / f".{path.name}.bridge2-tmp-{secrets.token_hex(16)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temp, flags, mode)
    published = False
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temp, path, follow_symlinks=False)
            published = True
        except FileExistsError:
            if not equal_ok:
                raise ValueError(f"create-only destination already exists: {path}")
            try:
                existing = real_file(path, max(len(raw), 1))
            except ValueError as exc:
                raise ValueError(f"create-only object fork: {path}") from exc
            require(existing == raw, f"create-only object fork: {path}")
        temp.unlink()
        fsync_directory(path.parent)
        return published
    finally:
        if os.path.lexists(temp):
            temp.unlink()


def write_new(path, raw, mode=0o600):
    _publish_new(path, raw, mode=mode, equal_ok=False)


def write_new_or_equal(path, raw):
    return _publish_new(path, raw, equal_ok=True)


def replace_canonical(path, value, observed=None):
    path = absolute(path)
    raw = canonical(value)
    scratch = path.parent / f".{path.name}.pending"
    write_new_or_equal(scratch, raw)
    require(load_head(path) == observed,
            f"persistent high-water changed after pending write: {path}")
    os.replace(scratch, path)
    fsync_directory(path.parent)


def now_utc():
    value = datetime.datetime.now(datetime.timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _der_value(raw, offset, tag):
    require(offset < len(raw) and raw[offset] == tag, "invalid public SPKI DER")
    offset += 1
    require(offset < len(raw), "truncated public SPKI DER")
    size = raw[offset]
    offset += 1
    if size & 0x80:
        count = size & 0x7f
        require(0 < count <= 4 and offset + count <= len(raw),
                "invalid public SPKI DER length")
        encoded = raw[offset:offset + count]
        require(encoded[0] != 0, "non-minimal public SPKI DER length")
        size = int.from_bytes(encoded, "big")
        require(size >= 128, "non-minimal public SPKI DER length")
        offset += count
    end = offset + size
    require(end <= len(raw), "truncated public SPKI DER")
    return raw[offset:end], end


def spki_jws_algorithm(spki_der):
    require(isinstance(spki_der, bytes), "registered owner SPKI is not bytes")
    outer, end = _der_value(spki_der, 0, 0x30)
    require(end == len(spki_der), "trailing public SPKI DER")
    algorithm, offset = _der_value(outer, 0, 0x30)
    key_bits, offset = _der_value(outer, offset, 0x03)
    require(offset == len(outer) and key_bits[:1] == b"\0",
            "invalid public SPKI bit string")
    oid, algorithm_offset = _der_value(algorithm, 0, 0x06)
    if oid == bytes.fromhex("2a8648ce3d0201"):
        curve, algorithm_offset = _der_value(algorithm, algorithm_offset, 0x06)
        require(
            algorithm_offset == len(algorithm) and
            curve == bytes.fromhex("2a8648ce3d030107") and
            len(key_bits) == 66 and key_bits[1:2] == b"\x04",
            "ES256 requires a registered P-256 public SPKI",
        )
        return "ES256"
    if oid == bytes.fromhex("2b6570"):
        require(
            algorithm_offset == len(algorithm) and len(key_bits) == 33,
            "EdDSA requires a registered Ed25519 public SPKI",
        )
        return "EdDSA"
    raise ValueError("registered owner SPKI is neither P-256 nor Ed25519")


def parse_ecdsa_der(raw):
    require(len(raw) >= 8 and raw[0] == 0x30 and raw[1] == len(raw) - 2,
            "OpenSSL returned a non-minimal ECDSA signature")
    at = 2
    values = []
    for _ in range(2):
        require(at + 2 <= len(raw) and raw[at] == 0x02, "invalid ECDSA DER integer")
        size = raw[at + 1]
        at += 2
        require(0 < size <= 33 and at + size <= len(raw), "invalid ECDSA DER integer size")
        value = raw[at:at + size]
        at += size
        require(not (len(value) > 1 and value[0] == 0 and value[1] < 0x80),
                "non-minimal ECDSA DER integer")
        require(value[0] < 0x80, "negative ECDSA DER integer")
        value = value.lstrip(b"\0")
        require(len(value) <= 32, "ES256 integer exceeds 256 bits")
        values.append(value.rjust(32, b"\0"))
    require(at == len(raw), "trailing ECDSA DER bytes")
    return b"".join(values)


def encode_ecdsa_der(raw):
    require(len(raw) == 64, "ES256 signature must be 64 bytes")
    encoded = []
    for value in (raw[:32], raw[32:]):
        value = value.lstrip(b"\0") or b"\0"
        if value[0] & 0x80:
            value = b"\0" + value
        encoded.append(b"\x02" + bytes([len(value)]) + value)
    body = b"".join(encoded)
    return b"\x30" + bytes([len(body)]) + body


def private_directory(path):
    path = real_directory(path)
    info = path.lstat()
    validate_private_directory_info(info, path)
    return path


def validate_private_directory_info(info, path):
    require(stat.S_ISDIR(info.st_mode), f"private key directory is not real: {path}")
    require(info.st_uid == os.getuid(), f"private key directory has wrong owner: {path}")
    require(stat.S_IMODE(info.st_mode) == 0o700,
            f"private key directory mode must be exactly 0700: {path}")


@contextlib.contextmanager
def private_directory_descriptor(path):
    path = private_directory(path)
    before = path.lstat()
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        validate_private_directory_info(opened, path)
        require((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino),
                f"private key directory changed while opening: {path}")
        yield path, fd
    finally:
        os.close(fd)


def validate_private_key_info(info, path):
    require(stat.S_ISREG(info.st_mode), f"private signing key is not regular: {path}")
    require(info.st_uid == os.getuid(), f"private signing key has wrong owner: {path}")
    require(stat.S_IMODE(info.st_mode) == 0o600,
            f"private signing key mode must be exactly 0600: {path}")
    require(info.st_nlink == 1, f"private signing key must have one link: {path}")
    require(0 < info.st_size <= 64 * 1024, f"private signing key size is invalid: {path}")


@contextlib.contextmanager
def private_key_descriptor(private_key):
    path = absolute(private_key)
    with private_directory_descriptor(path.parent) as (_, directory_fd):
        before = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        validate_private_key_info(before, path)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path.name, flags, dir_fd=directory_fd)
        try:
            opened = os.fstat(fd)
            validate_private_key_info(opened, path)
            require((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino),
                    f"private signing key changed while opening: {path}")
            yield fd
        finally:
            os.close(fd)


def read_private_key(private_key):
    with private_key_descriptor(private_key) as fd:
        chunks = []
        while True:
            chunk = os.read(fd, 8192)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def public_spki(private_key):
    with private_key_descriptor(private_key) as fd:
        return run(
            ["openssl", "pkey", "-in", f"/dev/fd/{fd}", "-pubout", "-outform", "DER"],
            pass_fds=(fd,),
        )


def keyed_rappid(owner, slug, private_key):
    spki = public_spki(private_key)
    rappid = R.mint_rappid(owner, slug, spki_der=spki)
    return rappid, spki


def sign_detached(value, private_key, kid):
    header = {"alg": "ES256", "b64": False, "crit": ["b64"], "kid": kid}
    protected = b64url(canonical(header))
    signing_input = protected.encode("ascii") + b"." + canonical(value)
    with private_key_descriptor(private_key) as fd:
        der = run(
            ["openssl", "dgst", "-sha256", "-sign", f"/dev/fd/{fd}"],
            data=signing_input, pass_fds=(fd,),
        )
    return protected + ".." + b64url(parse_ecdsa_der(der))


def openssl_verify(signing_input, signature, spki_der, algorithm, scratch_root):
    scratch_root = real_directory(scratch_root)
    stem = f".verify-{os.getpid()}-{hashlib.sha256(signing_input + signature).hexdigest()[:16]}"
    public_path = scratch_root / (stem + ".der")
    signature_path = scratch_root / (stem + ".sig")
    try:
        write_new(public_path, spki_der)
        if algorithm == "ES256":
            encoded_signature = encode_ecdsa_der(signature)
            command = [
                "openssl", "dgst", "-sha256", "-verify", public_path,
                "-keyform", "DER", "-signature", signature_path,
            ]
        else:
            require(len(signature) == 64, "EdDSA signature must be 64 bytes")
            encoded_signature = signature
            command = [
                "openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                "-keyform", "DER", "-inkey", public_path,
                "-sigfile", signature_path,
            ]
        write_new(signature_path, encoded_signature)
        result = subprocess.run(
            command,
            input=signing_input,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    finally:
        for path in (public_path, signature_path):
            if os.path.lexists(path):
                path.unlink()


def verify_detached(value, sig, spki_der, expected_kid, scratch_root):
    try:
        header, protected, signature = R.parse_detached_jws(sig)
        require(header["kid"] == expected_kid, "JWS kid does not match required signer")
        algorithm = spki_jws_algorithm(spki_der)
        require(header["alg"] == algorithm,
                f"JWS alg does not match registered owner key; expected {algorithm}")
    except (ValueError, TypeError) as exc:
        return False, str(exc)
    ok, why = REFERENCE_VERIFY_JWS(value, sig, spki_der, expected_kid=expected_kid)
    if ok or "cryptography is required" not in why:
        return ok, why
    try:
        require(R.Hb("rapp/1:rappid", spki_der) == R.rappid_parts(expected_kid)["hash"],
                "JWS key does not match the kid RAPPID tail")
        signing_input = protected.encode("ascii") + b"." + canonical(value)
        require(openssl_verify(signing_input, signature, spki_der, algorithm, scratch_root),
                "detached JWS signature is invalid")
        return True, "ok"
    except (OSError, ValueError, TypeError) as exc:
        return False, str(exc)


@contextlib.contextmanager
def registry_crypto(scratch_root):
    original = R.verify_detached_jws
    R.verify_detached_jws = (
        lambda value, sig, spki_der, expected_kid=None:
        verify_detached(value, sig, spki_der, expected_kid, scratch_root)
    )
    try:
        yield
    finally:
        R.verify_detached_jws = original


def registry_signature_verifier(registry, scratch_root):
    def verify(unsigned, sig, expected_signer=None):
        try:
            require(isinstance(sig, str) and sig,
                    "bridge/2 requires a non-null detached JWS")
            header = R.parse_detached_jws(sig)[0]
            kid = header["kid"]
            required = expected_signer or registry.estate_owner
            require(kid == required == registry.estate_owner,
                    "bridge frames must be signed by the estate owner")
            spki = registry.spki_der(required)
            require(spki is not None, "bridge signer has no registered SPKI")
            algorithm = spki_jws_algorithm(spki)
            require(header["alg"] == algorithm,
                    f"JWS alg does not match registered owner key; expected {algorithm}")
            utc = unsigned.get("utc")
            require(R.utc_valid(utc), "signed frame has no valid UTC")
            ok, why = registry.signer_acceptable(kid, utc)
            require(ok, why)
            return verify_detached(unsigned, sig, spki, kid, scratch_root)
        except (ValueError, TypeError) as exc:
            return False, str(exc)
    return verify


def strict_native(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate native JSON member")
            value[key] = item
        return value
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("native record is not valid UTF-8") from exc

    def invalid_constant(value):
        raise ValueError(f"invalid native JSON constant: {value}")

    try:
        value = json.loads(
            text, object_pairs_hook=pairs, parse_constant=invalid_constant
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("native record is not valid JSON") from exc
    require(isinstance(value, dict), "native JSON record must be an object")
    return value


def native_storage(root, chain_path, meta, tree):
    count = meta.get("count")
    sealed = meta.get("sealed_epochs", 0)
    epoch_size = meta.get("epoch_size", CHAINIO.EPOCH_SIZE)
    require(type(count) is int and 0 < count <= 2**53 - 1, "native HEAD count")
    require(type(sealed) is int and sealed >= 0, "native HEAD sealed_epochs")
    require(
        type(epoch_size) is int and 0 < epoch_size <= MAX_NATIVE_EPOCH_SIZE,
        f"native HEAD epoch_size must be in 1..{MAX_NATIVE_EPOCH_SIZE}",
    )
    require(sealed * epoch_size <= count, "native sealed storage exceeds count")
    records = []
    expected_files = [f"{chain_path}/HEAD.json"]
    for epoch in range(sealed):
        rel = f"{chain_path}/epochs/{epoch}.jsonl"
        expected_files.append(rel)
        lines = git_tree_epoch_lines(root, tree, rel, epoch_size)
        for line, value in enumerate(lines):
            records.append({
                "raw": value, "storage_path": rel, "storage_line": line + 1,
                "frame": strict_native(value),
            })
    for seq in range(sealed * epoch_size, count):
        rel = f"{chain_path}/{seq}.json"
        expected_files.append(rel)
        raw = git_tree_blob(root, tree, rel)
        records.append({
            "raw": raw, "storage_path": rel, "storage_line": None,
            "frame": strict_native(raw),
        })
    return records, expected_files


def verify_native_chain(root, revision, chain_path, main_ref,
                        repository=SOURCE_REPOSITORY, cache=None):
    chain_path = safe_relative(chain_path, "native chain path")
    root = check_git_commit(root, revision, main_ref, repository)
    key = (str(root), revision, chain_path, main_ref, repository)
    if cache is not None and key in cache:
        return cache[key]
    tree = git_tree_files(root, revision, chain_path)
    head_raw = git_tree_blob(root, tree, f"{chain_path}/HEAD.json")
    meta = strict_native(head_raw)
    records, _ = native_storage(root, chain_path, meta, tree)
    frames = [record["frame"] for record in records]
    require(len(frames) == len(records) == meta["count"], "native chain gap")
    head = None
    for seq, (frame, record) in enumerate(zip(frames, records)):
        require(frame == record["frame"], f"native storage/parser mismatch at seq {seq}")
        require(frame.get("seq") == seq, f"native seq gap at {chain_path}/{seq}")
        if chain_path == TICK_CHAIN_PATH:
            validate_tick_anchor(frame, seq, f"native tick anchor {seq}")
        ok, step, why = NATIVE_RAPP.verify_frame(
            frame, head=head, stream_id_of_record=meta.get("stream_id")
        )
        require(ok, f"native oracle refused {chain_path}/{seq}: {step}: {why}")
        head = frame
    require(head["frame_hash"] == meta.get("head_frame"), "native HEAD frame mismatch")
    result = {
        "meta": meta, "frames": frames, "records": records,
        "genesis": frames[0]["frame_hash"], "root": root, "revision": revision,
        "chain_path": chain_path, "repository": repository,
    }
    if cache is not None:
        cache[key] = result
    return result


def source_tuple(chain, seq):
    frame = chain["frames"][seq]
    record = chain["records"][seq]
    return {
        "repository": chain["repository"],
        "commit": chain["revision"],
        "chain_path": chain["chain_path"],
        "storage_path": record["storage_path"],
        "storage_line": record["storage_line"],
        "raw_sha256": sha256(record["raw"]),
        "raw_bytes": len(record["raw"]),
        "native_stream_id": frame["stream_id"],
        "native_genesis_frame_hash": chain["genesis"],
        "native_seq": frame["seq"],
        "native_frame_hash": frame["frame_hash"],
        "native_utc": frame["utc"],
    }


def validate_tick_anchor(frame, seq=None, label="tick anchor"):
    require(isinstance(frame, dict), f"{label} is not an object")
    require(frame.get("stream_id") == "tick:@kody-w/global",
            f"{label} has wrong stream")
    require(frame.get("kind") == "tick.anchor", f"{label} has wrong kind")
    actual_seq = frame.get("seq")
    require(type(actual_seq) is int and (seq is None or actual_seq == seq),
            f"{label} has wrong sequence")
    payload = frame.get("payload")
    require(isinstance(payload, dict) and type(payload.get("tick")) is int and
            payload["tick"] == actual_seq,
            f"{label} payload.tick must equal seq")


def provenance_for(chain, seq, ticks=None):
    frame = chain["frames"][seq]
    payload = frame.get("payload")
    require(isinstance(payload, dict), "native payload must be an object")
    native = source_tuple(chain, seq)
    is_tick = (
        frame.get("kind") == "tick.anchor" or
        frame.get("stream_id") == "tick:@kody-w/global"
    )
    has_tick = "tick" in payload
    has_tick_frame = "tick_frame" in payload
    if is_tick:
        validate_tick_anchor(frame, seq)
        require(not has_tick_frame, "native tick anchor unexpectedly references another tick")
        return native, None, None
    if not has_tick and not has_tick_frame:
        return native, None, None
    require(has_tick and has_tick_frame, "tick-referencing native payload is incomplete")
    tick = payload["tick"]
    tick_frame = payload["tick_frame"]
    require(type(tick) is int and 0 <= tick <= 2**53 - 1, "native tick reference is not uint53")
    require(isinstance(tick_frame, str) and HEX64.fullmatch(tick_frame),
            "native tick_frame is not 64 lowercase hex")
    require(ticks is not None, "tick-referencing native frame requires an external tick chain")
    require(ticks["repository"] == TICK_SOURCE_REPOSITORY,
            "tick chain repository is not the configured spine")
    require(ticks["chain_path"] == TICK_CHAIN_PATH,
            "tick chain path is not the configured spine")
    require(tick < len(ticks["frames"]), "native tick reference is beyond the verified spine")
    actual = ticks["frames"][tick]
    require(actual["frame_hash"] == tick_frame, "wrong or stale native tick_frame")
    return native, tick_frame, source_tuple(ticks, tick)


def validate_source_tuple(value, repository):
    require(isinstance(value, dict) and set(value) == SOURCE_KEYS, "native source tuple key set")
    require(value["repository"] == repository, "native source repository")
    require(HEX40.fullmatch(value["commit"] or ""), "native source commit")
    safe_relative(value["chain_path"], "native chain path")
    safe_relative(value["storage_path"], "native storage path")
    require(value["storage_path"].startswith(value["chain_path"] + "/"),
            "native storage path is outside its chain")
    require(value["storage_line"] is None or
            type(value["storage_line"]) is int and value["storage_line"] > 0,
            "native storage line")
    require(HEX64.fullmatch(value["raw_sha256"] or ""), "native raw SHA-256")
    require(type(value["raw_bytes"]) is int and
            0 < value["raw_bytes"] <= NATIVE_RECORD_MAX_BYTES,
            "native raw byte count")
    require(isinstance(value["native_stream_id"], str), "native stream id")
    require(HEX64.fullmatch(value["native_genesis_frame_hash"] or ""), "native genesis")
    require(type(value["native_seq"]) is int and 0 <= value["native_seq"] <= 2**53 - 1,
            "native sequence")
    require(HEX64.fullmatch(value["native_frame_hash"] or ""), "native frame hash")
    require(NATIVE_RAPP._UTC.match(value["native_utc"] or ""), "native UTC")


def frame_payload(native, tick_frame, tick_source):
    return {
        "profile": PROFILE,
        "native_source": native,
        "tick_frame": tick_frame,
        "tick_source": tick_source,
    }


def build_signed_frame(stream_id, seq, utc, payload, head, private_key, signer):
    prev = None if head is None else head["payload_hash"]
    frame = R.build_frame("memory.save", stream_id, seq, utc, payload, prev, prev_wave=None)
    unsigned = {key: value for key, value in frame.items() if key != "sig"}
    frame["sig"] = sign_detached(unsigned, private_key, signer)
    return frame


def protocol_entry(registry, name):
    matches = [
        entry for entry in registry.entries
        if entry["type"] == "protocol" and entry["name"] == name and not entry["deprecated"]
    ]
    require(len(matches) == 1, f"registry needs one live {name} protocol pin")
    return matches[0]


def validate_canonical_source(value):
    require(isinstance(value, dict) and set(value) == {"repository", "ref", "path"},
            "registry canonical_source key set")
    require(value["repository"] == SOURCE_REPOSITORY,
            "registry canonical_source repository")
    require(value["ref"] == CANONICAL_REF,
            "registry canonical_source ref")
    safe_relative(value["path"], "canonical registry path")


def verify_registry_raw(raw, trust_anchor, canonical_source, expected_genesis,
                        stream_id, scratch_root, persisted=None):
    validate_canonical_source(canonical_source)
    doc = R._strict_json(raw)
    require(raw == canonical(doc), "registry bytes are not canonical JCS")
    require(isinstance(doc, dict) and set(doc) == REGISTRY_KEYS, "registry top-level key set")
    require(doc["schema"] == "rapp/1-registry", "registry schema")
    require(doc["profile"] == REGISTRY_PROFILE, "registry profile")
    require(doc["canonical_source"] == canonical_source, "registry canonical_source mismatch")
    with registry_crypto(scratch_root):
        status, registry, why = REG.load_document(
            doc,
            entries_member="entries",
            trust_anchor=trust_anchor,
            persisted_seq=None if persisted is None else persisted["seq"],
        )
    require(status == "verified", f"registry refused: {why}")
    rapp_pin = protocol_entry(registry, "rapp/1")
    require(rapp_pin == {
        "type": "protocol", "name": "rapp/1",
        "spec_repo": RAPP1_REFERENCE["repository"],
        "spec_path": RAPP1_REFERENCE["spec_path"],
        "spec_hash": RAPP1_REFERENCE["spec_sha256"],
        "deprecated": False,
    }, "wrong canonical RAPP/1 protocol pin")
    bridge_pin = protocol_entry(registry, PROFILE)
    require(bridge_pin == {
        "type": "protocol", "name": PROFILE,
        "spec_repo": SOURCE_REPOSITORY,
        "spec_path": BRIDGE2_SPEC_PATH,
        "spec_hash": BRIDGE2_SPEC_SHA256,
        "deprecated": False,
    }, "wrong bridge/2 protocol pin")
    require(registry.family("memory.save") == "memory", "memory.save is not registry-bound to memory")
    genesis = registry.registered_genesis(stream_id)
    require(genesis is not None and genesis["frame_hash"] == expected_genesis,
            "registry genesis binding mismatch")
    if persisted is not None:
        seq = doc["registry_seq"]
        if seq == persisted["seq"]:
            require(sha256(raw) == persisted["sha256"], "same-sequence registry fork")
        else:
            require(seq == persisted["seq"] + 1, "registry sequence gap or rollback")
            old = persisted["doc"]
            require(doc["entries"][:len(old["entries"])] == old["entries"],
                    "registry append history was removed or rewritten")
    return doc, registry


def registry_from_git(root, checkpoint, source_revision, main_ref, config,
                      expected_genesis, scratch_root, persisted=None):
    require(
        main_ref == config["canonical_source"]["ref"] == CANONICAL_REF,
        "registry checkpoint ref differs from the configured canonical source ref",
    )
    require(HEX40.fullmatch(checkpoint or ""), "registry checkpoint must be a full SHA-1 commit")
    require(git(root, "rev-parse", "--verify", f"{checkpoint}^{{commit}}") == checkpoint,
            "registry checkpoint is not a commit")
    git_ancestor(root, checkpoint, main_ref, "registry checkpoint is not on canonical main")
    git_ancestor(root, checkpoint, source_revision,
                 "registry checkpoint is not an ancestor of the native source commit")
    raw = git_blob(root, checkpoint, config["canonical_source"]["path"])
    doc, registry = verify_registry_raw(
        raw, config["trust_anchor"], config["canonical_source"], expected_genesis,
        config["stream_id"], scratch_root, persisted=persisted,
    )
    return doc, registry, raw


def make_registry(canonical_source, owner, spki, stream_id, genesis_hash,
                  private_key, registry_seq=0, entries=None):
    if entries is None:
        entries = [
            {"type": "estate_owner", "rappid": owner},
            {"type": "spki", "rappid": owner,
             "spki_der_b64": base64.b64encode(spki).decode("ascii"), "deprecated": False},
            {"type": "protocol", "name": "rapp/1",
             "spec_repo": RAPP1_REFERENCE["repository"],
             "spec_path": RAPP1_REFERENCE["spec_path"],
             "spec_hash": RAPP1_REFERENCE["spec_sha256"], "deprecated": False},
            {"type": "protocol", "name": PROFILE, "spec_repo": SOURCE_REPOSITORY,
             "spec_path": BRIDGE2_SPEC_PATH, "spec_hash": BRIDGE2_SPEC_SHA256,
             "deprecated": False},
            {"type": "kind", "kind": "memory.save", "family": "memory", "deprecated": False},
            {"type": "genesis", "stream_id": stream_id,
             "frame_hash": genesis_hash, "deprecated": False},
        ]
    unsigned = {
        "schema": "rapp/1-registry",
        "profile": REGISTRY_PROFILE,
        "canonical_source": canonical_source,
        "registry_seq": registry_seq,
        "entries": entries,
    }
    return {**unsigned, "sig": sign_detached(unsigned, private_key, owner)}


def key_path(value, repository_roots, forbidden=()):
    value = value or os.environ.get("DOGG_RAPP1_BRIDGE_SIGNING_KEY")
    require(value, "signing configuration absent: set --signing-key or DOGG_RAPP1_BRIDGE_SIGNING_KEY")
    path = absolute(value)
    read_private_key(path)
    if isinstance(repository_roots, (str, os.PathLike)):
        repository_roots = (repository_roots,)
    for root in repository_roots:
        require(not path_within(path, root),
                "private signing key must be outside source repositories")
    for item in forbidden:
        require(not path_within(path, item), "private signing key must be outside state/output")
    return path


@contextlib.contextmanager
def controller_lock(state):
    with private_directory_descriptor(state) as (_, directory_fd):
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(".append.lock", flags, 0o600, dir_fd=directory_fd)
        try:
            opened = os.fstat(fd)
            require(stat.S_ISREG(opened.st_mode), "controller lock is not a regular file")
            require(opened.st_uid == os.getuid(), "controller lock has wrong owner")
            require(stat.S_IMODE(opened.st_mode) == 0o600,
                    "controller lock mode must be exactly 0600")
            require(opened.st_nlink == 1, "controller lock must have one link")
            os.fsync(directory_fd)
            fcntl.flock(fd, fcntl.LOCK_EX)
            current = os.stat(
                ".append.lock", dir_fd=directory_fd, follow_symlinks=False
            )
            require((current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino),
                    "controller lock changed while waiting")
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def append_paths(source_root, tick_source_root, state, outputs):
    source_root = source_repository_root(source_root)
    tick_source_root = source_repository_root(tick_source_root)
    state = real_directory(state)
    normalized = [absolute(output) for output in outputs]
    require(normalized, "at least one --out is required")
    require(not paths_overlap(source_root, tick_source_root),
            "planet and tick sources must be separate Git repositories")
    for repository_root in (source_root, tick_source_root):
        require(not paths_overlap(state, repository_root),
                "controller state must be disjoint from source repositories")
    for output in normalized:
        for repository_root in (source_root, tick_source_root):
            require(not paths_overlap(output, repository_root),
                    "bridge output must be disjoint from source repositories")
        require(not paths_overlap(output, state),
                "bridge output must be disjoint from controller state")
    for index, output in enumerate(normalized):
        for other in normalized[index + 1:]:
            require(not paths_overlap(output, other),
                    "bridge outputs must be pairwise disjoint")
    for output in normalized:
        real_directory(output if os.path.lexists(output) else output.parent)
    return source_root, tick_source_root, state, normalized


def trust_anchor(value):
    value = value or os.environ.get("DOGG_RAPP1_BRIDGE_TRUST_ANCHOR")
    require(R.rappid_valid(value), "explicit out-of-band trust anchor is required")
    return value


def config_value(canonical_source, chain_path, stream_id, anchor):
    return {
        "schema": STATE_SCHEMA,
        "profile": PROFILE,
        "canonical_source": canonical_source,
        "source_repository": SOURCE_REPOSITORY,
        "chain_path": chain_path,
        "tick_source_repository": TICK_SOURCE_REPOSITORY,
        "tick_chain_path": TICK_CHAIN_PATH,
        "stream_id": stream_id,
        "trust_anchor": anchor,
        "rapp1_reference": RAPP1_REFERENCE,
        "bridge2_spec_sha256": BRIDGE2_SPEC_SHA256,
    }


def initialize(source_root, source_revision, tick_source_root, tick_source_commit,
               chain_path, main_ref, owner, slug, canonical_registry_path,
               state, registry_out, signing_key):
    source_root = check_git_source(source_root, source_revision, main_ref)
    tick_source_root = check_git_source(
        tick_source_root, tick_source_commit, CANONICAL_REF,
        TICK_SOURCE_REPOSITORY,
    )
    chain_path = safe_relative(chain_path, "native chain path")
    require(chain_path == NATIVE_CHAIN_PATH,
            f"federated bridge source chain must be exactly {NATIVE_CHAIN_PATH}")
    canonical_registry_path = safe_relative(canonical_registry_path, "canonical registry path")
    state = absolute(state)
    registry_out = absolute(registry_out)
    require(not os.path.lexists(state), "state already exists; initialization is mint-once")
    require(not os.path.lexists(registry_out), "registry output is create-only")
    require(not paths_overlap(source_root, tick_source_root),
            "planet and tick sources must be separate Git repositories")
    for repository_root in (source_root, tick_source_root):
        require(not paths_overlap(state, repository_root) and
                not paths_overlap(registry_out, repository_root),
                "initial state and registry output must be disjoint from source repositories")
    require(not paths_overlap(state, registry_out),
            "initial state and registry output must be disjoint")
    real_directory(state.parent)
    real_directory(registry_out.parent)
    private_key = key_path(
        signing_key, (source_root, tick_source_root), (state, registry_out)
    )
    anchor, spki = keyed_rappid(owner, slug, private_key)
    stream_id = anchor + ":dogg-bridge"
    canonical_source = {
        "repository": SOURCE_REPOSITORY,
        "ref": CANONICAL_REF,
        "path": canonical_registry_path,
    }
    cache = {}
    chain = verify_native_chain(
        source_root, source_revision, chain_path, main_ref, cache=cache
    )
    ticks = verify_native_chain(
        tick_source_root, tick_source_commit, TICK_CHAIN_PATH, CANONICAL_REF,
        TICK_SOURCE_REPOSITORY, cache=cache,
    )
    native, tick_frame, tick_source = provenance_for(chain, 0, ticks)
    require(tick_source is not None,
            "every planet frame must resolve an external native tick anchor")
    projection_utc = now_utc()
    frame = build_signed_frame(
        stream_id, 0, projection_utc,
        frame_payload(native, tick_frame, tick_source), None, private_key, anchor,
    )
    registry = make_registry(
        canonical_source, anchor, spki, stream_id, frame["frame_hash"], private_key
    )
    registry_raw = canonical(registry)
    mkdir_durable(state)
    for name in ("frames", "blobs", "registries"):
        mkdir_durable(state / name)
    config = config_value(canonical_source, chain_path, stream_id, anchor)
    write_new(state / "config.json", canonical(config))
    write_new(state / "blobs" / f"{native['raw_sha256']}.bin", chain["records"][0]["raw"])
    if tick_source is not None:
        tick_chain = cache[(
            str(tick_source_root), tick_source_commit, TICK_CHAIN_PATH,
            CANONICAL_REF, TICK_SOURCE_REPOSITORY,
        )]
        write_new_or_equal(
            state / "blobs" / f"{tick_source['raw_sha256']}.bin",
            tick_chain["records"][tick_source["native_seq"]]["raw"],
        )
    write_new(state / "frames" / "0.json", canonical(frame))
    write_new(state / "registry-candidate.json", registry_raw)
    verify_registry_raw(
        registry_raw, anchor, canonical_source, frame["frame_hash"],
        stream_id, state,
    )
    write_new(registry_out, registry_raw)
    return {
        "status": "initialized-owner-action-required",
        "profile": PROFILE,
        "trust_anchor": anchor,
        "stream_id": stream_id,
        "registry_seq": 0,
        "registry_sha256": sha256(registry_raw),
        "genesis_frame_hash": frame["frame_hash"],
        "owner_action": "publish registry bytes at canonical_source on protected main, distribute trust_anchor out of band, then append with that commit checkpoint",
    }


def load_config(state):
    state = real_directory(state)
    config, _ = read_canonical(state / "config.json", CONFIG_KEYS)
    require(config["schema"] == STATE_SCHEMA and config["profile"] == PROFILE, "wrong state profile")
    require(config["source_repository"] == SOURCE_REPOSITORY, "state repository mismatch")
    require(config["chain_path"] == NATIVE_CHAIN_PATH, "state source chain mismatch")
    require(config["tick_source_repository"] == TICK_SOURCE_REPOSITORY,
            "state tick repository mismatch")
    require(config["tick_chain_path"] == TICK_CHAIN_PATH,
            "state tick chain mismatch")
    require(config["rapp1_reference"] == RAPP1_REFERENCE, "state RAPP/1 pin mismatch")
    require(config["bridge2_spec_sha256"] == BRIDGE2_SPEC_SHA256, "state bridge/2 pin mismatch")
    require(config["canonical_source"] == {
        "repository": SOURCE_REPOSITORY,
        "ref": CANONICAL_REF,
        "path": config["canonical_source"]["path"],
    }, "state canonical_source closure")
    safe_relative(config["canonical_source"]["path"], "canonical registry path")
    safe_relative(config["chain_path"], "native chain path")
    require(R.rappid_valid(config["trust_anchor"]), "state anchor")
    require(config["stream_id"] == config["trust_anchor"] + ":dogg-bridge", "state stream")
    return state, config


def load_head(path):
    if not os.path.lexists(path):
        return None
    head, _ = read_canonical(path, HEAD_KEYS)
    require(head["schema"] == HEAD_SCHEMA and head["profile"] == PROFILE, "wrong bridge head")
    require(type(head["registry_seq"]) is int and
            0 <= head["registry_seq"] <= UINT53_MAX,
            "bridge head registry sequence")
    require(HEX64.fullmatch(head["registry_sha256"] or ""),
            "bridge head registry hash")
    require(HEX40.fullmatch(head["registry_checkpoint"] or ""),
            "bridge head registry checkpoint")
    require(HEX40.fullmatch(head["source_commit"] or ""),
            "bridge head source commit")
    require(HEX40.fullmatch(head["tick_source_commit"] or ""),
            "bridge head tick source commit")
    safe_relative(head["chain_path"], "bridge head chain path")
    require(type(head["native_seq"]) is int and
            0 <= head["native_seq"] <= UINT53_MAX,
            "bridge head native sequence")
    require(HEX64.fullmatch(head["native_frame_hash"] or "") and
            HEX64.fullmatch(head["native_genesis_frame_hash"] or ""),
            "bridge head native hash")
    require(type(head["tick_native_seq"]) is int and
            0 <= head["tick_native_seq"] <= UINT53_MAX,
            "bridge head tick sequence")
    require(HEX64.fullmatch(head["tick_native_frame_hash"] or "") and
            HEX64.fullmatch(head["tick_native_genesis_frame_hash"] or ""),
            "bridge head tick hash")
    require(type(head["rapp_seq"]) is int and
            0 <= head["rapp_seq"] <= UINT53_MAX,
            "bridge head RAPP sequence")
    require(HEX64.fullmatch(head["rapp_frame_hash"] or "") and
            HEX64.fullmatch(head["rapp_payload_hash"] or ""),
            "bridge head RAPP hash")
    require(R.utc_valid(head["rapp_utc"]), "bridge head RAPP UTC")
    require(isinstance(head["stream_id"], str), "bridge head stream")
    require(head["native_seq"] == head["rapp_seq"],
            "bridge head native/RAPP sequence mismatch")
    return head


def validate_head_transition(current, candidate, label):
    if current is None:
        return
    require(candidate["stream_id"] == current["stream_id"], f"{label} stream fork")
    require(candidate["chain_path"] == current["chain_path"],
            f"{label} native source path changed")
    require(candidate["native_genesis_frame_hash"] ==
            current["native_genesis_frame_hash"], f"{label} native genesis changed")
    require(candidate["tick_native_genesis_frame_hash"] ==
            current["tick_native_genesis_frame_hash"], f"{label} tick genesis changed")
    require(candidate["rapp_seq"] >= current["rapp_seq"], f"{label} RAPP rollback")
    if candidate["rapp_seq"] == current["rapp_seq"]:
        require(
            candidate["rapp_frame_hash"] == current["rapp_frame_hash"] and
            candidate["rapp_payload_hash"] == current["rapp_payload_hash"] and
            candidate["rapp_utc"] == current["rapp_utc"],
            f"same-sequence {label} RAPP fork",
        )
        require(
            candidate["source_commit"] == current["source_commit"] and
            candidate["native_seq"] == current["native_seq"] and
            candidate["native_frame_hash"] == current["native_frame_hash"] and
            candidate["tick_source_commit"] == current["tick_source_commit"] and
            candidate["tick_native_seq"] == current["tick_native_seq"] and
            candidate["tick_native_frame_hash"] == current["tick_native_frame_hash"],
            f"same-sequence {label} source metadata fork",
        )
    require(candidate["registry_seq"] >= current["registry_seq"],
            f"{label} registry rollback")
    if candidate["registry_seq"] == current["registry_seq"]:
        require(candidate["registry_sha256"] == current["registry_sha256"],
                f"same-sequence {label} registry fork")


def validate_head_frame(head, frame, config, label):
    native = validate_frame_payload(frame, head["rapp_seq"], config)
    tick = frame["payload"]["tick_source"]
    require(
        frame["frame_hash"] == head["rapp_frame_hash"] and
        frame["payload_hash"] == head["rapp_payload_hash"] and
        frame["utc"] == head["rapp_utc"] and
        frame["stream_id"] == head["stream_id"] == config["stream_id"],
        f"same-sequence {label} RAPP fork",
    )
    require(
        native["commit"] == head["source_commit"] and
        native["chain_path"] == head["chain_path"] and
        native["native_seq"] == head["native_seq"] == head["rapp_seq"] and
        native["native_frame_hash"] == head["native_frame_hash"] and
        native["native_genesis_frame_hash"] == head["native_genesis_frame_hash"],
        f"{label} source metadata mismatch",
    )
    require(
        tick is not None and
        tick["commit"] == head["tick_source_commit"] and
        tick["native_seq"] == head["tick_native_seq"] and
        tick["native_frame_hash"] == head["tick_native_frame_hash"] and
        tick["native_genesis_frame_hash"] == head["tick_native_genesis_frame_hash"],
        f"{label} tick source metadata mismatch",
    )
    return native


def pending_head_path(root):
    return absolute(root) / ".HEAD.json.pending"


def _read_temp(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink in (1, 2),
                f"untrusted bridge temporary inode: {path}")
        chunks = []
        while True:
            chunk = os.read(fd, 8192)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks), (info.st_dev, info.st_ino)
    finally:
        os.close(fd)


def _numbered_object_paths(root, kind):
    directory = real_directory(absolute(root) / kind)
    numbered = []
    for path in directory.iterdir():
        match = re.fullmatch(r"([0-9]+)\.json", path.name)
        if match is None:
            continue
        try:
            seq = int(match.group(1))
        except ValueError as exc:
            raise ValueError(f"{kind} object sequence is not uint53: {path.name}") from exc
        require(seq <= UINT53_MAX, f"{kind} object sequence is not uint53: {path.name}")
        numbered.append((seq, path))
    numbered.sort(key=lambda item: item[0])
    require(
        all(seq == expected for expected, (seq, _) in enumerate(numbered)),
        f"{kind} object sequence gap",
    )
    return numbered


def _retained_object_counts(root):
    return {
        "frames": len(_numbered_object_paths(root, "frames")),
        "registries": len(_numbered_object_paths(root, "registries")),
    }


def _bound_head_to_objects(head, counts, label, allow_next=False,
                           frame_reason=None):
    if head is None:
        return
    frame_limit = counts["frames"] if allow_next else counts["frames"] - 1
    registry_limit = counts["registries"] if allow_next else counts["registries"] - 1
    require(
        head["rapp_seq"] <= frame_limit and head["native_seq"] <= frame_limit,
        frame_reason or f"{label} sequence is ahead of retained frame objects",
    )
    require(
        head["registry_seq"] <= registry_limit,
        f"{label} registry sequence is ahead of retained registry objects",
    )


def _head_object_references(root, heads, initialized_state=False):
    blob_names = set()
    for head in heads:
        require(
            type(head.get("rapp_seq")) is int and
            type(head.get("native_seq")) is int and
            type(head.get("registry_seq")) is int and
            0 <= head["rapp_seq"] <= UINT53_MAX and
            0 <= head["native_seq"] <= UINT53_MAX and
            0 <= head["registry_seq"] <= UINT53_MAX,
            "bridge head sequence is not uint53",
        )
    max_frame = max((head["rapp_seq"] for head in heads), default=-1)
    max_registry = max((head["registry_seq"] for head in heads), default=-1)
    if initialized_state and max_frame < 0:
        max_frame = 0
    frame_paths = [
        path for seq, path in _numbered_object_paths(root, "frames")
        if seq <= max_frame
    ]
    incomplete = len(frame_paths) != max_frame + 1
    for path in frame_paths:
        frame, _ = read_frame(path)
        for source in (
            frame["payload"].get("native_source"),
            frame["payload"].get("tick_source"),
        ):
            if isinstance(source, dict) and HEX64.fullmatch(source.get("raw_sha256", "")):
                blob_names.add(f"{source['raw_sha256']}.bin")
    return {
        "frame_max": max_frame,
        "registry_max": max_registry,
        "blobs": blob_names,
        "blobs_incomplete": incomplete,
    }


def cleanup_object_temporaries(root, current, pending, initialized_state=False):
    root = absolute(root)
    if not os.path.lexists(root):
        return
    heads = [head for head in (current, pending) if head is not None]
    references = _head_object_references(root, heads, initialized_state)
    locations = [(root, "root")]
    for name in ("frames", "blobs", "registries"):
        path = root / name
        if os.path.lexists(path):
            locations.append((real_directory(path), name))
    for directory, kind in locations:
        changed = False
        for path in list(directory.iterdir()):
            match = TEMP_NAME.fullmatch(path.name)
            if match is None:
                continue
            target_name = match.group("target")
            allowed = (
                kind == "frames" and re.fullmatch(r"[0-9]+\.json", target_name) or
                kind == "blobs" and re.fullmatch(r"[0-9a-f]{64}\.bin", target_name) or
                kind == "registries" and re.fullmatch(r"[0-9]+\.json", target_name) or
                kind == "root" and (
                    target_name == ".HEAD.json.pending" or
                    re.fullmatch(r"\.verify-[0-9]+-[0-9a-f]{16}\.(?:der|sig)", target_name)
                )
            )
            require(allowed, f"unrecognized bridge temporary name: {path}")
            raw, identity = _read_temp(path)
            target = directory / target_name
            if os.path.lexists(target):
                target_raw = real_file(target, max(len(raw), 1) + 1)
                target_info = target.stat()
                require(raw == target_raw or
                        identity == (target_info.st_dev, target_info.st_ino),
                        f"ambiguous bridge temporary collision: {path}")
            else:
                numbered = re.fullmatch(r"([0-9]+)\.json", target_name)
                referenced = (
                    kind == "frames" and numbered is not None and
                    int(numbered.group(1)) <= references["frame_max"] or
                    kind == "registries" and numbered is not None and
                    int(numbered.group(1)) <= references["registry_max"] or
                    kind == "blobs" and (
                        target_name in references["blobs"] or
                        references["blobs_incomplete"]
                    )
                )
                require(not referenced,
                        f"ambiguous bridge temporary references missing object: {path}")
            path.unlink()
            changed = True
        if changed:
            fsync_directory(directory)


def persisted_registry(state, head):
    if head is None:
        raw = real_file(state / "registry-candidate.json")
        doc = R._strict_json(raw)
        return {"seq": doc["registry_seq"], "sha256": sha256(raw), "doc": doc, "candidate": True}
    raw = real_file(state / "registries" / f"{head['registry_seq']}.json")
    require(sha256(raw) == head["registry_sha256"], "persisted registry hash mismatch")
    return {
        "seq": head["registry_seq"], "sha256": head["registry_sha256"],
        "doc": R._strict_json(raw), "candidate": False,
    }


def read_frame(path):
    frame, raw = read_canonical(path, R.FRAME_KEYS)
    return frame, raw


def validate_frame_payload(frame, seq, config=None):
    require(frame["kind"] == "memory.save", "bridge frame kind must be exactly memory.save")
    require(isinstance(frame["sig"], str) and frame["sig"],
            "bridge/2 requires a non-null detached JWS")
    payload = frame["payload"]
    require(isinstance(payload, dict) and set(payload) == PAYLOAD_KEYS, "bridge payload key set")
    require(payload["profile"] == PROFILE, "bridge payload profile")
    native = payload["native_source"]
    validate_source_tuple(native, SOURCE_REPOSITORY)
    require(native["native_seq"] == seq == frame["seq"], "native/RAPP sequence mismatch")
    if config is not None:
        require(native["chain_path"] == config["chain_path"],
                "projected native chain path differs from initialized source")
    require(isinstance(payload["tick_frame"], str) and
            HEX64.fullmatch(payload["tick_frame"]), "invalid projected tick_frame")
    validate_source_tuple(payload["tick_source"], TICK_SOURCE_REPOSITORY)
    require(payload["tick_source"]["native_frame_hash"] == payload["tick_frame"],
            "projected tick tuple/hash mismatch")
    require(payload["tick_source"]["chain_path"] == TICK_CHAIN_PATH,
            "projected tick source path")
    require(payload["tick_source"]["native_stream_id"] == "tick:@kody-w/global",
            "projected tick source stream")
    return native


def verify_opaque_payload(payload, blob_directory):
    native = payload["native_source"]
    raw = real_file(blob_directory / f"{native['raw_sha256']}.bin")
    require(len(raw) == native["raw_bytes"] and sha256(raw) == native["raw_sha256"],
            "native opaque blob mismatch")
    value = strict_native(raw)
    require(value.get("stream_id") == native["native_stream_id"] and
            value.get("seq") == native["native_seq"] and
            value.get("frame_hash") == native["native_frame_hash"] and
            value.get("utc") == native["native_utc"],
            "native opaque blob does not match its provenance tuple")
    native_payload = value.get("payload")
    require(isinstance(native_payload, dict), "native opaque payload is not an object")
    if (native["chain_path"] == "ticks" or value.get("kind") == "tick.anchor" or
            value.get("stream_id") == "tick:@kody-w/global"):
        validate_tick_anchor(value, native["native_seq"], "native opaque tick anchor")
    tick = payload["tick_source"]
    if tick is None:
        require(payload["tick_frame"] is None, "tick_frame without tick source")
        require("tick_frame" not in native_payload,
                "native tick_frame was omitted from bridge provenance")
        return
    require(native_payload.get("tick_frame") == payload["tick_frame"],
            "projected tick_frame differs from the native payload")
    require(native_payload.get("tick") == tick["native_seq"],
            "projected tick source sequence differs from the native payload")
    tick_raw = real_file(blob_directory / f"{tick['raw_sha256']}.bin")
    require(len(tick_raw) == tick["raw_bytes"] and sha256(tick_raw) == tick["raw_sha256"],
            "tick opaque blob mismatch")
    tick_value = strict_native(tick_raw)
    require(tick_value.get("stream_id") == tick["native_stream_id"] and
            tick_value.get("seq") == tick["native_seq"] and
            tick_value.get("frame_hash") == tick["native_frame_hash"] and
            tick_value.get("utc") == tick["native_utc"],
            "tick opaque blob does not match its provenance tuple")
    validate_tick_anchor(tick_value, tick["native_seq"], "tick opaque anchor")


def verify_frame_chain(state, config, registry, scratch_root, through=None):
    entries = list((state / "frames").iterdir())
    require(all(path.is_file() and path.suffix == ".json" and path.stem.isdigit()
                for path in entries), "unexpected candidate frame entry")
    names = sorted(int(path.stem) for path in entries)
    require(
        names and all(seq == expected for expected, seq in enumerate(names)),
        "candidate frame gap",
    )
    if through is not None:
        require(through <= names[-1],
                "controller RAPP rollback: retained frame chain is behind accepted head")
        names = names[:through + 1]
    head = None
    frames = []
    source_identity = None
    tick_genesis = None
    verifier = registry_signature_verifier(registry, scratch_root)
    for seq in names:
        frame, raw = read_frame(state / "frames" / f"{seq}.json")
        native = validate_frame_payload(frame, seq, config)
        identity = (native["native_stream_id"], native["native_genesis_frame_hash"])
        source_identity = identity if source_identity is None else source_identity
        require(identity == source_identity, "projected native identity/genesis changed")
        tick = frame["payload"]["tick_source"]
        if tick is not None:
            tick_genesis = tick["native_genesis_frame_hash"] if tick_genesis is None else tick_genesis
            require(tick["native_genesis_frame_hash"] == tick_genesis,
                    "projected tick genesis changed")
        ok, step, why = R.verify_frame(
            frame, head=head, stream_id_of_record=config["stream_id"],
            signature_verifier=verifier,
        )
        require(ok, f"RAPP frame {seq} refused at {step}: {why}")
        bound, why = registry.check_frame_binding(frame)
        require(bound, f"RAPP frame {seq} registry binding: {why}")
        verify_opaque_payload(frame["payload"], state / "blobs")
        frames.append((frame, raw))
        head = frame
    return frames


def verify_candidate_provenance(source_root, tick_source_root, candidate, main_ref,
                                current_revision, current_tick_commit, cache):
    payload = candidate["payload"]
    native = payload["native_source"]
    git_ancestor(source_root, native["commit"], current_revision,
                 "candidate source commit is not an ancestor of current source")
    historical = verify_native_chain(
        source_root, native["commit"], native["chain_path"], main_ref, cache=cache
    )
    require(native["native_seq"] < len(historical["frames"]),
            "candidate native sequence is absent from its historical commit")
    recorded_tick = payload["tick_source"]
    historical_ticks = verify_native_chain(
        tick_source_root, recorded_tick["commit"], TICK_CHAIN_PATH, CANONICAL_REF,
        TICK_SOURCE_REPOSITORY, cache=cache,
    )
    expected_native, expected_tick_frame, expected_tick = provenance_for(
        historical, native["native_seq"], historical_ticks
    )
    require(native == expected_native,
            "candidate native tuple is not the exact historical Git/native provenance")
    require(payload["tick_frame"] == expected_tick_frame and
            payload["tick_source"] == expected_tick,
            "candidate tick tuple is not the exact historical Git/native provenance")
    raw = historical["records"][native["native_seq"]]["raw"]
    require(raw == real_file(
        Path(cache["_state"]) / "blobs" / f"{native['raw_sha256']}.bin"
    ), "candidate native raw-byte mismatch")
    current = verify_native_chain(
        source_root, current_revision, native["chain_path"], main_ref, cache=cache
    )
    require(native["native_seq"] < len(current["frames"]) and
            current["frames"][native["native_seq"]]["frame_hash"] == native["native_frame_hash"] and
            current["genesis"] == native["native_genesis_frame_hash"],
            "candidate native frame is not retained by the current verified chain")
    require(expected_tick is not None, "planet projection omitted external tick provenance")
    git_ancestor(
        tick_source_root, expected_tick["commit"], current_tick_commit,
        "candidate tick commit is not an ancestor of current tick source",
    )
    tick_raw = historical_ticks["records"][expected_tick["native_seq"]]["raw"]
    require(tick_raw == real_file(
        Path(cache["_state"]) / "blobs" / f"{expected_tick['raw_sha256']}.bin"
    ), "candidate tick raw-byte mismatch")
    ticks = verify_native_chain(
        tick_source_root, current_tick_commit, TICK_CHAIN_PATH, CANONICAL_REF,
        TICK_SOURCE_REPOSITORY, cache=cache,
    )
    require(expected_tick["native_seq"] < len(ticks["frames"]) and
            ticks["frames"][expected_tick["native_seq"]]["frame_hash"] ==
            expected_tick["native_frame_hash"] and
            ticks["genesis"] == expected_tick["native_genesis_frame_hash"],
            "candidate tick is not retained by the current verified spine")
    require(payload["tick_frame"] == expected_tick["native_frame_hash"],
            "candidate wrong or stale tick_frame")


def head_value(registry_doc, registry_raw, registry_checkpoint, frame, config):
    native = frame["payload"]["native_source"]
    tick = frame["payload"]["tick_source"]
    require(tick is not None, "planet head has no external tick provenance")
    return {
        "schema": HEAD_SCHEMA,
        "profile": PROFILE,
        "registry_seq": registry_doc["registry_seq"],
        "registry_sha256": sha256(registry_raw),
        "registry_checkpoint": registry_checkpoint,
        "source_commit": native["commit"],
        "chain_path": native["chain_path"],
        "native_seq": native["native_seq"],
        "native_frame_hash": native["native_frame_hash"],
        "native_genesis_frame_hash": native["native_genesis_frame_hash"],
        "tick_source_commit": tick["commit"],
        "tick_native_seq": tick["native_seq"],
        "tick_native_frame_hash": tick["native_frame_hash"],
        "tick_native_genesis_frame_hash": tick["native_genesis_frame_hash"],
        "rapp_seq": frame["seq"],
        "rapp_frame_hash": frame["frame_hash"],
        "rapp_payload_hash": frame["payload_hash"],
        "rapp_utc": frame["utc"],
        "stream_id": config["stream_id"],
    }


def output_layout(out, expected_objects=None):
    out = absolute(out)
    if not os.path.lexists(out):
        real_directory(out.parent)
        mkdir_durable(out)
    else:
        real_directory(out)
    names = {entry.name for entry in out.iterdir()}
    require(names <= {
        "frames", "blobs", "registries", "HEAD.json", ".HEAD.json.pending",
    },
            f"unexpected bridge output entries: {out}")
    has_authority = (
        os.path.lexists(out / "HEAD.json") or
        os.path.lexists(out / ".HEAD.json.pending")
    )
    missing = []
    for name in ("frames", "blobs", "registries"):
        path = out / name
        if not os.path.lexists(path):
            missing.append(path)
            continue
        real_directory(path)
        if expected_objects is not None:
            entries = list(path.iterdir())
            require(
                all(stat.S_ISREG(entry.lstat().st_mode) for entry in entries),
                f"non-file or linked output object entry: {path}",
            )
            require(
                {entry.name for entry in entries} <= expected_objects[name],
                f"unexpected output object entry: {path}",
            )
    if missing:
        require(
            not has_authority,
            f"output layout recovery forbidden after HEAD/pending authority: {missing[0]}",
        )
    for path in missing:
        mkdir_durable(path)
    return out


def commit_head(path, head, observed):
    require(load_head(path) == observed,
            f"persistent high-water changed before replacement: {path}")
    validate_head_transition(observed, head, "persistent head")
    replace_canonical(path, head, observed=observed)


def deliver(state, out, frames, registry_doc, registry_raw, head):
    retained_registries = _numbered_object_paths(state, "registries")
    require(
        head["registry_seq"] < len(retained_registries),
        "controller registry objects are behind delivery head",
    )
    registry_objects = {
        path.name: real_file(path)
        for _, path in retained_registries[:head["registry_seq"] + 1]
    }
    require(
        registry_objects[f"{registry_doc['registry_seq']}.json"] == registry_raw,
        "controller registry object differs from selected checkpoint",
    )
    blob_names = {
        f"{source['raw_sha256']}.bin"
        for frame, _ in frames
        for source in (
            frame["payload"]["native_source"],
            frame["payload"]["tick_source"],
        )
        if source is not None
    }
    expected_objects = {
        "frames": {f"{frame['seq']}.json" for frame, _ in frames},
        "blobs": blob_names,
        "registries": set(registry_objects),
    }
    out = output_layout(out, expected_objects)
    existing = load_head(out / "HEAD.json")
    if existing is not None:
        require(existing["stream_id"] == head["stream_id"], "output stream fork")
        require(existing["rapp_seq"] <= head["rapp_seq"], "output RAPP rollback")
        if existing["rapp_seq"] == head["rapp_seq"]:
            require(existing["rapp_frame_hash"] == head["rapp_frame_hash"],
                    "same-sequence output RAPP fork")
        require(existing["native_genesis_frame_hash"] == head["native_genesis_frame_hash"],
                "output native genesis changed")
        require(existing["tick_native_genesis_frame_hash"] ==
                head["tick_native_genesis_frame_hash"],
                "output tick genesis changed")
        require(existing["registry_seq"] <= head["registry_seq"], "output registry rollback")
        if existing["registry_seq"] == head["registry_seq"]:
            require(existing["registry_sha256"] == head["registry_sha256"],
                    "same-sequence output registry fork")
    for name, raw in registry_objects.items():
        write_new_or_equal(out / "registries" / name, raw)
    for frame, raw in frames:
        for source in (frame["payload"]["native_source"], frame["payload"]["tick_source"]):
            if source is None:
                continue
            digest = source["raw_sha256"]
            blob = real_file(state / "blobs" / f"{digest}.bin")
            write_new_or_equal(out / "blobs" / f"{digest}.bin", blob)
    for frame, raw in frames:
        write_new_or_equal(out / "frames" / f"{frame['seq']}.json", raw)
    commit_head(out / "HEAD.json", head, existing)


def verify_output_objects(out, config, registry, registry_raw, expected_head,
                          scratch_root, allow_pending=False, state=None):
    out = real_directory(out)
    state = real_directory(state)
    expected_layout = {"frames", "blobs", "registries"}
    if os.path.lexists(out / "HEAD.json"):
        expected_layout.add("HEAD.json")
    if allow_pending:
        expected_layout.add(".HEAD.json.pending")
    require({entry.name for entry in out.iterdir()} == expected_layout, "output layout")
    reg_raw = real_file(
        out / "registries" / f"{expected_head['registry_seq']}.json"
    )
    require(reg_raw == registry_raw, "output registry bytes differ")
    frame_entries = list((out / "frames").iterdir())
    require(
        all(path.is_file() and path.suffix == ".json" and path.stem.isdigit()
            for path in frame_entries),
        "non-file or unknown output frame entry",
    )
    frame_entries.sort(key=lambda path: int(path.stem))
    require(
        len(frame_entries) == expected_head["rapp_seq"] + 1 and
        all(int(path.stem) == seq for seq, path in enumerate(frame_entries)),
        "output frame gap or unknown frame",
    )
    registry_entries = list((out / "registries").iterdir())
    registry_entries.sort(
        key=lambda path: int(path.stem)
        if path.suffix == ".json" and path.stem.isdigit() else -1
    )
    require(
        all(stat.S_ISREG(path.lstat().st_mode) and
            path.suffix == ".json" and path.stem.isdigit()
            for path in registry_entries) and
        len(registry_entries) == expected_head["registry_seq"] + 1 and
        all(int(path.stem) == seq for seq, path in enumerate(registry_entries)),
        "output registry gap or unknown registry",
    )
    for path in registry_entries:
        require(
            real_file(path) == real_file(state / "registries" / path.name),
            f"output registry differs from controller candidate: {path.name}",
        )
    verifier = registry_signature_verifier(registry, scratch_root)
    previous = None
    expected_blobs = set()
    source_identity = None
    tick_genesis = None
    for seq, frame_path in enumerate(frame_entries):
        frame, raw = read_frame(frame_path)
        require(raw == real_file(state / "frames" / f"{seq}.json"),
                f"output frame {seq} differs from controller candidate")
        if seq == 0:
            registered = registry.registered_genesis(config["stream_id"])
            require(
                registered is not None and
                frame["frame_hash"] == registered["frame_hash"],
                "output frame zero differs from the signed registry genesis",
            )
        native = validate_frame_payload(frame, seq, config)
        identity = (native["native_stream_id"], native["native_genesis_frame_hash"])
        source_identity = identity if source_identity is None else source_identity
        require(identity == source_identity, "output native identity/genesis changed")
        tick = frame["payload"]["tick_source"]
        if tick is not None:
            tick_genesis = tick["native_genesis_frame_hash"] if tick_genesis is None else tick_genesis
            require(tick["native_genesis_frame_hash"] == tick_genesis,
                    "output tick genesis changed")
        ok, step, why = R.verify_frame(
            frame, head=previous, stream_id_of_record=config["stream_id"],
            signature_verifier=verifier,
        )
        require(ok, f"output frame {seq} refused at {step}: {why}")
        bound, why = registry.check_frame_binding(frame)
        require(bound, f"output registry binding: {why}")
        for source in (native, frame["payload"]["tick_source"]):
            if source is None:
                continue
            expected_blobs.add(f"{source['raw_sha256']}.bin")
        verify_opaque_payload(frame["payload"], out / "blobs")
        previous = frame
    blob_entries = list((out / "blobs").iterdir())
    require(all(path.is_file() for path in blob_entries) and
            {path.name for path in blob_entries} == expected_blobs,
            "output blob gap or unknown blob")
    for name in expected_blobs:
        require(real_file(out / "blobs" / name) == real_file(state / "blobs" / name),
                f"output blob differs from controller candidate: {name}")
    validate_head_frame(expected_head, previous, config, "output head")
    require(
        expected_head["registry_seq"] == R._strict_json(registry_raw)["registry_seq"] and
        expected_head["registry_sha256"] == sha256(registry_raw),
        "output head registry metadata mismatch",
    )
    return expected_head


def verify_output(out, config, registry, registry_raw, expected_head, state):
    out = real_directory(out)
    state = real_directory(state)
    require(os.path.lexists(out / "HEAD.json"), "output persistent head is absent")
    head = load_head(out / "HEAD.json")
    require(head == expected_head, "output persistent head differs from controller state")
    require(
        real_file(out / "HEAD.json") == real_file(state / "HEAD.json"),
        "output persistent head bytes differ from controller state",
    )
    return verify_output_objects(
        out, config, registry, registry_raw, expected_head, state, state=state
    )


def _finish_pending_head(root, current, pending):
    head_path = root / "HEAD.json"
    pending_path = pending_head_path(root)
    require(load_head(head_path) == current,
            f"persistent high-water changed during pending recovery: {head_path}")
    require(load_head(pending_path) == pending,
            f"pending high-water changed during recovery: {pending_path}")
    os.replace(pending_path, head_path)
    fsync_directory(root)


def _remove_abandoned_pending(root, current, pending):
    pending_path = pending_head_path(root)
    require(load_head(root / "HEAD.json") == current,
            f"persistent high-water changed during pending cleanup: {root}")
    require(load_head(pending_path) == pending,
            f"pending high-water changed during cleanup: {pending_path}")
    pending_path.unlink()
    fsync_directory(root)


def _pending_primary_dependencies(root, current, pending, initialized_state=False):
    accepted_last = -1 if current is None else current["rapp_seq"]
    baseline_last = 0 if initialized_state and current is None else accepted_last
    retained = _retained_object_counts(root)
    registry_path = root / "registries" / f"{pending['registry_seq']}.json"
    if (pending["rapp_seq"] < retained["frames"] and
            os.path.lexists(registry_path)):
        return True
    if current is not None:
        require(
                current["rapp_seq"] < retained["frames"] and
                os.path.lexists(
                    root / "registries" / f"{current['registry_seq']}.json"
                ),
                f"ambiguous pending head accompanies accepted-object rollback: {root}")
    novel_exists = retained["frames"] > baseline_last + 1
    if current is None or (
            pending["registry_seq"], pending["registry_sha256"]
    ) != (current["registry_seq"], current["registry_sha256"]):
        novel_exists = novel_exists or os.path.lexists(registry_path)
    require(not novel_exists,
            f"ambiguous pending head has partial durable dependencies: {root}")
    _remove_abandoned_pending(root, current, pending)
    return False


def _registry_for_pending(source_root, source_revision, main_ref, config,
                          scratch_root, root, current, pending,
                          initialized_state=False):
    candidate0, _ = read_frame(root / "frames" / "0.json")
    persisted = None
    initialized = None
    if current is not None:
        raw = real_file(root / "registries" / f"{current['registry_seq']}.json")
        require(sha256(raw) == current["registry_sha256"],
                "accepted pending-recovery registry hash mismatch")
        persisted = {
            "seq": current["registry_seq"], "sha256": current["registry_sha256"],
            "doc": R._strict_json(raw), "candidate": False,
        }
    elif initialized_state:
        initialized = persisted_registry(root, None)
    doc, registry, raw = registry_from_git(
        source_root, pending["registry_checkpoint"], source_revision, main_ref,
        config, candidate0["frame_hash"], scratch_root,
        persisted=persisted,
    )
    if initialized is not None:
        require(doc["registry_seq"] == initialized["seq"] and
                sha256(raw) == initialized["sha256"],
                "pending genesis registry differs from initialized candidate")
    require(
        doc["registry_seq"] == pending["registry_seq"] and
        sha256(raw) == pending["registry_sha256"],
        "pending head registry metadata mismatch",
    )
    return doc, registry, raw


def _registry_prefix_for_pending_output(source_root, source_revision, main_ref,
                                        state, output, config, current, pending):
    controller_head = load_head(state / "HEAD.json")
    require(
        controller_head is not None and
        pending["registry_seq"] <= controller_head["registry_seq"],
        "pending output registry jump is ahead of accepted controller registry",
    )
    candidate0, _ = read_frame(state / "frames" / "0.json")
    controller_objects = _numbered_object_paths(state, "registries")
    require(
        controller_head["registry_seq"] < len(controller_objects),
        "accepted controller registry is ahead of retained registry objects",
    )
    persisted = None
    selected = None
    accepted = None
    for seq, path in controller_objects[:controller_head["registry_seq"] + 1]:
        raw = real_file(path)
        doc, registry = verify_registry_raw(
            raw, config["trust_anchor"], config["canonical_source"],
            candidate0["frame_hash"], config["stream_id"], state,
            persisted=persisted,
        )
        require(doc["registry_seq"] == seq,
                f"controller registry object sequence mismatch: {path.name}")
        digest = sha256(raw)
        persisted = {
            "seq": seq, "sha256": digest, "doc": doc, "candidate": False,
        }
        if seq <= pending["registry_seq"]:
            output_raw = real_file(output / "registries" / path.name)
            require(
                output_raw == raw,
                f"pending output registry differs from controller state: {path.name}",
            )
        if current is not None and seq == current["registry_seq"]:
            require(
                digest == current["registry_sha256"],
                "accepted pending-recovery registry hash mismatch",
            )
        if seq == pending["registry_seq"]:
            selected = (doc, registry, raw)
        if seq == controller_head["registry_seq"]:
            accepted = (doc, raw)
    require(
        accepted is not None and
        accepted[0]["registry_seq"] == controller_head["registry_seq"] and
        sha256(accepted[1]) == controller_head["registry_sha256"],
        "accepted controller registry metadata mismatch",
    )
    require(selected is not None, "pending output registry is absent from controller state")
    require(
        selected[0]["registry_seq"] == pending["registry_seq"] and
        sha256(selected[2]) == pending["registry_sha256"],
        "pending head registry metadata mismatch",
    )
    git_doc, git_registry, git_raw = registry_from_git(
        source_root, pending["registry_checkpoint"], source_revision, main_ref,
        config, candidate0["frame_hash"], state,
    )
    require(
        git_raw == selected[2],
        "pending output registry differs from its canonical checkpoint",
    )
    return git_doc, git_registry, git_raw


def recover_controller_pending(source_root, source_revision, tick_source_root,
                               tick_source_commit, main_ref, state, config):
    current = load_head(state / "HEAD.json")
    pending_path = pending_head_path(state)
    pending = load_head(pending_path)
    retained = _retained_object_counts(state)
    _bound_head_to_objects(
        current, retained, "accepted controller head",
        frame_reason=(
            "controller RAPP rollback: retained frame chain is behind accepted head"
        ),
    )
    _bound_head_to_objects(
        pending, retained, "pending controller head", allow_next=True
    )
    cleanup_object_temporaries(
        state, current, pending, initialized_state=current is None
    )
    if pending is None:
        return current, False
    require(pending["stream_id"] == config["stream_id"] and
            pending["chain_path"] == config["chain_path"],
            "pending controller head differs from initialized state")
    validate_head_transition(current, pending, "pending controller")
    if not _pending_primary_dependencies(
            state, current, pending, initialized_state=True):
        return current, False
    doc, registry, raw = _registry_for_pending(
        source_root, source_revision, main_ref, config, state, state,
        current, pending, initialized_state=True,
    )
    frames = verify_frame_chain(
        state, config, registry, state, through=pending["rapp_seq"]
    )
    require(len(frames) == pending["rapp_seq"] + 1,
            "pending controller frame rollback")
    validate_head_frame(pending, frames[-1][0], config, "pending controller")
    if current is not None:
        validate_head_frame(
            current, frames[current["rapp_seq"]][0], config,
            "accepted controller",
        )
    cache = {"_state": str(state)}
    for frame, _ in frames:
        verify_candidate_provenance(
            source_root, tick_source_root, frame, main_ref, source_revision,
            tick_source_commit, cache,
        )
    if current is not None:
        git_ancestor(
            source_root, current["source_commit"], pending["source_commit"],
            "pending controller source commit moved backward or forked",
        )
        git_ancestor(
            tick_source_root, current["tick_source_commit"],
            pending["tick_source_commit"],
            "pending controller tick commit moved backward or forked",
        )
        git_ancestor(
            source_root, current["registry_checkpoint"],
            pending["registry_checkpoint"],
            "pending controller registry checkpoint moved backward or forked",
        )
    require(raw == real_file(state / "registries" / f"{doc['registry_seq']}.json"),
            "pending controller registry object differs from checkpoint")
    _finish_pending_head(state, current, pending)
    return pending, True


def verify_controller_accepted(source_root, source_revision, tick_source_root,
                               tick_source_commit, main_ref, state, config, head):
    if head is None:
        return
    git_ancestor(source_root, head["source_commit"], source_revision,
                 "non-fast-forward Git source")
    persisted = persisted_registry(state, head)
    candidate0, _ = read_frame(state / "frames" / "0.json")
    doc, registry, raw = registry_from_git(
        source_root, head["registry_checkpoint"], source_revision, main_ref,
        config, candidate0["frame_hash"], state, persisted=persisted,
    )
    require(
        doc["registry_seq"] == head["registry_seq"] and
        sha256(raw) == head["registry_sha256"],
        "accepted controller registry metadata mismatch",
    )
    cache = {"_state": str(state)}
    chain = verify_native_chain(
        source_root, source_revision, config["chain_path"], main_ref, cache=cache
    )
    require(chain["genesis"] == head["native_genesis_frame_hash"],
            "native genesis changed; bridge/2 refuses re-genesis")
    require(chain["frames"][-1]["seq"] >= head["native_seq"],
            "native source rollback")
    require(chain["frames"][head["native_seq"]]["frame_hash"] ==
            head["native_frame_hash"], "same-sequence native source fork")
    ticks = verify_native_chain(
        tick_source_root, tick_source_commit, config["tick_chain_path"],
        CANONICAL_REF, TICK_SOURCE_REPOSITORY, cache=cache,
    )
    git_ancestor(
        tick_source_root, head["tick_source_commit"], tick_source_commit,
        "non-fast-forward tick source",
    )
    require(ticks["genesis"] == head["tick_native_genesis_frame_hash"],
            "tick genesis changed; bridge/2 refuses re-genesis")
    require(head["tick_native_seq"] < len(ticks["frames"]),
            "tick source rollback")
    require(ticks["frames"][head["tick_native_seq"]]["frame_hash"] ==
            head["tick_native_frame_hash"], "same-sequence tick source fork")
    frames = verify_frame_chain(
        state, config, registry, state, through=head["rapp_seq"]
    )
    require(len(frames) == head["rapp_seq"] + 1,
            "controller RAPP rollback: retained frame chain is behind accepted head")
    validate_head_frame(head, frames[-1][0], config, "controller")
    for frame, _ in frames:
        verify_candidate_provenance(
            source_root, tick_source_root, frame, main_ref, source_revision,
            tick_source_commit, cache,
        )


def recover_output_pending(source_root, source_revision, tick_source_root,
                           tick_source_commit, main_ref, state, output, config):
    output = absolute(output)
    if not os.path.lexists(output):
        return None, False
    current = load_head(output / "HEAD.json")
    pending = load_head(pending_head_path(output))
    if current is None and pending is None:
        output_layout(output)
    if current is not None or pending is not None:
        retained = _retained_object_counts(output)
        controller_retained = _retained_object_counts(state)
        _bound_head_to_objects(current, retained, "accepted output head")
        _bound_head_to_objects(
            pending, retained, "pending output head", allow_next=True
        )
        _bound_head_to_objects(current, controller_retained, "accepted output head")
        _bound_head_to_objects(pending, controller_retained, "pending output head")
    cleanup_object_temporaries(output, current, pending)
    if pending is None:
        return current, False
    require(pending["stream_id"] == config["stream_id"] and
            pending["chain_path"] == config["chain_path"],
            "pending output head differs from initialized state")
    validate_head_transition(current, pending, "pending output")
    if not _pending_primary_dependencies(output, current, pending):
        return current, False
    accepted_registry_seq = -1 if current is None else current["registry_seq"]
    if pending["registry_seq"] > accepted_registry_seq + 1:
        _, registry, registry_raw = _registry_prefix_for_pending_output(
            source_root, source_revision, main_ref, state, output, config,
            current, pending,
        )
    else:
        _, registry, registry_raw = _registry_for_pending(
            source_root, source_revision, main_ref, config, state, output,
            current, pending,
        )
    verify_output_objects(
        output, config, registry, registry_raw, pending, state,
        allow_pending=True, state=state,
    )
    controller_head = load_head(state / "HEAD.json")
    if controller_head is not None:
        require(pending["rapp_seq"] >= controller_head["rapp_seq"],
                "pending output is behind the accepted controller head")
    cache = {"_state": str(state)}
    if current is not None:
        current_frame, _ = read_frame(
            output / "frames" / f"{current['rapp_seq']}.json"
        )
        validate_head_frame(current, current_frame, config, "accepted output")
    for seq, frame_path in _numbered_object_paths(output, "frames"):
        if seq > pending["rapp_seq"]:
            break
        frame, _ = read_frame(frame_path)
        verify_candidate_provenance(
            source_root, tick_source_root, frame, main_ref, source_revision,
            tick_source_commit, cache,
        )
    if current is not None:
        git_ancestor(
            source_root, current["source_commit"], pending["source_commit"],
            "pending output source commit moved backward or forked",
        )
        git_ancestor(
            tick_source_root, current["tick_source_commit"],
            pending["tick_source_commit"],
            "pending output tick commit moved backward or forked",
        )
        git_ancestor(
            source_root, current["registry_checkpoint"],
            pending["registry_checkpoint"],
            "pending output registry checkpoint moved backward or forked",
        )
    _finish_pending_head(output, current, pending)
    return pending, True


def _append_locked(source_root, source_revision, tick_source_root,
                   tick_source_commit, main_ref, registry_checkpoint,
                   state, outputs, signing_key, explicit_anchor=None):
    source_root = check_git_source(source_root, source_revision, main_ref)
    tick_source_root = check_git_source(
        tick_source_root, tick_source_commit, CANONICAL_REF,
        TICK_SOURCE_REPOSITORY,
    )
    require(not paths_overlap(source_root, tick_source_root),
            "planet and tick sources must be separate Git repositories")
    state, config = load_config(state)
    anchor = trust_anchor(explicit_anchor)
    require(anchor == config["trust_anchor"], "untrusted anchor differs from initialized estate")
    private_key = key_path(
        signing_key, (source_root, tick_source_root), (state, *outputs)
    )
    derived, _ = keyed_rappid(
        R.rappid_parts(anchor)["owner"], R.rappid_parts(anchor)["slug"], private_key
    )
    require(derived == anchor, "signing key does not match the out-of-band anchor")
    prior_head, recovered_state = recover_controller_pending(
        source_root, source_revision, tick_source_root, tick_source_commit,
        main_ref, state, config,
    )
    if prior_head is not None:
        require(prior_head["stream_id"] == config["stream_id"], "state stream fork")
        require(prior_head["chain_path"] == config["chain_path"],
                "native source path changed")
    verify_controller_accepted(
        source_root, source_revision, tick_source_root, tick_source_commit,
        main_ref, state, config, prior_head,
    )
    recovered_output = False
    for output in outputs:
        _, recovered = recover_output_pending(
            source_root, source_revision, tick_source_root, tick_source_commit,
            main_ref, state, output, config,
        )
        recovered_output = recovered_output or recovered
    persisted = persisted_registry(state, prior_head)
    candidate0, _ = read_frame(state / "frames" / "0.json")
    registry_doc, registry, registry_raw = registry_from_git(
        source_root, registry_checkpoint, source_revision, main_ref, config,
        candidate0["frame_hash"], state,
        persisted=None if persisted["candidate"] else persisted,
    )
    if persisted["candidate"]:
        require(registry_doc["registry_seq"] == persisted["seq"] and
                sha256(registry_raw) == persisted["sha256"],
                "published genesis registry differs from initialized candidate")
    cache = {"_state": str(state)}
    chain = verify_native_chain(
        source_root, source_revision, config["chain_path"], main_ref, cache=cache
    )
    ticks = verify_native_chain(
        tick_source_root, tick_source_commit, config["tick_chain_path"],
        CANONICAL_REF, TICK_SOURCE_REPOSITORY, cache=cache,
    )
    if prior_head is not None:
        require(prior_head["stream_id"] == config["stream_id"], "state stream fork")
        require(prior_head["chain_path"] == config["chain_path"], "native source path changed")
        require(chain["genesis"] == prior_head["native_genesis_frame_hash"],
                "native genesis changed; bridge/2 refuses re-genesis")
        git_ancestor(source_root, prior_head["source_commit"], source_revision,
                     "non-fast-forward Git source")
        git_ancestor(
            tick_source_root, prior_head["tick_source_commit"], tick_source_commit,
            "non-fast-forward tick source",
        )
        git_ancestor(source_root, prior_head["registry_checkpoint"], registry_checkpoint,
                     "registry/main checkpoint moved backward or forked")
        require(chain["frames"][-1]["seq"] >= prior_head["native_seq"], "native source rollback")
        old = chain["frames"][prior_head["native_seq"]]
        require(old["frame_hash"] == prior_head["native_frame_hash"],
                "same-sequence native source fork")
        require(ticks["genesis"] == prior_head["tick_native_genesis_frame_hash"],
                "tick genesis changed; bridge/2 refuses re-genesis")
        require(prior_head["tick_native_seq"] < len(ticks["frames"]),
                "tick source rollback")
        require(ticks["frames"][prior_head["tick_native_seq"]]["frame_hash"] ==
                prior_head["tick_native_frame_hash"],
                "same-sequence tick source fork")
    frames = verify_frame_chain(state, config, registry, state)
    if prior_head is not None:
        require(prior_head["rapp_seq"] < len(frames),
                "controller RAPP rollback: retained frame chain is behind accepted head")
        accepted = frames[prior_head["rapp_seq"]][0]
        validate_head_frame(prior_head, accepted, config, "controller")
    first_unaccepted = 0 if prior_head is None else prior_head["rapp_seq"] + 1
    for frame, _ in frames[first_unaccepted:]:
        verify_candidate_provenance(
            source_root, tick_source_root, frame, main_ref, source_revision,
            tick_source_commit, cache,
        )
    target = chain["frames"][-1]["seq"]
    require(frames[-1][0]["seq"] <= target, "candidate history is ahead of native source")
    while frames[-1][0]["seq"] < target:
        seq = frames[-1][0]["seq"] + 1
        native, tick_frame, tick_source = provenance_for(chain, seq, ticks)
        require(tick_source is not None,
                "every planet frame must resolve an external native tick anchor")
        utc = now_utc()
        if utc < frames[-1][0]["utc"]:
            utc = frames[-1][0]["utc"]
        frame = build_signed_frame(
            config["stream_id"], seq, utc,
            frame_payload(native, tick_frame, tick_source),
            frames[-1][0], private_key, anchor,
        )
        verifier = registry_signature_verifier(registry, state)
        ok, step, why = R.verify_frame(
            frame, head=frames[-1][0], stream_id_of_record=config["stream_id"],
            signature_verifier=verifier,
        )
        require(ok, f"new RAPP frame refused at {step}: {why}")
        bound, why = registry.check_frame_binding(frame)
        require(bound, why)
        raw = canonical(frame)
        write_new_or_equal(state / "blobs" / f"{native['raw_sha256']}.bin",
                           chain["records"][seq]["raw"])
        if tick_source is not None:
            write_new_or_equal(
                state / "blobs" / f"{tick_source['raw_sha256']}.bin",
                ticks["records"][tick_source["native_seq"]]["raw"],
            )
        # The create-only frame is the candidate completion marker; retries reuse it.
        write_new_or_equal(state / "frames" / f"{seq}.json", raw)
        frames.append((frame, raw))
    require(registry.registered_genesis(config["stream_id"])["frame_hash"] ==
            frames[0][0]["frame_hash"], "registered genesis changed")
    head = head_value(
        registry_doc, registry_raw, registry_checkpoint, frames[target][0], config
    )
    write_new_or_equal(
        state / "registries" / f"{registry_doc['registry_seq']}.json", registry_raw
    )
    for output in outputs:
        deliver(state, output, frames[:target + 1], registry_doc, registry_raw, head)
    commit_head(state / "HEAD.json", head, prior_head)
    for output in outputs:
        verify_output(output, config, registry, registry_raw, head, state)
    return {
        "status": (
            "unchanged"
            if prior_head == head and not recovered_state and not recovered_output
            else "advanced"
        ),
        "profile": PROFILE,
        "frames_verified": target + 1,
        "rapp_seq": target,
        "rapp_frame_hash": head["rapp_frame_hash"],
        "native_seq": head["native_seq"],
        "native_frame_hash": head["native_frame_hash"],
        "registry_seq": head["registry_seq"],
        "registry_sha256": head["registry_sha256"],
        "outputs": len(outputs),
    }


def append(source_root, source_revision, tick_source_root, tick_source_commit,
           main_ref, registry_checkpoint, state, outputs, signing_key,
           explicit_anchor=None):
    source_root, tick_source_root, state, outputs = append_paths(
        source_root, tick_source_root, state, outputs
    )
    with controller_lock(state):
        return _append_locked(
            source_root, source_revision, tick_source_root, tick_source_commit,
            main_ref, registry_checkpoint, state, outputs, signing_key,
            explicit_anchor,
        )


def verify_command(source_root, source_revision, tick_source_root,
                   tick_source_commit, main_ref, registry_checkpoint,
                   state, output, explicit_anchor=None):
    source_root = check_git_source(source_root, source_revision, main_ref)
    tick_source_root = check_git_source(
        tick_source_root, tick_source_commit, CANONICAL_REF,
        TICK_SOURCE_REPOSITORY,
    )
    require(not paths_overlap(source_root, tick_source_root),
            "planet and tick sources must be separate Git repositories")
    state, config = load_config(state)
    output = real_directory(output)
    require(not paths_overlap(state, source_root),
            "controller state must be disjoint from the native repository")
    require(not paths_overlap(state, tick_source_root),
            "controller state must be disjoint from the tick repository")
    require(not paths_overlap(output, source_root),
            "bridge output must be disjoint from the native repository")
    require(not paths_overlap(output, tick_source_root),
            "bridge output must be disjoint from the tick repository")
    require(not paths_overlap(output, state),
            "bridge output must be disjoint from controller state")
    require(not os.path.lexists(pending_head_path(state)),
            "controller pending head requires locked append recovery")
    require(not os.path.lexists(pending_head_path(output)),
            "output pending head requires locked append recovery")
    anchor = trust_anchor(explicit_anchor)
    require(anchor == config["trust_anchor"], "untrusted anchor differs from initialized estate")
    head = load_head(state / "HEAD.json")
    require(head is not None, "controller has no accepted head")
    persisted = persisted_registry(state, head)
    candidate0, _ = read_frame(state / "frames" / "0.json")
    registry_doc, registry, registry_raw = registry_from_git(
        source_root, registry_checkpoint, source_revision, main_ref, config,
        candidate0["frame_hash"], state, persisted=persisted,
    )
    require(registry_doc["registry_seq"] == head["registry_seq"] and
            sha256(registry_raw) == head["registry_sha256"],
            "verified registry differs from persistent controller head")
    require(registry_checkpoint == head["registry_checkpoint"],
            "registry/main checkpoint differs from persistent controller head")
    chain = verify_native_chain(
        source_root, source_revision, config["chain_path"], main_ref, cache={}
    )
    ticks = verify_native_chain(
        tick_source_root, tick_source_commit, config["tick_chain_path"],
        CANONICAL_REF, TICK_SOURCE_REPOSITORY, cache={},
    )
    require(chain["genesis"] == head["native_genesis_frame_hash"], "native genesis changed")
    require(chain["frames"][-1]["seq"] >= head["native_seq"], "native rollback")
    require(chain["frames"][head["native_seq"]]["frame_hash"] == head["native_frame_hash"],
            "native fork")
    git_ancestor(source_root, head["source_commit"], source_revision,
                 "non-fast-forward Git source")
    git_ancestor(
        tick_source_root, head["tick_source_commit"], tick_source_commit,
        "non-fast-forward tick source",
    )
    require(ticks["genesis"] == head["tick_native_genesis_frame_hash"],
            "tick genesis changed")
    require(head["tick_native_seq"] < len(ticks["frames"]),
            "tick rollback")
    require(ticks["frames"][head["tick_native_seq"]]["frame_hash"] ==
            head["tick_native_frame_hash"], "tick fork")
    frames = verify_frame_chain(state, config, registry, state, through=head["rapp_seq"])
    require(frames[-1][0]["frame_hash"] == head["rapp_frame_hash"], "controller RAPP head mismatch")
    cache = {"_state": str(state)}
    for frame, _ in frames:
        verify_candidate_provenance(
            source_root, tick_source_root, frame, main_ref, source_revision,
            tick_source_commit, cache,
        )
    verify_output(output, config, registry, registry_raw, head, state)
    return {
        "status": "verified", "profile": PROFILE,
        "frames_verified": head["rapp_seq"] + 1,
        "rapp_frame_hash": head["rapp_frame_hash"],
        "native_frame_hash": head["native_frame_hash"],
        "registry_sha256": head["registry_sha256"],
    }


def advance_registry(registry_in, registry_out, signing_key, explicit_anchor,
                     source_root, tick_source_root):
    source_root = source_repository_root(source_root)
    tick_source_root = source_repository_root(tick_source_root)
    require(not paths_overlap(source_root, tick_source_root),
            "planet and tick sources must be separate Git repositories")
    private_key = key_path(
        signing_key, (source_root, tick_source_root), (registry_out,)
    )
    anchor = trust_anchor(explicit_anchor)
    raw = real_file(registry_in)
    doc = R._strict_json(raw)
    canonical_source = doc.get("canonical_source")
    validate_canonical_source(canonical_source)
    stream_entries = [entry for entry in doc.get("entries", []) if entry.get("type") == "genesis"
                      and not entry.get("deprecated")]
    require(len(stream_entries) == 1, "registry update requires one live bridge genesis")
    stream_id = stream_entries[0]["stream_id"]
    verify_registry_raw(
        raw, anchor, canonical_source, stream_entries[0]["frame_hash"],
        stream_id, real_directory(absolute(registry_out).parent),
    )
    derived, spki = keyed_rappid(
        R.rappid_parts(anchor)["owner"], R.rappid_parts(anchor)["slug"], private_key
    )
    require(derived == anchor, "signing key does not match anchor")
    require(REG.Registry(doc["entries"]).spki_der(anchor) == spki, "registry owner SPKI changed")
    updated = make_registry(
        canonical_source, anchor, spki, stream_id, stream_entries[0]["frame_hash"],
        private_key, registry_seq=doc["registry_seq"] + 1, entries=doc["entries"],
    )
    raw = canonical(updated)
    require(not os.path.lexists(registry_out), "registry update output is create-only")
    require(not path_within(registry_out, source_root),
            "registry candidate output must be outside the planet repository")
    require(not path_within(registry_out, tick_source_root),
            "registry candidate output must be outside the tick repository")
    write_new(registry_out, raw)
    return {
        "status": "registry-candidate-created",
        "registry_seq": updated["registry_seq"],
        "registry_sha256": sha256(raw),
        "owner_action": "publish these exact bytes at canonical_source on protected main and use that commit as the next checkpoint",
    }


def generate_key(path, source_root, tick_source_root):
    source_root = source_repository_root(source_root)
    tick_source_root = source_repository_root(tick_source_root)
    require(not paths_overlap(source_root, tick_source_root),
            "planet and tick sources must be separate Git repositories")
    path = absolute(path)
    require(not path_within(path, source_root) and
            not path_within(path, tick_source_root),
            "private key output must be outside source repositories")
    with private_directory_descriptor(path.parent) as (_, directory_fd):
        try:
            os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("private key output is create-only")
        raw = run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout"])
        require(raw.startswith(b"-----BEGIN EC PRIVATE KEY-----\n") and
                raw.endswith(b"-----END EC PRIVATE KEY-----\n"),
                "OpenSSL returned an unexpected private key encoding")
        flags = (
            os.O_RDWR | os.O_CREAT | os.O_EXCL |
            getattr(os, "O_NOFOLLOW", 0)
        )
        fd = os.open(path.name, flags, 0o600, dir_fd=directory_fd)
        try:
            with os.fdopen(fd, "w+b", closefd=False) as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(fd)
                handle.seek(0)
                require(handle.read(len(raw) + 1) == raw, "private key readback mismatch")
            validate_private_key_info(os.fstat(fd), path)
        finally:
            os.close(fd)
        os.fsync(directory_fd)
    require(read_private_key(path) == raw, "private key readback mismatch")
    return {
        "status": "local-private-key-created",
        "path": str(path),
        "warning": "keep this PEM outside repositories, bridge outputs, logs, and CI artifacts",
    }


def add_source_args(parser):
    parser.add_argument("--source-root", default=".")
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--tick-source-root", required=True)
    parser.add_argument("--tick-source-commit", required=True)
    parser.add_argument("--main-ref", default="refs/remotes/origin/main")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("generate-key", help="explicit local ES256 key generation")
    keygen.add_argument("--source-root", default=".")
    keygen.add_argument("--tick-source-root", required=True)
    keygen.add_argument("--out", required=True)
    init = commands.add_parser("init", help="mint one bridge stream and signed registry candidate")
    add_source_args(init)
    init.add_argument("--chain", required=True)
    init.add_argument("--owner", required=True)
    init.add_argument("--slug", default="dogg-rapp1-bridge")
    init.add_argument("--canonical-registry-path", required=True)
    init.add_argument("--state", required=True)
    init.add_argument("--registry-out", required=True)
    init.add_argument("--signing-key")
    app = commands.add_parser("append", help="verify native history and append forward-only projections")
    add_source_args(app)
    app.add_argument("--registry-checkpoint", required=True)
    app.add_argument("--state", required=True)
    app.add_argument("--out", action="append", required=True)
    app.add_argument("--signing-key")
    app.add_argument("--trust-anchor")
    verify = commands.add_parser("verify", help="verify registry, native source, state and one output")
    add_source_args(verify)
    verify.add_argument("--registry-checkpoint", required=True)
    verify.add_argument("--state", required=True)
    verify.add_argument("--out", required=True)
    verify.add_argument("--trust-anchor")
    advance = commands.add_parser("advance-registry", help="sign the next monotonic registry checkpoint")
    advance.add_argument("--source-root", default=".")
    advance.add_argument("--tick-source-root", required=True)
    advance.add_argument("--registry-in", required=True)
    advance.add_argument("--registry-out", required=True)
    advance.add_argument("--signing-key")
    advance.add_argument("--trust-anchor")
    args = parser.parse_args(argv)
    try:
        if args.command == "generate-key":
            result = generate_key(
                args.out, args.source_root, args.tick_source_root
            )
        elif args.command == "init":
            result = initialize(
                args.source_root, args.source_revision, args.tick_source_root,
                args.tick_source_commit, args.chain, args.main_ref, args.owner,
                args.slug, args.canonical_registry_path, args.state,
                args.registry_out, args.signing_key,
            )
        elif args.command == "append":
            result = append(
                args.source_root, args.source_revision, args.tick_source_root,
                args.tick_source_commit, args.main_ref,
                args.registry_checkpoint, args.state, args.out, args.signing_key,
                args.trust_anchor,
            )
        elif args.command == "verify":
            result = verify_command(
                args.source_root, args.source_revision, args.tick_source_root,
                args.tick_source_commit, args.main_ref,
                args.registry_checkpoint, args.state, args.out,
                args.trust_anchor,
            )
        else:
            result = advance_registry(
                args.registry_in, args.registry_out, args.signing_key,
                args.trust_anchor, args.source_root, args.tick_source_root,
            )
    except (OSError, ValueError, TypeError, UnicodeError, subprocess.SubprocessError) as exc:
        print(f"bridge/2 refused: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
