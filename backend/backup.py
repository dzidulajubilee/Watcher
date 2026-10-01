#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Watcher IDS Dashboard — database backups (standard library only).

    backup.py backup                     take a backup now (run by watcher-backup.timer)
    backup.py list                       list backups
    backup.py restore NAME [--only config,events,dns] [--yes]
                                         restore (the service must be STOPPED —
                                         `watcher --restore` does that for you)

Settings come from environment variables (see /etc/watcher/backup.conf):
    BACKUP_DIR               /var/backups/watcher
    BACKUP_KEEP              2        complete backups to keep
    BACKUP_DATABASES         "config events dns"
    BACKUP_VERIFY            yes      PRAGMA quick_check on each copy
    BACKUP_MIN_FREE_PERCENT  10       never let the disk drop below this
                                      (config.db is exempt while its copy is
                                       at most 1/10 of the free space)

Design notes
------------
* Copies use SQLite's online backup API in ONE step (pages=-1): a single read
  transaction gives a consistent snapshot while ingest keeps writing (WAL).
  A stepwise backup restarts whenever another connection writes — under
  continuous ingest it never finishes (measured: 113 restarts in 12 s).
  VACUUM INTO was rejected for large databases: it rebuilds every index
  (large sorts + temporary files); a page copy is predictable.
* config.db (users, webhooks, threat intel, suppression, settings) is copied
  first — it is small and the hardest to recreate.
* Each database is checked against free space BEFORE copying; one that would
  push the disk below BACKUP_MIN_FREE_PERCENT is skipped (and reported),
  the others still run.
* A backup is written to  .partial-<name>/  and renamed to  <name>/  only when
  every copy succeeded and verified, then fsynced.  Incomplete backups are
  never listed, restored or counted for rotation.
* Rotation deletes the oldest complete backups only AFTER a new one succeeds.
"""

import argparse
import datetime as _dt
import fcntl
import json
import os
import shutil
import socket
import sqlite3
import sys
import time
from pathlib import Path

DATA_DIR  = Path(os.environ.get("WATCHER_DATA_DIR", "/var/lib/watcher"))
DATABASES = {"config": "config.db", "events": "events.db", "dns": "dns.db"}
ORDER     = ("config", "events", "dns")
NAME_FMT  = "watcher-%Y%m%d-%H%M%S"
PARTIAL   = ".partial-"
MANIFEST  = "manifest.json"
VERSION   = "1.10.0"


def log(msg: str):
    print(f"[{_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024


def settings() -> dict:
    env = os.environ
    s = {
        "dir":      Path(env.get("BACKUP_DIR", "/var/backups/watcher")),
        "keep":     env.get("BACKUP_KEEP", "2"),
        "dbs":      env.get("BACKUP_DATABASES", "config events dns").replace(",", " ").split(),
        "verify":   env.get("BACKUP_VERIFY", "yes").strip().lower() in ("1", "yes", "true", "on"),
        "min_free": env.get("BACKUP_MIN_FREE_PERCENT", "10"),
    }
    try:
        s["keep"] = int(s["keep"]); assert s["keep"] >= 1
    except (ValueError, AssertionError):
        raise SystemExit("BACKUP_KEEP must be a whole number >= 1")
    try:
        s["min_free"] = float(s["min_free"]); assert 0 <= s["min_free"] < 100
    except (ValueError, AssertionError):
        raise SystemExit("BACKUP_MIN_FREE_PERCENT must be between 0 and 99")
    bad = [d for d in s["dbs"] if d not in DATABASES]
    if bad or not s["dbs"]:
        raise SystemExit(f"BACKUP_DATABASES: unknown {bad} (valid: config events dns)")
    s["dbs"] = [d for d in ORDER if d in s["dbs"]]
    target = s["dir"].resolve()
    if target == DATA_DIR.resolve() or DATA_DIR.resolve() in target.parents:
        raise SystemExit(f"BACKUP_DIR must not be inside {DATA_DIR} "
                         "(it would be removed with the data on package purge)")
    return s


def _fsync_dir(path: Path):
    try:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def complete_backups(root: Path) -> list:
    """Complete backups, newest first."""
    out = []
    if not root.is_dir():
        return out
    for p in root.iterdir():
        if not p.is_dir() or p.name.startswith(PARTIAL):
            continue
        try:
            _dt.datetime.strptime(p.name, NAME_FMT)
        except ValueError:
            continue
        m = p / MANIFEST
        if not m.is_file():
            continue
        try:
            man = json.loads(m.read_text())
        except (OSError, ValueError):
            continue
        out.append((p, man))
    return sorted(out, key=lambda x: x[0].name, reverse=True)


# ── backup ───────────────────────────────────────────────────────────────────

def copy_database(src_path: Path, dst_path: Path, verify: bool) -> dict:
    t0 = time.monotonic()
    src = sqlite3.connect(f"file:{src_path}?mode=ro", uri=True, timeout=30)
    dst = sqlite3.connect(str(dst_path))
    try:
        src.backup(dst, pages=-1)          # one step = one consistent snapshot
    finally:
        dst.close()
        src.close()
    with open(dst_path, "rb") as f:
        os.fsync(f.fileno())
    info = {"file": dst_path.name, "bytes": dst_path.stat().st_size,
            "copy_seconds": round(time.monotonic() - t0, 1)}
    if verify:
        t1 = time.monotonic()
        c = sqlite3.connect(f"file:{dst_path}?mode=ro", uri=True)
        try:
            result = c.execute("PRAGMA quick_check").fetchone()[0]
        finally:
            c.close()
        info["quick_check"] = result
        info["verify_seconds"] = round(time.monotonic() - t1, 1)
        if result != "ok":
            raise RuntimeError(f"quick_check on the copy returned: {result}")
    return info


def run_backup() -> int:
    s = settings()
    root = s["dir"]
    try:
        root.mkdir(parents=True, exist_ok=True)
        lock_fd = os.open(str(root / ".lock"), os.O_CREAT | os.O_RDWR, 0o640)
    except OSError as exc:
        log(f"Cannot write to {root}: {exc}")
        if exc.errno in (30, 13):          # EROFS / EACCES
            log("If you changed BACKUP_DIR, allow the scheduled service to write there:\n"
                "    sudo systemctl edit watcher-backup.service\n"
                "    [Service]\n    ReadWritePaths=" + str(root) + "\n"
                "and make the directory owned by the watcher user.")
        return 1
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock_fd)
        log("Another backup is already running — nothing to do.")
        return 2
    try:
        return _run_backup_locked(s, root)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def _run_backup_locked(s: dict, root: Path) -> int:

    # Remove partial folders left by crashed runs (only ours, older than 1 h)
    for p in root.glob(PARTIAL + "watcher-*"):
        if p.is_dir() and time.time() - p.stat().st_mtime > 3600:
            log(f"Removing incomplete backup from an earlier run: {p.name}")
            shutil.rmtree(p, ignore_errors=True)

    while True:          # names have 1 s resolution; runs are serialised by the lock
        name = _dt.datetime.now(_dt.timezone.utc).strftime(NAME_FMT)
        if not (root / name).exists() and not (root / (PARTIAL + name)).exists():
            break
        time.sleep(0.2)
    work = root / (PARTIAL + name)
    work.mkdir(mode=0o750)
    started = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    manifest = {"name": name, "watcher_version": VERSION, "host": socket.gethostname(),
                "started_utc": started, "databases": {}, "skipped": {}, "failed": {}}
    log(f"Backup {name} → {root}")

    for key in s["dbs"]:
        src = DATA_DIR / DATABASES[key]
        if not src.exists():
            manifest["skipped"][key] = "database file not found"
            log(f"  {key:6} skipped — {src} not found")
            continue
        size = src.stat().st_size
        wal = Path(str(src) + "-wal")
        need = size + (wal.stat().st_size if wal.exists() else 0)
        need = int(need * 1.05) + 16 * 1024 * 1024          # 5 % + 16 MB headroom
        st = os.statvfs(root)
        free, total = st.f_bavail * st.f_frsize, st.f_blocks * st.f_frsize
        floor = total * s["min_free"] / 100
        # config.db is tiny and holds what is hardest to recreate (users,
        # webhooks, threat intel, rules): it is exempt from the percentage
        # floor as long as its copy is at most a tenth of the free space.
        # The floor exists to stop the large events/dns copies filling the disk.
        small_enough = key == "config" and need * 10 <= free
        if free - need < floor and not small_enough:
            reason = (f"not enough space: needs ~{human(need)}, {human(free)} free, "
                      f"must keep {s['min_free']:g}% ({human(floor)}) free")
            manifest["skipped"][key] = reason
            log(f"  {key:6} SKIPPED — {reason}")
            continue
        try:
            log(f"  {key:6} copying {human(size)} …")
            info = copy_database(src, work / DATABASES[key], s["verify"])
            manifest["databases"][key] = info
            log(f"  {key:6} ok — {human(info['bytes'])} in {info['copy_seconds']} s"
                + (f", quick_check ok ({info['verify_seconds']} s)" if s["verify"] else ""))
        except Exception as exc:                              # keep going with the others
            manifest["failed"][key] = str(exc)
            log(f"  {key:6} FAILED — {exc}")
            try:
                (work / DATABASES[key]).unlink()
            except OSError:
                pass

    manifest["finished_utc"] = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    manifest["status"] = ("complete" if not manifest["failed"] and not manifest["skipped"]
                          else "partial" if manifest["databases"] else "failed")

    if not manifest["databases"]:
        shutil.rmtree(work, ignore_errors=True)
        log("Backup FAILED — no database could be copied.")
        return 1

    (work / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n")
    with open(work / MANIFEST, "rb") as f:
        os.fsync(f.fileno())
    _fsync_dir(work)
    final = root / name
    work.rename(final)
    _fsync_dir(root)
    log(f"Backup {name}: {manifest['status']} "
        f"({', '.join(manifest['databases'])} copied"
        + (f"; skipped: {', '.join(manifest['skipped'])}" if manifest['skipped'] else "")
        + (f"; failed: {', '.join(manifest['failed'])}" if manifest['failed'] else "") + ")")

    # Rotation: only now that a new backup exists; never touch partial ones.
    backups = complete_backups(root)
    for old, _ in backups[s["keep"]:]:
        log(f"Rotating out old backup {old.name}")
        shutil.rmtree(old, ignore_errors=True)
    return 0 if manifest["status"] == "complete" else 1


# ── list ─────────────────────────────────────────────────────────────────────

def run_list() -> int:
    s = settings()
    backups = complete_backups(s["dir"])
    if not backups:
        print(f"No backups in {s['dir']}")
        return 0
    print(f"Backups in {s['dir']} (newest first, keeping {s['keep']}):")
    for p, man in backups:
        dbs = ", ".join(f"{k} {human(v['bytes'])}" for k, v in man.get("databases", {}).items())
        extra = ""
        if man.get("skipped"): extra += f"  skipped: {', '.join(man['skipped'])}"
        if man.get("failed"):  extra += f"  failed: {', '.join(man['failed'])}"
        print(f"  {p.name}  [{man.get('status', '?')}]  {dbs}{extra}")
    return 0


# ── restore ──────────────────────────────────────────────────────────────────

def run_restore(name: str, only: str, yes: bool) -> int:
    s = settings()
    src_dir = s["dir"] / name
    if name.startswith(PARTIAL) or not (src_dir / MANIFEST).is_file():
        raise SystemExit(f"No complete backup named {name!r} in {s['dir']} "
                         "(see: watcher --list-backups)")
    man = json.loads((src_dir / MANIFEST).read_text())
    available = list(man.get("databases", {}))
    wanted = ([d.strip() for d in only.replace(",", " ").split()] if only else available)
    bad = [d for d in wanted if d not in available]
    if bad:
        raise SystemExit(f"Backup {name} does not contain: {', '.join(bad)} "
                         f"(it contains: {', '.join(available)})")

    # Exclude a scheduled backup from reading files while they are replaced
    lock_fd = os.open(str(s["dir"] / ".lock"), os.O_CREAT | os.O_RDWR, 0o640)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock_fd)
        raise SystemExit("A backup is running right now — try again when it has finished.")
    try:
        return _restore_locked(s, src_dir, name, wanted, yes)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def _restore_locked(s, src_dir, name, wanted, yes) -> int:
    # NOTE: the Watcher service must be stopped (open connections would keep
    # the replaced files alive and later writes would be lost).  The
    # `watcher --restore` command stops and restarts it around this call.
    print(f"Restore {name} → {DATA_DIR}: {', '.join(wanted)}")
    print("Current files will be MOVED (not deleted) to a pre-restore folder.")
    if not yes:
        if input("Type RESTORE to continue: ").strip() != "RESTORE":
            print("Cancelled — nothing changed.")
            return 1

    # Verify every copy before touching anything
    for key in wanted:
        f = src_dir / DATABASES[key]
        c = sqlite3.connect(f"file:{f}?mode=ro", uri=True)
        try:
            r = c.execute("PRAGMA quick_check").fetchone()[0]
        finally:
            c.close()
        if r != "ok":
            raise SystemExit(f"{f.name} in the backup failed quick_check ({r}) — nothing changed.")

    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    aside, n = DATA_DIR / f"pre-restore-{stamp}", 1
    while aside.exists():                     # unique even for restores in the same second
        n += 1
        aside = DATA_DIR / f"pre-restore-{stamp}-{n}"
    aside.mkdir(mode=0o750)
    owner = DATA_DIR.stat()          # restored files belong to the data dir's owner
    try:
        os.chown(aside, owner.st_uid, owner.st_gid)
    except PermissionError:
        pass
    for key in wanted:
        base = DATABASES[key]
        for suffix in ("", "-wal", "-shm"):
            cur = DATA_DIR / (base + suffix)
            if cur.exists():
                cur.rename(aside / (base + suffix))
        tmp = DATA_DIR / (base + ".restoring")
        shutil.copy2(src_dir / base, tmp)
        with open(tmp, "rb") as fh:
            os.fsync(fh.fileno())
        try:
            os.chown(tmp, owner.st_uid, owner.st_gid)
        except PermissionError:
            pass                      # not root: files are already ours
        os.chmod(tmp, 0o640)
        tmp.rename(DATA_DIR / base)
        print(f"  restored {base}")
    _fsync_dir(DATA_DIR)
    print(f"Previous files kept in {aside} — delete them once you are satisfied.")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Watcher IDS database backups")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("backup")
    sub.add_parser("list")
    r = sub.add_parser("restore")
    r.add_argument("name")
    r.add_argument("--only", default="", help="comma-separated: config,events,dns")
    r.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    a = ap.parse_args(argv)
    if a.cmd == "backup":
        return run_backup()
    if a.cmd == "list":
        return run_list()
    return run_restore(a.name, a.only, a.yes)


if __name__ == "__main__":
    sys.exit(main())
