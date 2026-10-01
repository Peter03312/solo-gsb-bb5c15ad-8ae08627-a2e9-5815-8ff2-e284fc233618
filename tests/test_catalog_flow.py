"""内存版仓储：仅用标准库验证发布/快照/撤销的业务编排逻辑。

不导入 sqlalchemy/fastapi：catalog 模块只含纯领域逻辑，
repository 中 ORM 函数在这里用内存实现替换，由 service/路由同款算法复用。
"""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dataclasses import dataclass, field
from types import SimpleNamespace

from app import catalog, repository
from app.solver import RuntimeRequirement, UnsatisfiableError, installation_order, solve
from app.version import SpecifierSet, Version


@dataclass
class Row:
    id: int
    plugin_name: str
    version: str
    sha256: str = ""
    filename: str = ""
    size_bytes: int = 0
    storage_path: str = ""
    published_revision: int = 0
    revoked_revision: int | None = None
    revoke_reason: str | None = None
    deps: list = field(default_factory=list)        # [(name, spec)]
    runtimes: list = field(default_factory=list)    # [(name, spec)]
    conflicts: list = field(default_factory=list)


class MemoryDB:
    def __init__(self):
        self.revisions: list[int] = []
        self.rows: list[Row] = []
        self.solutions: dict[tuple[int, str], dict] = {}
        self.batches: dict[str, dict] = {}
        self._next_id = 1
        self._next_sid = 1

    def add_revision(self):
        rev = (self.revisions[-1] + 1) if self.revisions else 1
        self.revisions.append(rev)
        return rev

    def visible_rows(self, revision):
        return [r for r in self.rows
                if r.published_revision <= revision
                and (r.revoked_revision is None or revision < r.revoked_revision)]


# ---- 用内存实现替换 repository 的 ORM 函数（与生产逻辑同构）----------------

def install(mdb: MemoryDB, pkgdir: str):
    def latest_revision(db):
        return db.revisions[-1] if db.revisions else 0

    def bump_revision(db, *, kind, plugin, version, note=None):
        return SimpleNamespace(revision=db.add_revision())

    def publish_version(db, *, metadata, src_path, original_filename, package_dir):
        catalog.validate_metadata_specs(metadata)
        if any(r.plugin_name == metadata.plugin and r.version == metadata.version
               for r in db.rows):
            raise catalog.PublishError(
                f"{metadata.plugin}=={metadata.version} 已发布，同名同版本不可改写")
        catalog.verify_sha256(src_path, metadata.sha256)
        path, size, _created = catalog.save_package_atomic(
            src_path, metadata.sha256, package_dir)
        rev = db.add_revision()
        row = Row(
            id=0, plugin_name=metadata.plugin, version=metadata.version,
            sha256=metadata.sha256,
            filename=os.path.basename(original_filename),
            size_bytes=size, storage_path=path, published_revision=rev,
            deps=[(d.plugin, d.spec or "") for d in metadata.dependencies],
            runtimes=[(r.name, r.spec or "") for r in metadata.runtimes],
            conflicts=list(metadata.conflicts),
        )
        row.id = mdb._next_id
        mdb._next_id += 1
        db.rows.append(row)
        return row, rev

    def revoke_version(db, *, plugin_name, version, reason):
        row = next((r for r in db.rows
                    if r.plugin_name == plugin_name and r.version == version), None)
        if row is None:
            raise catalog.PublishError(f"未找到 {plugin_name}=={version}")
        if row.revoked_revision is not None:
            raise catalog.PublishError(f"{plugin_name}=={version} 已撤销")
        rev = db.add_revision()
        row.revoked_revision = rev
        row.revoke_reason = reason
        return rev

    # ---- 批次（与 repository.publish_batch 语义同构的内存实现）----
    class _BatchOutcome:
        def __init__(self, batch_id, revision, cached, content_hash, members,
                     created_paths, batch_row):
            self.batch_id = batch_id
            self.revision = revision
            self.cached = cached
            self.content_hash = content_hash
            self.members = members
            self.created_paths = created_paths
            self.batch_row = batch_row

    class _BatchRow:
        def __init__(self, batch_id, content_hash, revision_id, member_count):
            self.batch_id = batch_id
            self.content_hash = content_hash
            self.revision_id = revision_id
            self.member_count = member_count
            self.created_at = None

    def get_batch(db, batch_id):
        rec = db.batches.get(batch_id)
        return None if rec is None else rec["row"]

    def _members_of(db, revision_no):
        return sorted(
            ((r, r.plugin_name) for r in db.rows
             if r.published_revision == revision_no),
            key=lambda t: (t[1], t[0].version))

    def _load_batch_outcome(db, batch_row, *, cached):
        members = [(name, r.version, r) for r, name in _members_of(db, batch_row.revision_id)]
        return _BatchOutcome(batch_row.batch_id, batch_row.revision_id, cached,
                             batch_row.content_hash, members, [], batch_row)

    def items_content_hash(items):
        metas = [m for m, _s, _f in items]
        hashes = [m.sha256 for m, _s, _f in items]
        h, _ = catalog.canonical_batch(metas, hashes)
        return h

    def publish_batch(db, *, batch_id, items, package_dir,
                      created_paths_sink=None):
        existing = db.batches.get(batch_id)
        if existing is not None:
            if existing["row"].content_hash != items_content_hash(items):
                raise catalog.BatchConflict(
                    f"批次 {batch_id} 已提交但内容不同")
            return _load_batch_outcome(db, existing["row"], cached=True)

        seen = set()
        for metadata, _src, _fname in items:
            key = (metadata.plugin, metadata.version)
            if key in seen:
                raise catalog.BatchConflict(
                    f"批次内插件名与版本组合重复：{metadata.plugin}=={metadata.version}")
            seen.add(key)
            if any(r.plugin_name == metadata.plugin and r.version == metadata.version
                   for r in db.rows):
                raise catalog.BatchConflict(
                    f"{metadata.plugin}=={metadata.version} 已发布，同名同版本不可改写")

        stored = []
        created_paths = []
        for metadata, src_path, filename in items:
            catalog.verify_sha256(src_path, metadata.sha256)
            path, size, created = catalog.save_package_atomic(
                src_path, metadata.sha256, package_dir)
            if created:
                created_paths.append(path)
                if created_paths_sink is not None:
                    created_paths_sink.append(path)
            stored.append((metadata, path, size, filename))

        rev = db.add_revision()  # 整个批次只产生一个修订
        for metadata, path, size, filename in stored:
            row = Row(
                id=mdb._next_id, plugin_name=metadata.plugin,
                version=metadata.version, sha256=metadata.sha256,
                filename=os.path.basename(filename), size_bytes=size,
                storage_path=path, published_revision=rev,
                deps=[(d.plugin, d.spec or "") for d in metadata.dependencies],
                runtimes=[(r.name, r.spec or "") for r in metadata.runtimes],
                conflicts=list(metadata.conflicts))
            mdb._next_id += 1
            db.rows.append(row)
        content_hash = items_content_hash(items)
        batch_row = _BatchRow(batch_id, content_hash, rev, len(items))
        db.batches[batch_id] = {"row": batch_row}
        members = [(name, r.version, r) for r, name in _members_of(db, rev)]
        return _BatchOutcome(batch_id, rev, False, content_hash, members,
                             created_paths, batch_row)

    def load_snapshot(db, revision):
        from app.solver import Candidate, Snapshot
        grouped: dict[str, list] = {}
        for r in db.visible_rows(revision):
            grouped.setdefault(r.plugin_name, []).append(Candidate(
                plugin=r.plugin_name,
                version=Version.parse(r.version),
                runtimes=tuple(RuntimeRequirement(n, SpecifierSet.parse(s))
                               for n, s in r.runtimes),
                dependencies=tuple((d, SpecifierSet.parse(s))
                                   for d, s in sorted(r.deps)),
                conflicts=tuple(sorted(r.conflicts)),
            ))
        return Snapshot(revision=revision, candidates_by_plugin={
            k: tuple(sorted(v, key=lambda c: c.version, reverse=True))
            for k, v in grouped.items()})

    def get_solution(db, revision, h):
        return db.solutions.get((revision, h))

    def save_solution(db, *, revision, request_hash, request, selection,
                      install_order):
        row = {"id": db._next_sid, "revision_id": revision,
               "request_hash": request_hash, "request": request,
               "selection": selection, "install_order": install_order}
        db._next_sid += 1
        db.solutions[(revision, request_hash)] = row
        return row

    def revoked_flags(db, ids):
        return {r.id: r.revoked_revision is not None
                for r in db.rows if r.id in ids}

    # ---- 安装包核验与修复（与 repository 同名函数语义同构；只读 DB）----
    def get_version_row(db, plugin_name, version):
        row = next((r for r in db.rows
                    if r.plugin_name == plugin_name and r.version == version), None)
        return None if row is None else (row, plugin_name)

    def versions_sharing_sha(db, sha256):
        return [(r.plugin_name, r.version, r.revoked_revision)
                for r in db.rows if r.sha256 == sha256]

    def inspect_version(db, plugin_name, version):
        got = get_version_row(db, plugin_name, version)
        if got is None:
            return None
        row, name = got
        status, actual = catalog.inspect_package_file(row.storage_path, row.sha256)
        return row, name, status, actual, versions_sharing_sha(db, row.sha256)

    def inspect_all(db, plugin_name=None):
        fc = {}
        sc = {}
        out = []
        for r in db.rows:
            if plugin_name is not None and r.plugin_name != plugin_name:
                continue
            if r.sha256 not in fc:
                fc[r.sha256] = catalog.inspect_package_file(r.storage_path, r.sha256)
            if r.sha256 not in sc:
                sc[r.sha256] = versions_sharing_sha(db, r.sha256)
            st, actual = fc[r.sha256]
            out.append((r, r.plugin_name, st, actual, sc[r.sha256]))
        return out

    def repair_version_file(db, *, plugin_name, version, src_path):
        got = get_version_row(db, plugin_name, version)
        if got is None:
            raise catalog.PublishError(f"未找到已发布版本 {plugin_name}=={version}")
        row, _name = got
        catalog.verify_sha256(src_path, row.sha256)
        previous, _ = catalog.inspect_package_file(row.storage_path, row.sha256)
        status, written = catalog.restore_package_atomic(
            src_path, row.sha256, row.storage_path)
        sharing = versions_sharing_sha(db, row.sha256)
        return repository.RepairOutcome(
            plugin=plugin_name, version=version, sha256=row.sha256,
            storage_path=row.storage_path, previous_status=previous,
            status=status, written=written, affected_versions=sharing,
            affected_count=len(sharing) if written else 0)

    repository.latest_revision = latest_revision
    repository.bump_revision = bump_revision
    repository.publish_version = publish_version
    repository.revoke_version = revoke_version
    repository.get_batch = get_batch
    repository.publish_batch = publish_batch
    repository.items_content_hash = staticmethod(items_content_hash)
    repository._load_batch_outcome = _load_batch_outcome
    repository.load_snapshot = load_snapshot
    repository.get_solution = get_solution
    repository.save_solution = save_solution
    repository.revoked_flags = revoked_flags
    repository.get_version_row = get_version_row
    repository.versions_sharing_sha = versions_sharing_sha
    repository.inspect_version = inspect_version
    repository.inspect_all = inspect_all
    repository.repair_version_file = repair_version_file


class Meta:
    def __init__(self, plugin, version, sha256, runtimes=(), dependencies=(),
                 conflicts=()):
        self.plugin = plugin
        self.version = version
        self.sha256 = sha256
        self.runtimes = [SimpleNamespace(name=n, spec=s) for n, s in runtimes]
        self.dependencies = [SimpleNamespace(plugin=n, spec=s)
                             for n, s in dependencies]
        self.conflicts = list(conflicts)


class MemoryFlowTests(unittest.TestCase):
    def setUp(self):
        self.pkgdir = tempfile.mkdtemp()
        self.db = MemoryDB()
        install(self.db, self.pkgdir)

    def _write_pkg(self, content: str):
        fd, path = tempfile.mkstemp(dir=self.pkgdir)
        with os.fdopen(fd, "wb") as f:
            f.write(content.encode())
        return path, hashlib.sha256(content.encode()).hexdigest()

    def publish(self, plugin, version, content, runtimes=(), deps=(), conflicts=()):
        path, sha = self._write_pkg(content)
        return repository.publish_version(
            self.db,
            metadata=Meta(plugin, version, sha, runtimes, deps, conflicts),
            src_path=path, original_filename=f"{plugin}-{version}.bin",
            package_dir=self.pkgdir)

    def batch_publish(self, batch_id, members):
        """members: [(plugin, version, content, runtimes, deps), ...]"""
        items = []
        for plugin, version, content, *rest in members:
            runtimes = rest[0] if len(rest) > 0 else ()
            deps = rest[1] if len(rest) > 1 else ()
            path, sha = self._write_pkg(content)
            items.append((Meta(plugin, version, sha, runtimes, deps),
                          path, f"{plugin}-{version}.bin"))
        return repository.publish_batch(
            self.db, batch_id=batch_id, items=items,
            package_dir=self.pkgdir)

    def test_full_lifecycle(self):
        self.publish("numpy", "2.1.0", "n2", runtimes=[("python", ">=3.10")])
        self.publish("numpy", "1.26.4", "n1", runtimes=[("python", ">=3.9,<3.10")])
        self.publish("dtk", "3.0.0", "d3", runtimes=[("python", ">=3.10")],
                     deps=[("numpy", ">=2,<3")])
        self.assertEqual(self.db.revisions, [1, 2, 3])

        # 同名同版本不可改写
        with self.assertRaises(catalog.PublishError):
            self.publish("numpy", "2.1.0", "n2",
                         runtimes=[("python", ">=3.10")])

        rev3 = 3
        snap = repository.load_snapshot(self.db, rev3)
        rts = [RuntimeRequirement("python", SpecifierSet.parse("3.11.*"))]
        plan = solve(snap, rts, {"dtk": SpecifierSet.parse("")})
        self.assertEqual(str(plan["numpy"].version), "2.1.0")
        self.assertEqual(installation_order(plan), ["numpy", "dtk"])

        h, _ = catalog.canonical_request(rts, {"dtk": ""})
        self.assertIsNone(repository.get_solution(self.db, rev3, h))
        sol = repository.save_solution(
            self.db, revision=rev3, request_hash=h, request={},
            selection={"numpy": {"version_id": 1}},
            install_order=["numpy", "dtk"])
        self.assertIs(repository.get_solution(self.db, rev3, h), sol)

        rev4 = repository.revoke_version(
            self.db, plugin_name="numpy", version="2.1.0", reason="缺陷")
        self.assertEqual(rev4, 4)
        self.assertIn("2.1.0", [r.version for r in self.db.visible_rows(rev3)
                                if r.plugin_name == "numpy"])
        self.assertEqual([r.version for r in self.db.visible_rows(rev4)
                          if r.plugin_name == "numpy"], ["1.26.4"])
        self.assertTrue(repository.revoked_flags(self.db, [1])[1])
        with self.assertRaises(catalog.PublishError):
            repository.revoke_version(self.db, plugin_name="numpy",
                                      version="2.1.0", reason="x")

    def test_bad_sha_rejected_before_row(self):
        path, _ = self._write_pkg("payload")
        before = len(self.db.rows)
        with self.assertRaises(catalog.PublishError):
            repository.publish_version(
                self.db, metadata=Meta("p", "1.0", "0" * 64),
                src_path=path, original_filename="p.bin",
                package_dir=self.pkgdir)
        self.assertEqual(len(self.db.rows), before)
        self.assertEqual(self.db.revisions, [])

    def test_invalid_dependency_spec_rejected(self):
        path, sha = self._write_pkg("x")
        with self.assertRaises(catalog.PublishError):
            repository.publish_version(
                self.db,
                metadata=Meta("p", "1.0", sha, dependencies=[("ghost", "~=1")]),
                src_path=path, original_filename="p.bin",
                package_dir=self.pkgdir)

    def test_solver_unsat_after_revoke(self):
        self.publish("base", "1.0.0", "b", deps=[("lib", "")])
        self.publish("lib", "1.0.0", "l")
        rev = self.db.revisions[-1]
        plan = solve(repository.load_snapshot(self.db, rev), [],
                     {"base": SpecifierSet.parse("")})
        self.assertEqual(set(plan), {"base", "lib"})

        repository.revoke_version(self.db, plugin_name="lib",
                                  version="1.0.0", reason=None)
        with self.assertRaises(UnsatisfiableError):
            solve(repository.load_snapshot(self.db, self.db.revisions[-1]), [],
                  {"base": SpecifierSet.parse("")})

    def test_canonical_hash_independent_of_key_order(self):
        rt = [RuntimeRequirement("python", SpecifierSet.parse("3.11.*"))]
        h1, _ = catalog.canonical_request(rt, {"a": ">=1", "b": ""})
        h2, _ = catalog.canonical_request(list(rt), {"b": "", "a": ">=1"})
        self.assertEqual(h1, h2)

    # ------------------------------------------------------------ 批次
    def test_batch_all_members_share_one_revision(self):
        out = self.batch_publish("b1", [
            ("blib", "1.0.0", "blib", (), ()),
            ("bapp", "1.0.0", "bapp", (), [("blib", ">=1")]),
        ])
        self.assertFalse(out.cached)
        self.assertEqual(out.revision, 1)
        self.assertEqual([m[0] for m in out.members], ["bapp", "blib"])
        self.assertTrue(all(pv.published_revision == 1
                            for _n, _v, pv in out.members))
        # 修订 0 为空，修订 1 两个成员同时可见且可解
        self.assertEqual(self.db.visible_rows(0), [])
        snap = repository.load_snapshot(self.db, 1)
        plan = solve(snap, [], {"bapp": SpecifierSet.parse("")})
        self.assertEqual(installation_order(plan), ["blib", "bapp"])

    def test_batch_idempotent_same_content_any_order(self):
        members = [("x", "1.0.0", "x1"), ("y", "1.0.0", "y1")]
        out1 = self.batch_publish("idem", members)
        self.assertFalse(out1.cached)
        # 相同内容、不同顺序 -> 原结果
        out2 = self.batch_publish("idem", list(reversed(members)))
        self.assertTrue(out2.cached)
        self.assertEqual(out2.revision, out1.revision)
        self.assertEqual(out2.content_hash, out1.content_hash)
        # 只产生了一个修订
        self.assertEqual(self.db.revisions, [1])

    def test_batch_same_id_different_content_conflict(self):
        self.batch_publish("cid", [("p", "1.0.0", "one")])
        with self.assertRaises(catalog.BatchConflict):
            self.batch_publish("cid", [("p", "1.0.0", "two")])

    def test_batch_duplicate_pair_within_batch(self):
        before = len(self.db.rows)
        with self.assertRaises(catalog.BatchConflict):
            self.batch_publish("dup", [("d", "1.0.0", "d"), ("d", "1.0.0", "d")])
        self.assertEqual(len(self.db.rows), before)
        self.assertEqual(self.db.revisions, [])

    def test_batch_member_already_exists_whole_batch_rejected(self):
        self.publish("old", "1.0.0", "old")
        rev_before = self.db.revisions[-1]
        with self.assertRaises(catalog.BatchConflict):
            self.batch_publish("b", [
                ("new", "1.0.0", "new"),
                ("old", "1.0.0", "old"),  # 已存在
            ])
        self.assertFalse(any(r.plugin_name == "new" for r in self.db.rows))
        self.assertEqual(self.db.revisions[-1], rev_before)

    def test_batch_bad_sha_rejected(self):
        fd, path = tempfile.mkstemp(dir=self.pkgdir)
        with os.fdopen(fd, "wb") as f:
            f.write(b"actual")
        items = [(Meta("z", "1.0.0", "0" * 64), path, "z.bin")]
        with self.assertRaises(catalog.PublishError):
            repository.publish_batch(
                self.db, batch_id="badsha", items=items,
                package_dir=self.pkgdir)
        self.assertEqual(self.db.revisions, [])
        self.assertNotIn("badsha", self.db.batches)

    # ------------------------------------------------ 安装包核验与修复
    def _row(self, plugin, version):
        return next(r for r in self.db.rows
                    if r.plugin_name == plugin and r.version == version)

    def _repair_src(self, content: str):
        fd, path = tempfile.mkstemp(dir=self.pkgdir)
        with os.fdopen(fd, "wb") as f:
            f.write(content.encode())
        return path

    def test_inspect_ok_missing_corrupt_and_sharing_count(self):
        # 两个不同插件版本使用**相同内容**（共享摘要），第三个独立
        self.publish("dup-a", "1.0.0", "same-bytes")
        self.publish("dup-b", "1.0.0", "same-bytes")
        self.publish("solo", "1.0.0", "solo-bytes")

        pv_a = self._row("dup-a", "1.0.0")
        pv_solo = self._row("solo", "1.0.0")

        # 全部完好
        found = repository.inspect_version(self.db, "dup-a", "1.0.0")
        _r, _n, status, actual, sharing = found
        self.assertEqual(status, catalog.STATUS_OK)
        self.assertEqual(actual, pv_a.sha256)
        self.assertEqual(len(sharing), 2)
        self.assertEqual([(n, v) for n, v, _rev in sharing],
                         [("dup-a", "1.0.0"), ("dup-b", "1.0.0")])

        inv = repository.inspect_all(self.db)
        self.assertEqual(len(inv), 3)
        statuses = [st for _r, _n, st, _a, _s in inv]
        self.assertEqual(statuses.count("ok"), 3)

        # 删除共享物理文件 -> 两个版本都 missing
        os.unlink(pv_a.storage_path)
        found = repository.inspect_version(self.db, "dup-b", "1.0.0")
        self.assertEqual(found[2], catalog.STATUS_MISSING)
        self.assertIsNone(found[3])

        # 写坏 solo 的文件 -> corrupt，actual 与记录不同
        with open(pv_solo.storage_path, "wb") as f:
            f.write(b"corrupted-content")
        found = repository.inspect_version(self.db, "solo", "1.0.0")
        _r, _n, status, actual, _sharing = found
        self.assertEqual(status, catalog.STATUS_CORRUPT)
        self.assertIsNotNone(actual)
        self.assertNotEqual(actual, pv_solo.sha256)

        inv = repository.inspect_all(self.db)
        summary = {}
        for _r, _n, st, _a, _s in inv:
            summary[st] = summary.get(st, 0) + 1
        self.assertEqual(summary, {"missing": 2, "corrupt": 1})

        # 未知版本
        self.assertIsNone(repository.inspect_version(self.db, "ghost", "9.9.9"))

    def test_inspect_includes_revoked_versions(self):
        self.publish("rv", "1.0.0", "rv-bytes")
        repository.revoke_version(self.db, plugin_name="rv", version="1.0.0",
                                  reason="旧包也要能核验")
        found = repository.inspect_version(self.db, "rv", "1.0.0")
        self.assertIsNotNone(found)
        self.assertEqual(found[2], catalog.STATUS_OK)
        inv = repository.inspect_all(self.db)
        self.assertEqual(len(inv), 1)

    def test_repair_missing_restores_all_sharing_versions_no_revision(self):
        self.publish("dup-a", "1.0.0", "same-bytes")
        self.publish("dup-b", "2.0.0", "same-bytes")
        revisions_before = list(self.db.revisions)
        pv_a = self._row("dup-a", "1.0.0")
        os.unlink(pv_a.storage_path)
        self.assertEqual(
            repository.inspect_version(self.db, "dup-a", "1.0.0")[2],
            catalog.STATUS_MISSING)

        outcome = repository.repair_version_file(
            self.db, plugin_name="dup-a", version="1.0.0",
            src_path=self._repair_src("same-bytes"))
        self.assertEqual(outcome.status, "repaired")
        self.assertTrue(outcome.written)
        self.assertEqual(outcome.previous_status, "missing")
        # 共享摘要的两个版本一并恢复
        self.assertEqual(outcome.affected_count, 2)
        self.assertEqual([(n, v) for n, v, _r in outcome.affected_versions],
                         [("dup-a", "1.0.0"), ("dup-b", "2.0.0")])
        # 修复不产生目录修订、不改元数据
        self.assertEqual(self.db.revisions, revisions_before)
        for name, ver in (("dup-a", "1.0.0"), ("dup-b", "2.0.0")):
            _r, _n, st, actual, _s = repository.inspect_version(self.db, name, ver)
            self.assertEqual(st, catalog.STATUS_OK)
            self.assertEqual(actual, self._row(name, ver).sha256)

    def test_repair_corrupt_file_is_atomically_replaced(self):
        self.publish("cr", "1.0.0", "orig-content")
        pv = self._row("cr", "1.0.0")
        with open(pv.storage_path, "wb") as f:
            f.write(b"broken")
        outcome = repository.repair_version_file(
            self.db, plugin_name="cr", version="1.0.0",
            src_path=self._repair_src("orig-content"))
        self.assertEqual(outcome.status, "repaired")
        self.assertEqual(outcome.previous_status, "corrupt")
        with open(pv.storage_path, "rb") as f:
            self.assertEqual(f.read(), b"orig-content")

    def test_repair_intact_file_is_not_rewritten(self):
        self.publish("ok", "1.0.0", "keep-me")
        pv = self._row("ok", "1.0.0")
        before = os.stat(pv.storage_path)
        outcome = repository.repair_version_file(
            self.db, plugin_name="ok", version="1.0.0",
            src_path=self._repair_src("keep-me"))
        self.assertEqual(outcome.status, "ok")
        self.assertFalse(outcome.written)
        self.assertEqual(outcome.affected_count, 0)
        # 完好文件不改写：inode/mtime 保持
        self.assertEqual(os.stat(pv.storage_path).st_ino, before.st_ino)

    def test_repair_sha_mismatch_rejected_and_original_kept(self):
        self.publish("mm", "1.0.0", "original")
        pv = self._row("mm", "1.0.0")
        os.unlink(pv.storage_path)  # 缺失状态
        # 提交内容与记录摘要不符：拒绝，且不得落任何文件到目标路径
        with self.assertRaises(catalog.PublishError):
            repository.repair_version_file(
                self.db, plugin_name="mm", version="1.0.0",
                src_path=self._repair_src("different-content"))
        self.assertFalse(os.path.exists(pv.storage_path))
        self.assertEqual(
            repository.inspect_version(self.db, "mm", "1.0.0")[2],
            catalog.STATUS_MISSING)

        # 损坏状态下同样拒绝，坏文件原样保留
        with open(pv.storage_path, "wb") as f:
            f.write(b"still-broken")
        with self.assertRaises(catalog.PublishError):
            repository.repair_version_file(
                self.db, plugin_name="mm", version="1.0.0",
                src_path=self._repair_src("different-content"))
        with open(pv.storage_path, "rb") as f:
            self.assertEqual(f.read(), b"still-broken")

    def test_repair_unknown_version_rejected(self):
        with self.assertRaises(catalog.PublishError):
            repository.repair_version_file(
                self.db, plugin_name="nope", version="1.0.0",
                src_path=self._repair_src("x"))

    def test_repair_concurrent_replacers_never_leave_partial_file(self):
        # 多次并发/重复修复同一缺失摘要：最终文件必完好，且每次读到的
        # 共享文件要么不存在要么完整，临时文件不得残留
        self.publish("cc1", "1.0.0", "concurrent-content")
        self.publish("cc2", "1.0.0", "concurrent-content")
        pv = self._row("cc1", "1.0.0")
        os.unlink(pv.storage_path)

        import threading
        errors = []

        def replace():
            try:
                src = self._repair_src("concurrent-content")
                repository.repair_version_file(
                    self.db, plugin_name="cc1", version="1.0.0", src_path=src)
            except Exception as e:  # noqa: BLE001
                errors.append(repr(e))

        threads = [threading.Thread(target=replace) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        self.assertEqual(errors, [])
        _r, _n, status, actual, sharing = repository.inspect_version(
            self.db, "cc2", "1.0.0")
        self.assertEqual(status, catalog.STATUS_OK)
        self.assertEqual(len(sharing), 2)
        leftovers = [n for n in os.listdir(os.path.dirname(pv.storage_path))
                     if n.startswith(".repair-")]
        self.assertEqual(leftovers, [])

    def test_publish_repairs_corrupt_existing_content_addressed_file(self):
        # 同摘要发布时发现既存内容寻址文件已损坏 -> 用完整上传原子扶正
        self.publish("first", "1.0.0", "shared-content")
        pv = self._row("first", "1.0.0")
        with open(pv.storage_path, "wb") as f:
            f.write(b"corrupt")
        # 另一插件发布相同内容（同摘要），不应引用坏文件
        path2, sha2 = self._write_pkg("shared-content")
        pv2, rev = repository.publish_version(
            self.db,
            metadata=Meta("second", "1.0.0", sha2),
            src_path=path2, original_filename="second-1.0.0.bin",
            package_dir=self.pkgdir)
        self.assertEqual(pv2.storage_path, pv.storage_path)
        self.assertEqual(
            repository.inspect_version(self.db, "first", "1.0.0")[2],
            catalog.STATUS_OK)


if __name__ == "__main__":
    unittest.main(verbosity=2)
