"""目录修订领域逻辑（不依赖任何 Web/ORM 框架，便于离线测试）。

包含：
* 发布元数据校验（版本号、范围、互斥、重复依赖）
* 安装包 SHA-256 校验与内容寻址原子落盘
* 请求规范化哈希（同请求同哈希）

ORM 持久化操作见 :mod:`app.repository`。
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import threading

from .solver import Candidate, RuntimeRequirement, Snapshot
from .version import InvalidSpecifier, InvalidVersion, SpecifierSet, Version

try:  # POSIX 进程间互斥（生产为 Linux 容器）；不可用时退化为仅进程内锁
    import fcntl
except ImportError:  # pragma: no cover - Windows 等平台
    fcntl = None

__all__ = [
    "PublishError", "BatchConflict", "BatchStorageError", "RepairError",
    "RepairStorageError",
    "validate_metadata_specs", "verify_sha256",
    "save_package_atomic", "inspect_package_file", "atomic_repair_file",
    "content_addressed_path", "canonical_request", "canonical_batch",
]


class PublishError(ValueError):
    """发布被拒绝（摘要不符、范围非法、重复版本等）。"""


class RepairError(PublishError):
    """修复被拒绝（版本不存在由上层处理；摘要不符等）。"""


class BatchConflict(PublishError):
    """批次冲突：同号不同内容，或批次内/与目录既有版本撞车（HTTP 409）。"""


class BatchStorageError(IOError):
    """批次包文件落盘失败（调用方须回滚事务并清理已落盘文件）。"""

    def __init__(self, message: str, created_paths: list[str] | None = None):
        super().__init__(message)
        self.created_paths = created_paths or []


class RepairStorageError(IOError):
    """修复写盘失败：原子替换未完成，调用方须明确拒绝并保留原文件。"""


# ---------------------------------------------------------------- 内容文件锁
#
# 同一个 SHA-256 对应同一个内容寻址文件。发布落盘、同摘要的修复替换必须在
# 文件级串行：既避免两个线程/进程同时写同一临时路径与替换窗口，也保证修复
# 不会覆盖一个刚刚由并发发布确认完好的文件。下载不持锁，只在替换完成后看到
# 旧（缺失/损坏）或新（完好）状态，os.replace 的原子性使其永远看不到半截文件。

_content_locks_guard = threading.Lock()
_content_locks: dict[str, threading.Lock] = {}


def _lock_for(path: str) -> threading.Lock:
    with _content_locks_guard:
        lock = _content_locks.get(path)
        if lock is None:
            lock = threading.Lock()
            _content_locks[path] = lock
        return lock


@contextlib.contextmanager
def content_file_lock(dest_dir: str, sha256: str):
    """对 ``(dest_dir, sha256)`` 对应的内容文件加进程内 + POSIX 排他锁。"""
    final_path = content_addressed_path(dest_dir, sha256)
    thread_lock = _lock_for(final_path)
    thread_lock.acquire()
    lock_path = os.path.join(os.path.dirname(final_path), ".locks", sha256)
    flock_fh = None
    try:
        if fcntl is not None:
            os.makedirs(os.path.dirname(lock_path), exist_ok=True)
            flock_fh = open(lock_path, "a+b")
            fcntl.flock(flock_fh.fileno(), fcntl.LOCK_EX)
        yield final_path
    finally:
        if flock_fh is not None:
            try:
                fcntl.flock(flock_fh.fileno(), fcntl.LOCK_UN)
            finally:
                flock_fh.close()
        thread_lock.release()


# ---------------------------------------------------------------- 校验

def validate_metadata_specs(metadata) -> None:
    """发布前校验：版本号合法、所有范围可解析、互斥项不含自身、依赖不重复。"""
    try:
        Version.parse(metadata.version)
    except InvalidVersion as e:
        raise PublishError(str(e)) from e

    for dep in metadata.dependencies:
        try:
            SpecifierSet.parse(dep.spec or "")
        except InvalidSpecifier as e:
            raise PublishError(f"依赖 {dep.plugin} 的版本范围无效: {e}") from e

    for rt in metadata.runtimes:
        try:
            SpecifierSet.parse(rt.spec or "")
        except InvalidSpecifier as e:
            raise PublishError(f"运行环境 {rt.name} 的版本范围无效: {e}") from e

    dep_names = [d.plugin for d in metadata.dependencies]
    if len(set(dep_names)) != len(dep_names):
        raise PublishError("同一依赖插件只能声明一条版本范围")

    rt_names = [r.name for r in metadata.runtimes]
    if len(set(rt_names)) != len(rt_names):
        raise PublishError("同一运行环境只能声明一条版本范围")

    if metadata.plugin in metadata.conflicts:
        raise PublishError("插件不能与自身互斥")


def verify_sha256(path: str, expected: str) -> None:
    actual = file_sha256(path)
    if actual != expected.lower():
        raise PublishError(
            f"安装包摘要不符：声明 {expected}，实际 {actual}，已拒绝写入")


def file_sha256(path: str) -> str:
    """流式计算文件 SHA-256。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def content_addressed_path(dest_dir: str, sha256: str) -> str:
    """内容寻址最终路径：``dest_dir/<sha 前两位>/<sha>``。"""
    return os.path.join(dest_dir, sha256[:2], sha256)


# 包文件核验状态：完好 / 缺失 / 损坏
STATE_INTACT = "intact"
STATE_MISSING = "missing"
STATE_CORRUPT = "corrupt"


def inspect_package_file(storage_path: str, expected_sha256: str,
                         ) -> tuple[str, int | None, str | None]:
    """核验内容寻址文件，返回 ``(状态, 字节数, 实际摘要)``。

    * 文件不存在 -> ``("missing", None, None)``；
    * 存在但重新计算的 SHA-256 与记录不符（或不可读）-> ``("corrupt", ...)``；
    * 摘要一致 -> ``("intact", 字节数, 实际摘要)``。
    """
    try:
        size = os.path.getsize(storage_path)
        actual = file_sha256(storage_path)
    except FileNotFoundError:
        return STATE_MISSING, None, None
    except OSError:
        return STATE_CORRUPT, None, None
    if actual != expected_sha256.lower():
        return STATE_CORRUPT, size, actual
    return STATE_INTACT, size, actual


def save_package_atomic(src_path: str, sha256: str, dest_dir: str,
                        ) -> tuple[str, int, bool]:
    """以 sha256 前两字符分桶做内容寻址，先写临时文件再原子重命名。

    返回 ``(最终路径, 字节数, 本次是否真正创建了文件)``。失败批次回滚时
    只需删除 created=True 的路径——已存在的内容寻址文件可能属于别的
    （已成功）发布，绝不能动。

    同摘要的发布/修复共用 :func:`content_file_lock`：文件已存在且完好时不
    改写；并发修复绝不会覆盖本次确认完好的文件。
    """
    sha256 = sha256.lower()
    os.makedirs(dest_dir, exist_ok=True)
    with content_file_lock(dest_dir, sha256) as final_path:
        os.makedirs(os.path.dirname(final_path), exist_ok=True)
        if os.path.exists(final_path):
            return final_path, os.path.getsize(final_path), False
        tmp_path = os.path.join(
            os.path.dirname(final_path),
            f".tmp-{os.getpid()}-{threading.get_ident()}-{sha256}")
        try:
            shutil.move(src_path, tmp_path)
            os.replace(tmp_path, final_path)
        finally:
            if os.path.exists(tmp_path):
                with contextlib.suppress(OSError):
                    os.unlink(tmp_path)
        return final_path, os.path.getsize(final_path), True


def atomic_repair_file(src_path: str, sha256: str, dest_dir: str,
                       ) -> tuple[str, str, bool]:
    """用摘要已核验的替换文件原子修复内容寻址文件。

    返回 ``(最终路径, 修复后状态, 是否真正替换)``：

    * 现存文件**完好** -> 绝不改写，``replaced=False``（status=intact）；
    * 现存文件缺失或损坏 -> 持同摘要锁，临时文件 + ``os.replace`` 原子替换，
      替换后重新核验；成功 ``replaced=True``（status=intact）；
    * 写盘/替换失败或替换后复核不通过 -> :class:`RepairStorageError`，
      原完好文件不动、原损坏文件尽量保留。
    """
    sha256 = sha256.lower()
    os.makedirs(dest_dir, exist_ok=True)
    with content_file_lock(dest_dir, sha256) as final_path:
        os.makedirs(os.path.dirname(final_path), exist_ok=True)
        state, _size, _actual = inspect_package_file(final_path, sha256)
        if state == STATE_INTACT:
            return final_path, STATE_INTACT, False

        tmp_path = os.path.join(
            os.path.dirname(final_path),
            f".repair-{os.getpid()}-{threading.get_ident()}-{sha256}")
        replaced = False
        try:
            try:
                shutil.move(src_path, tmp_path)
                os.replace(tmp_path, final_path)
                replaced = True
            except OSError as e:
                raise RepairStorageError(f"修复文件写盘失败: {e}") from e
            new_state, _size, _actual = inspect_package_file(final_path, sha256)
            if new_state != STATE_INTACT:
                raise RepairStorageError(
                    f"替换后复核未通过：状态 {new_state}，原记录摘要 {sha256}")
            return final_path, STATE_INTACT, True
        finally:
            if not replaced and os.path.exists(tmp_path):
                with contextlib.suppress(OSError):
                    os.unlink(tmp_path)


# ---------------------------------------------------------------- 请求规范化

def canonical_request(runtimes, targets: dict[str, str]) -> tuple[str, dict]:
    """规范化请求并计算 SHA-256：同请求（忽略键顺序）得到相同哈希。"""
    payload = {
        "runtimes": sorted(
            ({"name": r.name, "spec": str(r.spec)} for r in runtimes),
            key=lambda x: x["name"],
        ),
        "targets": {k: (v or "") for k, v in sorted(targets.items())},
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest(), payload


# ---------------------------------------------------------------- 批次规范化

def canonical_batch(metadatas, hashes) -> tuple[str, list[dict]]:
    """计算批次内容哈希。

    内容 = 每个成员的（插件、版本、SHA-256、规范化后的运行环境/依赖/
    互斥项），按 (插件, 版本) 排序后序列化——成员提交顺序不影响内容。
    调用方须先用 :func:`validate_metadata_specs` 完成逐项校验。
    """
    members = []
    for meta, sha in zip(metadatas, hashes):
        members.append({
            "plugin": meta.plugin,
            "version": meta.version,
            "sha256": sha,
            "runtimes": sorted(
                ({"name": r.name, "spec": r.spec or ""} for r in meta.runtimes),
                key=lambda x: x["name"]),
            "dependencies": sorted(
                ({"plugin": d.plugin, "spec": d.spec or ""}
                 for d in meta.dependencies),
                key=lambda x: x["plugin"]),
            "conflicts": sorted(meta.conflicts),
        })
    members.sort(key=lambda m: (m["plugin"], m["version"]))
    payload = {"members": members}
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest(), members


def collect_batch_package_files(db, storage_paths: list[str]) -> set[str]:
    """在新事务里查 storage_path 仍被任何版本行引用的路径。

    失败批次回滚后调用：引用集合之外的路径都是本次失败尝试引入的孤儿，
    由调用方删除；已被别的成功发布引用的内容寻址文件保留。
    """
    from .models import PluginVersion
    if not storage_paths:
        return set()
    referenced: set[str] = set()
    batch = 500
    for i in range(0, len(storage_paths), batch):
        chunk = storage_paths[i:i + batch]
        rows = db.query(PluginVersion.storage_path).filter(
            PluginVersion.storage_path.in_(chunk)).all()
        referenced.update(r[0] for r in rows)
    return referenced


def cleanup_orphan_files(db, created_paths: list[str]) -> None:
    """失败批次回滚后的尽力垃圾回收：只删数据库中再无版本引用的文件。"""
    unique_paths = [p for p in dict.fromkeys(created_paths)]
    try:
        referenced = collect_batch_package_files(db, unique_paths)
    except Exception:
        return
    for path in unique_paths:
        if path in referenced:
            continue
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except OSError:
            pass
