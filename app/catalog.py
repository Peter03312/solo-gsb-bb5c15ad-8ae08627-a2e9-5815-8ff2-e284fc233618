"""目录修订领域逻辑（不依赖任何 Web/ORM 框架，便于离线测试）。

包含：
* 发布元数据校验（版本号、范围、互斥、重复依赖）
* 安装包 SHA-256 校验与内容寻址原子落盘
* 请求规范化哈希（同请求同哈希）

ORM 持久化操作见 :mod:`app.repository`。
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil

from .solver import Candidate, RuntimeRequirement, Snapshot
from .version import InvalidSpecifier, InvalidVersion, SpecifierSet, Version

__all__ = [
    "PublishError", "BatchConflict", "BatchStorageError", "RepairStorageError",
    "validate_metadata_specs", "verify_sha256",
    "save_package_atomic", "restore_package_atomic", "inspect_package_file",
    "canonical_request", "canonical_batch",
    "STATUS_OK", "STATUS_MISSING", "STATUS_CORRUPT",
]

# 安装包核验状态（机器可读，与 HTTP 状态无关）
STATUS_OK = "ok"
STATUS_MISSING = "missing"
STATUS_CORRUPT = "corrupt"


class PublishError(ValueError):
    """发布被拒绝（摘要不符、范围非法、重复版本等）。"""


class BatchConflict(PublishError):
    """批次冲突：同号不同内容，或批次内/与目录既有版本撞车（HTTP 409）。"""


class BatchStorageError(IOError):
    """批次包文件落盘失败（调用方须回滚事务并清理已落盘文件）。"""

    def __init__(self, message: str, created_paths: list[str] | None = None):
        super().__init__(message)
        self.created_paths = created_paths or []


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
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    actual = h.hexdigest()
    if actual != expected.lower():
        raise PublishError(
            f"安装包摘要不符：声明 {expected}，实际 {actual}，已拒绝写入")


def save_package_atomic(src_path: str, sha256: str, dest_dir: str,
                        ) -> tuple[str, int, bool]:
    """以 sha256 前两字符分桶做内容寻址，先写临时文件再原子重命名。

    返回 ``(最终路径, 字节数, 本次是否真正创建了文件)``。失败批次回滚时
    只需删除 created=True 的路径——已存在的内容寻址文件可能属于别的
    （已成功）发布，绝不能动。
    """
    os.makedirs(dest_dir, exist_ok=True)
    bucket = os.path.join(dest_dir, sha256[:2])
    os.makedirs(bucket, exist_ok=True)
    final_path = os.path.join(bucket, sha256)
    size = os.path.getsize(src_path)
    created = False
    if not os.path.exists(final_path):
        tmp_path = _atomic_tmp_path(bucket, sha256)
        try:
            shutil.move(src_path, tmp_path)
            os.replace(tmp_path, final_path)
            created = True
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
    else:
        # 内容寻址目标已存在时通常无需落盘；但磁盘上的旧包可能已损坏
        # （长期保存介质损坏，或正由修复接口处理）。仅凭路径存在就跳过会让
        # 一次同摘要发布引用坏文件，因此先核验：损坏则用本次完整上传原子扶正，
        # 完好文件绝不改写，避免与并发下载/修复互相覆盖。
        if inspect_package_file(final_path, sha256)[0] != STATUS_OK:
            tmp_path = _atomic_tmp_path(bucket, sha256)
            try:
                shutil.copy2(src_path, tmp_path)
                os.replace(tmp_path, final_path)
            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
    return final_path, size, created


class RepairStorageError(IOError):
    """修复安装包写盘失败（原文件必须保持不变）。"""


def inspect_package_file(path: str, expected_sha256: str) -> tuple[str, str | None]:
    """核验磁盘上的内容寻址文件：返回 ``(状态, 实际摘要)``。

    * ``ok``      —— 文件存在且 SHA-256 与记录一致（actual == expected）；
    * ``missing`` —— 路径不存在（含悬挂路径/目录项丢失）；
    * ``corrupt`` —— 文件存在但摘要不符，或无法完整读取（I/O 错误、
                    读到半截内容等），此时 actual 尽量给出实测摘要，
                    无法读取时为 None。

    纯只读操作，不修改任何文件。
    """
    if not os.path.exists(path):
        return STATUS_MISSING, None
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        return STATUS_CORRUPT, None
    actual = h.hexdigest()
    if actual == expected_sha256.lower():
        return STATUS_OK, actual
    return STATUS_CORRUPT, actual


def _atomic_tmp_path(directory: str, sha256: str) -> str:
    """同目录唯一名临时文件：同目录 + os.replace 才是原子替换。

    随机后缀让多进程/多请求并发修复同一摘要时各自使用独立临时文件，
    互不踩踏；不使用固定名，避免并发清理到对方正在写入的临时文件。
    """
    return os.path.join(
        directory, f".repair-{os.getpid()}-{secrets.token_hex(8)}-{sha256}")


def restore_package_atomic(src_path: str, expected_sha256: str,
                           dest_path: str) -> tuple[str, bool]:
    """以只认记录摘要的方式原子修复一个内容寻址包文件。

    调用方须先用 :func:`verify_sha256` 确认上传件 ``src_path`` 的 SHA-256
    恰为记录值 ``expected_sha256``（不符应在路由层拒绝，不进入本函数）。

    * 目标完好（存在且摘要一致）：**不改写**，返回 ``("ok", False)``。
      并发的另一个修复/发布/下载已经确认过完好文件，绝不能互相覆盖。
    * 目标缺失或损坏：把上传件写到**目标所在目录**下的唯一临时文件，
      fsync 后用 :func:`os.replace` 原子换入，返回 ``("repaired", True)``。
      任何并发下载只会看到“旧文件/新文件”二者之一，读不到半截内容；
      写盘失败时只清理本次临时文件，原文件保持原样并抛
      :class:`RepairStorageError`。

    返回 ``(状态, 是否实际写入)``。
    """
    status, _actual = inspect_package_file(dest_path, expected_sha256)
    if status == STATUS_OK:
        return STATUS_OK, False

    dest_dir = os.path.dirname(dest_path) or "."
    os.makedirs(dest_dir, exist_ok=True)
    tmp_path = _atomic_tmp_path(dest_dir, expected_sha256)
    try:
        # 同目录临时文件保证 os.replace 是同文件系统的原子 rename
        with open(src_path, "rb") as fin, open(tmp_path, "wb") as fout:
            shutil.copyfileobj(fin, fout, length=1024 * 1024)
            fout.flush()
            try:
                os.fsync(fout.fileno())
            except OSError:
                # 某些文件系统（测试用 tmpfs/某些卷）不支持 fsync：
                # rename 原子性不依赖它，仅持久性保证弱化
                pass
        # 换入前最后一道防线：临时文件必须确为记录摘要，防止任何路径混淆
        tmp_status, _ = inspect_package_file(tmp_path, expected_sha256)
        if tmp_status != STATUS_OK:
            raise RepairStorageError(
                f"修复文件换入前复核失败（期望 {expected_sha256}）：原文件保留")
        try:
            os.replace(tmp_path, dest_path)
        except OSError as e:
            raise RepairStorageError(
                f"安装包原子替换失败: {e}；原文件保留") from e
    finally:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    return "repaired", True


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
