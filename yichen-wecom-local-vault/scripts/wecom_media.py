#!/usr/bin/env python3
"""Map WeCom message media to files the desktop client has already cached.

Read-only: walks the client's cache folders and parses message protobufs.
Never downloads, opens the app, or writes into the WeCom container.

Observed on macOS WeCom 5.x (see references/database-notes.md):
- image / file / voice descriptors carry the original file's MD5 in field 10,
  and the cache folder for that media is named after it;
- images keep up to three layers: ``<md5>_HD`` (the original as sent, whose
  content MD5 equals field 10), ``<md5>`` (preview) and ``<md5>_THUMB``;
- video folders are named ``md5(field 2)`` (the file id string) and video
  covers ``md5(field 7)`` (the cover URL).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

DEFAULT_PROFILES_ROOT = Path("~/Library/Containers/com.tencent.WeWorkMac/Data/Documents/Profiles").expanduser()
CACHE_KINDS = {
    "Images": "image",
    "Files": "file",
    "Voices": "voice",
    "Videos": "video",
    "Video_Thumbnail": "video_cover",
}
KIND_BY_CONTENT_TYPE = {14: "image", 15: "file", 16: "voice", 22: "video"}
KIND_LABELS = {"image": "图片", "file": "文件", "voice": "语音", "video": "视频"}
STATUS_LABELS = {
    "original": "原图已在本地",
    "preview_only": "只有预览图",
    "thumbnail_only": "只有缩略图",
    "downloaded": "已在本地",
    "cover_only": "只有视频封面",
    "missing": "本地没有",
}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".heic", ".webp", ".bmp", ".tif", ".tiff"}
VIDEO_EXTENSIONS = {".mp4", ".mov", ".m4v", ".avi"}
_KEY_DIR = re.compile(r"([0-9a-f]{32})(_HD|_THUMB)?")
_HEX32 = re.compile(rb"[0-9a-f]{32}")
_LONG_HEX = re.compile(rb"[0-9a-fA-F]{64,}")
_LONG_TOKEN = re.compile(rb"[\x21-\x7e]{32,}")
_MAX_DEPTH = 6


# --------------------------------------------------------------------------- protobuf


def _varint(data: bytes, position: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while position < len(data) and shift < 64:
        byte = data[position]
        position += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, position
        shift += 7
    raise ValueError("invalid varint")


def parse_fields(data: bytes) -> list[tuple[int, int | bytes]]:
    """Strictly parse one protobuf message; raise ValueError on anything odd."""
    fields: list[tuple[int, int | bytes]] = []
    position = 0
    while position < len(data):
        tag, position = _varint(data, position)
        number, wire = tag >> 3, tag & 7
        if number == 0:
            raise ValueError("field number 0")
        if wire == 0:
            value, position = _varint(data, position)
        elif wire == 1:
            value, position = data[position : position + 8], position + 8
        elif wire == 5:
            value, position = data[position : position + 4], position + 4
        elif wire == 2:
            length, position = _varint(data, position)
            if position + length > len(data):
                raise ValueError("truncated field")
            value, position = data[position : position + length], position + length
        else:
            raise ValueError(f"unsupported wire type {wire}")
        if position > len(data):
            raise ValueError("truncated field")
        fields.append((number, value))
    return fields


def _first(fields: list[tuple[int, int | bytes]]) -> dict[int, int | bytes]:
    result: dict[int, int | bytes] = {}
    for number, value in fields:
        result.setdefault(number, value)
    return result


def _text(value) -> str:
    if not isinstance(value, bytes):
        return ""
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return ""


def _int(value) -> int | None:
    return value if isinstance(value, int) else None


def _kind_from_name(name: str) -> str:
    suffix = Path(name).suffix.lower()
    if suffix in IMAGE_EXTENSIONS:
        return "image"
    if suffix in VIDEO_EXTENSIONS:
        return "video"
    return "file"


def _file_descriptor(fields: dict, kind_hint: str | None) -> dict | None:
    """Image / file / voice descriptor: f1 file id, f2 name, f4 size, f10 md5."""
    file_id, name, md5 = fields.get(1), fields.get(2), fields.get(10)
    if not (isinstance(file_id, bytes) and _LONG_HEX.fullmatch(file_id)):
        return None
    if not (isinstance(name, bytes) and isinstance(md5, bytes) and _HEX32.fullmatch(md5)):
        return None
    name_text = _text(name)
    kind = kind_hint or _kind_from_name(name_text)
    if kind == "video":
        kind = "file"
    ref = {
        "kind": kind,
        "name": name_text,
        "size": _int(fields.get(4)),
        "md5": md5.decode(),
        "keys": [md5.decode()],
    }
    if kind == "image":
        ref["width"], ref["height"] = _int(fields.get(5)), _int(fields.get(6))
    if kind == "voice" and _int(fields.get(7)):
        ref["duration_seconds"] = fields[7]
    return ref


def _video_descriptor(fields: dict) -> dict | None:
    """Video descriptor: f1 name, f2 file id token, f3 size, f4 seconds, f7 cover URL."""
    name, file_id = fields.get(1), fields.get(2)
    if not (isinstance(name, bytes) and isinstance(file_id, bytes) and _LONG_TOKEN.fullmatch(file_id)):
        return None
    if _int(fields.get(3)) is None:
        return None
    ref = {
        "kind": "video",
        "name": _text(name),
        "size": fields[3],
        "duration_seconds": _int(fields.get(4)),
        "width": _int(fields.get(5)),
        "height": _int(fields.get(6)),
        "keys": [hashlib.md5(file_id).hexdigest()],
    }
    cover = fields.get(7)
    if isinstance(cover, bytes) and cover:
        ref["cover_key"] = hashlib.md5(cover).hexdigest()
    return ref


def _walk(data: bytes, kind_hint: str | None, depth: int, found: list[dict]) -> None:
    if depth > _MAX_DEPTH or len(data) < 2:
        return
    try:
        fields = parse_fields(data)
    except (ValueError, IndexError):
        return
    first = _first(fields)
    if depth > 0 or kind_hint is not None:
        ref = _video_descriptor(first) if kind_hint == "video" else _file_descriptor(first, kind_hint)
        if ref:
            found.append(ref)
            return
    # A nested message item announces its own content type in field 5
    # (e.g. image parts of rich-text or merged-forward messages).
    child_hint = KIND_BY_CONTENT_TYPE.get(first.get(5)) if isinstance(first.get(5), int) else None
    for _, value in fields:
        if isinstance(value, bytes) and len(value) >= 8:
            _walk(value, child_hint, depth + 1, found)


def extract_media(content, content_type: int) -> list[dict]:
    """Return media references found in a message's raw ``content`` blob."""
    if content is None:
        return []
    data = content.encode() if isinstance(content, str) else bytes(content)
    if not data:
        return []
    found: list[dict] = []
    _walk(data, KIND_BY_CONTENT_TYPE.get(content_type), 0, found)
    unique: list[dict] = []
    seen: set[tuple] = set()
    for ref in found:
        marker = (ref["kind"], tuple(ref["keys"]))
        if marker not in seen:
            seen.add(marker)
            unique.append(ref)
    return unique


# --------------------------------------------------------------------------- cache index


def _profile_dirs(root: Path) -> list[Path]:
    """Accept a Profiles folder, one profile folder, or one Caches folder."""
    root = root.expanduser()
    if not root.is_dir():
        return []
    if any((root / name).is_dir() for name in CACHE_KINDS):
        return [root]
    if (root / "Caches").is_dir():
        return [root / "Caches"]
    return sorted(child / "Caches" for child in root.iterdir() if (child / "Caches").is_dir())


def _current_profile(root: Path) -> str | None:
    try:
        with (root / "setting.json").open(encoding="utf-8") as handle:
            value = json.load(handle).get("CurrentProfile")
    except (OSError, ValueError, AttributeError):
        return None
    return str(value) if value else None


def _layer(cache_kind: str, suffix: str | None) -> str:
    if cache_kind == "Images":
        return {"_HD": "original", "_THUMB": "thumbnail"}.get(suffix or "", "preview")
    return "file"


class MediaCache:
    """Index of ``<cache kind>/<year-month>/<key>[_HD|_THUMB]/<file>`` entries."""

    def __init__(self, root: str | Path | None = None):
        self.root = Path(root).expanduser() if root else DEFAULT_PROFILES_ROOT
        self.current_profile = _current_profile(self.root)
        self.caches = _profile_dirs(self.root)
        self.entries: dict[str, list[dict]] = {}
        for caches in self.caches:
            profile = caches.parent.name if caches.name == "Caches" else caches.name
            for cache_kind in CACHE_KINDS:
                base = caches / cache_kind
                if not base.is_dir():
                    continue
                for folder, _, files in os.walk(base):
                    match = _KEY_DIR.fullmatch(os.path.basename(folder))
                    if not match:
                        continue
                    for filename in files:
                        if filename.startswith("."):
                            continue
                        path = Path(folder) / filename
                        try:
                            stat = path.stat()
                        except OSError:
                            continue
                        self.entries.setdefault(match.group(1), []).append({
                            "cache_kind": cache_kind,
                            "layer": _layer(cache_kind, match.group(2)),
                            "profile": profile[:8],
                            "current_profile": profile == self.current_profile,
                            "path": str(path),
                            "cached_name": filename,
                            "size": stat.st_size,
                            "cached_at": int(getattr(stat, "st_birthtime", stat.st_mtime)),
                        })

    def lookup(self, key: str | None, cache_kinds: tuple[str, ...]) -> list[dict]:
        if not key:
            return []
        return [entry for entry in self.entries.get(key, []) if entry["cache_kind"] in cache_kinds]


def _pick(entries: list[dict], size: int | None) -> dict | None:
    """Prefer a size match, then the current profile, then the newest copy."""
    if not entries:
        return None
    return max(
        entries,
        key=lambda entry: (size is not None and entry["size"] == size, entry["current_profile"], entry["cached_at"]),
    )


def _md5_file(path: str) -> str:
    digest = hashlib.md5()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _local(entry: dict, size: int | None) -> dict:
    result = {
        "path": entry["path"],
        "cached_name": entry["cached_name"],
        "size": entry["size"],
        "cached_at": entry["cached_at"],
        "profile": entry["profile"],
    }
    if size is not None:
        result["size_match"] = entry["size"] == size
    return result


def resolve(ref: dict, cache: MediaCache, verify_md5: bool = False) -> dict:
    """Attach local cache status and the best local file to one media reference."""
    kind, size = ref["kind"], ref.get("size")
    key = ref["keys"][0]
    result = {key_: value for key_, value in ref.items() if key_ not in ("keys", "cover_key")}
    layers: dict[str, dict] = {}
    best = None
    if kind == "image":
        entries = cache.lookup(key, ("Images",))
        for layer in ("original", "preview", "thumbnail"):
            chosen = _pick([entry for entry in entries if entry["layer"] == layer], size if layer == "original" else None)
            if chosen:
                layers[layer] = _local(chosen, size if layer == "original" else None)
        if "original" in layers:
            status, best = "original", layers["original"]
        elif "preview" in layers:
            status, best = "preview_only", layers["preview"]
        elif "thumbnail" in layers:
            status, best = "thumbnail_only", layers["thumbnail"]
        else:
            status = "missing"
    elif kind == "video":
        chosen = _pick(cache.lookup(key, ("Videos",)), size)
        cover = _pick(cache.lookup(ref.get("cover_key"), ("Video_Thumbnail",)), None)
        if chosen:
            layers["video"] = _local(chosen, size)
        if cover:
            layers["cover"] = _local(cover, None)
        if chosen:
            status, best = "downloaded", layers["video"]
        elif cover:
            status, best = "cover_only", layers["cover"]
        else:
            status = "missing"
    else:
        kinds = ("Voices",) if kind == "voice" else ("Files", "Images", "Voices")
        # A file sent as an image only counts once its full original is cached.
        candidates = [entry for entry in cache.lookup(key, kinds) if entry["layer"] in ("file", "original")]
        chosen = _pick(candidates, size)
        status = "downloaded" if chosen else "missing"
        best = _local(chosen, size) if chosen else None
    if verify_md5 and best and ref.get("md5") and status in ("original", "downloaded"):
        best["md5_match"] = _md5_file(best["path"]) == ref["md5"]
    result["kind_label"] = KIND_LABELS.get(kind, kind)
    result["status"] = status
    result["status_label"] = STATUS_LABELS[status]
    result["local"] = best
    if layers:
        result["layers"] = list(layers)
    return result


def media_for_message(content, content_type: int, cache: MediaCache, verify_md5: bool = False) -> list[dict]:
    return [resolve(ref, cache, verify_md5) for ref in extract_media(content, content_type)]
