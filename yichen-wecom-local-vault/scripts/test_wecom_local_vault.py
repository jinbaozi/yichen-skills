#!/usr/bin/env python3
"""Offline unit tests; no WeCom process or user database is touched."""

from __future__ import annotations

import hashlib
import json
import os
import site
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from vault_cli import decode_content
from wecom_media import MediaCache, extract_media, media_for_message, resolve
from wecom_crypto import (
    PAGE_SIZE,
    SQLITE_HEADER,
    _wal_frames,
    database_format,
    decrypt_database_bytes,
    decrypt_page,
    encrypt_page_for_test,
    page_iv,
    page_key,
    verify_key,
)


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.key = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.page_one = bytearray(PAGE_SIZE)
        self.page_one[:16] = SQLITE_HEADER
        self.page_one[16:18] = (PAGE_SIZE).to_bytes(2, "big")
        self.page_one[21:24] = b"\x40\x20\x20"
        self.page_one[100] = 0x0D
        self.page_one[108:124] = b"offline-test-row"

    def test_page_one_round_trip_and_validation(self):
        encrypted = encrypt_page_for_test(self.key, bytes(self.page_one), 1)
        self.assertEqual(database_format(encrypted), "wecom-wxsqlite3-aes128")
        self.assertTrue(verify_key(self.key, encrypted))
        self.assertFalse(verify_key(bytes(16), encrypted))
        self.assertEqual(decrypt_page(self.key, encrypted, 1), bytes(self.page_one))

    def test_later_page_round_trip(self):
        page = bytes((index * 17) % 256 for index in range(PAGE_SIZE))
        encrypted = encrypt_page_for_test(self.key, page, 9)
        self.assertEqual(decrypt_page(self.key, encrypted, 9), page)

    def test_key_and_iv_are_page_specific(self):
        self.assertNotEqual(page_key(self.key, 1), page_key(self.key, 2))
        self.assertNotEqual(page_iv(1), page_iv(2))

    def test_wal_parser_stops_at_last_commit(self):
        wal_header = struct.pack(">IIIIIIII", 0x377F0682, 3007000, PAGE_SIZE, 0, 1, 2, 0, 0)
        frame_one = struct.pack(">IIIIII", 2, 0, 1, 2, 0, 0) + bytes(PAGE_SIZE)
        frame_two = struct.pack(">IIIIII", 3, 3, 1, 2, 0, 0) + bytes([1]) * PAGE_SIZE
        uncommitted = struct.pack(">IIIIII", 4, 0, 1, 2, 0, 0) + bytes([2]) * PAGE_SIZE
        frames = _wal_frames(wal_header + frame_one + frame_two + uncommitted, PAGE_SIZE)
        self.assertEqual([(page, commit) for page, commit, _ in frames], [(2, 0), (3, 3)])

    def test_wal_parser_skips_stale_salt_frames(self):
        wal_header = struct.pack(">IIIIIIII", 0x377F0682, 3007000, PAGE_SIZE, 0, 1, 2, 0, 0)
        stale_frame = struct.pack(">IIIIII", 2, 2, 9, 9, 0, 0) + bytes([7]) * PAGE_SIZE
        current_frame = struct.pack(">IIIIII", 3, 3, 1, 2, 0, 0) + bytes([8]) * PAGE_SIZE
        frames = _wal_frames(wal_header + stale_frame + current_frame, PAGE_SIZE)
        self.assertEqual([(page, commit) for page, commit, _ in frames], [(3, 3)])

    def test_database_and_committed_wal_round_trip(self):
        base_second_page = bytes([3]) * PAGE_SIZE
        updated_second_page = bytes([9]) * PAGE_SIZE
        encrypted_database = (
            encrypt_page_for_test(self.key, bytes(self.page_one), 1)
            + encrypt_page_for_test(self.key, base_second_page, 2)
        )
        wal_header = struct.pack(">IIIIIIII", 0x377F0682, 3007000, PAGE_SIZE, 0, 1, 2, 0, 0)
        wal_frame = (
            struct.pack(">IIIIII", 2, 2, 1, 2, 0, 0)
            + encrypt_page_for_test(self.key, updated_second_page, 2)
        )
        plaintext, details = decrypt_database_bytes(
            encrypted_database, self.key, wal_bytes=wal_header + wal_frame
        )
        self.assertEqual(plaintext, bytes(self.page_one) + updated_second_page)
        self.assertEqual(details["wal_frames_applied"], 1)


class ContentTests(unittest.TestCase):
    def test_plain_utf8(self):
        self.assertEqual(decode_content("企业微信测试".encode()), "企业微信测试")

    def test_simple_protobuf_string(self):
        text = "项目进展正常".encode()
        payload = bytes([0x0A, len(text)]) + text
        self.assertEqual(decode_content(payload), "项目进展正常")


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def pb(*fields) -> bytes:
    """Encode (field, value) pairs: int -> varint, bytes/str -> length-delimited."""
    out = bytearray()
    for number, value in fields:
        if isinstance(value, int):
            out += _varint(number << 3) + _varint(value)
        else:
            data = value.encode() if isinstance(value, str) else value
            out += _varint((number << 3) | 2) + _varint(len(data)) + data
    return bytes(out)


FILE_ID = "a1" * 100  # 200 hex chars, like the real 212-300 char file ids


def file_descriptor(name: str, payload: bytes, *, width=0, height=0) -> bytes:
    fields = [(1, FILE_ID), (2, name), (4, len(payload))]
    if width:
        fields += [(5, width), (6, height)]
    fields += [(8, "f" * 32), (10, hashlib.md5(payload).hexdigest())]
    return pb(*fields)


class MediaFixture(unittest.TestCase):
    """Temporary WeCom Profiles tree; nothing outside the temp folder is read."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "Profiles"
        self.profile = "A" * 32
        (self.root / self.profile / "Caches").mkdir(parents=True)
        (self.root / "setting.json").write_text(json.dumps({"CurrentProfile": self.profile}))

    def tearDown(self):
        self.temp.cleanup()

    def put(self, kind: str, folder: str, filename: str, data: bytes, month: str = "2026-09", profile: str | None = None) -> Path:
        path = self.root / (profile or self.profile) / "Caches" / kind / month / folder / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path


class MediaExtractionTests(unittest.TestCase):
    def test_image_descriptor_from_image_message(self):
        payload = b"original-image-bytes"
        refs = extract_media(file_descriptor("a.jpg", payload, width=1080, height=1920), 14)
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["kind"], "image")
        self.assertEqual(refs[0]["md5"], hashlib.md5(payload).hexdigest())
        self.assertEqual((refs[0]["width"], refs[0]["height"], refs[0]["size"]), (1080, 1920, len(payload)))

    def test_nested_rich_text_and_merged_forward_items(self):
        image = file_descriptor("pic.png", b"img", width=10, height=10)
        rich = pb((1, pb((5, 2), (101, pb((1, pb((1, 0))))))), (1, pb((5, 14), (103, image))), (4, 1))
        refs = extract_media(rich, 123)
        self.assertEqual([ref["kind"] for ref in refs], ["image"])
        merged = pb((1, pb((2, 1787625261), (5, 15), (103, file_descriptor("report.pdf", b"pdf")))), (2, "群聊的聊天记录"))
        refs = extract_media(merged, 4)
        self.assertEqual([(ref["kind"], ref["name"]) for ref in refs], [("file", "report.pdf")])

    def test_video_descriptor_uses_file_id_and_cover_url_hashes(self):
        token = "3069020102" + "x" * 60
        video = pb((1, "clip.mov"), (2, token), (3, 4096), (4, 12), (5, 480), (6, 640), (7, "https://cover.example/v"))
        refs = extract_media(video, 22)
        self.assertEqual(refs[0]["kind"], "video")
        self.assertEqual(refs[0]["keys"], [hashlib.md5(token.encode()).hexdigest()])
        self.assertEqual(refs[0]["cover_key"], hashlib.md5(b"https://cover.example/v").hexdigest())

    def test_no_false_positives(self):
        self.assertEqual(extract_media("普通文本消息".encode(), 2), [])
        self.assertEqual(extract_media(bytes(range(256)) * 4, 0), [])
        no_md5 = pb((1, FILE_ID), (2, "a.jpg"), (4, 10))
        self.assertEqual(extract_media(no_md5, 14), [])
        short_id = pb((1, "abcd"), (2, "a.jpg"), (4, 10), (10, "0" * 32))
        self.assertEqual(extract_media(short_id, 14), [])
        self.assertEqual(extract_media(None, 14), [])


class MediaResolutionTests(MediaFixture):
    def test_image_layers_and_md5_verification(self):
        payload = b"the original image"
        key = hashlib.md5(payload).hexdigest()
        self.put("Images", f"{key}_HD", "a.jpg", payload)
        self.put("Images", key, "a.jpg", b"preview")
        self.put("Images", f"{key}_THUMB", "a.jpg", b"t")
        cache = MediaCache(self.root)
        [media] = media_for_message(file_descriptor("a.jpg", payload, width=1, height=1), 14, cache, verify_md5=True)
        self.assertEqual(media["status"], "original")
        self.assertEqual(media["layers"], ["original", "preview", "thumbnail"])
        self.assertTrue(media["local"]["path"].endswith(f"{key}_HD/a.jpg"))
        self.assertTrue(media["local"]["size_match"])
        self.assertTrue(media["local"]["md5_match"])

    def test_image_without_original_needs_attention(self):
        payload = b"never opened"
        key = hashlib.md5(payload).hexdigest()
        self.put("Images", f"{key}_THUMB", "b.jpg", b"t")
        cache = MediaCache(self.root)
        [media] = media_for_message(file_descriptor("b.jpg", payload), 14, cache)
        self.assertEqual(media["status"], "thumbnail_only")
        self.put("Images", key, "b.jpg", b"preview")
        [media] = media_for_message(file_descriptor("b.jpg", payload), 14, MediaCache(self.root))
        self.assertEqual(media["status"], "preview_only")
        [media] = media_for_message(file_descriptor("c.jpg", b"other"), 14, cache)
        self.assertEqual((media["status"], media["local"]), ("missing", None))

    def test_file_copy_selection_and_integrity_flags(self):
        payload = b"%PDF statement"
        key = hashlib.md5(payload).hexdigest()
        descriptor = file_descriptor("statement.pdf", payload)
        other = self.put("Files", key, "statement.pdf", payload, profile="B" * 32)
        current = self.put("Files", key, "statement.pdf", payload)

        def pick():
            [media] = media_for_message(descriptor, 15, MediaCache(self.root), verify_md5=True)
            return media

        media = pick()
        self.assertEqual((media["status"], media["local"]["path"]), ("downloaded", str(current)))
        self.assertTrue(media["local"]["md5_match"])
        current.write_bytes(b"tampered")
        self.assertEqual(pick()["local"]["path"], str(other))  # a size match beats the current profile
        other.write_bytes(b"also bad")
        media = pick()
        self.assertFalse(media["local"]["size_match"])
        self.assertFalse(media["local"]["md5_match"])

    def test_file_ignores_image_preview_layers(self):
        payload = b"a png sent as a file"
        key = hashlib.md5(payload).hexdigest()
        self.put("Images", key, "x.png", b"preview only")
        [media] = media_for_message(file_descriptor("x.png", payload), 15, MediaCache(self.root))
        self.assertEqual(media["status"], "missing")

    def test_voice_and_video(self):
        voice = b"silk voice"
        self.put("Voices", hashlib.md5(voice).hexdigest(), "v.dat", voice)
        [media] = media_for_message(file_descriptor("v.silk", voice), 16, MediaCache(self.root))
        self.assertEqual((media["kind"], media["status"]), ("voice", "downloaded"))

        token, cover_url = "t" * 64, "https://cover.example/c"
        video = pb((1, "clip.mov"), (2, token), (3, 5), (7, cover_url))
        self.put("Video_Thumbnail", hashlib.md5(cover_url.encode()).hexdigest(), "cover", b"jpg")
        [media] = media_for_message(video, 22, MediaCache(self.root))
        self.assertEqual(media["status"], "cover_only")
        self.put("Videos", hashlib.md5(token.encode()).hexdigest(), "clip.mov", b"12345")
        [media] = media_for_message(video, 22, MediaCache(self.root))
        self.assertEqual((media["status"], media["layers"]), ("downloaded", ["video", "cover"]))
        self.assertTrue(media["local"]["size_match"])

    def test_cache_root_accepts_profiles_profile_or_caches_folder(self):
        payload = b"doc"
        self.put("Files", hashlib.md5(payload).hexdigest(), "d.txt", payload)
        ref = extract_media(file_descriptor("d.txt", payload), 15)[0]
        for root in (self.root, self.root / self.profile, self.root / self.profile / "Caches"):
            self.assertEqual(resolve(ref, MediaCache(root))["status"], "downloaded", root)
        self.assertEqual(MediaCache(Path(self.temp.name) / "absent").caches, [])


class MediaCliTests(MediaFixture):
    """Runs vault_cli.py against a tiny plaintext snapshot in a temp folder."""

    def setUp(self):
        super().setUp()
        self.snapshot = Path(self.temp.name) / "snapshot"
        self.snapshot.mkdir()
        self.original = b"opened image"
        self.unopened = b"unopened image"
        self.put("Images", hashlib.md5(self.original).hexdigest() + "_HD", "a.jpg", self.original)
        self.put("Images", hashlib.md5(self.unopened).hexdigest(), "b.jpg", b"preview")
        with sqlite3.connect(self.snapshot / "message.db") as db:
            db.execute("CREATE TABLE message_table (message_id INTEGER, server_id INTEGER, sequence INTEGER, sender_id INTEGER, conversation_id TEXT, content_type INTEGER, send_time INTEGER, flag INTEGER, content BLOB, extra_content BLOB, local_extra_content BLOB)")
            rows = [
                (1, 1, 1, 7, "R:1", 2, 1790000000, 0, "大家好".encode(), None, None),
                (2, 2, 2, 7, "R:1", 14, 1790000060, 0, file_descriptor("a.jpg", self.original), None, None),
                (3, 3, 3, 8, "R:1", 14, 1790000120, 0, file_descriptor("b.jpg", self.unopened), None, None),
            ]
            db.executemany("INSERT INTO message_table VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
        with sqlite3.connect(self.snapshot / "session.db") as db:
            db.execute("CREATE TABLE conversation_table (id TEXT, name TEXT, roomname_remark TEXT, last_message_time INTEGER, last_message_id INTEGER)")
            db.execute("INSERT INTO conversation_table VALUES ('R:1', '工厂群', '', 1790000120, 3)")
        with sqlite3.connect(self.snapshot / "user.db") as db:
            db.execute("CREATE TABLE user_table (id INTEGER, name TEXT)")
            db.executemany("INSERT INTO user_table VALUES (?,?)", [(7, "我"), (8, "工厂")])

    def env(self) -> dict:
        # A temp HOME keeps the real vault and config out of reach; keep the user
        # site-packages visible so pycryptodome installed with --user still loads.
        return dict(os.environ, HOME=self.temp.name, PYTHONUSERBASE=site.getuserbase())

    def run_cli(self, *args) -> dict:
        result = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("vault_cli.py")), *args],
            capture_output=True, text=True, env=self.env(),
        )
        if result.returncode:
            self.fail(result.stderr)
        return json.loads(result.stdout)

    def test_history_without_media_flag_is_unchanged(self):
        data = self.run_cli("history", "工厂群", "--snapshot", str(self.snapshot))
        self.assertEqual(data["count"], 3)
        self.assertTrue(all("media" not in message for message in data["messages"]))
        self.assertEqual(data["messages"][1]["type_name"], "图片")

    def test_history_with_media(self):
        data = self.run_cli("history", "工厂群", "--snapshot", str(self.snapshot), "--media", "--cache-root", str(self.root))
        statuses = [message["media"][0]["status"] for message in data["messages"] if "media" in message]
        self.assertEqual(statuses, ["original", "preview_only"])

    def test_media_report_lists_what_needs_opening(self):
        data = self.run_cli("media", "--snapshot", str(self.snapshot), "--cache-root", str(self.root))
        self.assertEqual(data["summary"], {"image": {"original": 1, "preview_only": 1}})
        self.assertEqual(data["needs_attention_count"], 1)
        self.assertEqual(data["needs_attention"][0]["name"], "b.jpg")
        self.assertEqual(data["conversations"][0]["needs_attention"], 1)

    def test_markdown_export_lists_media_paths(self):
        destination = Path(self.temp.name) / "out.md"
        self.run_cli("export", "工厂群", "--snapshot", str(self.snapshot), "--media", "--cache-root", str(self.root), "--output", str(destination))
        text = destination.read_text(encoding="utf-8")
        self.assertIn("[图片·原图已在本地] a.jpg → ", text)
        self.assertIn("[图片·只有预览图] b.jpg → ", text)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

    def test_missing_cache_root_fails_clearly(self):
        result = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("vault_cli.py")), "media", "--snapshot", str(self.snapshot), "--cache-root", str(Path(self.temp.name) / "nope")],
            capture_output=True, text=True, env=self.env(),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("找不到企业微信媒体缓存目录", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
