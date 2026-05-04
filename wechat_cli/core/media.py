"""Media file helpers.

Supported image inputs:
- Plain image files already cached by WeChat.
- Legacy desktop .dat images encrypted with a single-byte XOR key.
- macOS WeChat 4.x V2 .dat images. These use a small header, AES-128-ECB
  for the leading segment, and XOR for the tail. The AES/XOR keys are derived
  from the local kvcomm cache and account directory name, following the same
  scheme used by WeFlow.
- WeChat CDN images: downloaded directly from Tencent CDN when only a
  thumbnail is available locally. The CDN URL is extracted from the message
  XML and the image is decrypted with AES-128-CBC (zero IV).

Some V2 images unwrap to WeChat's wxgf HEVC container. If ffmpeg is installed,
the first HEVC frame is converted to a JPG; otherwise those images cannot be
converted to a normal image file.
"""

import hashlib
import os
import platform
import re
import shutil
import ssl
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from pathlib import Path

from Crypto.Cipher import AES


# WeChat CDN long-connection servers (tried in order; US accounts use uslong* servers).
_CDN_HOSTS = [
    "uslong1.wechat.com",
    "uslong2.wechat.com",
    "uslong3.wechat.com",
    "szlong.weixin.qq.com",
    "bjlong.weixin.qq.com",
    "shlong.weixin.qq.com",
    "gzlong.weixin.qq.com",
    "hklong.weixin.qq.com",
]
_CDN_TIMEOUT = 20
_WECHAT_DOWNLOAD_TIMEOUT = 30  # seconds to wait for WeChat to download images


_WECHAT_V2_MAGIC = b"\x07\x08V2\x08\x07"
_WECHAT_V2_HEADER_SIZE = 0x0F
_WECHAT_V2_CIPHERTEXT_OFFSET = 0x0F
_WECHAT_V2_CIPHERTEXT_END = 0x1F
_KVCOMM_PATTERN = re.compile(r"^key_(\d+)_.+\.statistic$", re.I)

_IMAGE_SIGNATURES = (
    ("jpg", ((0, b"\xff\xd8\xff"),), "_valid_jpg"),
    ("png", ((0, b"\x89PNG\r\n\x1a\n"),), "_valid_png"),
    ("gif", ((0, b"GIF87a"),), "_valid_gif"),
    ("gif", ((0, b"GIF89a"),), "_valid_gif"),
    ("bmp", ((0, b"BM"),), "_valid_bmp"),
    ("webp", ((0, b"RIFF"), (8, b"WEBP")), "_valid_webp"),
)


def _xor_bytes(data, key):
    return bytes(b ^ key for b in data)


def detect_wechat_image_xor_key(path):
    """Return (key, extension) for a WeChat encrypted image, or (None, None)."""
    try:
        with open(path, "rb") as f:
            header = f.read(64)
    except OSError:
        return None, None

    if not header:
        return None, None

    for ext, parts, validator_name in _IMAGE_SIGNATURES:
        first_offset, first_sig = parts[0]
        if len(header) <= first_offset:
            continue
        key = header[first_offset] ^ first_sig[0]
        matched = True
        for offset, sig in parts:
            end = offset + len(sig)
            if len(header) < end or _xor_bytes(header[offset:end], key) != sig:
                matched = False
                break
        if matched:
            decoded = _xor_bytes(header, key)
            validator = globals()[validator_name]
            if validator(decoded):
                return key, ext

    return None, None


def _valid_jpg(data):
    return len(data) >= 3 and data[:3] == b"\xff\xd8\xff"


def _valid_png(data):
    return len(data) >= 16 and data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR"


def _valid_gif(data):
    if len(data) < 10 or data[:6] not in (b"GIF87a", b"GIF89a"):
        return False
    width = int.from_bytes(data[6:8], "little")
    height = int.from_bytes(data[8:10], "little")
    return width > 0 and height > 0


def _valid_bmp(data):
    if len(data) < 26 or data[:2] != b"BM":
        return False
    file_size = int.from_bytes(data[2:6], "little")
    pixel_offset = int.from_bytes(data[10:14], "little")
    dib_size = int.from_bytes(data[14:18], "little")
    width = int.from_bytes(data[18:22], "little", signed=True)
    height = int.from_bytes(data[22:26], "little", signed=True)
    return (
        26 <= file_size <= 1024 * 1024 * 1024
        and 26 <= pixel_offset <= file_size
        and dib_size in (12, 40, 52, 56, 108, 124)
        and width != 0
        and height != 0
    )


def _valid_webp(data):
    if len(data) < 16 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        return False
    riff_size = int.from_bytes(data[4:8], "little")
    return riff_size > 4 and data[12:16] in (b"VP8 ", b"VP8L", b"VP8X")


def decrypt_wechat_image(path, output_dir=None):
    """Decrypt or normalize a WeChat image to a cache file.

    The original file is never modified. The returned path points to a decoded
    image under the temp directory.

    Returns:
        (output_path, extension) on success, otherwise (None, None).
    """
    decrypted, ext, cache_key = _decrypt_wechat_image_bytes(path)
    if decrypted is None or not ext:
        return None, None

    output_dir = output_dir or os.path.join(tempfile.gettempdir(), "wechat_cli_media")
    try:
        st = os.stat(path)
    except OSError:
        return None, None

    digest = hashlib.sha256(
        f"{os.path.abspath(path)}:{st.st_mtime_ns}:{st.st_size}:{cache_key}".encode("utf-8")
    ).hexdigest()[:24]
    out_path = os.path.join(output_dir, f"{digest}.{ext}")

    if os.path.exists(out_path):
        return out_path, ext

    tmp_path = None
    try:
        os.makedirs(output_dir, exist_ok=True)
        tmp_path = out_path + ".tmp"
        with open(tmp_path, "wb") as dst:
            dst.write(decrypted)
        os.replace(tmp_path, out_path)
    except OSError:
        try:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except OSError:
            pass
        return None, None

    return out_path, ext


def _decrypt_wechat_image_bytes(path):
    try:
        data = Path(path).read_bytes()
    except OSError:
        return None, None, None

    direct_ext = detect_image_extension(data)
    if direct_ext:
        return data, direct_ext, "raw"

    if _is_wechat_v2_dat(data):
        result = _decrypt_wechat_v2_dat(data, path)
        if result:
            decrypted, ext, key_id = result
            return decrypted, ext, key_id

    key, ext = detect_wechat_image_xor_key(path)
    if key is not None:
        return _xor_bytes(data, key), ext, f"xor:{key}"

    return None, None, None


def detect_image_extension(data):
    if len(data) < 12:
        return None
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if _valid_bmp(data[:64]):
        return "bmp"
    return None


def _is_wechat_v2_dat(data):
    return len(data) >= _WECHAT_V2_CIPHERTEXT_END and data[:6] == _WECHAT_V2_MAGIC


def _decrypt_wechat_v2_dat(data, path):
    ciphertext = data[_WECHAT_V2_CIPHERTEXT_OFFSET:_WECHAT_V2_CIPHERTEXT_END]
    for code in _collect_kvcomm_codes(path):
        xor_key = code & 0xFF
        for wxid in _collect_wxid_candidates(path):
            aes_key = hashlib.md5((str(code) + wxid).encode("utf-8")).hexdigest()[:16]
            if not _verify_v2_aes_key(aes_key, ciphertext):
                continue
            decrypted = _decrypt_wechat_v2_dat_with_keys(data, xor_key, aes_key)
            decrypted = _unwrap_wxgf(decrypted) if decrypted else decrypted
            if decrypted and detect_image_extension(decrypted):
                return decrypted, detect_image_extension(decrypted), f"v2:{code}:{wxid}:{aes_key}:{xor_key}"
    return None


def _decrypt_wechat_v2_dat_with_keys(data, xor_key, aes_key):
    if len(data) < _WECHAT_V2_HEADER_SIZE or not aes_key:
        return None
    header = data[:_WECHAT_V2_HEADER_SIZE]
    payload = data[_WECHAT_V2_HEADER_SIZE:]
    aes_size = _read_i32_le(header, 6)
    xor_size = _read_i32_le(header, 10)
    if aes_size < 0 or xor_size < 0:
        return None
    remainder = aes_size % 16
    aligned_aes_size = aes_size + (16 - remainder)
    if aligned_aes_size > len(payload):
        return None
    aes_data = payload[:aligned_aes_size]
    remaining = payload[aligned_aes_size:]
    if xor_size > len(remaining):
        return None

    plain_aes = b""
    if aes_data:
        try:
            cipher = AES.new(aes_key.encode("ascii")[:16], AES.MODE_ECB)
            plain_aes = _strict_remove_pkcs7_padding(cipher.decrypt(aes_data))
        except Exception:
            return None

    if xor_size:
        raw_len = len(remaining) - xor_size
        if raw_len < 0:
            return None
        raw_data = remaining[:raw_len]
        decoded_xor = _xor_bytes(remaining[raw_len:], xor_key)
        return plain_aes + raw_data + decoded_xor
    return plain_aes + remaining


def _verify_v2_aes_key(aes_key, ciphertext):
    try:
        cipher = AES.new(aes_key.encode("ascii")[:16], AES.MODE_ECB)
        return _looks_like_decrypted_v2_start(cipher.decrypt(ciphertext))
    except Exception:
        return False


def _looks_like_decrypted_v2_start(data):
    return (
        detect_image_extension(data) is not None
        or data.startswith(b"wxgf")
    )


def _read_i32_le(data, offset):
    if offset < 0 or offset + 4 > len(data):
        return -1
    value = data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24)
    if value & 0x80000000:
        value -= 0x100000000
    return value


def _strict_remove_pkcs7_padding(data):
    if not data:
        raise ValueError("empty decrypted data")
    pad = data[-1]
    if pad <= 0 or pad > 16 or pad > len(data):
        raise ValueError("invalid pkcs7 padding")
    if data[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid pkcs7 padding")
    return data[:-pad]


def _unwrap_wxgf(data):
    if not data or len(data) < 20 or not data.startswith(b"wxgf"):
        return data

    for i in range(4, min(len(data) - 12, 4096)):
        if data[i:i + 3] == b"\xff\xd8\xff":
            return data[i:]
        if data[i:i + 4] == b"\x89PNG":
            return data[i:]

    for hevc_data in _build_wxgf_hevc_candidates(data):
        jpg = _convert_hevc_to_jpg(hevc_data)
        if jpg and detect_image_extension(jpg) == "jpg":
            return jpg
    return data


def _build_wxgf_hevc_candidates(data):
    units = _extract_hevc_nalu_units(data)
    candidates = []

    def add(candidate):
        if candidate and len(candidate) >= 100 and candidate not in candidates:
            candidates.append(candidate)

    vps_starts = []
    for idx, unit in enumerate(units):
        if len(unit) < 2:
            continue
        nalu_type = (unit[0] >> 1) & 0x3F
        if nalu_type == 32:
            vps_starts.append(idx)

    groups = []
    for idx, start in enumerate(vps_starts):
        end = vps_starts[idx + 1] if idx + 1 < len(vps_starts) else len(units)
        group_units = units[start:end]
        has_vcl = any((((unit[0] >> 1) & 0x3F) in (1, 19, 20)) for unit in group_units if len(unit) >= 2)
        if has_vcl:
            merged = _merge_hevc_nalu_units(group_units)
            groups.append(merged)
    groups.sort(key=len, reverse=True)
    for group in groups:
        add(group)

    add(_merge_hevc_nalu_units(units))
    add(data[4:])
    return candidates


def _extract_hevc_nalu_units(data):
    starts = []
    i = 4
    while i < len(data) - 3:
        has_prefix4 = data[i:i + 4] == b"\x00\x00\x00\x01"
        has_prefix3 = data[i:i + 3] == b"\x00\x00\x01"
        if has_prefix4 or has_prefix3:
            starts.append(i)
            i += 4 if has_prefix4 else 3
            continue
        i += 1
    units = []
    for idx, start in enumerate(starts):
        end = starts[idx + 1] if idx + 1 < len(starts) else len(data)
        prefix_len = 4 if data[start:start + 4] == b"\x00\x00\x00\x01" else 3
        payload = data[start + prefix_len:end]
        if len(payload) >= 2 and (payload[0] & 0x80) == 0:
            units.append(payload)
    return units


def _merge_hevc_nalu_units(units):
    chunks = []
    for unit in units:
        if len(unit) >= 2:
            chunks.append(b"\x00\x00\x00\x01")
            chunks.append(unit)
    return b"".join(chunks)


def _convert_hevc_to_jpg(hevc_data):
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        return None
    tmp_dir = os.path.join(tempfile.gettempdir(), "wechat_cli_hevc")
    os.makedirs(tmp_dir, exist_ok=True)
    in_path = None
    out_path = None
    try:
        fd, in_path = tempfile.mkstemp(suffix=".hevc", dir=tmp_dir)
        os.close(fd)
        fd, out_path = tempfile.mkstemp(suffix=".jpg", dir=tmp_dir)
        os.close(fd)
        with open(in_path, "wb") as f:
            f.write(hevc_data)
        attempts = [
            ["-f", "hevc", "-i", in_path],
            ["-f", "h265", "-i", in_path],
            ["-i", in_path],
        ]
        for args in attempts:
            try:
                if os.path.exists(out_path):
                    os.unlink(out_path)
                proc = subprocess.run(
                    [ffmpeg, "-y", "-loglevel", "error", *args, "-frames:v", "1", out_path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                    check=False,
                )
                if proc.returncode == 0 and os.path.exists(out_path) and os.path.getsize(out_path) > 0:
                    with open(out_path, "rb") as f:
                        return f.read()
            except (OSError, subprocess.SubprocessError):
                continue
    finally:
        for p in (in_path, out_path):
            try:
                if p and os.path.exists(p):
                    os.unlink(p)
            except OSError:
                pass
    return None


def _collect_kvcomm_codes(path):
    codes = set()
    for kv_dir in _kvcomm_candidates(path):
        try:
            entries = os.listdir(kv_dir)
        except OSError:
            continue
        for name in entries:
            match = _KVCOMM_PATTERN.match(name)
            if not match:
                continue
            code = int(match.group(1))
            if 0 <= code <= 0xFFFFFFFF:
                codes.add(code)
    return sorted(codes)


def _kvcomm_candidates(path):
    home = Path.home()
    candidates = [
        home / "Library/Containers/com.tencent.xinWeChat/Data/Documents/app_data/net/kvcomm",
        home / "Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat/xwechat/net/kvcomm",
        home / "Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat/net/kvcomm",
        home / "Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat/net/kvcomm",
    ]
    normalized = str(Path(path).resolve()).replace("\\", "/")
    marker = "/xwechat_files"
    if marker in normalized:
        base = normalized.split(marker, 1)[0]
        candidates.append(Path(base) / "app_data/net/kvcomm")
    return list(dict.fromkeys(str(p) for p in candidates))


def _collect_wxid_candidates(path):
    candidates = []

    def push(value):
        value = (value or "").strip()
        if not value or value in candidates:
            return
        candidates.append(value)
        # Try stripping the last _suffix (e.g. wxid_abc123_a0e4 → wxid_abc123)
        if "_" in value:
            without_last = value.rsplit("_", 1)[0]
            if without_last and without_last not in candidates:
                candidates.append(without_last)
            prefix = value.split("_", 1)[0]
            if prefix and prefix not in candidates:
                candidates.append(prefix)

    p = Path(path).resolve()
    parts = p.parts
    if "xwechat_files" in parts:
        idx = parts.index("xwechat_files")
        if idx + 1 < len(parts):
            push(parts[idx + 1])
        root = Path(*parts[:idx + 1])
        try:
            for entry in root.iterdir():
                if entry.is_dir():
                    push(entry.name)
        except OSError:
            pass
    return candidates


# ---------------------------------------------------------------------------
# WeChat CDN image download
# ---------------------------------------------------------------------------

def _parse_image_xml_attrs(content):
    """Return the <img> attribute dict from a WeChat image message XML."""
    if not content:
        return {}
    try:
        idx = content.find("<msg")
        if idx < 0:
            return {}
        root = ET.fromstring(content[idx:])
        img = root.find(".//img")
        return dict(img.attrib) if img is not None else {}
    except ET.ParseError:
        return {}


def _cdn_fetch(cdn_url_bytes):
    """POST the binary CDN token to WeChat long-connection servers.

    Returns raw (encrypted) response bytes, or None if all hosts fail.
    The token format is WeChat's proprietary DER/ASN.1-like envelope.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    headers = {
        "Content-Type": "application/octet-stream",
        "User-Agent": "WeChat/4.1.8.100 CFNetwork/1568.100.1 Darwin/24.3.0",
    }
    for host in _CDN_HOSTS:
        try:
            req = urllib.request.Request(
                f"https://{host}/mmtls",
                data=cdn_url_bytes,
                method="POST",
                headers=headers,
            )
            with urllib.request.urlopen(req, context=ctx, timeout=_CDN_TIMEOUT) as resp:
                if resp.status == 200:
                    data = resp.read()
                    if data and len(data) > 32:
                        return data
        except Exception:
            continue
    return None


def _cdn_decrypt(data, aes_key_hex):
    """Decrypt WeChat CDN image data: AES-128-CBC with a zero IV.

    The CDN response is the raw ciphertext; the aeskey from the message XML
    is the 16-byte key (32 hex chars).  WeChat uses a zero IV.
    Returns decrypted bytes, or None on any error.
    """
    try:
        key = bytes.fromhex(aes_key_hex)[:16]
        aligned = len(data) - len(data) % 16
        if aligned <= 0:
            return None
        cipher = AES.new(key, AES.MODE_CBC, b"\x00" * 16)
        decrypted = cipher.decrypt(data[:aligned])
        # Strip PKCS#7 padding if present.
        pad = decrypted[-1]
        if 0 < pad <= 16 and decrypted[-pad:] == bytes([pad]) * pad:
            decrypted = decrypted[:-pad]
        return decrypted
    except Exception:
        return None


def try_cdn_download_image(content, output_dir=None):
    """Download a WeChat image directly from CDN, bypassing local cache.

    Parses the CDN URL and AES key from the message XML, attempts to
    download HD then mid resolution, decrypts, and caches the result.

    Args:
        content: Decompressed message_content XML string.
        output_dir: Directory for cached images (defaults to system temp).

    Returns:
        (path, extension) on success, (None, None) on failure.
    """
    attrs = _parse_image_xml_attrs(content)
    aes_key = attrs.get("aeskey", "")
    if not aes_key:
        return None, None

    # Prefer HD (cdnbigimgurl) when hdlength > 0, then mid (cdnmidimgurl).
    candidates = []
    hd_url = attrs.get("cdnbigimgurl", "")
    hd_size = int(attrs.get("hdlength", 0) or 0)
    if hd_url and hd_size > 0:
        candidates.append((hd_url, hd_size))
    mid_url = attrs.get("cdnmidimgurl", "")
    mid_size = int(attrs.get("hevc_mid_size", 0) or attrs.get("length", 0) or 0)
    if mid_url:
        candidates.append((mid_url, mid_size))

    output_dir = output_dir or os.path.join(tempfile.gettempdir(), "wechat_cli_media")

    for cdn_url_hex, _expected_size in candidates:
        # Check cache.
        cache_key = hashlib.sha256(
            (cdn_url_hex + aes_key).encode()
        ).hexdigest()[:24]
        for ext in ("jpg", "png", "gif", "webp", "bmp"):
            cached = os.path.join(output_dir, f"{cache_key}.{ext}")
            if os.path.exists(cached):
                return cached, ext

        try:
            cdn_bytes = bytes.fromhex(cdn_url_hex)
        except ValueError:
            continue

        raw = _cdn_fetch(cdn_bytes)
        if not raw:
            continue

        decrypted = _cdn_decrypt(raw, aes_key)
        if not decrypted:
            continue

        ext = detect_image_extension(decrypted)
        if not ext:
            decrypted = _unwrap_wxgf(decrypted)
            if decrypted:
                ext = detect_image_extension(decrypted)
        if not ext or not decrypted:
            continue

        try:
            os.makedirs(output_dir, exist_ok=True)
            out_path = os.path.join(output_dir, f"{cache_key}.{ext}")
            tmp = out_path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(decrypted)
            os.replace(tmp, out_path)
            return out_path, ext
        except OSError:
            continue

    return None, None


def _trigger_wechat_navigate_applescript(chat_name):
    """Navigate WeChat to a chat by display name using AppleScript + clipboard.

    Uses CMD+K (WeChat's "Jump to Chat" shortcut) with the chat name pasted
    from the clipboard to handle non-ASCII characters reliably.
    """
    try:
        subprocess.run(
            ["pbcopy"],
            input=chat_name.encode("utf-8"),
            timeout=3,
            check=True,
        )
    except Exception:
        return

    # Split into two osascript calls: first activate WeChat, then send keystrokes.
    # This avoids the -1712 AppleEvent timeout that occurs when WeChat is not
    # yet frontmost when System Events tries to inject keys.
    try:
        subprocess.run(
            ["osascript", "-e", 'tell application "WeChat" to activate'],
            timeout=5,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass

    time.sleep(1.0)

    script = """\
tell application "System Events"
    tell process "WeChat"
        keystroke "k" using command down
        delay 0.6
        keystroke "v" using command down
        delay 0.8
        key code 36
        delay 0.4
    end tell
end tell
"""
    try:
        subprocess.run(
            ["osascript", "-e", script],
            timeout=12,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def trigger_wechat_download(chat_username, img_dir, timeout=_WECHAT_DOWNLOAD_TIMEOUT, chat_name=None):
    """Ask the running WeChat app to navigate to a chat, then wait for full-size
    image files to appear on disk.

    WeChat downloads full-resolution images automatically when it renders a chat
    view.  We navigate using two methods in parallel: AppleScript search by
    display name (more reliable for group chats), and the ``weixin://`` URL
    scheme (works for direct contacts).

    Args:
        chat_username: The WeChat username/chatroom ID (e.g. ``52233857071@chatroom``).
        img_dir: The local ``Img/`` directory to monitor for new files.
        timeout: Maximum seconds to wait (default 30).
        chat_name: Display name of the chat, used for AppleScript search.

    Returns:
        List of newly-appeared full-size ``.dat`` file paths, or ``[]`` on
        failure / timeout.
    """
    if platform.system() != "Darwin":
        return []

    before = _dat_files_snapshot(img_dir)

    # Primary: AppleScript search by display name (handles group chats).
    if chat_name:
        _trigger_wechat_navigate_applescript(chat_name)

    # Secondary: URL scheme with percent-encoded username.
    try:
        encoded = urllib.parse.quote(chat_username, safe="")
        url = f"weixin://dl/chat?username={encoded}"
        subprocess.run(["open", url], timeout=5, check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

    # Poll for new full-size .dat files (not _t.dat thumbnails).
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(1)
        after = _dat_files_snapshot(img_dir)
        new_files = [
            p for p in (after - before)
            if not os.path.basename(p).endswith("_t.dat")
        ]
        if new_files:
            time.sleep(1)
            return new_files

    return []


def _dat_files_snapshot(directory):
    """Return a set of absolute paths for .dat files in *directory*."""
    try:
        return {
            os.path.join(directory, e.name)
            for e in os.scandir(directory)
            if e.is_file() and e.name.endswith(".dat")
        }
    except OSError:
        return set()
