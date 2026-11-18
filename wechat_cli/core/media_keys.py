"""Verified per-database keys; optional reuse of an existing WeFlow keychain item.

Never changes WeChat signing, starts a process debugger, or invokes sudo.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from Crypto.Cipher import AES
from ..keys.common import verify_enc_key
from .key_utils import get_key_info


def derive_media_key(master, page):
    """WeFlow stores a pre-KDF secret, not wechat-cli's per-DB AES key."""
    secrets = [bytes.fromhex(master)] if re.fullmatch(r'[a-fA-F0-9]{64}', master) else []
    secrets.append(master.encode())
    for secret in secrets:
        if len(secret) == 32 and verify_enc_key(secret, page):
            return secret.hex()
        key = hashlib.pbkdf2_hmac('sha512', secret, page[:16], 256000, 32)
        if verify_enc_key(key, page):
            return key.hex()
    return None


def media_key_path(app):
    return Path(app.keys_file).with_name('media_keys.json')


def load_media_keys(app):
    """Merge only HMAC-verified supplemental media keys into this invocation."""
    path = media_key_path(app)
    if not path.exists():
        return
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        raise ValueError('媒体密钥文件格式错误')
    for name, info in data.items():
        if not re.fullmatch(r'message/media_\d+\.db', name):
            continue
        key = info.get('enc_key') if isinstance(info, dict) else None
        if not isinstance(key, str) or not re.fullmatch(r'[a-fA-F0-9]{64}', key):
            continue
        db = Path(app.db_dir) / name
        if not db.exists():
            continue
        with db.open('rb') as handle:
            page = handle.read(4096)
        if len(page) == 4096 and verify_enc_key(bytes.fromhex(key), page):
            app.all_keys[name] = {'enc_key': key}


def reuse_weflow_media_keys(app):
    """Explicit opt-in: read existing safeStorage, derive and verify missing keys."""
    load_media_keys(app)
    pending = {}
    for db in (Path(app.db_dir) / 'message').glob('media_*.db'):
        if not re.fullmatch(r'media_\d+\.db', db.name):
            continue
        with db.open('rb') as handle:
            page = handle.read(4096)
        if len(page) != 4096:
            continue
        name = 'message/' + db.name
        info = get_key_info(app.all_keys, name)
        if not info or not verify_enc_key(bytes.fromhex(info['enc_key']), page):
            pending[name] = page
    if not pending:
        return 0
    config = Path.home() / 'Library/Application Support/weflow/WeFlow-config.json'
    if not config.exists():
        raise ValueError('没有可复用的本机 WeFlow 配置')
    data = json.loads(config.read_text(encoding='utf-8'))
    wrapped = [data.get('decryptKey', '')]
    configs = data.get('wxidConfigs', {})
    if isinstance(configs, dict):
        wrapped.extend(v.get('decryptKey', '') for v in configs.values() if isinstance(v, dict))
    try:
        result = subprocess.run(['security', 'find-generic-password', '-s', 'weflow Safe Storage', '-w'], capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError('无法读取现有 WeFlow 钥匙串条目；未修改微信或权限') from None
    if result.returncode:
        raise ValueError('现有 WeFlow 钥匙串条目不可读取；未修改微信或权限')
    wrapping = hashlib.pbkdf2_hmac('sha1', result.stdout.rstrip(b'\r\n'), b'saltysalt', 1003, 16)
    recovered = {}
    for value in set(v for v in wrapped if isinstance(v, str)):
        if not value.startswith('safe:'):
            continue
        try:
            raw = base64.b64decode(value[5:], validate=True)
            if raw[:3] != b'v10' or len(raw) < 19 or (len(raw) - 3) % 16:
                continue
            plain = AES.new(wrapping, AES.MODE_CBC, b' ' * 16).decrypt(raw[3:])
            pad = plain[-1]
            if not 0 < pad <= 16 or plain[-pad:] != bytes([pad]) * pad:
                continue
            master = plain[:-pad].decode()
        except (ValueError, UnicodeError):
            continue
        for name, page in pending.items():
            key = derive_media_key(master, page)
            if key:
                recovered[name] = {'enc_key': key}
    if not recovered:
        raise ValueError('WeFlow 已有密钥与当前媒体库不匹配；未保存无效密钥')
    target = media_key_path(app)
    previous = json.loads(target.read_text(encoding='utf-8')) if target.exists() else {}
    previous.update(recovered)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix='.media-keys-', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(previous, handle)
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    app.all_keys.update(recovered)
    return len(recovered)
