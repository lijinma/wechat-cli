"""Extract exact-chat VoiceInfo blobs and optionally transcode SILK to MP3."""
from contextlib import closing
from datetime import datetime
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile

from .key_utils import get_key_info
from .media_keys import load_media_keys
from ..keys.common import verify_enc_key
from .messages import (_iter_table_contexts, _is_safe_msg_table_name,
                       _load_name2id_maps, _resolve_sender_label,
                       _parse_message_content, _parse_xml_root,
                       decompress_content, _build_message_filters)


class VoiceStore:
    def __init__(self, app, output_dir=None, audio_format='mp3'):
        if audio_format not in ('mp3', 'silk'):
            raise ValueError('不支持的语音格式')
        self.app = app
        self.output = Path(output_dir or Path(app.keys_file).parent / 'voice-cache').expanduser().resolve()
        self.audio_format = audio_format
        self.connections = []
        self.unavailable = []
        load_media_keys(app)
        for db in sorted((Path(app.db_dir) / 'message').glob('media_*.db')):
            name = 'message/' + db.name
            info = get_key_info(app.all_keys, name)
            with db.open('rb') as handle:
                page = handle.read(4096)
            if not info or len(page) != 4096 or not verify_enc_key(bytes.fromhex(info['enc_key']), page):
                self.unavailable.append(name)
                continue
            conn = None
            try:
                path = app.cache.get(name)
                if not path:
                    self.unavailable.append(name)
                    continue
                conn = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
                conn.execute('SELECT voice_data FROM VoiceInfo LIMIT 1')
                self.connections.append(conn)
            except sqlite3.Error:
                if conn:
                    conn.close()
                self.unavailable.append(name)

    def close(self):
        for conn in self.connections:
            conn.close()
        self.connections = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def blob(self, chat, local_id, timestamp, server_id=0):
        matches = set()
        for conn in self.connections:
            if server_id:
                rows = conn.execute('SELECT v.voice_data FROM VoiceInfo v JOIN Name2Id n ON n.rowid=v.chat_name_id WHERE n.user_name=? AND v.svr_id=? AND v.create_time=?', (chat, server_id, timestamp)).fetchall()
            else:
                rows = []
            if not rows:
                rows = conn.execute('SELECT v.voice_data FROM VoiceInfo v JOIN Name2Id n ON n.rowid=v.chat_name_id WHERE n.user_name=? AND v.local_id=? AND v.create_time=?', (chat, local_id, timestamp)).fetchall()
            matches.update(bytes(row[0]) for row in rows if row[0])
        if len(matches) > 1:
            raise ValueError('语音匹配存在歧义，未导出')
        return next(iter(matches), None)

    def extract(self, chat, local_id, timestamp, server_id=0):
        blob = self.blob(chat, local_id, timestamp, server_id)
        if blob is None:
            return {'status': 'missing_media_key' if self.unavailable else 'not_downloaded', 'path': None}
        if not blob.startswith((b'\x02#!SILK_V3', b'#!SILK_V3')):
            raise ValueError('未知语音编码，未导出')
        digest = hashlib.sha256(blob).hexdigest()
        self.output.mkdir(parents=True, exist_ok=True, mode=0o700)
        target = self.output / (digest + '.' + self.audio_format)
        if target.exists() and target.stat().st_size:
            return {'status': 'ready', 'path': str(target)}
        with tempfile.TemporaryDirectory(dir=self.output) as directory:
            directory = Path(directory)
            silk = directory / 'voice.silk'
            silk.write_bytes(blob)
            if self.audio_format == 'silk':
                result = silk
            else:
                try:
                    import pilk
                except ImportError:
                    raise ValueError('MP3 转码需要安装 pilk（pip install pilk）；也可使用 --audio-format silk') from None
                ffmpeg = shutil.which('ffmpeg')
                if not ffmpeg:
                    raise ValueError('MP3 转码需要安装 ffmpeg；也可使用 --audio-format silk')
                pcm, result = directory / 'voice.pcm', directory / 'voice.mp3'
                try:
                    pilk.decode(str(silk), str(pcm), pcm_rate=24000)
                    if not pcm.exists() or not pcm.stat().st_size:
                        raise ValueError('语音解码为空')
                    subprocess.run([ffmpeg, '-nostdin', '-v', 'error', '-y', '-f', 's16le', '-ar', '24000', '-ac', '1', '-i', str(pcm), '-codec:a', 'libmp3lame', '-b:a', '48k', str(result)], capture_output=True, check=True, timeout=60)
                    subprocess.run([ffmpeg, '-nostdin', '-v', 'error', '-i', str(result), '-f', 'null', '-'], capture_output=True, check=True, timeout=60)
                except Exception:
                    raise ValueError('语音转码失败，未写入音频缓存') from None
            os.chmod(result, 0o600)
            os.replace(result, target)
        return {'status': 'ready', 'path': str(target)}

    def history_path(self, chat, local_id, timestamp):
        result = self.extract(chat, local_id, timestamp)
        if result['status'] == 'ready':
            return result['path']
        return '语音尚未下载' if result['status'] == 'not_downloaded' else '媒体库密钥缺失，可使用 voice --reuse-weflow-key'


def collect_voices(chat_ctx, names, display_name_fn, store, limit=50, offset=0, start_ts=None, end_ts=None):
    records, failures, seen = [], [], set()
    for tc in _iter_table_contexts(chat_ctx):
        table = tc['table_name']
        if not _is_safe_msg_table_name(table):
            raise ValueError('非法消息表名')
        try:
            with closing(sqlite3.connect(f"file:{tc['db_path']}?mode=ro", uri=True)) as conn:
                id_names = _load_name2id_maps(conn)
                clauses, params = _build_message_filters(start_ts, end_ts, msg_type_filter=(34,))
                rows = conn.execute(f'SELECT local_id,server_id,local_type,create_time,real_sender_id,message_content,WCDB_CT_message_content FROM [{table}] WHERE {" AND ".join(clauses)} ORDER BY create_time DESC,local_id DESC LIMIT ?', (*params, limit + offset)).fetchall()
                for local, server, typ, ts, sender_id, content, ct in rows:
                    identity = str(server) if server else f"{Path(tc['db_path']).name}:{local}"
                    if identity in seen:
                        continue
                    seen.add(identity)
                    body = decompress_content(content, ct)
                    if body is None:
                        raise ValueError('语音消息解压失败')
                    sender, body = _parse_message_content(body, typ, tc['is_group'])
                    label = _resolve_sender_label(sender_id, sender, tc['is_group'], tc['username'], tc['display_name'], names, id_names, display_name_fn)
                    tree = _parse_xml_root(body)
                    node = tree.find('.//voicemsg') if tree is not None else None
                    duration = int(node.get('voicelength', '0')) if node is not None else 0
                    records.append({'id': identity, 'local_id': local, 'server_id': str(server), 'timestamp': ts, 'time': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S'), 'sender': label, 'duration_ms': duration, 'status': 'pending', 'path': None})
        except (sqlite3.Error, ValueError):
            failures.append('消息库读取失败，结果可能不完整')
    records.sort(key=lambda r: (r['timestamp'], r['local_id']), reverse=True)
    selected = records[offset:offset + limit]
    selected.reverse()
    for record in selected:
        try:
            record.update(store.extract(chat_ctx['username'], record['local_id'], record['timestamp'], int(record['server_id'])))
        except ValueError as error:
            record['status'] = 'error'
            record['error'] = str(error)
    return selected, failures
