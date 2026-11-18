import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from Crypto.Cipher import AES
from click.testing import CliRunner
from wechat_cli.core.media_keys import derive_media_key, load_media_keys, reuse_weflow_media_keys
from wechat_cli.core.voice import VoiceStore, collect_voices
from wechat_cli.core.messages import collect_chat_history
from wechat_cli.main import cli


def encrypted_page(secret):
    salt, iv = bytes(range(16)), bytes(range(16, 32))
    key = hashlib.pbkdf2_hmac('sha512', secret, salt, 256000, 32)
    ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(b'A' * 4000)
    mac_key = hashlib.pbkdf2_hmac('sha512', key, bytes(b ^ 0x3a for b in salt), 2, 32)
    mac = hmac.new(mac_key, ciphertext + iv + struct.pack('<I', 1), hashlib.sha512).digest()
    return salt + ciphertext + iv + mac, key.hex()


class VoiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'message').mkdir()
        self.master = '0123456789abcdef' * 4
        page, key = encrypted_page(bytes.fromhex(self.master))
        self.page, self.key = page, key
        (self.root / 'message/media_0.db').write_bytes(page)
        self.media = self.root / 'plain-media.db'
        with sqlite3.connect(self.media) as c:
            c.executescript('CREATE TABLE Name2Id(user_name TEXT); CREATE TABLE VoiceInfo(chat_name_id INTEGER,local_id INTEGER,svr_id INTEGER,create_time INTEGER,voice_data BLOB);')
            c.executemany('INSERT INTO Name2Id VALUES (?)', [('target@chatroom',), ('other@chatroom',)])
            c.executemany('INSERT INTO VoiceInfo VALUES (?,?,?,?,?)', [(1,1,9001,100,b'\x02#!SILK_V3one'),(1,2,9002,200,b'\x02#!SILK_V3two'),(2,3,9999,300,b'\x02#!SILK_V3other')])
        self.app = SimpleNamespace(db_dir=str(self.root),keys_file=str(self.root/'all_keys.json'),all_keys={'message/media_0.db':{'enc_key':key}},cache=SimpleNamespace(get=lambda _:str(self.media)))
        self.table = 'Msg_' + hashlib.md5(b'target@chatroom').hexdigest()
        self.message = self.root / 'messages.db'
        with sqlite3.connect(self.message) as c:
            c.execute('CREATE TABLE Name2Id(user_name TEXT)')
            c.execute('INSERT INTO Name2Id VALUES (?)', ('sender',))
            c.execute(f'CREATE TABLE [{self.table}](local_id INTEGER,server_id INTEGER,local_type INTEGER,create_time INTEGER,real_sender_id INTEGER,message_content TEXT,WCDB_CT_message_content INTEGER)')
            c.executemany(f'INSERT INTO [{self.table}] VALUES (?,?,?,?,?,?,?)',[(1,9001,34,100,1,'sender:\n<msg><voicemsg voicelength="1000" aeskey="SECRET"/></msg>',0),(2,9002,34,200,1,'sender:\n<msg><voicemsg voicelength="2000" aeskey="SECRET"/></msg>',0),(3,9003,34,300,1,'sender:\n<msg><voicemsg voicelength="3000"/></msg>',0),(4,9004,1,400,1,'sender:\n普通文字',0)])
        self.ctx = {'query':'target@chatroom','username':'target@chatroom','display_name':'Test group','is_group':True,'db_path':str(self.message),'table_name':self.table}
        self.names = lambda user, _:user

    def store(self, **kwargs):
        store = VoiceStore(self.app, self.root/'audio', **kwargs)
        self.addCleanup(store.close)
        return store

    def test_binary_weflow_master_kdf_and_wrong_key(self):
        self.assertEqual(derive_media_key(self.master, self.page), self.key)
        self.assertIsNone(derive_media_key('f'*64, self.page))

    def test_supplemental_keys_are_verified_and_path_scoped(self):
        path = self.root/'media_keys.json'
        path.write_text(json.dumps({'message/media_0.db':{'enc_key':'0'*64},'../arbitrary.db':{'enc_key':self.key}}))
        self.app.all_keys.clear()
        load_media_keys(self.app)
        self.assertEqual(self.app.all_keys,{})
        path.write_text(json.dumps({'message/media_0.db':{'enc_key':self.key}}))
        load_media_keys(self.app)
        self.assertEqual(self.app.all_keys['message/media_0.db']['enc_key'],self.key)
        with patch('wechat_cli.core.media_keys.subprocess.run') as run:
            self.assertEqual(reuse_weflow_media_keys(self.app),0)
            run.assert_not_called()

    def test_weflow_existing_storage_recovery_saves_only_verified_keys(self):
        import base64
        import subprocess
        self.app.all_keys.clear()
        config = self.root/'Library/Application Support/weflow/WeFlow-config.json'
        config.parent.mkdir(parents=True)
        password = b'fixture-only-keychain-secret'
        wrapping = hashlib.pbkdf2_hmac('sha1',password,b'saltysalt',1003,16)
        plain = self.master.encode()+bytes([16])*16
        encrypted = b'v10'+AES.new(wrapping,AES.MODE_CBC,b' '*16).encrypt(plain)
        config.write_text(json.dumps({'decryptKey':'safe:'+base64.b64encode(encrypted).decode()}))
        result = subprocess.CompletedProcess([],0,stdout=password+b'\n',stderr=b'')
        with patch('wechat_cli.core.media_keys.Path.home',return_value=self.root),patch('wechat_cli.core.media_keys.subprocess.run',return_value=result):
            self.assertEqual(reuse_weflow_media_keys(self.app),1)
        target=self.root/'media_keys.json'
        self.assertEqual(target.stat().st_mode&0o777,0o600)
        self.assertEqual(json.loads(target.read_text())['message/media_0.db']['enc_key'],self.key)
        self.assertNotIn(self.master,target.read_text())
        self.assertFalse((self.root/'all_keys.json').exists())

    def test_keychain_denial_does_not_write_keys(self):
        import subprocess
        self.app.all_keys.clear()
        config=self.root/'Library/Application Support/weflow/WeFlow-config.json'
        config.parent.mkdir(parents=True)
        config.write_text(json.dumps({'decryptKey':'safe:unused'}))
        result=subprocess.CompletedProcess([],44,stdout=b'',stderr=b'denied')
        with patch('wechat_cli.core.media_keys.Path.home',return_value=self.root),patch('wechat_cli.core.media_keys.subprocess.run',return_value=result):
            with self.assertRaisesRegex(ValueError,'不可读取'):
                reuse_weflow_media_keys(self.app)
        self.assertFalse((self.root/'media_keys.json').exists())

    def test_exact_group_matching_and_no_other_chat_fallback(self):
        store = self.store(audio_format='silk')
        result=store.extract('target@chatroom',1,100,9001)
        self.assertEqual(Path(result['path']).read_bytes(),b'\x02#!SILK_V3one')
        self.assertEqual(Path(result['path']).stat().st_mode & 0o777,0o600)
        self.assertEqual(store.extract('target@chatroom',3,300,9003)['status'],'not_downloaded')
        self.assertEqual(store.extract('target@chatroom',3,300,0)['status'],'not_downloaded')
        self.assertEqual(store.extract('target@chatroom',3,300,9999)['status'],'not_downloaded')

    def test_ambiguous_media_not_exported(self):
        with sqlite3.connect(self.media) as c:
            c.execute('INSERT INTO VoiceInfo VALUES (1,1,9001,100,?)',(b'\x02#!SILK_V3conflict',))
        with self.assertRaisesRegex(ValueError,'歧义'):
            self.store(audio_format='silk').extract('target@chatroom',1,100,9001)

    def test_pagination_time_filter_missing_audio_and_no_xml_keys(self):
        store=self.store(audio_format='silk')
        records, failures=collect_voices(self.ctx,{},self.names,store,limit=2,offset=1)
        self.assertEqual([m['id'] for m in records],['9001','9002'])
        self.assertEqual(failures,[])
        self.assertTrue(all(m['status']=='ready' for m in records))
        self.assertNotIn('SECRET',json.dumps(records))
        records,_=collect_voices(self.ctx,{},self.names,store,limit=10,start_ts=200,end_ts=300)
        self.assertEqual([m['id'] for m in records],['9002','9003'])
        self.assertEqual(records[-1]['status'],'not_downloaded')

    def test_history_plain_text_unchanged_and_media_path_added(self):
        plain, failures=collect_chat_history(self.ctx,{},self.names,limit=10)
        self.assertEqual(failures,[])
        self.assertIn('普通文字',plain[-1])
        self.assertIn('aeskey="SECRET"',plain[0])
        store=self.store(audio_format='silk')
        media, failures=collect_chat_history(self.ctx,{},self.names,limit=10,resolve_media=True,voice_resolver=store.history_path)
        self.assertEqual(failures,[])
        self.assertEqual(media[-1],plain[-1])
        self.assertIn('.silk',media[0])
        self.assertNotIn('SECRET','\n'.join(media))

    def test_missing_key_status(self):
        self.app.all_keys.clear()
        store=self.store(audio_format='silk')
        self.assertEqual(store.extract('target@chatroom',1,100,9001)['status'],'missing_media_key')
        self.assertEqual(store.unavailable,['message/media_0.db'])

    def test_codec_missing_and_failed_conversion_do_not_poison_cache(self):
        store=self.store()
        with patch('wechat_cli.core.voice.shutil.which',return_value=None):
            with self.assertRaisesRegex(ValueError,'ffmpeg'):
                store.extract('target@chatroom',1,100,9001)
        self.assertEqual(list((self.root/'audio').glob('*.mp3')),[])

    def test_cli_json_schema_and_nonzero_missing_audio(self):
        self.app.msg_db_keys=[]
        self.app.decrypted_dir=''
        self.app.display_name_fn=self.names
        with patch('wechat_cli.core.context.AppContext',return_value=self.app),patch('wechat_cli.commands.voice.resolve_chat_context',return_value=self.ctx),patch('wechat_cli.commands.voice.get_contact_names',return_value={}):
            result=CliRunner().invoke(cli,['voice','target@chatroom','--audio-format','silk','--limit','10','--output-dir',str(self.root/'export')])
        self.assertEqual(result.exit_code,1,result.output)
        data=json.loads(result.output)
        self.assertEqual(data['count'],3)
        self.assertEqual(data['ready'],2)
        self.assertEqual(data['messages'][-1]['status'],'not_downloaded')
        self.assertNotIn('SECRET',result.output)

    def test_real_mp3_roundtrip(self):
        import importlib.util
        import math
        if not importlib.util.find_spec('pilk'):
            self.skipTest('optional pilk not installed')
        import pilk
        import shutil
        import subprocess
        if not shutil.which('ffmpeg') or not shutil.which('ffprobe'):
            self.skipTest('optional ffmpeg not installed')
        pcm=self.root/'generated.pcm'
        pcm.write_bytes(b''.join(struct.pack('<h',int(2000*math.sin(2*math.pi*440*i/24000))) for i in range(24000)))
        silk=self.root/'generated.silk'
        pilk.encode(str(pcm),str(silk),pcm_rate=24000,tencent=True)
        with sqlite3.connect(self.media) as c:
            c.execute('UPDATE VoiceInfo SET voice_data=? WHERE svr_id=9001',(silk.read_bytes(),))
        store=self.store()
        record=store.extract('target@chatroom',1,100,9001)
        duration=subprocess.run(['ffprobe','-v','error','-show_entries','format=duration','-of','csv=p=0',record['path']],capture_output=True,text=True,check=True)
        self.assertTrue(0.9<float(duration.stdout)<1.3)
        self.assertEqual(store.extract('target@chatroom',1,100,9001),record)


if __name__=='__main__':
    unittest.main()
