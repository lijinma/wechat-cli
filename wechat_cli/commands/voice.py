"""Export voice messages as structured JSON plus local audio files."""
import click
from ..core.contacts import get_contact_names
from ..core.messages import resolve_chat_context, parse_time_range, validate_pagination
from ..core.media_keys import reuse_weflow_media_keys
from ..core.voice import VoiceStore, collect_voices
from ..output.formatter import output


@click.command('voice')
@click.argument('chat_name')
@click.option('--limit', default=50, show_default=True, help='最近语音数量')
@click.option('--offset', default=0, help='分页偏移量')
@click.option('--start-time', default='', help='起始时间 YYYY-MM-DD [HH:MM[:SS]]')
@click.option('--end-time', default='', help='结束时间 YYYY-MM-DD [HH:MM[:SS]]')
@click.option('--output-dir', type=click.Path(file_okay=False), default=None, help='音频导出目录（默认本机私密缓存）')
@click.option('--audio-format', type=click.Choice(['mp3', 'silk']), default='mp3', show_default=True)
@click.option('--reuse-weflow-key', is_flag=True, help='复用现有 WeFlow 钥匙串配置，不修改微信签名或权限')
@click.option('--format', 'fmt', type=click.Choice(['json', 'text']), default='json')
@click.pass_context
def voice(ctx, chat_name, limit, offset, start_time, end_time, output_dir, audio_format, reuse_weflow_key, fmt):
    """导出群聊或私聊中的语音，按消息 ID、时间和会话匹配本地音频。"""
    app = ctx.obj
    try:
        validate_pagination(limit, offset, limit_max=None)
        start_ts, end_ts = parse_time_range(start_time, end_time)
        if reuse_weflow_key:
            reuse_weflow_media_keys(app)
        chat = resolve_chat_context(chat_name, app.msg_db_keys, app.cache, app.decrypted_dir)
        if not chat or not chat['db_path']:
            raise ValueError('找不到指定聊天的本机记录')
        names = get_contact_names(app.cache, app.decrypted_dir)
        with VoiceStore(app, output_dir, audio_format) as store:
            messages, failures = collect_voices(chat, names, app.display_name_fn, store, limit, offset, start_ts, end_ts)
            missing = list(store.unavailable)
    except ValueError as error:
        raise click.ClickException(str(error)) from None
    except Exception:
        raise click.ClickException('语音导出失败；未修改微信或权限') from None
    result = {'chat': chat['display_name'], 'username': chat['username'], 'is_group': chat['is_group'], 'count': len(messages), 'ready': sum(m['status'] == 'ready' for m in messages), 'offset': offset, 'limit': limit, 'audio_format': audio_format, 'messages': messages, 'unavailable_media_databases': missing, 'failures': failures or None}
    if fmt == 'json':
        output(result)
    else:
        output('\n'.join(f"[{m['time']}] {m['sender']}: [语音 {m['duration_ms'] / 1000:g}秒] {m['path'] or m.get('error') or m['status']}" for m in messages) or '无语音记录', 'text')
    if failures or any(m['status'] != 'ready' for m in messages):
        ctx.exit(1)
