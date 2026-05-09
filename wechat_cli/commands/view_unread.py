"""view-unread 命令 — 激活 WeChat 并跳转未读会话"""

import platform
import subprocess

import click


DEFAULT_WECHAT_APP = "/Applications/WeChat.app"
DEFAULT_WECHAT_BUNDLE_ID = "com.tencent.xinWeChat"


def _positive_int(ctx, param, value):
    if value <= 0:
        raise click.BadParameter("必须大于 0")
    return value


def _positive_float(ctx, param, value):
    if value <= 0:
        raise click.BadParameter("必须大于 0")
    return value


@click.command("view-unread")
@click.option("--count", default=10, callback=_positive_int, help="发送“下一条未读”快捷键的次数")
@click.option("--interval", default=0.2, callback=_positive_float, help="每次快捷键之间的间隔秒数")
@click.option("--app", "app_path", default=DEFAULT_WECHAT_APP, help="WeChat.app 路径")
@click.option("--bundle-id", default=DEFAULT_WECHAT_BUNDLE_ID, help="WeChat bundle identifier")
def view_unread(count, interval, app_path, bundle_id):
    """激活 WeChat，并通过快捷键跳转未读会话。

    \b
    示例:
      wechat-cli view-unread                  # 激活微信并尝试跳转 10 次未读
      wechat-cli view-unread --count 20       # 尝试跳转 20 次
      wechat-cli view-unread --interval 0.5   # 每次间隔 0.5 秒
    """
    if platform.system() != "Darwin":
        raise click.ClickException("view-unread 目前只支持 macOS")

    try:
        subprocess.run(["caffeinate", "-u", "-t", "100"], check=True)
    except FileNotFoundError as exc:
        raise click.ClickException("找不到 caffeinate，无法保持屏幕唤醒") from exc
    except subprocess.CalledProcessError as exc:
        raise click.ClickException("执行 caffeinate 失败，无法保持屏幕唤醒") from exc

    script = [
        "osascript",
        "-e", f'tell application "{app_path}" to activate',
        "-e", "delay 0.8",
        "-e", 'tell application "System Events"',
        "-e", f'set frontmost of the first process whose bundle identifier is "{bundle_id}" to true',
        "-e", "delay 0.2",
        "-e", f"repeat {count} times",
        "-e", "key code 125 using {option down, command down}",
        "-e", f"delay {interval}",
        "-e", "end repeat",
        "-e", "end tell",
    ]

    try:
        subprocess.run(script, check=True)
    except FileNotFoundError as exc:
        raise click.ClickException("找不到 osascript，无法执行 AppleScript") from exc
    except subprocess.CalledProcessError as exc:
        raise click.ClickException(
            "无法控制 WeChat。请确认 WeChat 已安装，并在系统设置的“隐私与安全性 -> 辅助功能”中允许终端控制电脑。"
        ) from exc

    click.echo(f"已激活 WeChat，并发送 {count} 次 Option+Command+Down。")
