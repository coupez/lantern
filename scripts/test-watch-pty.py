#!/usr/bin/env python3
"""Exercise the real terminal lifecycle. No third-party packages or LAN access."""
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'bin/lantern').resolve())

class Session:
    def __init__(self, args, width=100, height=24, env=None):
        self.master, self.slave = pty.openpty()
        self.before = termios.tcgetattr(self.slave)
        self.output = b''
        self.resize(width, height)
        self.process = subprocess.Popen([binary, *args], stdin=self.slave, stdout=self.slave,
                                        stderr=self.slave, env={**os.environ, 'TERM': 'xterm-256color', **(env or {})})

    def resize(self, width, height):
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', height, width, 0, 0))

    def read(self, seconds=.15):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if select.select([self.master], [], [], max(0, deadline-time.monotonic()))[0]:
                try:
                    data = os.read(self.master, 65536)
                except OSError as e:
                    if e.errno != errno.EIO:
                        raise
                    break
                if not data:
                    break
                self.output += data
        return self.output

    def until(self, text, seconds=5):
        deadline = time.monotonic() + seconds
        while text not in self.output and time.monotonic() < deadline:
            self.read(.05)
        assert text in self.output, (text, self.output[-3000:])

    def send(self, data):
        os.write(self.master, data)
        self.read()

    def finish(self, code=0, interactive=True):
        deadline = time.monotonic() + 5
        while self.process.poll() is None and time.monotonic() < deadline:
            self.read(.05)
        self.process.wait(timeout=.1)
        self.read(.05)
        assert self.process.returncode == code, self.output[-3000:]
        after = termios.tcgetattr(self.slave)
        before = self.before.copy()
        # Darwin sets the kernel PENDIN bookkeeping bit on any raw-to-canonical
        # transition, including Python's own tty.setraw/tcsetattr round trip.
        if sys.platform == 'darwin':
            before[3] &= ~termios.PENDIN
            after[3] &= ~termios.PENDIN
        assert after == before, ('terminal attributes not restored', before, after)
        if interactive:
            assert b'\x1b[?1049h' in self.output, 'alternate screen not entered'
            assert b'\x1b[?25h\x1b[?1049l' in self.output, 'cursor/screen not restored'
        else:
            assert b'\x1b[?1049h' not in self.output

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()
        os.close(self.master)
        os.close(self.slave)


def run(args, check, **kwargs):
    s = Session(args, **kwargs)
    try:
        check(s)
    finally:
        s.close()


def navigation(s):
    s.until(b'WATCHING')
    s.send(b' ')
    s.until(b'PAUSED')

    def frame():
        # Check the current screen, not a matching line from an earlier draw.
        return re.sub(rb'\x1b\[[0-9;]*[A-Za-z]', b'',
                      s.output.rsplit(b'\x1b[H\x1b[2K', 1)[-1])

    def selected(address):
        marker = '›● '.encode() + address
        assert marker in frame(), (marker, frame())

    # Default CSI, xterm application keys, screen/Linux, and rxvt variants.
    for home, end in ((b'\x1b[H', b'\x1b[F'), (b'\x1bOH', b'\x1bOF'),
                      (b'\x1b[1~', b'\x1b[4~'), (b'\x1b[7~', b'\x1b[8~')):
        s.send(end)
        selected(b'192.168.1.40')
        s.send(home)
        selected(b'192.168.1.1')

        # A short viewport forces the real inspector to scroll.
        s.resize(60, 12)
        s.send(b'\x1bOM')
        assert b'Device details' in frame(), frame()
        top = frame().split(b'\r\n')[5:9]
        s.send(end)
        bottom = frame().split(b'\r\n')[5:9]
        assert bottom != top, ('End did not scroll details', frame())
        s.send(home)
        assert frame().split(b'\r\n')[5:9] == top, ('Home did not restore details', frame())
        s.send(b'\x1bOM')
        assert b'Device details' not in frame(), frame()
        s.resize(100, 24)
        s.read(.15)

    # Keys inside a bracketed paste must remain inert.
    s.send(b'\x1b[200~\x1bOF\x1b[4~\x1b[8~\x1bOM\x1b[201~')
    selected(b'192.168.1.1')
    assert b'Device details' not in frame(), frame()
    s.send(b'q')
    s.finish()


run(['demo', '--watch', '--no-color'], navigation)
print('PASS terminal navigation: Home/End variants select and scroll; keypad Enter; paste isolation')


def interaction(s):
    s.until(b'WATCHING')
    s.send(b' ')
    s.until(b'PAUSED')
    s.send(b'/printer\r')
    s.until(b'1 matches')
    s.send(b'\r')
    s.until(b'TCP open')
    s.send(b'\x1b[6~\x1b[5~\r')
    s.send(b'\x1b')
    s.send(b'\x1b[B\r')
    s.until(b'studio-mac.local')
    s.resize(36, 10)
    s.read(.2)
    s.resize(120, 35)
    s.send(b'\r')
    # Bracketed paste must not quit or run commands.
    s.send(b'\x1b[200~q\x03r\x1b[201~')
    assert s.process.poll() is None
    s.send(b'r')
    s.until(b'missing')
    s.send(b'a')
    s.until(b'ACTIVITY')
    s.send(b'\x1b[6~\r')
    s.send(b'q')
    s.finish()

run(['demo', '--watch'], interaction)
print('PASS demo: selection, filter, inspector, pause, refresh, changes, resize, paste, quit')

for exit_key in (b'q', b'\x03'):
    def cancel(s):
        s.until(b'SCANNING')
        s.send(exit_key)
        s.finish()
    run(['demo', '--watch', '--no-color'], cancel)
print('PASS cancellation while scanning: q and Ctrl-C')

def no_color(s):
    s.until(b'WATCHING')
    s.send(b'q')
    s.finish()
    assert not re.search(rb'\x1b\[[0-9;]*m', s.output), 'SGR colors emitted'
run(['demo', '--watch', '--no-color'], no_color)
run(['demo', '--watch'], no_color, env={'NO_COLOR': '1'})
print('PASS --no-color and NO_COLOR keep keyboard navigation without SGR colors')

def automatic(s):
    s.until(b'WATCHING')
    s.until(b'missing', seconds=6)
    s.send(b'q')
    s.finish()
run(['demo', '--watch'], automatic)
print('PASS automatic refresh and change detection')

with tempfile.TemporaryDirectory(prefix='lantern-watch-') as directory:
    save = str(Path(directory) / 'snapshot.json')
    args = ['watch', '127.0.0.1', '--ports', 'none', '--no-icmp', '--no-dns', '--no-multicast', '--save', save]
    def saved(s):
        s.until(b'WATCHING')
        s.process.send_signal(signal.SIGTERM)
        s.finish()
        assert json.loads(Path(save).read_text())['target'] == '127.0.0.1/32'
    run(args, saved)
    print('PASS real loopback scan: snapshot save and SIGTERM restoration')

    def error(s):
        s.finish(code=1)
    run(args[:-1] + [str(Path(directory) / 'absent' / 'snapshot.json')], error)
    run(['watch', '127.0.0.1', '--concurrency', '0'], error)
    print('PASS snapshot error and invalid scan: terminal restored')

    def plain(s):
        s.until(b'cached neighbors')
        s.process.send_signal(signal.SIGTERM)
        s.finish(interactive=False)
    run(args + ['--plain', '--no-color'], plain)
    run(args + ['--no-color'], plain, env={'TERM': 'dumb'})
    print('PASS --plain and TERM=dumb skip alternate screen')

    p = subprocess.Popen([binary, *args, '--jsonl'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        while True:
            line = p.stdout.readline()
            assert line
            row = json.loads(line)
            if row.get('type') == 'report':
                break
        p.send_signal(signal.SIGTERM)
        stdout, stderr = p.communicate(timeout=5)
        assert p.returncode == 0 and b'\x1b' not in stdout + stderr
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()
    print('PASS redirected JSONL remains machine-readable')
