"""Direct native fixtures under the caller's identity, with private child custody."""
import codecs
import hashlib
import os
from pathlib import Path
import selectors
import shlex
import shutil
import signal
import subprocess
import tempfile
import threading
import time

from fixture_executor import deadline_seconds


def host_identity():
    status = Path('/proc/self/status').read_text().splitlines()
    fields = dict(line.split(':', 1) for line in status if ':' in line)
    try:
        selinux = Path('/proc/self/attr/current').read_text().strip().rstrip('\0')
    except OSError:
        selinux = None
    return dict(uid=os.getuid(), gid=os.getgid(), groups=os.getgroups(),
                kernel=os.uname().release, architecture=os.uname().machine,
                pageSize=os.sysconf('SC_PAGE_SIZE'), selinux=selinux,
                capabilities=fields.get('CapEff', '').strip(),
                seccomp=fields.get('Seccomp', '').strip())


def remove_fixture_tree(root):
    # Permission tests deliberately leave mode-zero directories. Restore only
    # owned directories after all fixture tasks have exited, never link targets.
    if not Path(root).exists():
        return
    os.chmod(root, 0o700, follow_symlinks=False)
    for directory, children, _ in os.walk(root, followlinks=False):
        for name in children:
            path = Path(directory) / name
            if not path.is_symlink():
                os.chmod(path, 0o700, follow_symlinks=False)
    shutil.rmtree(root)


class LocalExecutor:
    mode = 'local'
    console = None

    def __init__(self, output, prefix='fixture'):
        self.output = Path(output).resolve()
        self.output.mkdir(parents=True, exist_ok=True)
        self.shell = shutil.which('sh')
        if self.shell is None:
            raise RuntimeError('Native fixtures require a POSIX shell in PATH')
        self.identity = host_identity()
        self.uid, self.selinux = self.identity['uid'], self.identity['selinux']
        self.state = dict(host=self.identity)
        self.root = tempfile.mkdtemp(prefix='shroot-' + prefix + '-')
        self.directory = self.root
        self.closed = False
        self.keep = False
        self.active = set()
        self.lock = threading.Condition()

    @property
    def evidence(self):
        return dict(mode=self.mode, **self.identity, closed=self.closed, retained=self.keep)

    def fork(self, prefix='server'):
        return LocalExecutor(self.output, prefix)

    def execute(self, command, timeout=120, *, capture=False, on_line=None):
        return self.run([self.shell, '-c', command], timeout, on_line=on_line)

    def run(self, argv, timeout=120, *, on_line=None):
        deadline = None if timeout is None else time.monotonic() + deadline_seconds(timeout)
        with self.lock:
            if self.closed:
                raise RuntimeError('Fixture executor is closed')
            process = subprocess.Popen(argv, cwd=self.directory,
                env=dict(os.environ, TMPDIR=self.root), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
            self.active.add(process)
        output, pending = [], ''
        decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')

        def accept(text, final=False):
            nonlocal pending
            output.append(text)
            if on_line is not None:
                pending += text
                while '\n' in pending:
                    line, pending = pending.split('\n', 1)
                    on_line(line + '\n')
                if final and pending:
                    on_line(pending)
                    pending = ''

        # EOF alone does not imply command lifetime: a failed command can leave
        # descendants holding stdout. Observe its exact child exit independently.
        completed = ()

        def reap():
            process.wait()
            os.write(completed[1], b'x')

        reaper = threading.Thread(target=reap)
        try:
            completed = os.pipe2(os.O_CLOEXEC)
            reaper.start()
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                selector.register(completed[0], selectors.EVENT_READ)
                while True:
                    remaining = None if deadline is None else max(0, deadline - time.monotonic())
                    # EVENT_WAIT: child exit or output; external cancellation also wakes this wait.
                    events = selector.select(remaining)
                    if not events and deadline is not None and time.monotonic() >= deadline:
                        raise TimeoutError('Fixture command timed out: ' + shlex.join(argv)
                                           + '\n' + ''.join(output)[-8192:])
                    eof = False
                    for key, _ in events:
                        if key.fd == completed[0]:
                            selector.unregister(completed[0])
                            self._signal(process, signal.SIGKILL)
                        else:
                            chunk = os.read(process.stdout.fileno(), 65536)
                            accept(decoder.decode(chunk, final=not chunk), final=not chunk)
                            eof = not chunk
                    if eof:
                        break
            status = process.wait(timeout=None if deadline is None else max(0, deadline - time.monotonic()))
            # Match the shell/app receipt contract, including native SIGSYS probes.
            return dict(exitCode=status if status >= 0 else 128 - status, output=''.join(output))
        finally:
            # A failed fixture may leave descendants holding output pipes. Only
            # this invocation's private process group is eligible for cleanup.
            with self.lock:
                self._signal(process, signal.SIGKILL)
                process.wait()
                self.active.discard(process)
                self.lock.notify_all()
            if reaper.ident is not None:
                reaper.join()
            for fd in completed:
                os.close(fd)
            process.stdout.close()

    @staticmethod
    def _signal(process, number):
        try:
            os.killpg(process.pid, number)
        except ProcessLookupError:
            pass

    def cancel(self):
        with self.lock:
            for process in self.active:
                self._signal(process, signal.SIGKILL)

    def close(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
            active = tuple(self.active)
            for process in active:
                self._signal(process, signal.SIGKILL)
            # EVENT_WAIT: command owners reap their children and release their pipes.
            if not self.lock.wait_for(lambda: not self.active, timeout=30):
                raise TimeoutError('Local fixture commands did not release their processes')
        if not self.keep:
            remove_fixture_tree(self.root)

    def upload(self, source, target, **options):
        source, target = Path(source), Path(target)
        shutil.copyfile(source, target)
        with target.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        return dict(path=str(target), sha256=digest)

    def download(self, source, target, **options):
        return self.upload(source, target, **options)

    def chmod(self, mode, *targets):
        return self.execute(shlex.join(['chmod', mode, *map(str, targets)]))

    def native_path(self, target):
        return str(target)

    def host_tool(self, name):
        path = shutil.which(name)
        if path is None:
            raise RuntimeError('Native fixture requires host utility: ' + name)
        return path
