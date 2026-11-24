"""Hermes Connector Linux/macOS user-mode GUI and optional system tray.

Runs the SAME per-user CLI binary as a child. Never requests privileged
execution for remote commands or hides a running session from the user.
"""
import json
import os
import pathlib
import queue
import re
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

from state import State

CODE_RE = re.compile(r'(?i)(Код\s+МОСТ\s*:\s*)[A-Z0-9-]{4,6}')
SECRET_RE = re.compile(r'(?i)\b(ticket|token|secret|password|passphrase|authorization|api[_-]?key|mac)\s*[:=]\s*\S+')


def sanitize_journal(text):
    value = CODE_RE.sub(r'\1[скрыт]', text)
    value = SECRET_RE.sub(lambda m: m.group(1)+'=[скрыто]', value)
    return value.replace('\r', ' ').replace('\n', ' ')[:2048]


def cli_args(command, *params):
    if getattr(sys, 'frozen', False):
        return [sys.executable, command]+list(params)
    return [sys.executable, str(pathlib.Path(__file__).with_name('main.py')), command]+list(params)


class Journal:
    def __init__(self, path):
        self.path = pathlib.Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(self, text):
        line = time.strftime('%Y-%m-%d %H:%M:%S')+' '+sanitize_journal(text)+'\n'
        with self._lock:
            if self.path.exists() and self.path.stat().st_size > 512*1024:
                with self.path.open('rb') as source:
                    source.seek(-256*1024, 2)
                    tail = source.read()
                start = tail.find(b'\n')
                if start >= 0:
                    tail = tail[start+1:]
                temp = self.path.with_suffix('.tmp')
                temp.write_bytes(tail)
                os.chmod(temp, 0o600)
                os.replace(temp, self.path)
            with self.path.open('a', encoding='utf-8') as handle:
                handle.write(line)
            os.chmod(self.path, 0o600)

    def tail(self, maximum=10000):
        if not self.path.exists():
            return ''
        with self._lock:
            with self.path.open('rb') as source:
                source.seek(0, 2)
                length = source.tell()
                source.seek(max(0, length-maximum*3))
                raw = source.read().decode('utf-8', 'replace')
        return raw[-maximum:]


class ConnectorGUI:
    def __init__(self, resident=False):
        self.root = tk.Tk()
        self.root.title('Гермес Коннектор 0.3 · Linux/macOS')
        self.root.minsize(430, 330)
        self.root.geometry('510x395')
        self.root.protocol('WM_DELETE_WINDOW', self.hide_or_exit)
        self.state = State()
        self.journal = Journal(self.state.root/'activity.log')
        self.inbox = queue.Queue()
        self.process = None
        self.tray = None
        self.quitting = False
        self.mode = tk.StringVar(value='resident' if resident else 'support')
        self.gateway = tk.StringVar(value='auto')
        self.auto_off = tk.BooleanVar(value=False)
        self.minutes = tk.IntVar(value=60)
        self.status = tk.StringVar(value='Нет соединения · текущий пользователь: '+str(os.geteuid()))
        self.journal_open = False
        self._init_ui()
        self._init_tray()
        self.root.after(250, self._drain)
        if resident and self.tray is not None:
            self.root.withdraw()

    def _init_ui(self):
        body = ttk.Frame(self.root, padding=16)
        body.pack(fill='both', expand=True)
        ttk.Label(body, text='Hermes Connector', font=('Arial', 17, 'bold')).pack(anchor='w')
        ttk.Label(body, text='Команды выполняются от имени запустившего пользователя.').pack(anchor='w', pady=(1, 10))
        ttk.Label(body, textvariable=self.status, wraplength=470).pack(anchor='w', pady=(0, 10))
        modes = ttk.Frame(body)
        modes.pack(fill='x')
        ttk.Radiobutton(modes, text='Поддержка', variable=self.mode, value='support').pack(side='left')
        ttk.Radiobutton(modes, text='Постоянный агент', variable=self.mode, value='resident').pack(side='left', padx=16)
        route = ttk.Frame(body)
        route.pack(fill='x', pady=(9, 7))
        ttk.Label(route, text='Сервер МОСТ').pack(side='left', padx=(0, 10))
        ttk.Combobox(route, textvariable=self.gateway, width=18, state='readonly',
                     values=['auto','gr1','gr2']).pack(side='left')
        timer = ttk.Frame(body)
        timer.pack(fill='x', pady=(0, 9))
        ttk.Checkbutton(timer, text='Автоотключение (только поддержка)',
                        variable=self.auto_off).pack(side='left')
        ttk.Spinbox(timer, from_=5, to=1440, textvariable=self.minutes, width=7).pack(side='right')
        actions = ttk.Frame(body)
        actions.pack(fill='x', pady=(2, 8))
        ttk.Button(actions, text='Подключить', command=self.start).pack(side='left')
        ttk.Button(actions, text='Отключить', command=self.stop).pack(side='left', padx=7)
        ttk.Button(actions, text='Свернуть в трей', command=self.hide_or_exit).pack(side='left')
        maintenance = ttk.Frame(body)
        maintenance.pack(fill='x', pady=(0, 6))
        ttk.Button(maintenance, text='Установить SSH Client', command=lambda:self._run_setup('client')).pack(side='left')
        ttk.Button(maintenance, text='SSH Server', command=lambda:self._run_setup('server')).pack(side='left', padx=7)
        ttk.Button(maintenance, text='Автозапуск', command=self._autostart_dialog).pack(side='left')
        journalbar = ttk.Frame(body)
        journalbar.pack(fill='x', pady=(5, 0))
        ttk.Button(journalbar, text='▸ Журнал действий', command=self.toggle_journal).pack(side='left')
        ttk.Button(journalbar, text='Копировать', command=self.copy_journal).pack(side='right')
        self.journal_panel = ttk.Frame(body)
        self.journal_text = scrolledtext.ScrolledText(self.journal_panel, height=7, wrap='word', state='normal')
        self.journal_text.pack(fill='both', expand=True)
        self.journal_text.insert('end', self.journal.tail())
        self.journal_text.configure(state='disabled')

    def _init_tray(self):
        try:
            import pystray
            from PIL import Image, ImageDraw
            image = Image.new('RGB', (64, 64), '#17243b')
            draw = ImageDraw.Draw(image)
            draw.ellipse((8, 8, 56, 56), fill='#2d8dce')
            draw.text((23, 19), 'H', fill='white')
            menu = pystray.Menu(
                pystray.MenuItem('Открыть', lambda icon,item:self.inbox.put(('tray','show'))),
                pystray.MenuItem('Подключить', lambda icon,item:self.inbox.put(('tray','start'))),
                pystray.MenuItem('Отключить', lambda icon,item:self.inbox.put(('tray','stop'))),
                pystray.MenuItem('Выход', lambda icon,item:self.inbox.put(('tray','exit'))))
            self.tray = pystray.Icon('HermesConnector', image, 'Гермес Коннектор', menu)
            self.tray.run_detached()
        except Exception as exc:
            self.tray = None
            self.journal.append('Трей недоступен на этой системе: '+type(exc).__name__)

    def _child_reader(self, process):
        try:
            for raw in process.stdout:
                self.inbox.put(('log', raw.rstrip('\r\n')))
            exitcode = process.wait()
            self.inbox.put(('exited', exitcode))
        except (OSError, ValueError):
            self.inbox.put(('exited', -1))

    def _launch(self, command):
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, encoding='utf-8', errors='replace', bufsize=1)
        threading.Thread(target=self._child_reader, args=(child,), daemon=True).start()
        return child

    def start(self):
        if self.process is not None and self.process.poll() is None:
            self.status.set('Коннектор уже работает. Не создаём второй сеанс.')
            return
        mode = self.mode.get()
        if mode not in ('support', 'resident') or self.gateway.get() not in ('auto', 'gr1', 'gr2'):
            messagebox.showerror('Гермес', 'Некорректный режим или сервер')
            return
        command = cli_args('connect', '--mode', mode, '--gateway', self.gateway.get())
        if mode == 'support' and self.auto_off.get():
            try:
                duration = int(self.minutes.get())
                if not 5 <= duration <= 1440:
                    raise ValueError('out of range')
            except ValueError:
                messagebox.showwarning('Гермес', 'Период отключения должен быть 5–1440 минут')
                return
            command += ['--disconnect-after', str(duration)]
        try:
            self.process = self._launch(command)
            self.status.set('Запущен · '+('Постоянный агент' if mode == 'resident' else 'Поддержка'))
            self._append('Подключение запущено; доступ откроется только после согласования МОСТ')
        except OSError as exc:
            self.status.set('Запуск не выполнен: '+str(exc))

    def stop(self):
        if self.process is None or self.process.poll() is not None:
            self.status.set('Локальный исполнитель уже остановлен')
            return
        self.status.set('Завершаем локальный исполнитель и SSH-туннель…')
        self.process.terminate()
        self._append('Пользователь запросил завершение локального агента')

    def toggle_journal(self):
        if self.journal_open:
            self.journal_panel.pack_forget()
        else:
            self.journal_panel.pack(fill='both', expand=True, pady=(6,0))
        self.journal_open = not self.journal_open

    def copy_journal(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.journal.tail())
        self.status.set('Копирован очищенный от секретов журнал')

    def _append(self, text):
        self.journal.append(text)
        self.journal_text.configure(state='normal')
        self.journal_text.insert('end', time.strftime('%H:%M:%S')+'  '+text+'\n')
        if int(self.journal_text.index('end-1c').split('.')[0]) > 300:
            self.journal_text.delete('1.0', '100.0')
        self.journal_text.see('end')
        self.journal_text.configure(state='disabled')

    def _drain(self):
        while True:
            try:
                kind, value = self.inbox.get_nowait()
            except queue.Empty:
                break
            if kind == 'log':
                if value:
                    self._append(value)
                    # The enrollment code remains visible on screen for the
                    # owner, but is redacted from the on-disk activity journal.
                    if 'МОСТ:' in value:
                        self.status.set(value[:150])
            elif kind == 'exited':
                self.status.set('Локальный процесс завершён (код '+str(value)+').')
                self.process = None
            elif kind == 'tray':
                if value == 'show':
                    self.root.deiconify()
                    self.root.lift()
                elif value == 'start':
                    self.start()
                elif value == 'stop':
                    self.stop()
                elif value == 'exit':
                    self.exit()
        if not self.quitting:
            self.root.after(250, self._drain)

    def _run_setup(self, component):
        if not messagebox.askyesno('Установка OpenSSH',
             'Запустить установку '+component+' средствами ОС?\n\n'
             'Требуются права администратора для установки пакетов. '
             'Удалённые команды Гермеса по-прежнему будут выполняться '
             'только от имени текущего пользователя.\n\n'
             'Внимание: OpenSSH Server может открыть входящий TCP/22. Он не нужен '
             'для стандартного режима поддержки.'):
            return
        # A real terminal is required for sudo's password and explicit INSTALL.
        # The GUI never captures OS credentials or runs a silent elevation.
        import shlex
        command = ' '.join(shlex.quote(part) for part in
                           cli_args('setup-ssh', component, '--install'))
        try:
            if sys.platform == 'darwin':
                script = 'tell application "Terminal" to do script '+json.dumps(command)
                subprocess.Popen(['osascript', '-e', script], start_new_session=True)
            else:
                terminal = next((name for name in
                    ('x-terminal-emulator','gnome-terminal','konsole','xterm')
                    if __import__('shutil').which(name)), None)
                if terminal is None:
                    raise FileNotFoundError('desktop terminal not found')
                if terminal == 'gnome-terminal':
                    args = [terminal, '--', 'bash','-lc',command+'; read -p "Press Enter"']
                elif terminal == 'konsole':
                    args = [terminal, '-e', 'bash','-lc',command+'; read -p "Press Enter"']
                elif terminal == 'xterm':
                    args = [terminal, '-e', 'bash','-lc',command+'; read -p "Press Enter"']
                else:
                    args = [terminal, '-e', 'bash','-lc',command+'; read -p "Press Enter"']
                subprocess.Popen(args, start_new_session=True)
            self._append('Открыта отдельная консоль для проверки/установки OpenSSH '+component)
        except OSError:
            self.root.clipboard_clear()
            self.root.clipboard_append(command)
            messagebox.showinfo('Установка OpenSSH',
                'Графический терминал не найден. Команда скопирована в буфер обмена.\n'
                'Вставьте её в собственный терминал пользователя.')

    def _autostart_dialog(self):
        if not messagebox.askyesno('Постоянный агент',
                'Включить запуск Гермес Коннектора при следующем входе '
                'в текущую учётную запись?\n\n'
                'Постоянное разрешение должно быть предварительно согласовано '
                'в МОСТ. Вы сможете выключить автозапуск из этого окна.'):
            return
        try:
            task = subprocess.run(cli_args('autostart','enable','--confirm'),
                capture_output=True, text=True, timeout=12)
            if task.returncode != 0:
                raise RuntimeError((task.stderr or task.stdout).strip()[:350])
            self._append('Автозапуск включён в профиль текущего пользователя')
            messagebox.showinfo('Гермес', 'Автозапуск включён при следующем входе в ОС.')
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            messagebox.showwarning('Гермес', 'Не удалось включить автозапуск: '+str(exc))

    def hide_or_exit(self):
        if self.tray is not None:
            self.root.withdraw()
        elif messagebox.askyesno('Гермес',
                'Системный трей недоступен на этом рабочем столе.\n'
                'Закрытие остановит локальный агент. Выйти?'):
            self.exit()

    def exit(self):
        if self.quitting:
            return
        self.quitting = True
        self.stop()
        if self.tray is not None:
            try:
                self.tray.stop()
            except Exception:
                pass
        self.root.destroy()

    def run(self):
        self.root.mainloop()


def main(resident=False):
    app = ConnectorGUI(resident)
    if resident:
        app.root.after(1500, app.start)
    app.run()
