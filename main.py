# InfinityFree Site Manager - Kivy (Android-ready MVP)
# ---------------------------------------------------
import os, re, json, ssl, time, tempfile, datetime, socket, traceback
from pathlib import Path
from dataclasses import dataclass
from ftplib import FTP, FTP_TLS, error_perm
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.togglebutton import ToggleButton
from kivy.uix.popup import Popup
from kivy.core.window import Window
from kivy.properties import StringProperty
from kivy.clock import Clock

@dataclass
class SitePaths:
    essays_json: str = "data/essays.json"
    timeline_json: str = "data/timeline.json"
    style_css: str = "css/style.css"
    assets_dir: str = "assets"
    uploads_dir: str = "assets/uploads"
    index_html: str = "index.html"

class PatchedFTP_TLS(FTP_TLS):
    def __init__(self, context=None, fix_pasv_ip=True, *args, **kwargs):
        self._fix_pasv_ip = fix_pasv_ip
        self.context = context or ssl.create_default_context()
        super().__init__(*args, **kwargs)
        try:
            self.encoding = "utf-8"
        except Exception:
            pass
    def ntransfercmd(self, cmd, rest=None):
        conn, size = FTP.ntransfercmd(self, cmd, rest)
        if self._prot_p:
            conn = self.context.wrap_socket(conn, server_hostname=self.host, session=self.sock.session)
        return conn, size
    def makepasv(self):
        host, port = super().makepasv()
        if self._fix_pasv_ip:
            try:
                peer_ip = self.sock.getpeername()[0]
                return peer_ip, port
            except Exception:
                pass
        return host, port

class FtpClient:
    def __init__(self, host, username, password, port=21, use_tls=True, passive=True,
                 tls_min12=True, verify_cert=True, fix_pasv_ip=True, log=lambda m:None):
        self.host = host; self.username = username; self.password = password
        self.port = port; self.use_tls = use_tls; self.passive = passive
        self.tls_min12 = tls_min12; self.verify_cert = verify_cert; self.fix_pasv_ip = fix_pasv_ip
        self.ftp = None; self.log = log
    def _make_context(self):
        import ssl
        ctx = ssl.create_default_context()
        if self.tls_min12:
            try: ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            except Exception: pass
        if not self.verify_cert:
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        return ctx
    def connect(self):
        self.log(f"Connecting to {self.host}:{self.port} (TLS={self.use_tls}) ...")
        if self.use_tls:
            ctx = self._make_context()
            ftps = PatchedFTP_TLS(context=ctx, fix_pasv_ip=self.fix_pasv_ip)
            ftps.connect(self.host, self.port, timeout=40); ftps.auth(); ftps.prot_p()
            ftps.login(self.username, self.password); ftps.set_pasv(self.passive)
            try: ftps.encoding = "utf-8"
            except Exception: pass
            self.ftp = ftps
        else:
            ftp = FTP(); ftp.connect(self.host, self.port, timeout=40)
            ftp.login(self.username, self.password); ftp.set_pasv(self.passive)
            try: ftp.encoding = "utf-8"
            except Exception: pass
            self.ftp = ftp
        self.log("Connected and logged in.")
    def close(self):
        try:
            if self.ftp: self.ftp.quit()
        except Exception:
            try: self.ftp.close()
            except Exception: pass
        finally: self.ftp = None
    def nlst(self, path):
        items = []
        try: items = self.ftp.nlst(path)
        except error_perm as e:
            if not str(e).startswith('550'): raise
        return items
    def _retry(self, fn, *args, **kwargs):
        import ssl, socket
        try: return fn(*args, **kwargs)
        except (ssl.SSLEOFError, ssl.SSLWantReadError, socket.timeout, OSError) as e:
            self.log(f"Transient FTPS error: {e}; reconnecting and retrying once...")
            try: self.close()
            except Exception: pass
            self.connect(); return fn(*args, **kwargs)
    def download_file(self, remote_path, local_path):
        self.log(f"Downloading: {remote_path} -> {local_path}")
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        with open(local_path, 'wb') as f:
            def _retr(): self.ftp.retrbinary(f"RETR {remote_path}", f.write)
            self._retry(_retr)
    def upload_file_atomic(self, local_path, remote_path):
        self.log(f"Uploading: {local_path} -> {remote_path}")
        remote_tmp = remote_path + ".tmp_upload"
        rdir = os.path.dirname(remote_path).replace("\\", "/")
        self.ensure_remote_dir(rdir)
        with open(local_path, 'rb') as f:
            def _stor_tmp(): self.ftp.storbinary(f"STOR {remote_tmp}", f, blocksize=256*1024)
            self._retry(_stor_tmp)
        try: self.ftp.delete(remote_path)
        except Exception: pass
        self.ftp.rename(remote_tmp, remote_path)
    def ensure_remote_dir(self, remote_dir):
        parts = [p for p in remote_dir.replace("\\", "/").split("/") if p]
        path = ""
        for p in parts:
            path = f"{path}/{p}" if path else f"/{p}" if not p.startswith("/") else p
            try: self.ftp.mkd(path)
            except Exception: pass
    def autodetect_site_root(self, candidates=None):
        if candidates is None: candidates = ["", "/htdocs"]
        try:
            htdocs_children = self.nlst("/htdocs")
            for c in htdocs_children:
                if c and c not in candidates: candidates.append(c)
        except Exception: pass
        markers = [SitePaths().index_html, SitePaths().essays_json, SitePaths().timeline_json]
        def has_markers(root):
            root_clean = root.strip("/")
            for m in markers:
                rp = f"/{root_clean}/{m}" if root_clean else f"/{m}"
                try: self.ftp.size(rp)
                except Exception:
                    parent = os.path.dirname(rp); name = os.path.basename(rp)
                    try:
                        listing = self.nlst(parent)
                        if not any(name in item for item in listing): return False
                    except Exception: return False
            return True
        for cand in candidates:
            c = cand;  c = ("/" + c) if (c and not c.startswith("/")) else c
            self.log(f"Checking site root candidate: {c or '/'}")
            try:
                if has_markers(c.strip("/")):
                    self.log(f"Detected site root: {c or '/'}"); return c or "/"
            except Exception as e: self.log(f"  skip: {e}")
        raise RuntimeError("Failed to detect site root. Please set it manually.")

class Workspace:
    def __init__(self, root_dir: Path):
        self.root = root_dir; self.site_paths = SitePaths()
        (self.root / self.site_paths.assets_dir).mkdir(parents=True, exist_ok=True)
        (self.root / self.site_paths.uploads_dir).mkdir(parents=True, exist_ok=True)
    @property
    def essays_path(self): return self.root / self.site_paths.essays_json
    @property
    def timeline_path(self): return self.root / self.site_paths.timeline_json
    @property
    def style_path(self): return self.root / self.site_paths.style_css

class LogView(ScrollView):
    text = StringProperty("")
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.label = Label(text=self.text, size_hint_y=None, halign='left', valign='top')
        self.label.bind(texture_size=self._update_height); self.add_widget(self.label)
    def _update_height(self, *args):
        self.label.text_size = (self.width - 20, None)
        self.label.height = self.label.texture_size[1] + 20
    def append(self, msg):
        ts = time.strftime("%H:%M:%S"); self.text += f"[{ts}] {msg}\n"
        self.label.text = self.text; Clock.schedule_once(lambda *_: self.scroll_y_to_end(), 0.01)
    def scroll_y_to_end(self): self.scroll_y = 0

class RootUI(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', **kwargs)
        form = GridLayout(cols=2, size_hint_y=None, height='320dp', padding=10, row_default_height='36dp', spacing=6)
        self.in_host = TextInput(text='ftpupload.net', multiline=False, hint_text="Host")
        self.in_user = TextInput(text='', multiline=False, hint_text="Username")
        self.in_pass = TextInput(text='', multiline=False, hint_text="Password", password=True)
        self.in_port = TextInput(text='21', multiline=False, hint_text="Port")
        self.chk_tls = ToggleButton(text="Use TLS (Explicit)", state='down', size_hint_y=None, height='36dp')
        self.chk_verify = ToggleButton(text="Verify Cert", state='down', size_hint_y=None, height='36dp')
        self.chk_pasv_fix = ToggleButton(text="Fix PASV IP", state='down', size_hint_y=None, height='36dp')
        self.in_site_root = TextInput(text='', multiline=False, hint_text="Site root (empty = auto)")
        form.add_widget(Label(text='FTP Host')); form.add_widget(self.in_host)
        form.add_widget(Label(text='Username')); form.add_widget(self.in_user)
        form.add_widget(Label(text='Password')); form.add_widget(self.in_pass)
        form.add_widget(Label(text='Port')); form.add_widget(self.in_port)
        form.add_widget(Label(text='TLS')); form.add_widget(self.chk_tls)
        form.add_widget(Label(text='Verify Cert')); form.add_widget(self.chk_verify)
        form.add_widget(Label(text='Fix PASV IP')); form.add_widget(self.chk_pasv_fix)
        form.add_widget(Label(text='Site Root')); form.add_widget(self.in_site_root)
        btns = BoxLayout(size_hint_y=None, height='50dp', spacing=8, padding=(10,0,10,0))
        self.btn_connect = Button(text='Connect & Pull'); self.btn_pull = Button(text='Pull Only'); self.btn_push = Button(text='Push Changes')
        btns.add_widget(self.btn_connect); btns.add_widget(self.btn_pull); btns.add_widget(self.btn_push)
        self.log = LogView(size_hint_y=1)
        self.add_widget(form); self.add_widget(btns); self.add_widget(self.log)
        self.ftp_client = None; self.site_root_remote = ""
        tmpdir = Path(tempfile.mkdtemp(prefix="ifree_site_")); self.workspace = Workspace(tmpdir); self.paths = self.workspace.site_paths
        self.btn_connect.bind(on_release=lambda *_: self.on_connect_and_pull())
        self.btn_pull.bind(on_release=lambda *_: self.on_pull_only())
        self.btn_push.bind(on_release=lambda *_: self.on_push())
        self.log.append(f"Local workspace: {self.workspace.root}")
    def _log(self, msg): self.log.append(msg)
    def _connect(self):
        if self.ftp_client: return
        try:
            host = self.in_host.text.strip(); user = self.in_user.text.strip(); password = self.in_pass.text
            port = int(self.in_port.text.strip() or "21")
            use_tls = (self.chk_tls.state == 'down'); verify_cert = (self.chk_verify.state == 'down'); fix_pasv_ip = (self.chk_pasv_fix.state == 'down')
            self.ftp_client = FtpClient(host, user, password, port, use_tls, passive=True, tls_min12=True, verify_cert=verify_cert, fix_pasv_ip=fix_pasv_ip, log=self._log)
            self.ftp_client.connect()
            sr = self.in_site_root.text.strip()
            if not sr:
                sr = self.ftp_client.autodetect_site_root(); self.in_site_root.text = sr
            self.site_root_remote = sr.rstrip("/")
        except Exception as e:
            self._log(f"ERROR: {e}"); traceback.print_exc()
            if self.ftp_client:
                try: self.ftp_client.close()
                except Exception: pass
            self.ftp_client = None; raise
    def _pull_site(self):
        assert self.ftp_client and self.site_root_remote
        sp = self.paths
        def rp(rel): return ("/" + rel) if self.site_root_remote in ("", "/") else f"{self.site_root_remote}/{rel}"
        for rel in [sp.essays_json, sp.timeline_json, sp.style_css, sp.index_html]:
            try:
                dest = self.workspace.root / rel; self.ftp_client.download_file(rp(rel), str(dest))
            except Exception as e: self._log(f"skip {rel}: {e}")
        (self.workspace.root / sp.assets_dir).mkdir(parents=True, exist_ok=True)
        (self.workspace.root / sp.uploads_dir).mkdir(parents=True, exist_ok=True)
        self._log("Pulled and staged locally.")
    def on_connect_and_pull(self):
        try: self._connect(); self._pull_site(); self._alert("Success", "Connected and pulled.")
        except Exception as e: self._alert("Error", str(e))
    def on_pull_only(self):
        try:
            if not self.ftp_client: self._connect()
            self._pull_site(); self._alert("Success", "Re-pulled.")
        except Exception as e: self._alert("Error", str(e))
    def on_push(self):
        try:
            if not self.ftp_client or not self.site_root_remote:
                self._alert("Info", "Connect & Pull first."); return
            sp = self.paths; root = self.site_root_remote.rstrip("/")
            def rp(rel): return (root + "/" + rel) if root else ("/" + rel)
            to_upload = []
            if (self.workspace.essays_path.exists()): to_upload.append((self.workspace.essays_path, rp(sp.essays_json)))
            if (self.workspace.timeline_path.exists()): to_upload.append((self.workspace.timeline_path, rp(sp.timeline_json)))
            if (self.workspace.style_path.exists()): to_upload.append((self.workspace.style_path, rp(sp.style_css)))
            for sub in [sp.assets_dir, sp.uploads_dir]:
                local_dir = self.workspace.root / sub
                if local_dir.exists():
                    for p in local_dir.rglob("*"):
                        if p.is_file():
                            rel = p.relative_to(self.workspace.root).as_posix(); to_upload.append((p, rp(rel)))
            for local_path, remote_path in to_upload:
                try: self.ftp_client.upload_file_atomic(str(local_path), remote_path)
                except Exception as e: self._log(f"Upload failed {local_path} -> {remote_path}: {e}")
            self._log("Push complete."); self._alert("Success", "Push complete.")
        except Exception as e: self._alert("Error", str(e))
    def _alert(self, title, message):
        content = BoxLayout(orientation='vertical', padding=10, spacing=8)
        content.add_widget(Label(text=message)); btn = Button(text='OK', size_hint_y=None, height='48dp')
        content.add_widget(btn); popup = Popup(title=title, content=content, size_hint=(0.8, 0.4))
        btn.bind(on_release=popup.dismiss); popup.open()

class IFSMApp(App):
    def build(self):
        self.title = "InfinityFree Site Manager (Android)"
        try: Window.minimum_width, Window.minimum_height = (900, 600)
        except Exception: pass
        return RootUI()

if __name__ == "__main__":
    IFSMApp().run()
