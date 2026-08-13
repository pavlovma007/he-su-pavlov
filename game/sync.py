import ftplib
import io
import json
import os
import random
import time


def unique_filename(key: str) -> str:
    ts = time.strftime("%Y%m%d%H%M%S")
    rand = random.randint(1000, 9999)
    return f"{key}-{ts}-{rand}.json"


class FtpStore:
    def __init__(self, host, port=21, user="", password="", base_path=""):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.base_path = base_path.strip("/")

    def _connect(self):
        """Подключиться к FTP. Сервер может капризничать (временные таймауты,
        «421 Login timeout» и т.п.), поэтому пробуем несколько раз с паузами."""
        last = None
        for attempt in range(4):
            ftp = ftplib.FTP()
            try:
                ftp.connect(self.host, self.port, timeout=30)
                ftp.login(self.user, self.password)
                ftp.voidcmd("TYPE I")
                if self.base_path:
                    try:
                        ftp.cwd("/" + self.base_path)
                    except ftplib.all_errors:
                        ftp.mkd(self.base_path)
                        ftp.cwd("/" + self.base_path)
                return ftp
            except Exception as e:
                last = e
                try:
                    ftp.close()
                except Exception:
                    pass
                print(f"связь с FTP прервалась (попытка {attempt + 1}/4): {e}")
                time.sleep(3 * (attempt + 1))
        raise last

    def _ensure_dir(self, ftp, folder):
        for part in [p for p in (folder or "").split("/") if p]:
            try:
                ftp.cwd(part)
            except ftplib.all_errors:
                ftp.mkd(part)
                ftp.cwd(part)

    def upload_json(self, folder, key, data):
        path = f"{folder}/{unique_filename(key)}" if folder else unique_filename(key)
        self.upload_text(path, pretty_json_text(data))
        return path

    def upload_text(self, relpath, text):
        ftp = self._connect()
        try:
            folder = os.path.dirname(relpath) or ""
            self._ensure_dir(ftp, folder)
            bio = io.BytesIO(text.encode("utf-8"))
            ftp.storbinary(f"STOR {os.path.basename(relpath)}", bio)
        finally:
            ftp.quit()

    def read_text(self, relpath):
        ftp = self._connect()
        try:
            bio = io.BytesIO()
            ftp.retrbinary(f"RETR {relpath}", bio.write)
            return bio.getvalue().decode("utf-8")
        finally:
            ftp.quit()

    def list_filenames(self, folder):
        ftp = self._connect()
        try:
            if folder:
                try:
                    ftp.cwd(folder)
                except ftplib.all_errors:
                    return []
            try:
                entries = list(ftp.mlsd())
                return [n for n, facts in entries if facts.get("type", "file") == "file"]
            except ftplib.all_errors:
                return [n for n in ftp.nlst() if not n.endswith("/")]
        finally:
            ftp.quit()

    def list_folder(self, folder):
        out = []
        for name in self.list_filenames(folder):
            rel = f"{folder}/{name}" if folder else name
            text = self.read_text(rel)
            try:
                data = json.loads(text)
            except ValueError:
                data = {"_raw": text}
            data["_file"] = rel
            out.append(data)
        return out

    def exists(self, relpath):
        ftp = self._connect()
        try:
            try:
                ftp.size(relpath)
                return True
            except ftplib.all_errors:
                return False
        finally:
            ftp.quit()


def pretty_json_text(data) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)
