import ftplib
import io
import time

import pytest

from reset import _list_items, remove_folder


def _ftp(ftp_server):
    ftp = ftplib.FTP()
    ftp.connect(ftp_server["host"], ftp_server["port"], timeout=15)
    ftp.login(ftp_server["user"], ftp_server["password"])
    ftp.voidcmd("TYPE I")
    return ftp


def test_remove_folder_deletes_entire_tree(ftp_server):
    """remove_folder убирает папку целиком: файлы, вложенные папки, саму папку."""
    ftp = _ftp(ftp_server)
    base = f"reset-test-{time.time_ns()}"   # изолируемся от папок других тестов
    for folder in [base, f"{base}/marks", f"{base}/ballots",
                   f"{base}/meta", f"{base}/meta/phase"]:
        ftp.mkd(folder)
    ftp.storbinary(f"STOR {base}/marks/1.json", io.BytesIO(b"{}"))
    ftp.storbinary(f"STOR {base}/meta/candidates.json", io.BytesIO(b"{}"))
    ftp.storbinary(f"STOR {base}/meta/phase/REGISTRATION.json", io.BytesIO(b"{}"))

    total = remove_folder(ftp, base, "/")

    assert total == 3
    with pytest.raises(ftplib.all_errors):
        ftp.cwd(base)   # папка удалена целиком
    ftp.quit()


def test_list_items_nlst_fallback_detects_subfolder():
    """Сервер без MLSD: NLST не ставит '/' у папок и присылает '.'/'..'.
    Вложенная папка должна распознаться как папка, а мусор - отсеяться."""
    class FakeFTP:
        def mlsd(self):
            raise TimeoutError("no mlsd")
        def nlst(self):
            return ["..", ".", "phase", "pubkey.txt", "candidates.json"]
        def cwd(self, path):
            if path in ("phase", "/", "meta", ".."):
                return
            raise ftplib.error_perm("550 not a directory")

    items = _list_items(FakeFTP(), "meta", "/")
    assert ("phase", "dir") in items
    assert ("pubkey.txt", "file") in items
    assert ("candidates.json", "file") in items
    assert not any(n in (".", "..") for n, _ in items)


def test_remove_folder_skips_missing(ftp_server):
    """Нет папки - не ошибка, просто ноль удалённых."""
    ftp = _ftp(ftp_server)
    assert remove_folder(ftp, "nonexistent-folder", "/") == 0
    ftp.quit()
