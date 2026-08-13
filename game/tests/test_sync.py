import ftplib
from unittest import mock

from sync import FtpStore


def test_connect_retries_transient_failure():
    """Сервер пару раз отвечает «421 Login timeout» — _connect должен пережить
    это и вернуть соединение с 3-й попытки, а не уронить скрипт."""
    login_attempts = []

    class FlakyFTP:
        def connect(self, host, port, timeout=30):
            pass

        def login(self, user, password):
            login_attempts.append(user)
            if len(login_attempts) < 3:
                raise ftplib.error_temp("421 Login timeout (15 seconds)")

        def voidcmd(self, cmd):
            pass

        def close(self):
            pass

    store = FtpStore("host", 21, "u", "p")
    with mock.patch("ftplib.FTP", FlakyFTP), mock.patch("sync.time.sleep"):
        ftp = store._connect()

    assert len(login_attempts) == 3
    assert isinstance(ftp, FlakyFTP)


def test_upload_text_roundtrip(store):
    store.upload_text("meta/hello.txt", "привет\n")
    assert store.read_text("meta/hello.txt") == "привет\n"


def test_upload_json_unique_names(store):
    p1 = store.upload_json("marks", "17", {"mark": 17})
    p2 = store.upload_json("marks", "17", {"mark": 17})
    assert p1 != p2
    assert store.exists(p1)
    assert len(store.list_filenames("marks")) == 2


def test_list_folder_adds_file(store):
    store.upload_json("marks", "17", {"mark": 17})
    items = store.list_folder("marks")
    assert len(items) == 1
    assert items[0]["mark"] == 17
    assert items[0]["_file"].startswith("marks/")


def test_exists_missing(store):
    assert not store.exists("meta/phase")


def test_upload_json_multilevel_folder(store):
    p = store.upload_json("meta/phase", "REGISTRATION", {"phase": "REGISTRATION"})
    assert p.startswith("meta/phase/")
    assert store.exists(p)
    items = store.list_folder("meta/phase")
    assert len(items) == 1
    assert items[0]["phase"] == "REGISTRATION"
