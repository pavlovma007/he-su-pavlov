import threading
import tempfile
import time

import pytest
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer


@pytest.fixture(scope="session")
def ftp_server():
    root = tempfile.mkdtemp(prefix="vote_ftp_")
    authorizer = DummyAuthorizer()
    authorizer.add_user("vote", "vote", root, perm="elradfmwMT")
    handler = FTPHandler
    handler.authorizer = authorizer
    server = FTPServer(("127.0.0.1", 0), handler)
    port = server.socket.getsockname()[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield {"host": "127.0.0.1", "port": port, "user": "vote", "password": "vote", "root": root}
    server.close_all()


@pytest.fixture()
def store(ftp_server):
    from sync import FtpStore
    base = "game-%d" % int(time.time() * 1000)   # изолированная папка на каждый тест
    return FtpStore(ftp_server["host"], ftp_server["port"],
                    ftp_server["user"], ftp_server["password"], base_path=base)
