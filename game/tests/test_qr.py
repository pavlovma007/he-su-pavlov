import pytest

import qr


def test_render_qr_terminal_returns_block_chars():
    s = qr.render_qr_terminal('{"mark": 17}')
    assert isinstance(s, str)
    assert len(s) > 0
    assert any(ch in s for ch in "█▀▄")          # есть полублоки


def test_decode_from_segno_png():
    pyzbar = pytest.importorskip("pyzbar.pyzbar", exc_type=ImportError)
    segno = pytest.importorskip("segno")
    from PIL import Image
    import io as _io

    q = segno.make('{"mark": 42}', error="m")
    buf = _io.BytesIO()
    q.save(buf, kind="png", scale=8)
    buf.seek(0)
    tmp = "/tmp/qr_test_42.png"
    with open(tmp, "wb") as f:
        f.write(buf.read())
    assert qr.decode_qr_from_image(tmp) == 42
