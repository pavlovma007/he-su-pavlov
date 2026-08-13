import json


def render_qr_terminal(data: str) -> str:
    import segno
    qr = segno.make(data, error="m")
    matrix = qr.matrix
    lines = []
    for row in range(0, len(matrix), 2):
        top = matrix[row]
        bottom = matrix[row + 1] if row + 1 < len(matrix) else [False] * len(matrix)
        line = ""
        for t, b in zip(top, bottom):
            if t and b:
                line += "█"
            elif t and not b:
                line += "▀"
            elif not t and b:
                line += "▄"
            else:
                line += " "
        lines.append(line)
    return "\n".join(lines)


def _extract_mark(payload: str):
    try:
        return int(json.loads(payload)["mark"])
    except Exception:
        try:
            return int(payload.strip())
        except Exception:
            return None


def decode_qr_from_image(path: str):
    """Читает снимок, возвращает метку (int) или None."""
    try:
        from PIL import Image
        import pyzbar.pyzbar as pyzbar
        img = Image.open(path)
        codes = pyzbar.decode(img)
        if not codes:
            return None
        return _extract_mark(codes[0].data.decode("utf-8", "replace"))
    except Exception:
        return None
