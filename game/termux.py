import subprocess


def capture_photo(path: str) -> bool:
    """Фото с фронтальной/основной камеры через termux-api."""
    try:
        r = subprocess.run(["termux-camera-photo", "-c", "0", path],
                           capture_output=True, timeout=15)
        return r.returncode == 0
    except Exception:
        return False


def toast(text: str) -> None:
    try:
        subprocess.run(["termux-toast", "-g", "top", text],
                       capture_output=True, timeout=10)
    except Exception:
        pass


def vibrate(ms: int = 100) -> None:
    try:
        subprocess.run(["termux-vibrate", "-d", str(ms)],
                       capture_output=True, timeout=10)
    except Exception:
        pass
