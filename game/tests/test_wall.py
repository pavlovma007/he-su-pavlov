import view
from agency import AgencyEngine

CANDIDATES = [{"id": 1, "name": "Кандидат №1"}, {"id": 2, "name": "Кандидат №2"}]


def test_publish_wall_uploads_index_html(store, tmp_path):
    agency = AgencyEngine(store, CANDIDATES, key_path=str(tmp_path / "reg.pem"))
    agency.start()
    view.publish_wall(store)
    assert store.exists("meta/index.html")
    html = store.read_text("meta/index.html")
    assert "Фаза" in html
    assert "setTimeout" in html                      # JS-автообновление
    assert "7000" in html                            # таймер автообновления на 7 секунд
    assert "Итог" in html


def test_publish_wall_overwrites(store, tmp_path):
    agency = AgencyEngine(store, CANDIDATES, key_path=str(tmp_path / "reg.pem"))
    agency.start()
    view.publish_wall(store)
    view.publish_wall(store)                         # перезапись - это «живой экран»
    assert store.exists("meta/index.html")
