#!/bin/sh
# Установка игры «Выборы» в Termux.
# Запуск:  curl https://mapavlov.ru/vote-game/install.sh | sh
set -e

BASE_URL="https://mapavlov.ru/vote-game"
VOTE_DIR="$HOME/vote-game"

echo "==> Обновление пакетов Termux"
pkg update -y

echo "==> Установка python и системных пакетов"
pkg install -y python termux-api clang zbar python-pillow 2>/dev/null \
  || pkg install -y python termux-api clang zbar

echo "==> Python-зависимости"
pip install pyaes==1.6.1 segno==1.6.1 pyzbar==0.1.9 2>/dev/null \
  || pip install pyaes segno pyzbar
pkg install -y python-pycryptodome 2>/dev/null || pip install pycryptodome

echo "==> Каталог игры"
mkdir -p "$VOTE_DIR"
cd "$VOTE_DIR"

echo "==> Скачивание и распаковка игры"
curl -fsSL "$BASE_URL/vote-game.tar.gz" -o vote-game.tar.gz
tar xzf vote-game.tar.gz
rm -f vote-game.tar.gz
chmod +x *.py

if [ ! -f config.json ]; then
  echo "==> ВНИМАНИЕ: config.json не найден в архиве."
  echo "    Запусти ./elector.py — он спросит адрес сервера и сам возьмёт config.json оттуда."
fi

echo ""
echo "Готово! Запуск ролей:"
echo "  Агентство (регистратор + стена):  cd ~/vote-game && ./agency.py"
echo "  Участник:                         cd ~/vote-game && ./elector.py"
echo "  Проверка голосов:                 cd ~/vote-game && ./verify.py"
echo "Подробности: README.md"
