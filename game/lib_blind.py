from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, GCD
from Crypto.Hash import SHA256
import random


# utils
def bytes_to_int(b):
	"""Преобразует байты в целое число (big-endian для совместимости с криптостандартами)."""
	return int.from_bytes(b, byteorder='big')

def int_to_bytes(i):
	"""Преобразует целое число в байты (big-endian)."""
	if i == 0:
		return b'\x00'
	length = (i.bit_length() + 7) // 8
	return i.to_bytes(length, byteorder='big')

def hash_message_to_int(message_bytes: bytes) -> int:
	return int.from_bytes(SHA256.new(message_bytes).digest(), 'big')

def export_public_key(pub_key) -> bytes:
	"""Сериализует публичный ключ в PEM-формат."""
	return pub_key.export_key(format='PEM')

def import_public_key(pem_bytes) -> RSA.RsaKey:
	"""Десериализует публичный ключ из PEM."""
	return RSA.import_key(pem_bytes)

def export_private_key(priv_key) -> bytes:
	"""Сериализует приватный ключ (осторожно!)."""
	return priv_key.export_key(format='PEM')

def import_private_key(pem_bytes) -> RSA.RsaKey:
	"""Десериализует приватный ключ."""
	return RSA.import_key(pem_bytes)


def keygen(bits):
	"""Генерирует пару ключей (публичный, приватный) с использованием PyCryptodome."""
	key = RSA.generate(bits)
	return key.publickey(), key

def blind(message_bytes: bytes, public_key):
	"""
	Слепит сообщение для слепой подписи.
	Возвращает: (blinded_message_int, blind_factor_r)
	"""
	n = public_key.n
	e = public_key.e
	# Хешируем сообщение, чтобы гарантировать его размер < n
	msg_hash = SHA256.new(message_bytes).digest()
	msg_int = bytes_to_int(msg_hash)
	if msg_int >= n:
		raise ValueError("Хеш сообщения не помещается в модуль RSA. Увеличьте размер ключа.")
	# Генерация blinding factor r
	while True:
		r = random.randrange(2, n)
		if GCD(r, n) == 1:
			break
	blinded = (pow(r, e, n) * msg_int) % n
	return blinded, r

def unblind(blinded_signature: int, r: int, public_key):
	"""Расслепляет подпись."""
	n = public_key.n
	r_inv = inverse(r, n)
	unblinded = (blinded_signature * r_inv) % n
	return unblinded

def signature(message_bytes: bytes, private_key):
	"""Подписывает хеш сообщения приватным ключом."""
	n = private_key.n
	d = private_key.d
	msg_hash = SHA256.new(message_bytes).digest()
	msg_int = bytes_to_int(msg_hash)
	if msg_int >= n:
		raise ValueError("Хеш сообщения не помещается в модуль RSA.")
	return pow(msg_int, d, n)

def verify(signature_int: int, public_key):
	"""Верифицирует подпись, возвращая хеш сообщения (int)."""
	n = public_key.n
	e = public_key.e
	return pow(signature_int, e, n)