import rsa, os, random
import pyaes, hashlib
import math
from rsa import VerificationError, PublicKey
import rsa.transform

def bytes_to_int(b):
	return rsa.transform.bytes2int(b)
	#return int.from_bytes(b, byteorder='little')
def int_to_bytes(i):
	return rsa.transform.int2bytes(i)
	#length = math.ceil(i.bit_length() / 8)
	#return i.to_bytes(length, byteorder='little')

class Registrator:
	"registrator"
	MARKSLIST = []
	private_key=None
	public_key=None

	def __init__(self):
		self.public_key, self.private_key = rsa.newkeys(512)
		print('Registrator сформировал свои ключи')

	def public_elector_list(self):
		print('Registrator. public MARKSLIST=', self.MARKSLIST)

	def io_get_pub_key(self) -> bytes:
		return self.public_key.save_pkcs1()
	
	def io_elector_sign(self,  makrs, unknownBulshitInfo:int)->bytes:
		# по признакам проверим избирателя, он как то себя представить должен. 
		# тут просто код, который знает только он
		if makrs not in self.MARKSLIST:
			raise Exception("Ты не понятно кто и тебя нет в списках")
		# подписываем его барахло
		signResult = rsa.sign(int_to_bytes(unknownBulshitInfo), self.private_key, hash_method='SHA-1')
		return signResult

	
class Agency:
	"Agency"
	def __init__(sellf, r:Registrator):
		pass

class Elector:
	"elector"
	marks = None 
	public_key=None
	private_key=None
	voteStorage = None
	signedHashOfPubKeyByRegistrator=None
	pubKeyAsBytes=None
	# hash of pub key
	pubKeyHash=None
	#
	blinded=None
	blindInverse=None

	def __init__(self, r:Registrator, a:Agency):
		self.marks = random.randint(2, 2 ** 64)
		self.r = r; self.a = a
	
	def vote(self, candidate):
		self.voteStorage = candidate

	def register_new_keyPair(self):
		# делам новую пару ключей для этого голосования и считаем сразу хеш от публичного ключа
		self.public_key, self.private_key = rsa.newkeys(512)
		m = hashlib.sha256()
		self.pubKeyAsBytes = self.public_key.save_pkcs1() 
		m.update(self.pubKeyAsBytes)
		self.pubKeyHash:bytes = m.digest() # хэш от публичного ключа

		# вслепую подпишем эту пару в регистраторе, представившись "признаками"
		# готовим слепую подпись
		boolshitForSignAfterBlind:int = bytes_to_int(self.pubKeyHash)
		rPubKey:PublicKey = PublicKey.load_pkcs1(self.r.io_get_pub_key())
		self.blinded, self.blindInverse = rPubKey.blind(boolshitForSignAfterBlind)

		signedBlind:bytes = self.r.io_elector_sign(self.marks, self.blinded)
		self.signedHashOfPubKeyByRegistrator = rPubKey.unblind(bytes_to_int(signedBlind), self.blindInverse)
		# на всякий случай проверим сами корректность подписи	
		isOk = rsa.verify(self.pubKeyHash, int_to_bytes(self.signedHashOfPubKeyByRegistrator), rPubKey)
		print('blind sign is', isOk)

		# 

	


import sys
# самый простой тест на адекватность
public_key, private_key = rsa.newkeys(2048)



# Этот метод не работает потому что sign\verify по среди которых blind не расползнают метод 
# шифрования хеша, который там конкатенруется для этих алгоритмов в опред формат
#  
# mes:int = 100
# #blind 
# blinded, inv = public_key.blind(mes)
# blinded_bytes = int_to_bytes(blinded)
# #sign
# signedBlind = rsa.sign(blinded_bytes, private_key, hash_method='SHA-1')
# signedBlind_int = bytes_to_int(signedBlind)
# #unblind
# undblinded = public_key.unblind(signedBlind_int, inv)
# undblinded_bytes = int_to_bytes(undblinded)
# #verify
# isOk = rsa.verify(int_to_bytes(mes), undblinded_bytes, public_key)
# print('test', isOk)
# # Ну и чего ??? нифига он не работает как надо 


# Этот тест тоже провален - rsa.sign\verify не могут нормально работать в паре с их blind\unblind
# import rsa.core
# mes:int = 100
# #blind 
# blinded, inv = public_key.blind(mes)
# blinded_bytes = int_to_bytes(blinded)
# #sign
# h = hashlib.md5()
# h.update(blinded_bytes)
# h:bytes = h.digest() # stage 1 of sign
# h_int:int = bytes_to_int(h) % 100500
# signedBlind_int = rsa.core.encrypt_int(h_int, private_key.d, private_key.n) 
# #unblind
# undblinded:int = public_key.unblind(signedBlind_int, inv)
# undblinded_bytes = int_to_bytes(undblinded)
# #verify
# decrypted = rsa.core.decrypt_int(undblinded, public_key.e, public_key.n) 
# assert h == decrypted
# sys.exit()
##################################################################
r = Registrator() # там возникнет пара ключей "для конкретного голосования"
a = Agency(r)
e = Elector(r, a)

# согласовали признаки избирателя на этапе регистрации
r.MARKSLIST.append(e.marks)
r.public_elector_list()

# теперь началось голосование
print('теперь началось голосование')

e.register_new_keyPair()
e.vote("Candidate #2")

