import os, random, sys, pprint
import pyaes, hashlib
import math, pickle
import lib_blind

N = 128

# utils
def bytes_to_int(b):
	# return rsa.transform.bytes2int(b)
	return int.from_bytes(b, byteorder='little')
def int_to_bytes(i):
	# return rsa.transform.int2bytes(i)
	length = math.ceil(i.bit_length() / 8)
	return i.to_bytes(length, byteorder='little')
def hash_of_pub_key(pub_key) -> int:
		m = hashlib.sha256()
		pubKeyAsBytes = pickle.dumps(pub_key)
		m.update(pubKeyAsBytes)
		# хэш от публичного ключа
		result = bytes_to_int(m.digest()) % sys.maxsize
		return result



class Registrator:
	"registrator"
	MARKSLIST = []
	private_key=None
	public_key=None

	def __init__(self):
		self.public_key, self.private_key = lib_blind.keygen(2 ** N)
		print('Registrator сформировал свои ключи')

	def do_public_elector_list(self):
		print('Registrator. public MARKSLIST=' , self.MARKSLIST)

	def io_get_pub_key(self) -> bytes:
		print('Registrator. отдал свой публичный ключ, кому-то, кто запросил')
		return pickle.dumps(self.public_key)
	
	def io_elector_sign(self,  mark_1, unknownBulshitInfo:int)->int:
		# по признакам проверим избирателя, он как то себя представить должен. 
		# тут просто код, который знает только он
		if mark_1 not in self.MARKSLIST:
			raise Exception("Ты не понятно кто и тебя нет в списках")
		# подписываем его барахло
		signResult_int =  lib_blind.signature(unknownBulshitInfo, self.private_key)
		print(f'\nRegistrator. подписал для {mark_1} число {unknownBulshitInfo} , отправил ему подпись {signResult_int}\n')
		return signResult_int
	
class Agency:
	"Agency"
	r:Registrator = None
	rPubKey=None
	authorized_keys=[]
	published_encripted_ballots=[]
	secret_keys=[]

	def __init__(self, r:Registrator):
		self.r = r
		rPubKeyInfo = pickle.loads(self.r.io_get_pub_key())
		self.rPubKey = lib_blind.Key(rPubKeyInfo[0], rPubKeyInfo[1])

	def io_authorize_keys(self, payload):
		e_public_key_pickled, e_signedHashOfPubKeyByRegistrator = payload

		e_public_key = pickle.loads(e_public_key_pickled)
		e_hashOfElectorPubKey = hash_of_pub_key(e_public_key)
		# check 1
		if hash_of_pub_key(e_public_key) != e_hashOfElectorPubKey:
			raise Exception('Agency. ваш публичный ключ не совпал с хешэм, который вы предоставили')
		# check 2
		hash_again = lib_blind.verefy(e_signedHashOfPubKeyByRegistrator, self.rPubKey)
		if hash_again != e_hashOfElectorPubKey:
			raise Exception('Agency. проверка подписи хеша вашего ключа ключём Регистратора не пройдена')
		self.authorized_keys.append({
			'public_key': e_public_key_pickled, 
			'public_key_sign': e_signedHashOfPubKeyByRegistrator, 
		})
		print('Agency. проверил подпись публичного ключа избирателя. её подписал действительно Регистратор\nдобавил её в список авторизованных]')

	def io_get_public_authorized_keys(self):
		print('Agency. показал список авторизованных ключей')
		return self.authorized_keys

	def io_submit_ballot(self, payload):
		"агенство принимает зашифрованный бюлетень, выполняет проверки, и если ок - публикует открыто в списке бюлетеней. "
		"ПО избирателя ждет точной публикации , чтобы опубликовать и отправить в агенство ключи для расшифровки"
		encripted_ballot = payload["encripted_ballot"]
		pubKeyAsBytes = payload["public_key"]
		e_pub_key = pickle.loads(pubKeyAsBytes)
		encripted_ballot_sign = payload["encripted_ballot_sign"]
		# проверяем авторизован ли предлагаемый публичный ключ
		isAuthorized = False
		for a in self.authorized_keys:
			if a['public_key'] == pubKeyAsBytes:
				isAuthorized = True
				break
		if not isAuthorized:
			raise Exception("Agency. предложенный публичный ключ не авторизован")
		# проверяем подпись
		encripted_ballot_again = lib_blind.verefy(encripted_ballot_sign, e_pub_key)
		if encripted_ballot != encripted_ballot_again:
			raise Exception('Agency. подпись шифрованного бюлетеня не подходит. бюлетень отвергнут')
		# всё ок. публикуем . 
		self.published_encripted_ballots.append(payload)
		print('\nAgency. проверил подпись Шифрованного бюлетня-ОК, проверил что этот публичный в списке авторизованных')
		print('добавил шифрованный бюлетень в список опубликованных шифрованных бюлетней :-P у менянет выбора : все ок и яне понимаю что в нём.')

	def io_get_public_published_encripted_ballots(self):
		print('Agency. выдал список опубликованных бюлетней')
		return self.published_encripted_ballots
	

	def io_submit_secret_keys(self, mark_2, public_key_asBytes, secret_keys:bytes, secret_keys_signed ):
		e_pub_key = pickle.loads(public_key_asBytes)
		# проверяем авторизован ли юзер 
		isAuthorized = False
		for t in self.authorized_keys:
			if t['public_key'] == public_key_asBytes:
				isAuthorized = True
				break
		if not isAuthorized:
			raise Exception('Agency. вы не авторизованы')
		# проверяет подпись
		secret_keys_int = bytes_to_int(secret_keys)
		if secret_keys_int != lib_blind.verefy(secret_keys_signed, e_pub_key):
			raise Exception('Agency. проверка подписи секретных ключей не пройдена')
		# все ок - публикуем ключи
		self.secret_keys.append({
			"mark_2": mark_2,
			"public_key": public_key_asBytes,
			"secret_keys": secret_keys, 
			"secret_keys_sign": secret_keys_signed, 
		})
		print('Agency. проверил избирателя - он авторизован, проверил подпись им секретного ключа его шифрованного бюлетеня - ок, публикую секретный пароль от его бюлетеня')

	def io_get_public_secret_keys(self):
		print('Agency. Отдаю список опубликованных паролей от бюлетеней')
		return self.secret_keys

class Elector:
	"elector"

	# признак, которым представляемся Регистратору, вместо аутентификации
	mark_1 = None 
	# другая метка для связи двух документов : "шифрованный бюлетень" и "ключ для расшифровки бюлетеня" 
	# чтобы исключить необходимость полного перебора при проверке бюлетеней, 
	# это просто "какая то метка" для связи документов. 
	mark_2 = None
	public_key=None
	private_key=None
	signedHashOfPubKeyByRegistrator=None

	# важно. два числа. необходимы для матем расчёта подписи публ ключа так, 
	# чтобы регистратор не знал публ ключ 
	blinded=None
	blindInverse=None

	# загруженный публичный ключ регистратора
	rPubKey=None
	# знак, что наши ключи приняты как авторизованные для голосования
	is_keys_is_authorised = False

	def __init__(self, r:Registrator, a:Agency):
		self.mark_1 = random.randint(2, 2 ** 64)
		self.mark_2 = random.randint(2, 2 ** 64)
		self.r = r; self.a = a
	
	def register_new_keyPair(self):
		# содаём и регистрируем подписываем (только Публ) у регистратора "вслепую" пару ключей
		# делам новую пару ключей для этого голосования
		self.public_key, self.private_key = lib_blind.keygen(2 ** N)

		# вслепую подпишем эту пару в регистраторе, представившись "признаками" которые заранее согласованы с регисратором
		# готовим слепую подпись
		self.hashOfElectorPubKey = hash_of_pub_key(self.public_key)
		msg = self.hashOfElectorPubKey
		print('\nElector. hash of my pub_key is\n', msg)
		# загрузили себе публичный ключ
		if not self.rPubKey:
			keyInf = pickle.loads(self.r.io_get_pub_key())
			self.rPubKey = lib_blind.Key(keyInf[0], keyInf[1])
			assert self.rPubKey == self.r.public_key # TODO remove

		self.blinded, self.blindInverse    =    lib_blind.blind(msg, self.r.public_key )#

		signedBlind_int:int = self.r.io_elector_sign(self.mark_1, self.blinded)
		# тут "магия" мы расчитали подпись. она такая как будто регистратор видел наш публичный ключ, а он не видел.
		self.signedHashOfPubKeyByRegistrator = lib_blind.unblind(signedBlind_int, self.blindInverse, self.r.public_key) # 
				
		# на всякий случай проверим сами корректность подписи	
		msg_again = lib_blind.verefy(self.signedHashOfPubKeyByRegistrator, self.rPubKey) #
		if msg != msg_again:
			raise Exception('Elector. Error. шифрование не дало того эффекта который требуется для голосование. почему ? наверное ваш blind не комутативен')

		print('\nElector. регистратор подписал нам хеш публ ключа, не глядя. подпись=\n', self.signedHashOfPubKeyByRegistrator)
	
	def authorize_keys(self):
		"у Агенства акторизуем ключи и ждём, чтобы оно публично подтвердило, что ключи приняты"
		payload = (	pickle.dumps(self.public_key), 
			 		self.signedHashOfPubKeyByRegistrator )
		self.a.io_authorize_keys(payload)
		# ждём пока Агентство открыто для всех опубликует наши ключи , как авторизованные
		isPublished = False
		while True:
			if isPublished:
				break
			aut_keys = self.a.io_get_public_authorized_keys()
			for _, ak in enumerate(aut_keys):
				if pickle.dumps(self.public_key)==ak['public_key'] :
					# значит опубликовали... это сигнал, чтобы публиковать секреты
					isPublished = True
					break 
		self.is_keys_is_authorised = True
		
		# теперь мы авторизованы

	def vote(self, candidate):
		"создаём бюлетень, шифруем его новым, секретным ключём, и отправляем в агентство пачку шифров"
		print('Elector. создаём бюлетень, шифруем его новым, секретным ключём, и отправляем в агентство пачку шифров')
		# делаем шифро-ключ
		self.secret_keys = os.urandom(16)
		# шифровальщик
		aes = pyaes.AESModeOfOperationCTR(self.secret_keys)
		# шифруем наше волеизъявление симметрично ключём secret_keys
		encripted_ballot = aes.encrypt(candidate)
		encripted_ballot_int = bytes_to_int(encripted_ballot)
		# 
		encripted_ballot_sign = lib_blind.signature(encripted_ballot_int, self.private_key)
		payload = {
			# используем другую метку, не ту, которой авторизовывались на регистраторе
			"mark_2": self.mark_2,
			"public_key": pickle.dumps(self.public_key), 
			"encripted_ballot": encripted_ballot_int, 
			"encripted_ballot_sign":encripted_ballot_sign
		}
		self.a.io_submit_ballot(payload)
		
		# ждём пока опубликуют чтобы опубликовать ключи
		isPublished = False
		while True:
			if isPublished: break
			for _,a in enumerate(self.a.io_get_public_published_encripted_ballots()):
				if payload == a:
					isPublished = True
					break
		# теперь публикуем ключи для расшифровки
		secret_keys_int = bytes_to_int(self.secret_keys)
		secret_keys_signed = lib_blind.signature(secret_keys_int, self.private_key)
		self.a.io_submit_secret_keys(self.mark_2, pickle.dumps(self.public_key), self.secret_keys, secret_keys_signed)
		# todo убедиться что ключи опубликованы, иначе отправить еще раз 


		


##################################################################
r = Registrator() # там возникнет пара ключей "для конкретного голосования"
a = Agency(r)
e = Elector(r, a)

# согласовали признаки избирателя на этапе регистрации
r.MARKSLIST.append(e.mark_1)
r.do_public_elector_list()

# теперь началось голосование
print('теперь началось голосование')

e.register_new_keyPair()
e.authorize_keys()
e.vote("Candidate #2")


### проверка голосов
print('\nпроверка голосов! \nПубличная информация из которой ...\nЛЮБОЙ ЧУВЫРЛА может САМ посчитать результаты Тайных Цифровых выборов')
print('')
print('авторизованные ключи', )
pprint.pprint(a.io_get_public_authorized_keys())
print('\nшифрованные бюлетени')
pprint.pprint(a.io_get_public_published_encripted_ballots())
print('\nключи от шифрованных бюлетеней')
pprint.pprint(a.io_get_public_secret_keys())

list_authorised = a.io_get_public_authorized_keys()
list_encripted = a.io_get_public_published_encripted_ballots()
list_secret_keys = a.io_get_public_secret_keys()
def secret_get_by_mark(mark_2):
	for d in list_secret_keys:
		if d['mark_2'] == mark_2:
			return d['secret_keys']
def is_pubKeyAuthorized(pubkeyBytes):
	result = False
	for d in list_authorised:
		if d['public_key'] == pubkeyBytes:
			result = True
	return result
print()
for d in list_encripted:
	pubKeyAsByte = d['public_key']
	if not is_pubKeyAuthorized(pubKeyAsByte):
		continue
	mark_2 = d['mark_2']
	encripted_ballot = d['encripted_ballot']
	secret_key = secret_get_by_mark(mark_2)
	if secret_key and encripted_ballot:
		# расшифруем бюлетень
		aes = pyaes.AESModeOfOperationCTR(secret_key)
		# шифруем наше волеизъявление симметрично ключём secret_keys
		encripted_ballot_bytes = int_to_bytes(encripted_ballot)
		ballot = aes.decrypt(encripted_ballot_bytes)
		print('ГОЛОС ЗА КАНДИДАТА:', ballot.decode())
	