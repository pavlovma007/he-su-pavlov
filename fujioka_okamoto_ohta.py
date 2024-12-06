# $ pip install rsa
# sudo python3.8 -m pip install pyaes
import rsa, os, random
import pyaes
import math
from rsa import VerificationError, PublicKey

def bytes_to_int(b):
	return int.from_bytes(b, byteorder='little')
def int_to_bytes(i):
	length = math.ceil(i.bit_length() / 8)
	return i.to_bytes(length, byteorder='little')
	
################################ Registrator 

MARKSLIST = []
class Registrator:
	public_key = None
	private_key = None

	def generate_keys(self):
		self.public_key, self.private_key = rsa.newkeys(512)
		print('Registrator сформировал свои ключи')
		
	def __init__(self):
		self.generate_keys()
		#print(self.public_key, self.public_key.blind, self.public_key.unblind)
	
	# io
	def get_raw_ca_public_key(self):
		print('Registrator. сказал свой публичный ключ')
		return self.public_key
		
	# шаг 3 V: удостоверяется, что бюллетень действительный и принадлежит легитимному и не голосовавшему избирателю 
	# (TODO как проверяет ? - второй вопрос. например по публичному ключу и подпись)
	# v_pub_key = None, signed_blind_signed_ballot=None всегда. ибо нефиг
	# mark - voter сам придумал эту метку и при регистрации сообщил её регистратору. её и публикуют в списках избирателей.
	def sign_voter_ballot(self, v_pub_key, blind_signed_ballot, signed_blind_signed_ballot, mark):
		if mark not in MARKSLIST:
			return 
		# try:
			# rsa.verify(
				# str(blind_signed_ballot).encode(), 
				# signed_blind_signed_ballot, 
				# v_pub_key
			# )
		# except VerificationError:
			# raise Exception('Verify error')
			# return (None, {'message': 'Verify error'})
		
		# # ПРОВЕРКА ПРОЙДЕНА; о чём она? что именно voter подписал blind_signed_ballot, получив signed_blind_signed_ballot 
		# # т.е. эта пара соответствует данному pub_key
		# "TODO глупо тут предоставлять регистратору свой pub_key. лучше его вовсе не передавать. пусть он их просто подпишет"
		
		#print(f'Registrator маскирующим шифрованием выдал подпись. мне известно: v_pub_key={v_pub_key} blind_signed_ballot={blind_signed_ballot} signed_blind_signed_ballot={signed_blind_signed_ballot}')
		return rsa.sign(str(blind_signed_ballot).encode(), self.private_key, 'SHA-1')
		
r = Registrator()


################################ VoteCounter

class VoteCounter:
	# этим ключем проверяем голоса
	voter_public_key = None 
	# шифрованные бюлетени голосующих
	encrypted_votes = []
	# расшифрованные бюлетени
	decrypted_votes = []
	
	def __init__(self, r):
		self.voter_public_key = r.get_raw_ca_public_key()
		
	# TODO hidden_encrypted_ballot не нужен. передаю None специально, чтобы не было сомнений. убрать
	# io
	def accept_vote_from_voter(self, mark, encrypted_ballot, hidden_encrypted_ballot):
		"принять голос. TODO по идее надо бы проверить подпись. ради этого всё и делалось"

		#voter_public_key = get_raw_registrator_public_key()
		#is_ok = rsa.verify(encrypted_ballot, hidden_encrypted_ballot, self.voter_public_key)
		#if not is_ok:
		#	return False

		for index, elem in enumerate(self.encrypted_votes):
			if elem['mark'] == mark:
				# чел заменил свой голос - новый бюлетень
				self.encrypted_votes[index] = {'mark': mark,
										  'encrypted_ballot': encrypted_ballot ,
										  #'hidden_encrypted_ballot': list(hidden_encrypted_ballot)
										  }
				break
		else:
			# новый бюлетень в копилку 
			self.encrypted_votes.append({'mark': mark,
									'encrypted_ballot': encrypted_ballot,
									#'hidden_encrypted_ballot': list(hidden_encrypted_ballot)
									})
		print('VoteCounter. encrypted_votes=', self.encrypted_votes)
		return True


	def public_final_set_ballot(self):
		print('')
		print('VoteCounter. encrypted_votes=', self.encrypted_votes)
		print('VoteCounter. decrypted_votes=', self.decrypted_votes)
		print('')
	# io
	def accept_secret_key_from_voter(self, mark, secret_key):
		for index, elem in enumerate(self.encrypted_votes):
			if elem['mark'] == mark:
				encrypted_ballot = elem['encrypted_ballot']
				break
		aes = pyaes.AESModeOfOperationCTR(secret_key)
		decrypted_ballot = aes.decrypt(encrypted_ballot)
		print('decrypted_ballot=', decrypted_ballot)

		for index, elem in enumerate(self.decrypted_votes):
			if elem['mark'] == mark:
				self.decrypted_votes[index] = {'mark': mark,
										  'secret_key': secret_key,
										  'ballot': decrypted_ballot.decode('utf-8')} # str(decrypted_ballot)
				break
		else:
			self.decrypted_votes.append({'mark': mark,
									'secret_key': list(secret_key),
									'ballot': decrypted_ballot.decode('utf-8')})

		print('VoteCounter. decrypted_votes=', self.decrypted_votes)
		return True

voteCounter = VoteCounter(r)

###############################  Voter 

class Voter:
	user_id = '100500'
	public_key, private_key = rsa.newkeys(512)
	choises = ["Candidate1", "Candidate2", "Candidate3"]
	votes = None
	# ключ для симметричного шифрования бюлетеней
	secret_keys = None
	# симметрично шифрованные белетени
	encrypted_ballots = None
	# два длинных числа, сразу два, список
	blind_signed_ballots = None 
	signed_blind_signed_ballots = None
	registrator_signed_ballots = None
	# кеш публичного ключа регистратора, чтобы не запрашивать два раза
	registrator_public_key = None
	# просто случайная "уникальная" метка, выдуманная для упрощения сопоставления бюлетеней и ключей... наверное её стоит убрать. т.к. она вероятно не уникальна
	marks = None
	# пометка, что голоса отправлены на подсчёт
	is_sent_to_vote_counter = False
	# пометка что контрольный ключ отправлена (который позволяет прочитать бюлетень)
	is_secret_key_sent = False
	
	def __init__(self):
		pass
		self.get_secret_key_2()
		
		self.marks = random.randint(2, 2 ** 64)
		
	def vote_1(self, choseIndex):
		self.votes = self.choises[choseIndex]
		
	def get_secret_key_2(self):
		self.secret_keys = os.urandom(16)
		return self.secret_keys
	
	def encrypt_ballot_3(self):
		aes = pyaes.AESModeOfOperationCTR(self.secret_keys)
		# шифруем наше волеизъявление симметрично ключём secret_keys
		ciphertext = aes.encrypt(self.votes)
		self.encrypted_ballots = ciphertext
		#print('Voter. encrypted_ballot сформирован')
		#print(self.encrypted_ballots)
	
	def blind_sign_ballot_4(self, r:Registrator):
		if not self.registrator_public_key:
			self.registrator_public_key = r.get_raw_ca_public_key()
		# от всего шифрованного бюлетеня делаем blind всего одного первого байта. 
		# получаем два длинных числа, сразу два
		self.blind_signed_ballots = self.registrator_public_key.blind(self.encrypted_ballots[0]) # https://stuvel.eu/python-rsa-doc/reference.html#rsa.PublicKey.blind
		#print('Voter. blind_signed_ballot=', str(list(self.blind_signed_ballots)))
		'тут потенциально может быть ситуация что много голосующих , а в байте 256 и пары начнут повторятся'
		"там возможно внутри blind рандомизатор, но надо тест писать и возможно передавать более длинный кусок шифра для blind"
	
	# как выяснилось этот этап вообще не нужен. даже вреден. т.к. убрал в других местах "закладки" злых людей. 
	# без него все хорошо работает, поэтому добавил тут сразу return 
	def sign_blind_signed_ballot_5(self):
		return 
		# соединяем оба этих больших числа и подписываем их своим приватным
		self.signed_blind_signed_ballots = rsa.sign( str(self.blind_signed_ballots).encode(), 
														self.private_key, 'SHA-1')
		#print('signed_blind_signed_ballot',  str(list(self.signed_blind_signed_ballots)))
		"TODO тут потенциально ошибка. второе число не должно покидать voter по идее, только первое. "
		"надо перечитать описание алгоритма"
	
	def send_to_registrator_6(self, r:Registrator):
		if not self.registrator_public_key:
			self.registrator_public_key = r.get_raw_ca_public_key()
			
		unblinded = self.registrator_public_key.unblind( # https://stuvel.eu/python-rsa-doc/reference.html#rsa.PublicKey.unblind
			bytes_to_int(
				r.sign_voter_ballot(None, #self.get_voter_public_key()
									self.blind_signed_ballots, 
									None,  # self.signed_blind_signed_ballots
									self.marks)  
			), self.blind_signed_ballots[1]   )
		print('6', unblinded)
		# unblinded это нам регистратор, подписал наши бюлетени "не глядя"
		self.registrator_signed_ballots = unblinded
		#print('Voter. registrator_signed_ballot=', str(self.registrator_signed_ballots))
	
	# надо такое запретить, ибо нефиг - добавил return в начало
	# io
	def get_voter_public_key(self):
		return
		print('Voter. Сказал свой публичный ключ')
		return self.public_key
	
	def send_to_vote_counter_7(self, vc):
		## TODO проверка ЦП
		#voter_public_key = r.public_key
		#print('TODO', self.encrypted_ballots, self.registrator_signed_ballots)
		#is_ok = rsa.verify(self.encrypted_ballots, int_to_bytes(self.registrator_signed_ballots), voter_public_key)
		#if not is_ok:
		#	return False		
		
		
		# отсылаем свой голос на подсчёт голосов
		is_ok = vc.accept_vote_from_voter(self.marks, self.encrypted_ballots,
							None #int_to_bytes(self.registrator_signed_ballots)
							)
		if is_ok:
			self.is_sent_to_vote_counter = True
			return 'OK'
		else:
			raise Exception("Vote counter error")
	# io
	def send_secret_key_to_voteCounter(self, voteCounter):
		is_ok = voteCounter.accept_secret_key_from_voter(self.marks, self.secret_keys)
		if is_ok:
			self.is_secret_key_sent = True

v = Voter()
# регистрация 
print('РЕГИСТРАЦИЯ')
MARKSLIST.append(v.marks)
print('избираели:', MARKSLIST)


#голосование
print('НАЧАЛОСЬ ГОЛОСОВАНИЕ')
v.vote_1(1)
v.get_secret_key_2()
v.encrypt_ballot_3()
v.blind_sign_ballot_4(r)
v.sign_blind_signed_ballot_5()
v.send_to_registrator_6(r)

# отправка вычисленного но шифрованного бюлетеня
v.send_to_vote_counter_7(voteCounter)

# дата окончания голосования настала, voteCounter публикует шифрованные бюлетени, которые он получил. 
voteCounter.public_final_set_ballot()

# наступила дата когда начинаем расшифровывать бюлетени. Voter публикует пару своих секретных ключиков.
# разрешаем всем людям расшифровать бюлетени
v.send_secret_key_to_voteCounter(voteCounter)


