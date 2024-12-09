import rsa # TODO убрать зависимость
#from fractions import gcd
from random import randrange, random
from collections import namedtuple
from math import log, gcd
from binascii import hexlify, unhexlify

def is_prime(n, k=30):
	if n <= 3:
		return n == 2 or n == 3
	neg_one = n - 1

	s, d = 0, neg_one
	while not d & 1:
		s, d = s+1, d>>1
	assert 2 ** s * d == neg_one and d & 1

	for i in range(k):
		a = randrange(2, neg_one)
		x = pow(a, d, n)
		if x in (1, neg_one):
			continue
		for r in range(1, s):
			x = x ** 2 % n
			if x == 1:
				return False
			if x == neg_one:
				break
		else:
			return False
	return True

def randprime(N=10**8):
	p = 1
	while not is_prime(p):
		p = randrange(N)
	return p

def multinv(modulus, value):
	x, lastx = 0, 1
	a, b = modulus, value
	while b:
		a, q, b = b, a // b, a % b
		x, lastx = lastx - q * x, x
	result = (1 - lastx * modulus) // value
	if result < 0:
		result += modulus
	assert 0 <= result < modulus and value * result % modulus == 1
	return result

KeyPair = namedtuple('KeyPair', 'public private')
Key = namedtuple('Key', 'exponent modulus')

def keygen(N, public=None) -> KeyPair:
	prime1 = randprime(N)
	prime2 = randprime(N)
	composite = prime1 * prime2
	totient = (prime1 - 1) * (prime2 - 1)
	if public is None:
		while True:
			private = randrange(totient)
			if gcd(private, totient) == 1:
				break
		public = multinv(totient, private)
	else:
		private = multinv(totient, public)
	assert public * private % totient == gcd(public, totient) == gcd(private, totient) == 1
	assert pow(pow(1234567, public, composite), private, composite) == 1234567
	return KeyPair(Key(public, composite), Key(private, composite))

def signature(msg, privkey) -> int:
	coded = pow(int(msg), *privkey)% privkey[1]
	return coded

def blindingfactor(N) -> int:
	# b=random()*(N-1)
	# r=int(b)
	# while (gcd(r,N)!=1):
	#     r=r+1
	# return r
	for _ in range(1000):
		blind_r = rsa.randnum.randint(N - 1)
		if rsa.prime.are_relatively_prime(N, blind_r):
			return blind_r

def blind(msg,pubkey) -> int:
	inv=blindingfactor(pubkey[1]) # можно считать "иногда" , но "всегда" - надёжнее
	m=int(msg)
	blindmsg=(pow(inv,*pubkey)*m)% pubkey[1]
	return blindmsg, inv

def unblind(msg,r,pubkey) -> int:
	bsm=int(msg)
	ubsm=(bsm*multinv(pubkey[1],r))% pubkey[1]
	return ubsm

def verefy(msg:int, pubkey) -> int:
	return pow(int(msg),*pubkey)%pubkey[1]
