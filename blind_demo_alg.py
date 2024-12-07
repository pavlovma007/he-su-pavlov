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

def keygen(N, public=None):
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

def signature(msg, privkey):
    f=open('_signedfile','w')
    coded = pow(int(msg), *privkey)% privkey[1]
    f.write(str(coded))
    return str(coded)

def blindingfactor(N):
    # b=random()*(N-1)
    # r=int(b)
    # while (gcd(r,N)!=1):
    #     r=r+1
    # return r
    for _ in range(1000):
        blind_r = rsa.randnum.randint(N - 1)
        if rsa.prime.are_relatively_prime(N, blind_r):
            return blind_r

def blind(msg,pubkey):
    f=open('_blindmsg','w')
    r=blindingfactor(pubkey[1]) # можно считать "иногда" , но "всегда" - надёжнее
    m=int(msg)
    blindmsg=(pow(r,*pubkey)*m)% pubkey[1]
    print( "Blinded Message "+str(blindmsg))
    f.write(str(blindmsg))
    return r

def unblind(msg,r,pubkey):
	f=open('_unblindsigned','w')
	bsm=int(msg)
	ubsm=(bsm*multinv(pubkey[1],r))% pubkey[1]
	print( "Unblinded Signed Message "+str(ubsm))
	f.write(str(ubsm))

def verefy(msg,pubkey):
    print( "Message After Verification "+str(pow(int(msg),*pubkey)%pubkey[1]))

if __name__ == '__main__':
    # Alice key pair
    pubkey, privkey = keygen(2 ** 2048)

    
    # bob wants to send msg after blinding it
    f=open('msg')
    msg=f.read()
    msg=msg.rstrip()
    print( "Original Message "+str(msg))
    r=blind(msg,pubkey)
    #print('r=', r) # is a second part of blind 


    #Alice receives the blind message and signs it
    bf=open('_blindmsg')
    m=bf.read()
    sig1 = signature(m, privkey)
    print( "Blinded Signed Message "+sig1)    

    #Bob recieves the signed message and unblinds it
    h=open('_signedfile')
    signedmsg=h.read()
    unblind(signedmsg,r,pubkey)
    
    #verifier verefis the message
    i=open('_unblindsigned')
    ubsignedmsg=i.read()
    verefy(ubsignedmsg,pubkey)
    # as result : Alice not kwnow what she sign, bob send it, and verify is correct



    # just sign 
    justSign = signature(msg, privkey)
    print('Just simple sign EQ UN blinded signed ', justSign)

'''
FIRST RUN 
Original Message 123461273647812341278364871263487612873461782634786
Blinded Message 121173258031917732355019731363890985886452909496494798939313717150482864959909286288356565921673573394146400135129619902388495782479740996192910620465752104538994365705676396590539351002584085788136812284648424929371075116473818154267064237312235390801812911203032426911417817403810151639404694768657531011078
Blinded Signed Message 79930724707936773710931107478246916088429079189415725323037602103620820240755110654212486063678461434055741105236842032175426722018039150040564920311592216883220870450105226359631665833037710180542051067346283836652567446943331105392698270181808820850795724459969898231477732505411527356948742138398722446610
Unblinded Signed Message 135211806768563260517909992712751221107996421423732387026115852896553327609413138401842837887882786549580263981932830464616665559678100975550420431519924928335580536348086765198034991087605340157487189430034772972013244538020467933686837510706432022729501135482506110612536331214889355639211526490526139797428
Message After Verification 123461273647812341278364871263487612873461782634786
Just simple sign EQ UN blinded signed  135211806768563260517909992712751221107996421423732387026115852896553327609413138401842837887882786549580263981932830464616665559678100975550420431519924928335580536348086765198034991087605340157487189430034772972013244538020467933686837510706432022729501135482506110612536331214889355639211526490526139797428

SECOND RUN
Original Message 123461273647812341278364871263487612873461782634786
Blinded Message 14085225238561156408871990517324530423657067005676610980544674349496664159406363035209442933244521485766092568786819629157394221933768071968208830382564812179274474381268051219032018085798390046175411077874962408990043372502333927682219784892795021829055076226140798507076555945793746177058762384055342109898
Blinded Signed Message 91959304556814946803879498983943979621803971430832990010498573661500119913353894605924303168646778861398436198856494044203139192962574875706637856892179654732536143814228242386086798340692477765661742724758427098542281156520372404326532931224541840694470421510272564402461737293191829748320409729855047566
Unblinded Signed Message 5074095975657998188747006501931095970905033146323195008787952743321522389611931063126581549884237987916229819170354069881063873604391768853660380434561923039680775959757997860856562641083830470318697273525441758663037095215156752647318936852787546910228033580499112120729026046557189515378885343581743142894
Message After Verification 123461273647812341278364871263487612873461782634786
Just simple sign EQ UN blinded signed  5074095975657998188747006501931095970905033146323195008787952743321522389611931063126581549884237987916229819170354069881063873604391768853660380434561923039680775959757997860856562641083830470318697273525441758663037095215156752647318936852787546910228033580499112120729026046557189515378885343581743142894
'''