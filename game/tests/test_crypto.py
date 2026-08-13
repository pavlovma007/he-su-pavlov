import lib_blind


def test_blind_sign_roundtrip():
    pub, priv = lib_blind.keygen(2048)
    msg = b"hello world"
    blinded, r = lib_blind.blind(msg, pub)
    sig = pow(blinded, priv.d, priv.n)          # регистратор подписывает вслепую
    un = lib_blind.unblind(sig, r, pub)
    assert lib_blind.verify(un, pub) == lib_blind.hash_message_to_int(msg)


def test_direct_signature_verify():
    pub, priv = lib_blind.keygen(2048)
    msg = b"vote data"
    sig = lib_blind.signature(msg, priv)
    assert lib_blind.verify(sig, pub) == lib_blind.hash_message_to_int(msg)


def test_import_export_roundtrip():
    pub, priv = lib_blind.keygen(2048)
    pem = lib_blind.export_public_key(pub)
    assert lib_blind.import_public_key(pem).n == pub.n
    pem_priv = lib_blind.export_private_key(priv)
    assert lib_blind.import_private_key(pem_priv).d == priv.d
