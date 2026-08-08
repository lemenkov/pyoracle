# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

import sys
from binascii import hexlify, unhexlify
from hashlib import md5, pbkdf2_hmac, sha1, sha512
from secrets import token_bytes

from Crypto.Cipher import AES, DES


# O3LOGON (DES): the pre-10g thin authenticator (TTI_3LOGA 0x52 -> TTI_3LOGON
# 0x51). This is the path the Oracle JDBC thin driver uses against Oracle 9i —
# and now pyoracle, gated on the negotiated field version (#90). (10g+ thin
# clients instead use OSESSKEY/0x76 with an AES session key over the same DES
# verifier; that's the o5logon path below. OCI/sqlplus uses OSESSKEY even on
# 9i, which is why the OCI capture first misled us — the *thin* 9i path is
# O3LOGON.) The flow: the server returns AUTH_SESSKEY (an 8-byte session key
# DES-encrypted under the account's DES verifier); we decrypt it with the
# verifier (`KeySess`, from des_verifier) to recover the plaintext session key,
# then DES-encrypt the zero-padded password under it to get AUTH_PASSWORD.
# VALIDATED 2026-06-17 against a real JDBC-thin -> 9.2.0.4 capture: verifier
# E242A414206906CB + sesskey 83B9CF7F17B84F76 reproduces AUTH_PASSWORD
# F18CC9AF1CE5A7E8 byte-for-byte (see tests/test_crypto.py).
def o3logon(Sess: bytes, KeySess: bytes, Password: bytes) -> tuple[bytes, bytes, bytes]:
    IVec = bytes(8)

    cipher = DES.new(KeySess[0:8], DES.MODE_CBC, IVec)
    SrvSess = cipher.decrypt(Sess)

    N = (8 - (len(Password) % 8)) % 8
    CliPass = Password + bytes(N)

    cipher = DES.new(SrvSess[0:8], DES.MODE_CBC, IVec)
    AuthPass = cipher.encrypt(CliPass)
    return (AuthPass, b'', b'')


def des_verifier(User: bytes, Password: bytes) -> bytes:
    # The classic Oracle DES password verifier (pre-11g / O3LOGON): the
    # uppercased UTF-16BE username+password, DES-CBC encrypted under the fixed
    # key 0x0123456789ABCDEF, then DES-CBC encrypted again under the last 8
    # bytes of that — the verifier is the last 8 bytes of the second pass.
    IVec = bytes(8)
    CliPass = norm(User + Password)
    Inter = DES.new(unhexlify('0123456789ABCDEF'), DES.MODE_CBC, IVec).encrypt(CliPass)[
        -8:
    ]
    return DES.new(Inter, DES.MODE_CBC, IVec).encrypt(CliPass)[-8:]


def o5logon(
    Sess: bytes,
    Salt: bytes | None,
    DerivedSalt: bytes | None,
    User: bytes,
    Password: bytes,
) -> tuple[bytes, bytes, bytes, int, bytes]:
    # 10g (#47): an AES session key but NO verifier salt — the account has only
    # the legacy DES verifier. The AES key is that 8-byte verifier zero-padded to
    # 16; the rest is the salt-less 128-bit path (XOR cat_key + md5 ConnKey).
    if (Salt is None) and (DerivedSalt is None):
        KeySess = des_verifier(User, Password) + bytes(8)
        return o5logon0(Sess, KeySess, None, None, Password, 128)
    # 128 bits
    if (Salt is None) and (DerivedSalt is not None):
        IVec = bytes(8)
        CliPass = norm(User + Password)

        cipher = DES.new(unhexlify('0123456789ABCDEF'), DES.MODE_CBC, IVec)
        Rest1 = cipher.encrypt(CliPass)

        cipher = DES.new(Rest1[:-8], DES.MODE_CBC, IVec)
        Rest2 = cipher.encrypt(CliPass)

        KeySess = Rest2[:-8] + bytes(8)
        return o5logon0(Sess, KeySess, DerivedSalt, None, Password, 128)
    # 192 bits
    elif (Salt is not None) and (DerivedSalt is None):
        KeySess = sha1(Password + Salt).digest() + bytes(4)
        return o5logon0(Sess, KeySess, DerivedSalt, None, Password, 192)
    # 256 bits
    elif (Salt is not None) and (DerivedSalt is not None):
        Data = pbkdf2_hmac('sha512', Password, Salt + b'AUTH_PBKDF2_SPEEDY_KEY', 4096)
        KeySess = sha512(Data + Salt).digest()[0:32]
        DerivedKey = token_bytes(16) + Data
        return o5logon0(Sess, KeySess, DerivedSalt, DerivedKey, Password, 256)
    # something else we don't know anything about it
    else:
        raise Exception('unsupported key scheme')


def o5logon0(
    Sess: bytes,
    KeySess: bytes,
    DerivedSalt: bytes | None,
    DerivedKey: bytes | None,
    Password: bytes,
    Bits: int,
) -> tuple[bytes, bytes, bytes, int, bytes]:
    IVec = bytes(16)

    cipher = AES.new(KeySess, AES.MODE_CBC, IVec)
    SrvSess = cipher.decrypt(Sess)

    CliSess = (
        pad2(token_bytes(40), 8)
        if SrvSess[40:] == pad2(b'', 8)
        else token_bytes(len(SrvSess))
    )

    cipher = AES.new(KeySess, AES.MODE_CBC, IVec)
    AuthSess = cipher.encrypt(CliSess)

    CatKey = cat_key(SrvSess, CliSess, DerivedSalt, Bits)

    ConnKey = conn_key(CatKey, DerivedSalt, Bits)

    AuthPass = encrypt_password(ConnKey, Password)

    SpeedyKey = b''
    SpeedyKeyInd = 0
    if DerivedKey is not None:
        cipher = AES.new(ConnKey, AES.MODE_CBC, IVec)
        SpeedyKey = cipher.encrypt(DerivedKey)
        SpeedyKeyInd = 1

    return (AuthPass, AuthSess, SpeedyKey, SpeedyKeyInd, ConnKey)


def encrypt_password(ConnKey: bytes, Password: bytes) -> bytes:
    # AES-CBC (IV = 0) of the padded password under the session ConnKey — the
    # exact transform o5logon uses for AUTH_PASSWORD. Factored out so the
    # changepassword flow can reuse it for AUTH_NEWPASSWORD with the session key
    # established at login (#21). pad1 prepends a fixed 16-byte block the server
    # discards, so a fresh random prefix (as oracledb sends) is not required.
    cipher = AES.new(ConnKey, AES.MODE_CBC, bytes(16))
    return cipher.encrypt(pad1(Password))


def validate(Resp: bytes, Key: bytes) -> bool:
    IVec = bytes(16)
    cipher = AES.new(Key, AES.MODE_CBC, IVec)
    Haystack = cipher.decrypt(Resp)

    Needle = b'SERVER_TO_CLIENT'
    return Needle in Haystack


##
## Private funs
##


def norm(Bytes: bytes) -> bytes:
    Data = [
        item
        for sublist in map(lambda x: norm_utf8_char(ord(x)), Bytes.decode('utf-8'))
        for item in sublist
    ]
    N = (8 - (len(Data) % 8)) % 8
    return bytes(Data) + bytes(N)


def norm_utf8_char(C: int) -> tuple[int, int]:
    if C > 255:
        return (0, 63)
    elif (97 <= C) and (C <= 122):
        return (0, C - 32)
    else:
        return (0, C)


def pad1(Bytes: bytes) -> bytes:
    Remainder = 16 - (len(Bytes) % 16)
    return pad2(b'', 16) + pad2(Bytes, Remainder)


def pad2(Bytes: bytes, PaddingSymbol: int) -> bytes:
    return Bytes + bytes([PaddingSymbol for x in range(PaddingSymbol)])


def cat_key(X: bytes, Y: bytes, DerivedSalt: bytes | None, Bits: int) -> bytes:
    if Bits == 128:
        if DerivedSalt is None:
            return bin_xor(X[16:32], Y[16:32])
        else:
            return Y[0:16] + X[0:16]
    elif Bits == 192:
        if DerivedSalt is None:
            return bin_xor(X[16:40], Y[16:40])
        else:
            raise Exception('unsupported key size', 192)
    elif Bits == 256:
        return Y + X
    else:
        raise Exception('unsupported key size', Bits)


def bin_xor(X: bytes, Y: bytes) -> bytes:
    p = int.from_bytes(X, sys.byteorder)
    q = int.from_bytes(Y, sys.byteorder)
    return (p ^ q).to_bytes(len(X), sys.byteorder)


def conn_key(Data: bytes, DerivedSalt: bytes | None, Bits: int) -> bytes:
    if Bits == 128:
        if DerivedSalt is None:
            return md5(Data).digest()
        else:
            return pbkdf2_hmac('sha512', hexlify(Data), DerivedSalt, 3)
    elif Bits == 192:
        if DerivedSalt is None:
            return md5(Data[0:16]).digest() + md5(Data[16:24]).digest()[0:8]
        else:
            raise Exception('unsupported key size', 192)
    elif Bits == 256:
        # AES-256 needs a 32-byte key; pbkdf2_hmac('sha512', ...) defaults to the
        # full 64-byte digest, so request 32 explicitly. (SDER iteration count
        # is 3, matching the server's AUTH_PBKDF2_SDER_COUNT.) The PBKDF2
        # password must be the UPPERCASE hex of the key material — oracledb uses
        # temp_key.hex().upper(); lowercase hex yields a different ConnKey and
        # the server rejects AUTH_PASSWORD with ORA-01017.
        if DerivedSalt is None:
            raise ValueError('AES-256 connection key requires a PBKDF2 salt')
        return pbkdf2_hmac('sha512', hexlify(Data).upper(), DerivedSalt, 3, dklen=32)
    else:
        raise Exception('unsupported key size', Bits)
