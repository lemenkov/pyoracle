# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

from Crypto.Cipher import AES
from Crypto.Cipher import DES
from binascii import hexlify
from binascii import unhexlify
from hashlib import md5
from hashlib import pbkdf2_hmac
from hashlib import sha1
from hashlib import sha512
from secrets import token_bytes
import sys

# O3LOGON (DES) is the pre-11g authenticator. XE 11g negotiates O5LOGON, so
# this path stays untested against our testbed; kept for older servers.
def o3logon(Sess: bytes, KeySess: bytes, Password: bytes) -> tuple[bytes, bytes, bytes]:
    IVec = bytes(8)

    cipher = DES.new(KeySess[0:8], DES.MODE_CBC, IVec)
    SrvSess = cipher.decrypt(Sess)

    N = (8 - (len(Password) % 8 )) % 8
    CliPass = Password + bytes(N)

    cipher = DES.new(SrvSess[0:8], DES.MODE_CBC, IVec)
    AuthPass = cipher.encrypt(CliPass)
    return (AuthPass, b"", b"")

def o5logon(Sess: bytes, Salt: bytes | None, DerivedSalt: bytes | None, User: bytes, Password: bytes) -> tuple[bytes, bytes, bytes, int, bytes]:
    # 128 bits
    if (Salt is None) and (DerivedSalt is not None):
        IVec = bytes(8)
        CliPass = norm(User + Password)

        cipher = DES.new(unhexlify("0123456789ABCDEF"), DES.MODE_CBC, IVec)
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
        Data = pbkdf2_hmac('sha512', Password, Salt + b"AUTH_PBKDF2_SPEEDY_KEY", 4096)
        KeySess = sha512(Data + Salt).digest()[0:32]
        DerivedKey = token_bytes(16) + Data
        return o5logon0(Sess, KeySess, DerivedSalt, DerivedKey, Password, 256)
    # something else we don't know anything about it
    else:
        raise Exception("unsupported key scheme")

def o5logon0(Sess: bytes, KeySess: bytes, DerivedSalt: bytes | None, DerivedKey: bytes | None, Password: bytes, Bits: int) -> tuple[bytes, bytes, bytes, int, bytes]:
    IVec = bytes(16)

    cipher = AES.new(KeySess, AES.MODE_CBC, IVec)
    SrvSess = cipher.decrypt(Sess)

    CliSess = pad2(token_bytes(40), 8) if SrvSess[40:] == pad2(b"", 8) else token_bytes(len(SrvSess))

    # The 256-bit (12c+ AES) scheme PKCS#7-pads the client session key and the
    # speedy key with a full extra 16-byte block before encryption, and the
    # server validates that padding (omitting it gives ORA-01017). The combined
    # key still uses the UNPADDED CliSess. The 192-bit (11g) path keeps its
    # existing 0x08-padded CliSess and sends no speedy key, so it is unaffected.
    cipher = AES.new(KeySess, AES.MODE_CBC, IVec)
    AuthSess = cipher.encrypt(pad2(CliSess, 16) if Bits == 256 else CliSess)

    CatKey = cat_key(SrvSess, CliSess, DerivedSalt, Bits)

    ConnKey = conn_key(CatKey, DerivedSalt, Bits)

    cipher = AES.new(ConnKey, AES.MODE_CBC, IVec)
    AuthPass = cipher.encrypt(pad1(Password))

    SpeedyKey = b""
    SpeedyKeyInd = 0
    if DerivedKey is not None:
        cipher = AES.new(ConnKey, AES.MODE_CBC, IVec)
        SpeedyKey = cipher.encrypt(pad2(DerivedKey, 16))
        SpeedyKeyInd = 1

    return (AuthPass, AuthSess, SpeedyKey, SpeedyKeyInd, ConnKey)

def validate(Resp: bytes, Key: bytes) -> bool:
    IVec = bytes(16)
    cipher = AES.new(Key, AES.MODE_CBC, IVec)
    Haystack = cipher.decrypt(Resp)

    Needle = b"SERVER_TO_CLIENT"
    return Needle in Haystack

##
## Private funs
##

def norm(Bytes: bytes) -> bytes:
    Data = [item for sublist in map(lambda x: norm_utf8_char(ord(x)), Bytes.decode('utf-8')) for item in sublist]
    N = (8 - (len(Data) % 8 )) % 8
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
    return pad2(b"", 16) + pad2(Bytes, Remainder)

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
            raise Exception("unsupported key size", 192)
    elif Bits == 256:
        return Y + X
    else:
        raise Exception("unsupported key size", Bits)

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
            raise Exception("unsupported key size", 192)
    elif Bits == 256:
        # AES-256 needs a 32-byte key; pbkdf2_hmac('sha512', ...) defaults to the
        # full 64-byte digest, so request 32 explicitly. (SDER iteration count
        # is 3, matching the server's AUTH_PBKDF2_SDER_COUNT.)
        return pbkdf2_hmac('sha512', hexlify(Data), DerivedSalt, 3, dklen=32)
    else:
        raise Exception("unsupported key size", Bits)
