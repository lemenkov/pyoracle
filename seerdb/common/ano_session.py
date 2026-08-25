# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Bridge from the ANO negotiation result to the session cipher + MAC (#437).

After the negotiation (:mod:`seerdb.common.ano`) selects an encryption and a
data-integrity algorithm and the DH exchange yields a session key, these helpers
instantiate the per-session :class:`~seerdb.common.ano_cipher.AnoAESCipher` and
:class:`~seerdb.common.ano_mac.AnoMac`, and fold the auth key in after login.

Key material (re-expressed from go-ora's ``activateAlgorithm`` / ``SetKeyFolding``):
  * AES key   = ``session_key[:keysize]`` (16/24/32 for AES-128/192/256),
  * IV        = ``session_key[32:48]`` (the DH IV, ``session_key[32:64]``, [:16]),
  * MAC key   = the full ``session_key`` (the MAC takes its own prefix),
  * key fold  = ``session_key[i] ^= auth_key[i]`` after authentication.

Only the AES ciphers and SHA-2 MACs are wired up; the legacy RC4/DES and
MD5/SHA-1 algorithms are deferred (see the cipher/MAC modules).
"""

from seerdb.common.ano import ENCRYPTION_ALGO_IDS, INTEGRITY_ALGO_IDS
from seerdb.common.ano_cipher import AnoAESCipher, AnoCipherError
from seerdb.common.ano_mac import AnoMac, AnoMacError

# Selected encryption algorithm ID -> AES key length.
_AES_KEYSIZE = {
    ENCRYPTION_ALGO_IDS['AES128']: 16,
    ENCRYPTION_ALGO_IDS['AES192']: 24,
    ENCRYPTION_ALGO_IDS['AES256']: 32,
}
# Selected data-integrity algorithm ID -> hashlib name.
_INTEGRITY_NAME = {
    INTEGRITY_ALGO_IDS['SHA256']: 'SHA256',
    INTEGRITY_ALGO_IDS['SHA384']: 'SHA384',
    INTEGRITY_ALGO_IDS['SHA512']: 'SHA512',
}

_IV_OFFSET = 0x20  # the DH IV is session_key[32:64]


def make_cipher(AlgoId: int, SessionKey: bytes) -> AnoAESCipher | None:
    """Build the session cipher for the negotiated encryption algorithm.

    Returns ``None`` when no encryption was selected (algorithm 0). Raises for a
    non-AES algorithm (RC4/DES are not implemented).
    """
    if AlgoId == 0:
        return None
    KeySize = _AES_KEYSIZE.get(AlgoId)
    if KeySize is None:
        raise AnoCipherError(f'unsupported encryption algorithm id {AlgoId} (AES only)')
    return AnoAESCipher(SessionKey[:KeySize], SessionKey[_IV_OFFSET : _IV_OFFSET + 16])


def make_mac(AlgoId: int, SessionKey: bytes, ClientSide: bool = True) -> AnoMac | None:
    """Build the session MAC for the negotiated data-integrity algorithm.

    Returns ``None`` when no integrity was selected (algorithm 0). Raises for a
    non-SHA-2 algorithm (MD5/SHA-1 are not implemented).
    """
    if AlgoId == 0:
        return None
    Name = _INTEGRITY_NAME.get(AlgoId)
    if Name is None:
        raise AnoMacError(f'unsupported integrity algorithm id {AlgoId} (SHA-2 only)')
    return AnoMac(
        SessionKey,
        SessionKey[_IV_OFFSET : _IV_OFFSET + 32],
        Name,
        ClientSide=ClientSide,
    )


def fold_key(SessionKey: bytes, AuthKey: bytes) -> bytes:
    """XOR the authentication session key into the negotiation session key.

    Applied after login; the cipher + MAC are then rebuilt from the result.
    """
    Folded = bytearray(SessionKey)
    for I in range(min(len(Folded), len(AuthKey))):
        Folded[I] ^= AuthKey[I]
    return bytes(Folded)
