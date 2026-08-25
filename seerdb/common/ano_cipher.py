# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Oracle native network encryption — the AES-CBC cipher (#437, phase 3).

Once the ANO negotiation (see :mod:`seerdb.common.ano`) selects AES and the
Diffie-Hellman exchange yields a session key + IV, each TTC data packet is
encrypted with this cipher before framing. The construction (re-expressed from
go-ora's ``OracleNetworkCBCCryptor``, MIT) is plain AES-CBC with an Oracle
padding twist:

  * the plaintext is zero-padded up to the 16-byte block size (no padding block
    is added when it is already aligned), and
  * a single trailing byte holding ``padding_count + 1`` (so 1..16) is appended
    *after* the ciphertext.

The IV is fixed per cipher instance (AES does not chain the IV across packets in
this scheme — unlike the legacy DES path, which is intentionally not implemented
here). AES-128/192/256 are selected purely by the key length (16/24/32 bytes).

The wire behaviour is validated end-to-end against a real server in a later
phase; here it is exercised by round-trips and a NIST AES-CBC known-answer test.
"""

from Crypto.Cipher import AES

BLOCK_SIZE = 16


class AnoCipherError(Exception):
    """Malformed ANO ciphertext (bad length or padding marker)."""


class AnoAESCipher:
    """Oracle native AES-CBC encryption for ANO data packets."""

    def __init__(self, Key: bytes, Iv: bytes):
        if len(Key) not in (16, 24, 32):
            raise AnoCipherError(f'AES key must be 16/24/32 bytes, got {len(Key)}')
        if len(Iv) < BLOCK_SIZE:
            raise AnoCipherError('AES IV must be at least 16 bytes')
        self._key = Key
        self._iv = Iv[:BLOCK_SIZE]

    def encrypt(self, Data: bytes) -> bytes:
        # Zero-pad up to the block size (0 padding when already aligned), then
        # append (padding + 1) as the trailing marker byte.
        Padding = (BLOCK_SIZE - len(Data) % BLOCK_SIZE) % BLOCK_SIZE
        Cipher = AES.new(self._key, AES.MODE_CBC, self._iv)
        CipherText = Cipher.encrypt(Data + bytes(Padding))
        return CipherText + bytes([Padding + 1])

    def decrypt(self, Data: bytes) -> bytes:
        if not Data:
            raise AnoCipherError('empty ANO ciphertext')
        Marker = Data[-1]
        CipherText = Data[:-1]
        if len(CipherText) % BLOCK_SIZE != 0:
            raise AnoCipherError('ANO ciphertext is not a whole number of blocks')
        if not 1 <= Marker <= BLOCK_SIZE:
            raise AnoCipherError(f'bad ANO padding marker {Marker}')
        Cipher = AES.new(self._key, AES.MODE_CBC, self._iv)
        Plain = Cipher.decrypt(CipherText)
        # Marker is padding_count + 1; strip the padding_count trailing bytes.
        return Plain[: len(Plain) - (Marker - 1)]
