# IMPORT
from kryptoon import __internal__ as _internal # type: ignore
import os

# MAIN
class ChaCha20Poly1305:
    def __init__(self, secretkey: bytes) -> None:
        self.secretkey = secretkey
        #
        return
    #
    def encrypt(
            self,
            buffer: bytes,
            *,
            nonce: bytes | None = None,
            aad: bytes | None = None,
            append: bool = True
        ) -> bytes:
        #
        nonce = nonce if nonce else os.urandom(12)
        ciphertext = _internal.chencrypt(self.secretkey, nonce, buffer, aad) #type: ignore
        if append:
            return nonce + ciphertext # type: ignore
        else:
            return ciphertext # type: ignore
    #
    def decrypt(
            self,
            buffer: bytes,
            *,
            nonce: bytes | None = None,
            aad: bytes | None = None,
        ) -> bytes:
        if nonce is None:
            nonce = buffer[:12]
            rest = buffer[12:]
        else:
            rest = buffer
        cleartext = _internal.chdecrypt(self.secretkey, nonce, rest, aad) # type: ignore
        return cleartext # type: ignore
    #
    @staticmethod
    def staticencrypt(
            secretkey: bytes,
            buffer: bytes,
            *,
            nonce: bytes | None = None,
            aad: bytes | None = None,
            append: bool = True
        ) -> bytes:
        #
        nonce = nonce if nonce else os.urandom(12)
        ciphertext = _internal.chencrypt(secretkey, nonce, buffer, aad) #type: ignore
        if append:
            return nonce + ciphertext # type: ignore
        else:
            return ciphertext # type: ignore
    #
    @staticmethod
    def staticdecrypt(
        secretkey: bytes,
        buffer: bytes,
        *,
        nonce: bytes | None = None,
        aad: bytes | None = None,
        ) -> bytes:
        #
        if nonce is None:
            nonce = buffer[:12]
            rest = buffer[12:]
        else:
            rest = buffer
        cleartext = _internal.chdecrypt(secretkey, nonce, rest, aad) # type: ignore
        return cleartext # type: ignore

class XChaCha20Poly1305:
    def __init__(self, secretkey: bytes) -> None:
        self.secretkey = secretkey
        #
        return
    #
    def encrypt(
            self,
            buffer: bytes,
            *,
            nonce: bytes | None = None,
            aad: bytes | None = None,
            append: bool = True
        ) -> bytes:
        #
        nonce = nonce if nonce else os.urandom(24)
        ciphertext = _internal.xchencrypt(self.secretkey, nonce, buffer, aad) #type: ignore
        if append:
            return nonce + ciphertext # type: ignore
        else:
            return ciphertext # type: ignore
    #
    def decrypt(
            self,
            buffer: bytes,
            *,
            nonce: bytes | None = None,
            aad: bytes | None = None,
        ) -> bytes:
        #
        if nonce is None:
            nonce = buffer[:24]
            rest = buffer[24:]
        else:
            rest = buffer
        cleartext = _internal.xchdecrypt(self.secretkey, nonce, rest, aad) # type: ignore
        return cleartext # type: ignore
    #
    @staticmethod
    def staticencrypt(
            secretkey: bytes,
            buffer: bytes,
            *,
            nonce: bytes | None = None,
            aad: bytes | None = None,
            append: bool = True
        ) -> bytes:
        #
        nonce = nonce if nonce else os.urandom(24)
        ciphertext = _internal.xchencrypt(secretkey, nonce, buffer, aad) #type: ignore
        if append:
            return nonce + ciphertext # type: ignore
        else:
            return ciphertext # type: ignore
    #
    @staticmethod
    def staticdecrypt(
        secretkey: bytes,
        buffer: bytes,
        *,
        nonce: bytes | None = None,
        aad: bytes | None = None,
        ) -> bytes:
        #
        if nonce is None:
            nonce = buffer[:24]
            rest = buffer[24:]
        else:
            rest = buffer
        cleartext = _internal.xchdecrypt(secretkey, nonce, rest, aad) # type: ignore
        return cleartext # type: ignore
