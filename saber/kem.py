from utils.binary_utils import int2bytes
from utils.algorithms import *
from pke import PKE
from typing import Tuple

class KEM:
    
    def __init__(self, **constants):
        self.constants = constants
        self.pke = PKE(**self.constants)

    def KeyGen(self) -> Tuple[bytes, bytes]:
        """
        Returns the public key and the secret key in two separate byte arrays of size SABER_PUBLICKEYBYTES and SABER_SECRETKEYBYTES respectively.
        Function from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=34.16) specification.
        """

        PublicKey_cpa, SecretKey_cpa = self.pke.KeyGen()
        hash_pk = sha3_256(PublicKey_cpa).digest()
        z = randombytes(self.constants["SABER_KEYBYTES"])
        SecretKey_cca = z + hash_pk + PublicKey_cpa + SecretKey_cpa
        PublicKey_cca = PublicKey_cpa

        return PublicKey_cca, SecretKey_cca

    def Encaps(self, PublicKey_cca: bytes) -> Tuple[bytes, bytes]:
        """
        Generates a session key and the ciphertext corresponding the k. 
        Function from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=34.51) specification.
        """

        m = randombytes(self.constants["SABER_KEYBYTES"])
        m = sha3_256(m).digest()
        hash_pk = sha3_256(PublicKey_cca).digest()
        buf = hash_pk + m
        rk = sha3_512(buf).digest()
        r, k = rk[:self.constants["SABER_KEYBYTES"]], rk[self.constants["SABER_KEYBYTES"]:]
        CipherText_cca = self.pke.Enc(m, r, PublicKey_cca)
        r_prime = sha3_256(CipherText_cca).digest()
        rk_prime = r_prime + k
        SessionKey_cca = sha3_256(rk_prime).digest()

        return SessionKey_cca, CipherText_cca

    def Decaps(self, CipherText_cca: bytes, SecretKey_cca: bytes) -> bytes:
        """
        Returns a secret key by decapsulating the received cipherte.
        Function from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=35.09) specification.
        """

        def unpack(SecretKey_cca: bytes):
            remainder = SecretKey_cca
            z, remainder = remainder[:self.constants["SABER_KEYBYTES"]], remainder[self.constants["SABER_KEYBYTES"]:]
            hash_pk, remainder = remainder[:self.constants["SABER_HASHBYTES"]], remainder[self.constants["SABER_HASHBYTES"]:]
            PublicKey_cpa, remainder = remainder[:self.constants["SABER_INDCPA_PUBLICKEYBYTES"]], remainder[self.constants["SABER_INDCPA_PUBLICKEYBYTES"]:]
            SecretKey_cpa = remainder

            return z, hash_pk, PublicKey_cpa, SecretKey_cpa

        z, hash_pk, PublicKey_cpa, SecretKey_cpa = unpack(SecretKey_cca)
        m = self.pke.Dec(CipherText_cca, SecretKey_cpa)
        buf = hash_pk + m
        rk = sha3_512(buf).digest()
        r, k = rk[:self.constants["SABER_KEYBYTES"]], rk[self.constants["SABER_KEYBYTES"]:]
        CipherText_prime_cca = self.pke.Enc(m, r, PublicKey_cpa)
        c = verify(CipherText_prime_cca, CipherText_cca, self.constants["SABER_BYTES_CCA_DEC"])
        r_prime = sha3_256(CipherText_cca).digest()
        if c == 0:
            temp = r_prime + k
        else:
            temp = r_prime + z
        SessionKey_cca = sha3_256(temp).digest()

        return SessionKey_cca
