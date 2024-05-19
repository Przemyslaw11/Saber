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

        PublicKeycpa, SecretKeycpa = self.pke.KeyGen()

        hash_pk = sha3_256(PublicKeycpa).digest()
        hash_input = hash_pk + PublicKeycpa[:self.constants["SABER_INDCPA_PUBLICKEYBYTES"]]
        hash_pk = sha3_256(hash_input).digest()

        z = randombytes(self.constants["SABER_KEYBYTES"])

        SecretKeycca = z + hash_pk + PublicKeycpa + SecretKeycpa

        PublicKeycca = PublicKeycpa

        return PublicKeycca, SecretKeycca

    def Encaps(self, PublicKeycca: bytes) -> Tuple[bytes, bytes]:
        """
        Generates a session key and the ciphertext corresponding the k. 
        Function from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=34.51) specification.
        """

        m = randombytes(self.constants["SABER_KEYBYTES"])
        m = sha3_256(m).digest()

        hash_pk = sha3_256(PublicKeycca).digest()
        hash_input = hash_pk + PublicKeycca[:self.constants["SABER_INDCPA_PUBLICKEYBYTES"]]
        hash_pk = sha3_256(hash_input).digest()

        buf = hash_pk + m

        rk = sha3_512(buf).digest()

        r, k = rk[:self.constants["SABER_KEYBYTES"]], rk[self.constants["SABER_KEYBYTES"]:]

        CipherTextcca = self.pke.Enc(m, r, PublicKeycca)

        hash_input_2 = r + CipherTextcca + int2bytes(self.constants["SABER_BYTES_CCA_DEC"], 4)
        r_prime = sha3_256(hash_input_2).digest()

        rk_prime = r_prime + k

        SessionKeycca = sha3_256(rk_prime).digest()

        return SessionKeycca, CipherTextcca

    def Decaps(self, CipherTextcca: bytes, SecretKeycca: bytes) -> bytes:
        """
        Returns a secret key by decapsulating the received cipherte.
        Function from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=35.09) specification.
        """

        z = SecretKeycca[:self.constants["SABER_KEYBYTES"]]
        hash_pk = SecretKeycca[self.constants["SABER_KEYBYTES"]: self.constants["SABER_KEYBYTES"] + self.constants["SABER_HASHBYTES"]]
        PublicKeycpa = SecretKeycca[
            self.constants["SABER_KEYBYTES"] + self.constants["SABER_HASHBYTES"]:
            self.constants["SABER_KEYBYTES"] +
            self.constants["SABER_HASHBYTES"] +
            self.constants["SABER_INDCPA_PUBLICKEYBYTES"]
        ]
        SecretKeycpa = SecretKeycca[
            self.constants["SABER_KEYBYTES"] + self.constants["SABER_HASHBYTES"] +
            self.constants["SABER_INDCPA_PUBLICKEYBYTES"]:
        ]

        m = self.pke.Dec(CipherTextcca, SecretKeycpa)

        buf = hash_pk + m

        rk = sha3_512(buf + int2bytes(2 * self.constants["SABER_KEYBYTES"], 4)).digest()

        r, k = rk[:self.constants["SABER_KEYBYTES"]], rk[self.constants["SABER_KEYBYTES"]:]

        CipherText_prime_cca = self.pke.Enc(m, r, PublicKeycpa)

        c = verify(CipherText_prime_cca, CipherTextcca, self.constants["SABER_BYTES_CCA_DEC"])

        r_prime = sha3_256(r + CipherTextcca + int2bytes(self.constants["SABER_BYTES_CCA_DEC"], 4)).digest()

        temp = r_prime + k if c == 0 else r_prime + z

        SessionKeycca = sha3_256(temp + int2bytes(2 * self.constants["SABER_KEYBYTES"], 4)).digest()

        return SessionKeycca
