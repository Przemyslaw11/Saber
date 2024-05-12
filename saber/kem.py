from saber.utils.binary_utils import int2bytes
from utils.algorithms import *
from saber.pke import PKE
from typing import Tuple

class KEM:
    
    def __init__(self, **constants):
        self.KeyGen = self.KeyGen
        self.Encaps = self.Encaps
        self.Decaps = self.Decaps
        self.constants = constants

    def KeyGen(self) -> Tuple[bytes, bytes]:
        '''Returns the public key and the secret key in two separate byte arrays of size
SABER_PUBLICKEYBYTES and SABER_SECRETKEYBYTES respectively. Function from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=29.49) specification.'''
        PublicKeycpa, SecretKeycpa = PKE.KeyGen()

        hash_pk = sha3_256(PublicKeycpa).digest()
        hash_input = hash_pk + PublicKeycpa[:self.constants["SABER_INDCPA_PUBLICKEYBYTES"]]
        hash_pk = sha3_256(hash_input).digest()

        z = randombytes(self.constants["SABER_KEYBYTES"])

        SecretKeycca = z + hash_pk + PublicKeycpa + SecretKeycpa

        PublicKeycca = PublicKeycpa

        return PublicKeycca, SecretKeycca

    def Encaps(self, PublicKeycca: bytes) -> Tuple[bytes, bytes]:
        '''Generates a session key and the ciphertext corresponding the k.  Function from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=29.49) specification.'''
        m = randombytes(self.constants["SABER_KEYBYTES"])
        m = sha3_256(m).digest()

        hash_pk = sha3_256(PublicKeycca).digest()
        hash_input = hash_pk + PublicKeycca[:self.constants["SABER_INDCPA_PUBLICKEYBYTES"]]
        hash_pk = sha3_256(hash_input).digest()

        buf = hash_pk + m

        rk = sha3_512(buf).digest()

        r, k = rk[:self.constants["SABER_KEYBYTES"]], rk[self.constants["SABER_KEYBYTES"]:]

        CipherTextcca = PKE.Enc(m, r, PublicKeycca)

        hash_input_2 = r + CipherTextcca + int2bytes(self.constants["SABER_BYTES_CCA_DEC"], 4)
        r_prime = sha3_256(hash_input_2).digest()

        rk_prime = r_prime + k

        SessionKeycca = sha3_256(rk_prime).digest()

        return SessionKeycca, CipherTextcca