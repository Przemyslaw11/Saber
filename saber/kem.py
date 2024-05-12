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