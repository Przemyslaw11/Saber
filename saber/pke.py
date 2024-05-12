from saber.utils.polynomial import Polynomial
from utils.algorithms import *
from typing import Tuple
import numpy as np

class PKE:

    def __init__(self, **constants):
        self.keygen = self.KeyGen
        self.encrypt = self.Enc
        self.decrypt = self.Dec
        self.constants = constants

    def KeyGen(self) -> Tuple[bytes, bytes]:
        '''Generates public and secret key pair as byte strings of length
SABER_INDCPA_PUBKEYBYTES and SABER_INDCPA_SECRETKEYBYTES respectively. Function from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=29.49) specification.'''
        seedAAA = randombytes(self.constants["SABER_SEEDBYTES"])
        seedAAA = shake_128(seedAAA).digest(self.constants["SABER_SEEDBYTES"])
        seedsss = randombytes(self.constants["SABER_NOISE_SEEDBYTES"])

        AAA = gen_matrix(seedAAA, self.constants["SABER_L"], self.constants["SABER_L"],
                         self.constants["SABER_EQ"], self.constants["SABER_ET"])
        sss = gen_secret(seedsss, self.constants["SABER_L"], self.constants["SABER_L"],
                         self.constants["SABER_EP"], self.constants["SABER_ET"])

        AAAT = [list(i) for i in zip(*AAA)]
        bbb = matrix_vector_mul(AAAT, sss, self.constants["SABER_EQ"])

        hhh_coeffs = np.random.randint(0, self.constants["SABER_L"], self.constants["SABER_L"])
        hhh = [Polynomial(hhh_coeffs[i], self.constants["SABER_L"]) for i in range(self.constants["SABER_L"])]
        bbb = [(bbb[i] + hhh[i]) % self.constants["SABER_Q"] for i in range(self.constants["SABER_L"])]

        bbbp = [shiftright(poly, self.constants["SABER_EQ"] - self.constants["SABER_EP"]) for poly in bbb]

        SecretKeycpa = polvec2bs(sss)
        pk = polvec2bs(bbbp)

        PublicKeycpa = seedAAA + pk

        return PublicKeycpa, SecretKeycpa