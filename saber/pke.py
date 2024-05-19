from utils.polynomial import Polynomial
from utils.algorithms import *
from typing import Tuple
import numpy as np

class PKE:

    def __init__(self, **constants):
        self.constants = constants

    def KeyGen(self) -> Tuple[bytes, bytes]:
        """
        Generates public and secret key pair as byte strings of length SABER_INDCPA_PUBKEYBYTES and SABER_INDCPA_SECRETKEYBYTES respectively.
        Function from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=32.20) specification.
        """

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

    def Enc(self, m: bytes, seedsss: bytes, PublicKeycpa: bytes) -> bytes:
        """
        Receives a 256-bit message m, a random seed of length SABER SEEDBYTES and the public key PublicKeycpa as the inputs and computes the corresponding ciphertext CipherTextcpa.
        Function from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=32.67) specification.
        """

        seedAAA, pk = PublicKeycpa[:self.constants["SABER_SEEDBYTES"]], PublicKeycpa[self.constants["SABER_SEEDBYTES"]:]
        AAA = gen_matrix(seedAAA, self.constants["SABER_L"], self.constants["SABER_L"],
                         self.constants["SABER_EQ"], self.constants["SABER_ET"])
        s_prime = gen_secret(seedsss, self.constants["SABER_L"], self.constants["SABER_L"],
                             self.constants["SABER_EP"], self.constants["SABER_ET"])
        b_prime = matrix_vector_mul(AAA, s_prime, self.constants["SABER_Q"])

        h = bs2pol(randombytes(self.constants["SABER_POLYBYTES"]))
        for i in range(self.constants["SABER_L"]):
            b_prime[i] += h

        b_rounded = [shiftright(poly, self.constants["SABER_EQ"] - self.constants["SABER_EP"]) for poly in b_prime]

        mp = bs2pol(m)
        mp_shifted = shiftleft(mp, self.constants["SABER_EP"] - 1)

        cm = inner_prod(bs2polvec(pk, self.constants["SABER_L"]), s_prime, self.constants["SABER_P"])
        h1 = bs2pol(randombytes(self.constants["SABER_POLYBYTES"]))
        cm = cm - mp_shifted + h1 % self.constants["SABER_P"]
        cm_rounded = shiftright(cm, self.constants["SABER_EP"] - self.constants["SABER_ET"])

        CipherTextcpa = pol2bs(cm_rounded) + polvec2bs(b_rounded)

        return CipherTextcpa

    def Dec(self, CipherTextcpa: bytes, SecretKeycpa: bytes) -> bytes:
        """
        Receives generated CipherTextcpa and SecretKeycpa as inputs and computes the decrypted message m.
        Function from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=32.79) specification
        """

        sss = bs2polvec(SecretKeycpa, self.constants["SABER_L"])
        cm_rounded = bs2pol(CipherTextcpa[:self.constants["SABER_POLYBYTES"]])
        b_rounded = bs2polvec(CipherTextcpa[self.constants["SABER_POLYBYTES"]:], self.constants["SABER_L"])

        cm_rounded = shiftleft(cm_rounded, self.constants["SABER_EP"] - self.constants["SABER_ET"])

        v = inner_prod(b_rounded, sss, self.constants["SABER_P"])
        cm_rounded = shiftright(cm_rounded, self.constants["SABER_EP"] - 1)

        h2 = bs2pol(randombytes(self.constants["SABER_POLYBYTES"]))
        m_prime = v - cm_rounded + h2 % self.constants["SABER_P"]
        m = pol2bs(shiftright(m_prime, self.constants["SABER_EP"] - 1))

        return m