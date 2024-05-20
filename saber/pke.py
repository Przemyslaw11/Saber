from utils.polynomial import Polynomial
from utils.algorithms import *
from typing import Tuple

class PKE:

    def __init__(self, **constants):
        self.constants = constants
        self.n = self.constants["SABER_N"]
        self.l = self.constants["SABER_L"]
        self.q = 2**self.constants["SABER_EQ"]
        self.p = 2**self.constants["SABER_EP"]
        self.t = 2**self.constants["SABER_ET"]
        self.h1 = Polynomial([
            2**(self.constants["SABER_EQ"] - self.constants["SABER_EP"] - 1)
        ] * self.constants["SABER_N"], self.q)
        self.h2 = Polynomial([
            2**(self.constants["SABER_EP"] - 2) -\
            2**(self.constants["SABER_EP"] - self.constants["SABER_ET"] - 1) +\
            2**(self.constants["SABER_EQ"] - self.constants["SABER_EP"] - 1)
        ] * self.constants["SABER_N"], self.q)
        self.h = [self.h1 for _ in range(self.constants["SABER_L"])]

    def KeyGen(self) -> Tuple[bytes, bytes]:
        """
        Generates public and secret key pair as byte strings of length SABER_INDCPA_PUBKEYBYTES and SABER_INDCPA_SECRETKEYBYTES respectively.
        Function from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=32.20) specification.
        """

        seed_A = randombytes(self.constants["SABER_SEEDBYTES"])
        seed_A = shake_128(seed_A).digest(self.constants["SABER_SEEDBYTES"])
        seed_s = randombytes(self.constants["SABER_NOISE_SEEDBYTES"])
        A = gen_matrix(seed_A, self.l, self.n, self.constants["SABER_EQ"])
        s = gen_secret(seed_s, self.l, self.n, self.constants["SABER_MU"], self.q)
        b = matrix_vector_mul(transpose_matrix(A), s, self.q)
        b = [b[i] + self.h[i] for i in range(self.l)]
        b_p = [shiftright(poly, self.constants["SABER_EQ"] - self.constants["SABER_EP"]) % self.p for poly in b]
        SecretKey_cpa = polvec2bs(s, self.q)
        pk = polvec2bs(b_p, self.p)
        PublicKey_cpa = seed_A + pk

        return PublicKey_cpa, SecretKey_cpa

    def Enc(self, m: bytes, seed_s_prime: bytes, PublicKey_cpa: bytes) -> bytes:
        """
        Receives a 256-bit message m, a random seed of length SABER SEEDBYTES and the public key PublicKey_cpa as the inputs and computes the corresponding ciphertext CipherTextcpa.
        Function from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=32.67) specification.
        """

        assert len(m) == 32, "The message encrypted with PKE should be of length 256 bits (32 bytes)."

        seed_A, pk = PublicKey_cpa[:self.constants["SABER_SEEDBYTES"]], PublicKey_cpa[self.constants["SABER_SEEDBYTES"]:]
        A = gen_matrix(seed_A, self.l, self.n, self.constants["SABER_EQ"])
        s_prime = gen_secret(seed_s_prime, self.l, self.n, self.constants["SABER_MU"], self.q)
        b_prime = matrix_vector_mul(A, s_prime, self.q)
        b_prime = [b_prime[i] + self.h[i] for i in range(self.l)]
        b_prime = [shiftright(poly, self.constants["SABER_EQ"] - self.constants["SABER_EP"]) % self.p  for poly in b_prime]
        b = bs2polvec(pk, self.l)
        v_prime = inner_prod(b, [poly % self.p for poly in s_prime], self.p)
        m_p = bs2pol(m)
        m_p = shiftleft(m_p % self.p, self.constants["SABER_EP"] - 1)
        c_m = shiftright(v_prime - (m_p % self.p) + (self.h1 % self.p), self.constants["SABER_EP"] - self.constants["SABER_ET"])
        CipherText_cpa = pol2bs(c_m % self.t, self.t) + polvec2bs(b_prime, self.p)

        return CipherText_cpa

    def Dec(self, CipherText_cpa: bytes, SecretKey_cpa: bytes) -> bytes:
        """
        Receives generated CipherText_cpa and SecretKey_cpa as inputs and computes the decrypted message m.
        Function from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=32.79) specification
        """

        s = bs2polvec(SecretKey_cpa, self.l)
        c_m, c_t = CipherText_cpa[:32*self.constants["SABER_ET"]], CipherText_cpa[32*self.constants["SABER_ET"]:]
        c_m = bs2pol(c_m)
        c_m = shiftleft(c_m % self.p, self.constants["SABER_EP"] - self.constants["SABER_ET"])
        b_prime = bs2polvec(c_t, self.l)
        v = inner_prod(b_prime, [poly % self.p for poly in s], self.p)
        m_prime = shiftright(v - c_m % self.p + self.h2 % self.p, self.constants["SABER_EP"] - 1)
        m = pol2bs(m_prime % 2, 2)

        return m