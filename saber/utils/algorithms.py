from typing import List

import numpy as np
from secrets import token_bytes
from hashlib import sha3_256, sha3_512, shake_128

from utils.polynomial import Polynomial
from utils.binary_utils import *


def shiftleft(pin: Polynomial, s: int) -> Polynomial:
    "Algorithm 7 from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=25.36) specification."

    N = pin.N
    pin_coeffs = pin.coeffs
    for i in range(256):
        pin_coeffs[i] = pin_coeffs[i] << s
    
    return Polynomial(pin_coeffs, N)


def shiftright(pin: Polynomial, s: int) -> Polynomial:
    "Algorithm 8 from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=25.36) specification."

    N = pin.N
    pin_coeffs = pin.coeffs
    for i in range(256):
        pin_coeffs[i] = pin_coeffs[i] >> s
    
    return Polynomial(pin_coeffs, N)


def bs2pol(bs: bytes) -> Polynomial:
    "Algorithm 9 from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=26.51) specification."

    assert len(bs) % 32 == 0, "The length of the byte string should be a multiple of 256 bits."
    k = len(bs) // 32
    N = 2**k
    bit_string = bytes2bits(bs)
    coeffs = np.zeros(256, dtype=int)
    for i in range(255, -1, -1):
        coeffs[255 - i] = bits2int(bit_string[i*k:(i + 1)*k])
    return Polynomial(list(coeffs), N)


def pol2bs(pin: Polynomial) -> bytes:
    "Algorithm 10 from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=26.51) specification."

    N = pin.N
    k = int(np.log2(N))
    bit_string = np.zeros(k * 256, dtype=int)
    for i in range(256):
        bits = int2bits(int(pin[255 - i]), k)
        bit_string[i*k:(i + 1)*k] = bits
    return bits2bytes(bit_string)


def bs2polvec(bs: bytes, l: int) -> List[Polynomial]:
    "Algorithm 11 from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=26.51) specification."

    assert len(bs) % 32 == 0, "The length of the byte string should be a multiple of 256 bits."
    k = (len(bs) // 32) // l
    v = list()
    for i in range(l - 1, -1, -1):
        v.append(bs2pol(bs[i*k*32:(i + 1)*k*32]))
    return v


def polvec2bs(v: List[Polynomial]) -> bytes:
    "Algorithm 12 from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=26.51) specification."

    l = len(v)
    bss = list()
    for i in range(l - 1, -1, -1):
        bss.append(pol2bs(v[i]))
    return b''.join(bss)


def hamming_weight(a: np.ndarray) -> int:
    "'HammingWeight' supporting function from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=28.71) specification."

    return np.count_nonzero(np.ndarray)


def randombytes(saber_seedbytes: int) -> bytes:
    "'Randombytes' supporting function from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=29.09) specification."

    return token_bytes(saber_seedbytes)


def poly_mul(a: Polynomial, b: Polynomial, p: int) -> Polynomial:
    "'PolyMul' supporting function from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=29.27) specification."

    a_coeffs = a.coeffs
    b_coeffs = b.coeffs
    c_coeffs = np.zeros(a.n, dtype=int)
    for i in range(a.n):
        c_coeffs[i] = a_coeffs[i] * b_coeffs[i]
    c = Polynomial(list(c_coeffs), p)
    return c


def matrix_vector_mul(M: List[List[Polynomial]], v: List[Polynomial], q: int) -> List[Polynomial]:
    "'MatrixVectorMul' supporting function from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=29.49) specification."

    l = len(M)
    mv = list()
    for i in range(l):
        c = Polynomial([], N=q)
        for j in range(l):
            c += poly_mul(M[i][j], v[j], q)
        mv.append(c)
    return mv


def inner_prod(a: List[Polynomial], b: List[Polynomial], p: int) -> Polynomial:
    "'InnerProd' supporting function from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=30.09) specification."

    l = len(a)
    c = Polynomial([], N=p)
    for i in range(l):
        c += poly_mul(a[i], b[i], p)
    return c


def verify(bs_0: bytes, bs_1: bytes, input_length: int) -> bool:
    "'Verify' supporting function from the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=30.48) specification."

    assert len(bs_0) == len(bs_1), "The byte strings should be of the same length."
    assert len(bs_0) == input_length, "The length of the byte strings should be equal to the input length."
    return 1 - int(bs_0 == bs_1)   # the function returns 0 if the byte strings are equal
