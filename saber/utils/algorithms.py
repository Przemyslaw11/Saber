from typing import Dict, List, Union

import numpy as np


class Polynomial():
    """
    Polynomial class to represent elements in the quotient ring. The coefficients of the polynomial are stored by the ascending order of the power of x. So the polynomial x^2 + 3 is represented as [3, 0, 1].
    """

    def __init__(self, coeffs: Union[Dict, List], N: int):
        self.N = N
        self.n = 256

        if isinstance(coeffs, dict):
            # Initialize the coefficients array
            input_coeffs = np.zeros(max(coeffs.keys()) + 1, dtype=int)
            for key, value in coeffs.items():
                input_coeffs[key] = value
        elif isinstance(coeffs, list):
            input_coeffs = np.array(coeffs)

        # Set the coefficients
        self._set_coeffs(input_coeffs)
    
    def _set_coeffs(self, input_coeffs: np.ndarray):
        
        # Perform the polynomial division
        divisor = np.poly1d([1] + [0] * (self.n - 1) + [1])
        _, r = np.polydiv(np.poly1d(np.flip(input_coeffs)), divisor)

        # Keep the coefficients within the modulus range [0, N-1]
        r = np.poly1d(r.c % self.N)

        # Store the coefficients
        self.coeffs = np.zeros(self.n, dtype=int)
        for i, c in enumerate(np.flip(r.c)):
            self.coeffs[i] = c
        
        # Set the polynomial
        self.np_poly1d = np.poly1d(np.flip(self.coeffs))

    # Overload the getter method
    def __getitem__(self, key) -> int:
        assert key < self.n, "Index out of bounds. Index should be strictly less than the degree of the polynomial."
        return self.coeffs[key]
    
    def __str__(self) -> str:
        return str(self.np_poly1d)


def int2bytes(n: int, byte_length: int) -> bytes:
    return n.to_bytes(byte_length, 'big')

def int2bits(n: int, bit_length: int) -> np.ndarray:
    result = np.zeros(bit_length, dtype=np.uint8)
    unpacked = np.unpackbits(np.frombuffer(int2bytes(n, n.bit_length()), dtype=np.uint8))[-bit_length:]

    if unpacked.size > 0:
        result[-len(unpacked):] = unpacked
    
    return result

def bytes2bits(b: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(b, dtype=np.uint8))

def bytes2int(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def bits2int(bits: np.ndarray) -> int:
    return np.sum(bits * 2**np.arange(len(bits) - 1, -1, -1))

def bits2bytes(bits: np.ndarray) -> bytes:
    return np.packbits(bits).tobytes()


def shiftleft(pin: Polynomial, s: int) -> Polynomial:
    N = pin.N
    pin_coeffs = pin.coeffs
    for i in range(256):
        pin_coeffs[i] = pin_coeffs[i] << s
    
    return Polynomial(pin_coeffs, N)


def shiftright(pin: Polynomial, s: int) -> Polynomial:
    N = pin.N
    pin_coeffs = pin.coeffs
    for i in range(256):
        pin_coeffs[i] = pin_coeffs[i] >> s
    
    return Polynomial(pin_coeffs, N)


def bs2pol(bs: bytes) -> Polynomial:
    assert len(bs) % 32 == 0, "The length of the byte string should be a multiple of 256 bits."
    k = len(bs) // 32
    N = 2**k
    bit_string = bytes2bits(bs)
    coeffs = np.zeros(256, dtype=int)
    for i in range(255, -1, -1):
        coeffs[255 - i] = bits2int(bit_string[i*k:(i + 1)*k])
    return Polynomial(list(coeffs), N)


def pol2bs(pin: Polynomial) -> bytes:
    N = pin.N
    k = int(np.log2(N))
    bit_string = np.zeros(k * 256, dtype=int)
    for i in range(256):
        bits = int2bits(int(pin[255 - i]), k)
        bit_string[i*k:(i + 1)*k] = bits
    return bits2bytes(bit_string)


def bs2polvec(bs: bytes, l: int) -> List[Polynomial]:
    assert len(bs) % 32 == 0, "The length of the byte string should be a multiple of 256 bits."
    k = (len(bs) // 32) // l
    v = list()
    for i in range(l - 1, -1, -1):
        v.append(bs2pol(bs[i*k*32:(i + 1)*k*32]))
    return v


def polvec2bs(v: List[Polynomial]) -> bytes:
    l = len(v)
    bss = list()
    for i in range(l - 1, -1, -1):
        bss.append(pol2bs(v[i]))
    return b''.join(bss)
