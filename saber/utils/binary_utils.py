import numpy as np

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