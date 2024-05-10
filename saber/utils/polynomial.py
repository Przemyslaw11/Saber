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

    def __getitem__(self, key) -> int:
        assert key < self.n, "Index out of bounds. Index should be strictly less than the degree of the polynomial."
        return self.coeffs[key]
    
    def __add__(self, other: 'Polynomial') -> 'Polynomial':
        assert self.N == other.N, "The moduli of the polynomials should be the same."
        other_coeffs = other.coeffs
        result_coeffs = np.zeros(self.n, dtype=int)
        for i in range(self.n):
            result_coeffs[i] = (self.coeffs[i] + other_coeffs[i])
        return Polynomial(list(result_coeffs), self.N)
    
    def __str__(self) -> str:
        return str(self.np_poly1d)
