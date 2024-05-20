# Cryptography_project_2024

It is a repository with the source code and materials for the project of the 2024 class of the *Cryptography methods in data science* course at the AGH University of Krakow. The scope of the project is to implement the post-quantum [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/index.html) algorithm in a high-level programming language - Python.

The implementation is based on the SABER specification document, esspecially relevant sections are:
- [Section 2](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=7.37): General algorithm specification,
- [Section 8](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=23.80): Technical Specifications.

# Relevant links

- SABER main page: https://www.esat.kuleuven.be/cosic/pqcrypto/saber/index.html
- Specification PDF (located in `/materials/saberspecround3.pdf`): https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf
- Official SABER implementation in C: https://github.com/KULeuven-COSIC/SABER
- Third party C++ implementation: https://github.com/itzmeanjan/saber

# Getting started

1. Install the `saber` package:  
    `pip install -e .`

2. Play with the use cases located in the `/saber/usecases.ipynb` notebook [file](https://github.com/Przemyslaw11/Cryptography_project_2024/blob/main/saber/usecases.ipynb).
