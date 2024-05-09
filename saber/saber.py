from argparse import ArgumentParser

from pke import PKE
from kem import KEM
from utils.constants import CONSTANTS_MAP

class SABER:
    
    def __init__(self, version: str = "light"):
        constants = CONSTANTS_MAP[version]
        self.pke = PKE(**constants)
        self.kem = KEM(**constants)


if __name__ == "__main__":
    
    # Parse the command line arguments
    parser = ArgumentParser()
    parser.add_argument("-v", "--version", type=str, default="light", choices=["light", "default", "fire"], 
                        help="The version of the SABER algorithm to use.")
    args = parser.parse_args()

    # Initialize the SABER algorithm
    saber = SABER(**vars(args))
