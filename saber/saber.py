from argparse import ArgumentParser

from pke import PKE
from kem import KEM
from utils.constants import CONSTANTS_MAP

class SABER:
    
    def __init__(self, version: str = "light", mu: int = 4):
        constants = CONSTANTS_MAP[version]

        # Validate the SABER parameters' values
        assert mu % 2 == 0, "The value of mu should be even."
        assert mu  < 2**constants["SABER_EP"], "The value of mu should be less than p."

        constants["SABER_MU"] = mu
        
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
