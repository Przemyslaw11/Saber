from pke import PKE
from kem import KEM

class SABER:
    
    def __init__(self):
        self.pke = PKE()
        self.kem = KEM()


if __name__ == "__main__":
    saber = SABER()
    print("SABER instantiated successfully!")
