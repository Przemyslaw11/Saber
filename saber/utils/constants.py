CONSTANTS_LIGHT_SABER = {
    "SABER_L":                      2,
    "SABER_EQ":                     13,
    "SABER_EP":                     10,
    "SABER_ET":                     3,
    "SABER_SEEDBYTES":              32,
    "SABER_NOISE_SEEDBYTES":        32,
    "SABER_KEYBYTES":               32,
    "SABER_HASHBYTES":              32,
    "SABER_INDCPA_PUBLICKEYBYTES":  672,
    "SABER_INDCPA SECRETKEYBYTES":  832,
    "SABER_PUBLICKEYBYTES":         672,
    "SABER_SECRETKEYBYTES":         1568,
    "SABER_BYTES_CCA_DEC":          736,

    # Additional parameters, apart from table 8 (https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=22.95)
    "SABER_N":                      256,
    "SABER_MU":                     4,
}

CONSTANTS_SABER = {
    "SABER_L":                      3,
    "SABER_EQ":                     13,
    "SABER_EP":                     10,
    "SABER_ET":                     4,
    "SABER_SEEDBYTES":              32,
    "SABER_NOISE_SEEDBYTES":        32,
    "SABER_KEYBYTES":               32,
    "SABER_HASHBYTES":              32,
    "SABER_INDCPA_PUBLICKEYBYTES":  992,
    "SABER_INDCPA SECRETKEYBYTES":  1248,
    "SABER_PUBLICKEYBYTES":         992,
    "SABER_SECRETKEYBYTES":         2304,
    "SABER_BYTES_CCA_DEC":          1088,

    # Additional parameters, apart from table 8 (https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=22.95)
    "SABER_N":                      256,
    "SABER_MU":                     4,
}

CONSTANTS_FIRE_SABER = {
    "SABER_L":                      4,
    "SABER_EQ":                     13,
    "SABER_EP":                     10,
    "SABER_ET":                     6,
    "SABER_SEEDBYTES":              32,
    "SABER_NOISE_SEEDBYTES":        32,
    "SABER_KEYBYTES":               32,
    "SABER_HASHBYTES":              32,
    "SABER_INDCPA_PUBLICKEYBYTES":  1312,
    "SABER_INDCPA SECRETKEYBYTES":  1664,
    "SABER_PUBLICKEYBYTES":         1312,
    "SABER_SECRETKEYBYTES":         3040,
    "SABER_BYTES_CCA_DEC":          1472,

    # Additional parameters, apart from table 8 (https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf#page=22.95)
    "SABER_N":                      256,
    "SABER_MU":                     4,
}

CONSTANTS_MAP = {
    "light": CONSTANTS_LIGHT_SABER,
    "default": CONSTANTS_SABER,
    "fire": CONSTANTS_FIRE_SABER
}