"""
Partie 2 : retrouver la clé maître de 64 bits à partir de K16.

1. Remonter le cadencement de clé.
   La somme des décalages vaut 28, donc C16 || D16 = C0 || D0 = PC1(K).
   Comme K16 = PC2(C16 || D16), PC2^-1 donne 48 des 56 bits de PC1(K).
   Les 8 bits supprimés par PC2 restent inconnus.

2. Recherche exhaustive sur ces 8 bits (256 essais).
   Chaque candidat de 56 bits est remis en 64 bits par PC1^-1, puis on
   chiffre le message clair : la bonne clé redonne le chiffré juste.
   Cette vérification par chiffrement est indispensable, car les 256
   candidats produisent tous exactement la même K16.

3. Ajout des bits de parité.
   PC1 ignore les bits 8, 16, ..., 64. Par convention DES, chaque octet de
   la clé doit avoir un nombre impair de bits à 1.
"""

from itertools import product

from tables_des import PC1, PC2
from des import chiffrer_bloc
from utils_bits import hex_vers_bits, inverser_table

PC1_INV = inverser_table(PC1, 64)
PC2_INV = inverser_table(PC2, 56)

# Positions (0-indexées) dans C0 || D0 que PC2 n'utilise pas
POSITIONS_INCONNUES = [i for i, v in enumerate(PC2_INV) if v == 0]


def k16_vers_cle56_partielle(k16):
    """Place les 48 bits de K16 dans C0 || D0 ; les bits inconnus valent None."""
    return [k16[v - 1] if v else None for v in PC2_INV]


def cle56_vers_cle64(cle56):
    """Remet une clé de 56 bits sur 64 bits via PC1^-1 (bits de parité à 0)."""
    return [cle56[v - 1] if v else 0 for v in PC1_INV]


def ajouter_parite(cle64):
    """Fixe le dernier bit de chaque octet pour obtenir une parité impaire."""
    cle = list(cle64)
    for i in range(0, 64, 8):
        cle[i + 7] = 1 - (sum(cle[i:i + 7]) % 2)
    return cle


def retrouver_cle(k16, message_hex, chiffre_hex, verbeux=True):
    """
    Teste les 256 complétions possibles de K16 et renvoie la clé de 64 bits
    (avec bits de parité) qui chiffre message_hex en chiffre_hex, ou None.
    """
    message = hex_vers_bits(message_hex)
    chiffre = hex_vers_bits(chiffre_hex)
    base = k16_vers_cle56_partielle(k16)

    if verbeux:
        positions = ", ".join(str(p + 1) for p in POSITIONS_INCONNUES)
        print(f"Bits de C0||D0 absents de K16 (positions 1 à 56) : {positions}")

    for essai, bits in enumerate(product((0, 1), repeat=len(POSITIONS_INCONNUES)), start=1):
        cle56 = list(base)
        for pos, b in zip(POSITIONS_INCONNUES, bits):
            cle56[pos] = b
        cle64 = cle56_vers_cle64(cle56)
        if chiffrer_bloc(message, cle64) == chiffre:
            if verbeux:
                print(f"Clé trouvée à l'essai {essai} sur {2 ** len(POSITIONS_INCONNUES)}")
            return ajouter_parite(cle64)

    return None
