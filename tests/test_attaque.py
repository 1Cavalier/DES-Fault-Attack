"""
Tests de l'implémentation DES et de l'attaque.

Lancement depuis la racine du dépôt : python -m unittest discover tests
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from des import chiffrer_bloc  # noqa: E402
from attaque_k16 import retrouver_k16  # noqa: E402
from recherche_cle import retrouver_cle  # noqa: E402
from donnees import MESSAGE_CLAIR_HEX, CHIFFRE_JUSTE_HEX, CHIFFRES_FAUX_HEX  # noqa: E402
from utils_bits import hex_vers_bits, bits_vers_hex  # noqa: E402


class TestDES(unittest.TestCase):
    def test_vecteur_connu(self):
        # Exemple classique (J. Orlin Grabbe, "The DES Algorithm Illustrated")
        cle = hex_vers_bits("133457799BBCDFF1")
        message = hex_vers_bits("0123456789ABCDEF")
        self.assertEqual(bits_vers_hex(chiffrer_bloc(message, cle), ""), "85E813540F0AB405")


class TestAttaque(unittest.TestCase):
    def test_k16_unique(self):
        resultat = retrouver_k16(CHIFFRE_JUSTE_HEX, CHIFFRES_FAUX_HEX, verbeux=False)
        self.assertIsNotNone(resultat["k16"])

    def test_cle_redonne_le_chiffre(self):
        k16 = retrouver_k16(CHIFFRE_JUSTE_HEX, CHIFFRES_FAUX_HEX, verbeux=False)["k16"]
        cle = retrouver_cle(k16, MESSAGE_CLAIR_HEX, CHIFFRE_JUSTE_HEX, verbeux=False)
        self.assertIsNotNone(cle)
        chiffre = bits_vers_hex(chiffrer_bloc(hex_vers_bits(MESSAGE_CLAIR_HEX), cle))
        self.assertEqual(chiffre, CHIFFRE_JUSTE_HEX)
        # Parité impaire sur chaque octet
        for i in range(0, 64, 8):
            self.assertEqual(sum(cle[i:i + 8]) % 2, 1)


if __name__ == "__main__":
    unittest.main()
