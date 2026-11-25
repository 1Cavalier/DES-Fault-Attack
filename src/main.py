"""
Attaque par fautes sur le DES : point d'entrée.

Enchaîne les deux parties de l'attaque sur les données du sujet :
  1. retrouver la sous-clé du dernier tour K16 (attaque_k16.py) ;
  2. en déduire la clé maître de 64 bits (recherche_cle.py).

Lancement : python src/main.py
"""

from donnees import MESSAGE_CLAIR_HEX, CHIFFRE_JUSTE_HEX, CHIFFRES_FAUX_HEX
from attaque_k16 import retrouver_k16
from recherche_cle import retrouver_cle
from des import chiffrer_bloc
from utils_bits import bits_vers_hex, bits_vers_str, hex_vers_bits


def main():
    print("=== Attaque par fautes sur le DES ===\n")
    print(f"Message clair   : {MESSAGE_CLAIR_HEX}")
    print(f"Chiffré juste   : {CHIFFRE_JUSTE_HEX}\n")

    print("--- Étape 1 : recherche de K16 ---")
    resultat = retrouver_k16(CHIFFRE_JUSTE_HEX, CHIFFRES_FAUX_HEX)
    k16 = resultat["k16"]
    if k16 is None:
        print("\nK16 n'est pas déterminée de façon unique, arrêt.")
        return 1

    k16_hex = f"{int(bits_vers_str(k16), 2):012X}"
    print(f"\nK16 = {' '.join(bits_vers_str(k16[i:i + 6]) for i in range(0, 48, 6))}")
    print(f"K16 = {k16_hex} (hexadécimal)\n")

    print("--- Étape 2 : recherche de la clé complète ---")
    cle = retrouver_cle(k16, MESSAGE_CLAIR_HEX, CHIFFRE_JUSTE_HEX)
    if cle is None:
        print("Aucune clé ne redonne le chiffré juste.")
        return 1

    print(f"\nClé DES (64 bits, parité impaire) : {bits_vers_hex(cle, '')}")

    # Contrôle final indépendant
    verif = bits_vers_hex(chiffrer_bloc(hex_vers_bits(MESSAGE_CLAIR_HEX), cle))
    print(f"DES(message clair, clé)          : {verif}")
    print("Vérification :", "OK" if verif == CHIFFRE_JUSTE_HEX else "ÉCHEC")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
