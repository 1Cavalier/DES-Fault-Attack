"""
Implémentation pédagogique du DES (chiffrement d'un bloc de 64 bits).

Elle sert à deux choses dans le projet :
  - fournir la fonction S-box utilisée par l'attaque sur le dernier tour ;
  - vérifier qu'une clé candidate chiffre bien le message clair en le
    chiffré juste, ce qui permet de lever l'ambiguïté sur les 8 bits de
    clé que K16 ne contient pas.

Ce code n'est pas optimisé et ne doit pas servir à protéger des données.
"""

from tables_des import IP, IP_INV, E, P, S_BOXES, PC1, PC2, DECALAGES
from utils_bits import permuter, xor_bits, rotation_gauche, entier_vers_bits


def appliquer_sbox(index_sbox, bloc6):
    """
    Passe 6 bits dans la S-box numéro index_sbox (0 à 7) et renvoie un entier de 4 bits.

    Les bits extrêmes (b1, b6) donnent la ligne, les 4 bits centraux la colonne.
    """
    ligne = (bloc6[0] << 1) | bloc6[5]
    colonne = (bloc6[1] << 3) | (bloc6[2] << 2) | (bloc6[3] << 1) | bloc6[4]
    return S_BOXES[index_sbox][ligne][colonne]


def fonction_f(r, sous_cle):
    """Fonction de tour F(R, K) = P(S(E(R) xor K)) sur 32 bits."""
    entree = xor_bits(permuter(r, E), sous_cle)
    sortie = []
    for s in range(8):
        sortie += entier_vers_bits(appliquer_sbox(s, entree[6 * s:6 * s + 6]), 4)
    return permuter(sortie, P)


def generer_sous_cles(cle64):
    """Calcule les 16 sous-clés de 48 bits à partir d'une clé de 64 bits."""
    cd = permuter(cle64, PC1)
    c, d = cd[:28], cd[28:]
    sous_cles = []
    for decalage in DECALAGES:
        c = rotation_gauche(c, decalage)
        d = rotation_gauche(d, decalage)
        sous_cles.append(permuter(c + d, PC2))
    return sous_cles


def chiffrer_bloc(message64, cle64):
    """Chiffre un bloc de 64 bits avec une clé de 64 bits (16 tours de Feistel)."""
    bloc = permuter(message64, IP)
    l, r = bloc[:32], bloc[32:]
    for k in generer_sous_cles(cle64):
        l, r = r, xor_bits(l, fonction_f(r, k))
    # Pas d'échange après le dernier tour : on recolle R16 || L16
    return permuter(r + l, IP_INV)
