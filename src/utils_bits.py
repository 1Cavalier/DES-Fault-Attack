"""
Fonctions utilitaires de manipulation de bits.

Les blocs sont représentés par des listes d'entiers 0/1, bit de poids fort
en premier (le bit 1 de la norme DES est l'élément d'indice 0).
"""


def hex_vers_bits(hex_str):
    """Convertit une chaîne hexadécimale (espaces tolérés) en liste de bits."""
    hex_str = hex_str.replace(" ", "")
    return [int(b) for b in bin(int(hex_str, 16))[2:].zfill(len(hex_str) * 4)]


def bits_vers_hex(bits, separateur=" "):
    """Convertit une liste de bits (longueur multiple de 8) en hexadécimal par octets."""
    octets = [bits[i:i + 8] for i in range(0, len(bits), 8)]
    return separateur.join(f"{bits_vers_entier(o):02X}" for o in octets)


def bits_vers_str(bits):
    """Représentation compacte d'une liste de bits, par exemple '010011'."""
    return "".join(map(str, bits))


def bits_vers_entier(bits):
    """Interprète une liste de bits comme un entier non signé."""
    valeur = 0
    for b in bits:
        valeur = (valeur << 1) | b
    return valeur


def entier_vers_bits(valeur, taille):
    """Écrit un entier non signé sur 'taille' bits."""
    return [(valeur >> (taille - 1 - i)) & 1 for i in range(taille)]


def xor_bits(a, b):
    """XOR bit à bit de deux listes de même longueur."""
    return [x ^ y for x, y in zip(a, b)]


def permuter(bits, table):
    """Applique une table de permutation DES (1-indexée) à une liste de bits."""
    return [bits[i - 1] for i in table]


def inverser_table(table, taille_entree=None):
    """
    Construit la table inverse d'une permutation 1-indexée.

    Pour une table de compression (PC-2 par exemple), les positions de
    l'entrée qui n'apparaissent pas dans la table restent à 0 dans la
    table inverse : elles correspondent aux bits perdus.
    """
    taille = taille_entree or len(table)
    inverse = [0] * taille
    for position_sortie, position_entree in enumerate(table, start=1):
        inverse[position_entree - 1] = position_sortie
    return inverse


def rotation_gauche(bits, n):
    """Rotation circulaire à gauche de n positions."""
    return bits[n:] + bits[:n]
