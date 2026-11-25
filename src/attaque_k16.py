"""
Partie 1 : retrouver la sous-clé K16 par analyse différentielle de fautes.

Principe
--------
Au dernier tour du DES :
    L16 = R15
    R16 = L15 xor F(R15, K16)
et le chiffré vaut C = IP^-1(R16 || L16).

Si une faute modifie R15 en R15*, L15 n'est pas touché, donc :
    R16 xor R16* = F(R15, K16) xor F(R15*, K16)
                 = P( S(E(R15) xor K16) xor S(E(R15*) xor K16) )

En appliquant IP au chiffré on lit directement R16 et L16 = R15, aussi bien
pour le chiffré juste que pour les chiffrés fautifs. En appliquant P^-1 à
R16 xor R16*, on obtient la différence en sortie de chaque S-box.
Pour chaque S-box, on teste les 64 valeurs possibles des 6 bits de K16
correspondants et on ne garde que celles qui reproduisent la différence
observée. La bonne valeur est compatible avec toutes les fautes : on
compte les votes et on retient les candidats présents dans chacune.
"""

from collections import Counter

from tables_des import IP, E, P
from des import appliquer_sbox
from utils_bits import hex_vers_bits, permuter, xor_bits, inverser_table, bits_vers_entier, bits_vers_str

P_INV = inverser_table(P)


def separer_r16_l16(chiffre_bits):
    """
    Annule la permutation finale IP^-1 en appliquant IP au chiffré.

    Renvoie (R16, L16). Attention à l'ordre : le DES n'échange pas les
    moitiés au dernier tour, la moitié gauche du résultat est donc R16.
    """
    bloc = permuter(chiffre_bits, IP)
    return bloc[:32], bloc[32:]


def cles_compatibles(index_sbox, r15, r15_fautif, diff_sortie):
    """
    Liste les valeurs de 6 bits de K16 compatibles avec une faute pour une S-box.

    diff_sortie est la différence de 4 bits observée en sortie de la S-box.
    Renvoie None si l'entrée de la S-box n'est pas modifiée par la faute :
    dans ce cas les 64 valeurs conviennent et la faute n'apporte rien.
    """
    entree = permuter(r15, E)[6 * index_sbox:6 * index_sbox + 6]
    entree_fautive = permuter(r15_fautif, E)[6 * index_sbox:6 * index_sbox + 6]
    if entree == entree_fautive:
        return None

    candidates = []
    for k in range(64):
        k_bits = [(k >> (5 - i)) & 1 for i in range(6)]
        s1 = appliquer_sbox(index_sbox, xor_bits(entree, k_bits))
        s2 = appliquer_sbox(index_sbox, xor_bits(entree_fautive, k_bits))
        if s1 ^ s2 == diff_sortie:
            candidates.append(k)
    return candidates


def retrouver_k16(chiffre_juste_hex, chiffres_faux_hex, verbeux=True):
    """
    Retrouve K16 à partir du chiffré juste et des chiffrés fautifs.

    Renvoie un dictionnaire :
        'k16'        : liste de 48 bits (None si une S-box reste ambiguë)
        'candidats'  : pour chaque S-box, la liste des valeurs retenues
    """
    r16, r15 = separer_r16_l16(hex_vers_bits(chiffre_juste_hex))

    # Précalcul pour chaque faute : R15 fautif et différence en sortie des S-box
    fautes = []
    for texte in chiffres_faux_hex:
        r16_f, r15_f = separer_r16_l16(hex_vers_bits(texte))
        diff_sbox = permuter(xor_bits(r16, r16_f), P_INV)
        fautes.append((r15_f, diff_sbox))

    if verbeux:
        print("R16 (juste)        =", bits_vers_str(r16))
        print("L16 = R15 (juste)  =", bits_vers_str(r15))
        print(f"Nombre de chiffrés fautifs : {len(fautes)}\n")

    candidats_par_sbox = []
    for s in range(8):
        votes = Counter()
        nb_exploitables = 0
        for r15_f, diff_sbox in fautes:
            diff = bits_vers_entier(diff_sbox[4 * s:4 * s + 4])
            cles = cles_compatibles(s, r15, r15_f, diff)
            if cles is None:
                continue
            nb_exploitables += 1
            votes.update(cles)

        # La bonne valeur doit être compatible avec toutes les fautes exploitables
        retenus = [k for k, v in votes.items() if v == nb_exploitables] if nb_exploitables else []
        candidats_par_sbox.append(sorted(retenus))

        if verbeux:
            texte = ", ".join(f"{k:06b}" for k in retenus) or "aucun"
            print(f"S-box {s + 1} : {nb_exploitables:2d} fautes exploitables -> candidat(s) : {texte}")

    if all(len(c) == 1 for c in candidats_par_sbox):
        k16 = []
        for c in candidats_par_sbox:
            k16 += [(c[0] >> (5 - i)) & 1 for i in range(6)]
    else:
        k16 = None

    return {"k16": k16, "candidats": candidats_par_sbox}
