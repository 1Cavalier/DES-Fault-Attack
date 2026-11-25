# Attaque par fautes sur le DES

Retrouver la clé secrète d'un chiffrement DES à partir d'un chiffré correct et de 32 chiffrés obtenus en injectant une faute au 15e tour (Differential Fault Analysis). L'attaque récupère d'abord la sous-clé du dernier tour K16, puis la clé complète de 64 bits.

## Contexte

Projet réalisé en Master 1 à l'UVSQ (Université Paris-Saclay), dans le cadre de l'UE Calcul sécurisé, année universitaire [À COMPLÉTER].
Travail réalisé [À COMPLÉTER : seul / en binôme avec ...].

Les attaques par fautes font partie des attaques physiques sur les implémentations cryptographiques (cartes à puce, composants embarqués) : en perturbant le circuit pendant le calcul (glitch d'horloge, laser, variation de tension), l'attaquant obtient des chiffrés erronés dont la comparaison avec le chiffré correct révèle des informations sur la clé.

## Fonctionnalités

- Implémentation complète du DES (chiffrement d'un bloc, cadencement de clé), vérifiée sur un vecteur de test connu.
- Recherche de K16 : pour chacune des 8 S-boxes, test des 64 valeurs possibles des 6 bits de clé et conservation de celles compatibles avec toutes les fautes.
- Remontée du cadencement de clé : 48 bits de la clé sont déduits de K16 via PC-2^-1 et PC-1^-1.
- Recherche exhaustive des 8 bits manquants (256 essais), chaque candidat étant validé en rechiffrant le message clair.
- Calcul des bits de parité (parité impaire par octet) et affichage de la clé en hexadécimal.
- Tests unitaires.

## Principe de l'attaque

Au dernier tour du DES :

```
L16 = R15
R16 = L15 xor F(R15, K16)
C   = IP^-1(R16 || L16)
```

Une faute sur R15 donne R15* sans modifier L15. On a donc :

```
R16 xor R16* = P( S(E(R15) xor K16) xor S(E(R15*) xor K16) )
```

En appliquant IP aux chiffrés, on lit R16 et R15 directement. En appliquant P^-1 à R16 xor R16*, on obtient la différence en sortie de chaque S-box. Chaque faute exploitable réduit l'ensemble des 6 bits de clé possibles pour la S-box concernée ; avec les 32 fautes du sujet, une seule valeur subsiste pour chaque S-box.

K16 ne contient que 48 des 56 bits utiles de la clé. Comme la somme des décalages du cadencement vaut 28, on a C16 || D16 = C0 || D0, ce qui permet de replacer ces 48 bits dans la clé et de chercher les 8 restants par force brute.

## Technologies utilisées

- Python 3 (bibliothèque standard uniquement)
- unittest pour les tests

## Structure du projet

```
des-fault-attack/
├── src/
│   ├── main.py            Point d'entrée : enchaîne les deux étapes
│   ├── donnees.py         Message clair, chiffré juste et chiffrés fautifs
│   ├── tables_des.py      Tables standard du DES (IP, E, P, S-boxes, PC-1, PC-2)
│   ├── des.py             Implémentation du DES
│   ├── attaque_k16.py     Étape 1 : recherche de K16
│   ├── recherche_cle.py   Étape 2 : clé complète et bits de parité
│   └── utils_bits.py      Conversions et opérations sur les bits
├── tests/
│   └── test_attaque.py    Tests du DES et de l'attaque
├── .gitignore
├── LICENSE
└── README.md
```

## Installation et prérequis

- Python 3.8 ou plus récent
- Aucune dépendance externe

```bash
git clone https://github.com/[VOTRE-PSEUDO]/des-fault-attack.git
cd des-fault-attack
```

## Utilisation

Lancer l'attaque :

```bash
python src/main.py
```

Lancer les tests :

```bash
python -m unittest discover tests
```

## Exemple de sortie

```
--- Étape 1 : recherche de K16 ---
S-box 1 : 12 fautes exploitables -> candidat(s) : 000010
S-box 2 : 12 fautes exploitables -> candidat(s) : 101000
S-box 3 : 12 fautes exploitables -> candidat(s) : 111001
S-box 4 : 12 fautes exploitables -> candidat(s) : 011100
S-box 5 : 12 fautes exploitables -> candidat(s) : 101011
S-box 6 : 12 fautes exploitables -> candidat(s) : 011100
S-box 7 : 12 fautes exploitables -> candidat(s) : 111000
S-box 8 : 12 fautes exploitables -> candidat(s) : 100000

K16 = 000010 101000 111001 011100 101011 011100 111000 100000
K16 = 0A8E5CADCE20 (hexadécimal)

--- Étape 2 : recherche de la clé complète ---
Bits de C0||D0 absents de K16 (positions 1 à 56) : 9, 18, 22, 25, 35, 38, 43, 54
Clé trouvée à l'essai 163 sur 256

Clé DES (64 bits, parité impaire) : 85FD200D64BF08C8
DES(message clair, clé)          : A0 74 4D D9 70 B4 D2 81
Vérification : OK
```

## Pistes d'amélioration

- Calculer le nombre minimal de fautes nécessaires pour déterminer K16 de façon unique.
- Étendre l'attaque à des fautes injectées plus tôt (14e tour ou avant).
- Ajouter des contre-mesures et montrer qu'elles bloquent l'attaque (double calcul et comparaison, vérification par déchiffrement).
- Accepter les données d'entrée depuis un fichier pour rejouer l'attaque sur d'autres jeux de fautes.

## Auteur

[À COMPLÉTER : Prénom Nom] - Master 1, UVSQ / Université Paris-Saclay

## Licence

Ce projet est distribué sous licence MIT. Voir le fichier [LICENSE](LICENSE).
