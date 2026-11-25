"""
Données de l'attaque fournies par le sujet.

On dispose d'un message clair, de son chiffré correct, et de 32 chiffrés
obtenus en provoquant une faute sur le registre R15 (sortie du 15e tour)
pendant le chiffrement du même message avec la même clé.
Les valeurs sont données en hexadécimal, octets séparés par des espaces.
"""

# Message clair (64 bits)
MESSAGE_CLAIR_HEX = "EF AE 3D 83 DF 23 AD 2A"

# Chiffrement sans faute (référence)
CHIFFRE_JUSTE_HEX = "A0 74 4D D9 70 B4 D2 81"

# Chiffrements fautifs (faute sur un bit de R15 au 15e tour)
CHIFFRES_FAUX_HEX = [
    "A0 34 59 9F 70 B5 DA 80",
    "A0 75 6D D9 70 34 C2 D5",
    "E0 76 5D 98 78 F1 D2 81",
    "80 71 5D 59 75 F4 86 D4",
    "A0 75 45 DC 30 B5 D2 11",
    "A0 F4 5D C9 71 B4 DA 80",
    "A9 35 4D D8 70 30 D2 95",
    "E4 74 1C D8 79 F0 92 A1",
    "A1 71 49 59 71 B4 94 95",
    "A4 74 44 D8 30 94 D2 81",
    "A0 A4 4D CD 63 B4 D2 81",
    "AD 34 0D F8 70 B0 D3 C1",
    "A4 64 0E D9 71 B5 92 A1",
    "A1 54 49 D9 74 B4 C0 81",
    "A6 65 4C DD 70 94 D2 85",
    "E0 24 4D DD 66 B4 D2 C8",
    "A4 71 0D F9 70 B4 53 C1",
    "E0 64 5F D9 70 BD D2 81",
    "A0 51 4D D9 F4 B4 86 91",
    "E2 65 5D D5 30 F0 D2 85",
    "E0 74 CD C9 74 B4 96 C8",
    "A0 79 4D D8 70 A4 52 81",
    "74 74 1D C9 70 BC 92 81",
    "A1 31 49 D8 B0 A4 96 93",
    "F4 74 1C D1 30 F0 F2 81",
    "A1 74 CD C9 60 B6 96 81",
    "B4 7C 4C D8 54 A4 C3 81",
    "34 34 09 8F 70 B5 92 81",
    "A1 34 69 D8 30 A4 C2 C3",
    "B4 76 0C 99 70 B5 F2 81",
    "81 74 5D D9 64 F6 C2 C0",
    "B4 75 4C DD 54 B5 C3 11",
]
