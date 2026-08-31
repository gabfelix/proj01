#!/usr/bin/env python3

from ciphers import VigenereCipher
from collections import Counter

CUSTOM_ALFABETO = [
    "A",
    "B",
    "C",
    "D",
    "E",
    "F",
    "G",
    "H",
    "I",
    "J",
    "K",
    "L",
    "M",
    "N",
    "O",
    "P",
    "Q",
    "R",
    "S",
    "T",
    "U",
    "V",
    "W",
    "X",
    "Y",
    "Z",
    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
    "g",
    "h",
    "i",
    "j",
    "k",
    "l",
    "m",
    "n",
    "o",
    "p",
    "q",
    "r",
    "s",
    "t",
    "u",
    "v",
    "w",
    "x",
    "y",
    "z",
    "Á",
    "À",
    "Â",
    "Ã",
    "Ä",
    "É",
    "È",
    "Ê",
    "Ë",
    "Í",
    "Ì",
    "Î",
    "Ï",
    "Ó",
    "Ò",
    "Ô",
    "Õ",
    "Ö",
    "Ú",
    "Ù",
    "Û",
    "Ü",
    "Ç",
    "á",
    "à",
    "â",
    "ã",
    "ä",
    "é",
    "è",
    "ê",
    "ë",
    "í",
    "ì",
    "î",
    "ï",
    "ó",
    "ò",
    "ô",
    "õ",
    "ö",
    "ú",
    "ù",
    "û",
    "ü",
    "ç",
]

cipher = VigenereCipher(CUSTOM_ALFABETO)


def ioc(s: str, normalized: bool = True) -> float:
    n = len(s)
    if n <= 1.0:
        return 0.0
    fs: dict[str, float] = Counter(s)
    sum_of_matches = sum(count * (count - 1) for count in fs.values())
    if not normalized:
        return sum_of_matches / (n * (n - 1))
    else:
        return sum_of_matches / ((n * (n - 1)) / len(CUSTOM_ALFABETO))


def estimate_key_length(ct: str, max: int = 20) -> int:
    filtered_ct = [c for c in ct if c in cipher.alphabet]
    iocs = []
    for length in range(1, max + 1):
        columns = ["" for _ in range(length)]
        for i, char in enumerate(filtered_ct):
            columns[i % length] += char
        avg_ioc = sum(ioc(col) for col in columns) / length
        iocs.append((length, avg_ioc))

    baseline = sum(ioc for _, ioc in iocs) / len(iocs)
    threshold = baseline * 1.5
    print(f"thres: {threshold}")

    candidate_key_lengths = []
    for l, ic in iocs:
        if ic > threshold:
            print(f"col {l}: {ic}")
            candidate_key_lengths.append(l)

    if len(candidate_key_lengths) == 0:
        return -1  # ERROR
    return candidate_key_lengths[0]


def score_text(text: str) -> float:
    freqs = {
        "a": 12.21,
        "b": 1.01,
        "c": 3.35,
        "d": 4.21,
        "e": 13.19,
        "f": 1.07,
        "g": 1.08,
        "h": 1.22,
        "i": 5.49,
        "j": 0.30,
        "k": 0.13,
        "l": 3.00,
        "m": 5.07,
        "n": 5.02,
        "o": 10.22,
        "p": 3.01,
        "q": 1.10,
        "r": 6.73,
        "s": 7.35,
        "t": 5.07,
        "u": 4.46,
        "v": 1.72,
        "w": 0.05,
        "x": 0.28,
        "y": 0.04,
        "z": 0.45,
        "ã": 0.83,
        "â": 0.03,
        "á": 0.41,
        "à": 0.04,
        "ç": 0.40,
        "é": 0.52,
        "ê": 0.36,
        "í": 0.18,
        "ó": 0.17,
        "õ": 0.04,
        "ô": 0.01,
        "ú": 0.11,
        "A": 0.12,
        "E": 0.13,
        "O": 0.10,
    }
    return sum(freqs.get(char, 0.0) for char in text)


def crack(ct: str, key_length: int) -> str:
    iterations = 0

    filtered_ct = [c for c in ciphertext if c in cipher.alphabet]
    columns = ["" for _ in range(key_length)]

    for i, char in enumerate(filtered_ct):
        columns[i % key_length] += char

    # if we got the key length right, each column is a simple caesar cipher, since they share the same letter from the key
    primary_key_guess = ""
    for col in columns:
        best_char = ""
        best_score = -1.0

        # try every possible letter and see which one fits the target frequency the best
        for possible_key_char in cipher.alphabet:
            iterations += 1
            score = score_text(cipher.decrypt(col, possible_key_char))
            if score > best_score:
                best_score = score
                best_char = possible_key_char
        # add it to the key
        primary_key_guess += best_char
    print(f"Ran {iterations} iterations")
    return primary_key_guess


if __name__ == "__main__":
    test_key = "limaosinhoinho"
    msg = (
        "Acriptografiasemprefoiumaferramentaessencialparaahumanidadedesdeostemposantigos"
        "Odesejodeocultarinformaçõesimportantesimpulsionouodesenvolvimentodecifrascomplexas"
        "Quandoolhamosparaaevoluçãodascomunicaçõespercebemosqueanecessidadedeprivacidadeesegurança"
        "moldouatecnologiamodernaHojeemdiausamosalgoritmosmatemáticosavançadosparaproteger"
        "nossosdadospessoaisegarantirqueasmensagenscheguemapenasaosdestinatárioscorretos"
        "Acomplexidadedoalfabetoeamatemáticaportrásdacodificaçãotornamaanáliseestatística"
        "fascinanteedesafiadora"
    )
    ciphertext = cipher.encrypt(msg, test_key)
    print(f"ciphertext: {ciphertext[:20]}...")
    kl = estimate_key_length(ciphertext)
    if kl < 1:
        print("Failed to estimate key length (no columns met IoC threshold)")
        exit(1)
    print(f"key length: {kl}")
    cracked_key = crack(ciphertext, kl)
    print(f"guessed key: {cracked_key}")
    print(f"decrypted: {cipher.decrypt(ciphertext, cracked_key)[:50]}...")
