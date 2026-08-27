#!/usr/bin/env python3

from itertools import cycle, islice

ALFABETO = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    
    'Á', 'À', 'Â', 'Ã', 'Ä', 'É', 'È', 'Ê', 'Ë', 'Í', 'Ì', 'Î', 'Ï', 
    'Ó', 'Ò', 'Ô', 'Õ', 'Ö', 'Ú', 'Ù', 'Û', 'Ü', 'Ç',
    
    'á', 'à', 'â', 'ã', 'ä', 'é', 'è', 'ê', 'ë', 'í', 'ì', 'î', 'ï', 
    'ó', 'ò', 'ô', 'õ', 'ö', 'ú', 'ù', 'û', 'ü', 'ç'
]


# TODO: What if letter is not in alphabet?
def to_num(letter: str) -> str:
    if len(letter) < 1: raise ValueError("Cannot convert \"{letter}\" to alphabet number")
    return ALFABETO.index(letter[0])


def shift_value(letter: str) -> str:
    return to_num(letter) + 1 # This 1-indexed


def to_letter(num: int) -> str:
    if num >= len(ALFABETO): raise ValueError(f"Invalid alphabet index {num}")
    return ALFABETO[max(0, num)]


def enc(m: str, k: str) -> str:
    if len(m) == 0 or len(k) == 0:
        raise ValueError("Empty parameter in encryption function")
    if len(k) > len(m):
        k = k[:len(m)]
        print(f"WARNING: Key longer than message, truncating key to \"{k}\"")
    # Repetir se menor
    if len(k) < len(m):
        k = "".join(islice(cycle(k), len(m)))
        pass
    print(f"DEBUG: Resolved key: {k}")
    res = ''
    for i, pl in enumerate(m):
        cl = (to_num(pl) + to_num(k[i])) % len(ALFABETO) # message and key have the same length here
        crypt_char = to_letter(cl)
        res += crypt_char
    return res

print(to_num('a'))
print(to_letter(25))
print(f'ciphertext: {enc('atacarbasesul', 'limao')}')