#!/usr/bin/env python3
# Testa o ataque de Kasiski com chaves conhecidas, em portugues e ingles.

from kasiski import ALFABETO, normaliza, ataque

TEXTO_PT = normaliza("""
    A criptografia e a pratica de tecnicas para comunicacao segura na presenca
    de terceiros. Trata-se de construir e analisar protocolos que impecam que
    terceiros leiam mensagens privadas. A seguranca da informacao moderna esta
    ligada a matematica, a ciencia da computacao e a engenharia. As aplicacoes
    incluem o comercio eletronico, os cartoes de pagamento, as moedas digitais
    e as comunicacoes militares. Antes da era moderna, a criptografia era
    sinonimo de codificacao, a conversao de informacao de um estado legivel
    para um aparente absurdo. O originador compartilha a tecnica apenas com os
    destinatarios pretendidos, para impedir o acesso de adversarios. Desde o
    desenvolvimento das maquinas de cifragem por rotor e o advento dos
    computadores, os metodos tornaram-se cada vez mais complexos.
    """)

TEXTO_EN = normaliza("""
    The Vigenere cipher encrypts alphabetic text using a series of interwoven
    Caesar ciphers, based on the letters of a keyword. It is a form of
    polyalphabetic substitution. First described in the sixteenth century, the
    cipher is easy to understand and implement, but it resisted all attempts to
    break it for three centuries, which earned it the description of the
    indecipherable cipher. The primary weakness is the repeating nature of the
    key. If a cryptanalyst guesses the length of the key, the cipher text can
    be treated as interwoven Caesar ciphers, broken individually. The Kasiski
    examination and the Friedman test both help determine the key length by
    looking at repeated groups of letters in the cipher text.
    """)


def cifra(msg, chave):
    return "".join(ALFABETO[(ALFABETO.index(c) + ALFABETO.index(chave[i % len(chave)])) % 26]
                   for i, c in enumerate(msg))


CASOS = [
    (TEXTO_PT, "LIMA"), (TEXTO_PT, "LIMAO"), (TEXTO_PT, "SEGURANCA"),
    (TEXTO_PT, "CRIPTOGRAFIA"),
    (TEXTO_EN, "KEY"), (TEXTO_EN, "SECRET"), (TEXTO_EN, "CRYPTOGRAPHY"),
    (TEXTO_EN, "COMPUTERSECURITY"),
]

acertos = 0
for msg, chave in CASOS:
    achada, texto, _ = ataque(cifra(msg, chave), verboso=False)
    ok = achada == chave and texto == msg
    acertos += ok
    print(f"  [{'OK ' if ok else 'ERRO'}] chave {chave:<18} -> {achada}")

print(f"\n{acertos}/{len(CASOS)} casos corretos")

# Limite do metodo: com pouco texto nao ha repeticoes suficientes.
print("\nDegradacao com criptograma curto (chave SEGURANCA, 9 letras):")
for tam in [100, 200, 400, 800, len(TEXTO_PT)]:
    msg = TEXTO_PT[:tam]
    try:
        achada, _, _ = ataque(cifra(msg, "SEGURANCA"), verboso=False)
    except ValueError:
        achada = "sem repeticoes"
    print(f"  {tam:>4} letras ({tam // 9:>3} por coluna) -> {achada}")
