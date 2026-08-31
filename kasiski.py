#!/usr/bin/env python3
# Ataque a cifra de Vigenere: exame de Kasiski + teste do qui-quadrado.
#
# Kasiski estima o tamanho da chave pelas distancias entre trechos repetidos
# no criptograma. O qui-quadrado quebra cada coluna comparando a distribuicao
# de letras com a frequencia esperada do idioma.
#
# Trabalha com o alfabeto de 26 letras: acentos, espacos e pontuacao sao
# removidos antes da analise.

import unicodedata
from collections import Counter

ALFABETO = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Frequencias em % — fonte: pt.wikipedia.org/wiki/Frequência_de_letras
FREQ_PT = {'A': 14.63, 'B': 1.04, 'C': 3.88, 'D': 4.99, 'E': 12.57, 'F': 1.02,
           'G': 1.30, 'H': 1.28, 'I': 6.18, 'J': 0.40, 'K': 0.02, 'L': 2.78,
           'M': 4.74, 'N': 5.05, 'O': 10.73, 'P': 2.52, 'Q': 1.20, 'R': 6.53,
           'S': 7.81, 'T': 4.34, 'U': 4.63, 'V': 1.67, 'W': 0.01, 'X': 0.21,
           'Y': 0.01, 'Z': 0.47}

FREQ_EN = {'A': 8.17, 'B': 1.49, 'C': 2.78, 'D': 4.25, 'E': 12.70, 'F': 2.23,
           'G': 2.02, 'H': 6.09, 'I': 6.97, 'J': 0.15, 'K': 0.77, 'L': 4.03,
           'M': 2.41, 'N': 6.75, 'O': 7.51, 'P': 1.93, 'Q': 0.10, 'R': 5.99,
           'S': 6.33, 'T': 9.06, 'U': 2.76, 'V': 0.98, 'W': 2.36, 'X': 0.15,
           'Y': 1.97, 'Z': 0.07}


def normaliza(texto):
    """Remove acentos e pontuacao, deixa so as 26 letras maiusculas."""
    d = unicodedata.normalize("NFD", texto)
    d = "".join(c for c in d if unicodedata.category(c) != "Mn")
    return "".join(c for c in d.upper() if c in ALFABETO)


def distancias(ct):
    """Distancias entre ocorrencias de trechos repetidos (n-gramas de 3 a 5)."""
    dists = []
    for n in range(3, 6):
        posicoes = {}
        for i in range(len(ct) - n + 1):
            posicoes.setdefault(ct[i:i + n], []).append(i)
        for pos in posicoes.values():
            for a in range(len(pos)):
                for b in range(a + 1, len(pos)):
                    dists.append(pos[b] - pos[a])
    return dists


def candidatos_tamanho(ct, max_tam=20):
    """
    Tamanhos de chave provaveis, pelo exame de Kasiski.

    Se um trecho do texto claro se repete E a chave esta na mesma fase, o
    criptograma repete — logo a distancia e multipla do tamanho da chave.

    Evidencia = fracao das distancias divisiveis por L, vezes L. Como uma
    distancia qualquer e divisivel por L em 1/L das vezes, evidencia 1.0
    significa "igual ao acaso".

    A evidencia nao separa L de seus multiplos (ambos pontuam ~L), entao
    devolvemos os candidatos fortes junto com seus divisores. Quem decide
    e o qui-quadrado.
    """
    dists = distancias(ct)
    if not dists:
        return []

    evid = {L: sum(1 for d in dists if d % L == 0) / len(dists) * L
            for L in range(2, max_tam + 1)}

    maior = max(evid.values())
    fortes = [L for L, e in evid.items() if e >= 0.6 * maior]

    tamanhos = set(fortes)
    for L in fortes:
        tamanhos.update(d for d in range(2, L) if L % d == 0)
    return sorted(tamanhos)[:8], evid


def quebra_coluna(coluna, freq):
    """
    Testa os 26 deslocamentos e devolve a letra de menor qui-quadrado.

        X2 = (1/n) * soma de (O - E)^2 / E,  com E = p*n + 0.2

    A divisao por n torna o valor comparavel entre tamanhos de chave
    diferentes (colunas de chaves longas tem menos amostras). O 0.2 evita
    que uma unica ocorrencia de letra rara reprove o deslocamento correto.
    """
    n = len(coluna)
    melhor, melhor_x2 = 'A', float('inf')
    for s in range(26):
        obs = Counter((ALFABETO.index(c) - s) % 26 for c in coluna)
        x2 = sum((obs.get(i, 0) - (freq[ALFABETO[i]] / 100 * n + 0.2)) ** 2
                 / (freq[ALFABETO[i]] / 100 * n + 0.2) for i in range(26)) / n
        if x2 < melhor_x2:
            melhor, melhor_x2 = ALFABETO[s], x2
    return melhor, melhor_x2


def decifra(ct, chave):
    return "".join(ALFABETO[(ALFABETO.index(c) - ALFABETO.index(chave[i % len(chave)])) % 26]
                   for i, c in enumerate(ct))


def ataque(ct, verboso=True):
    """Roda o ataque completo e devolve (chave, texto_claro, idioma)."""
    candidatos, evid = candidatos_tamanho(ct)
    if not candidatos:
        raise ValueError("Criptograma curto demais: nenhum trecho repetido.")

    if verboso:
        print("Evidencia por tamanho de chave (1.0 = acaso):")
        for L in sorted(evid, key=evid.get, reverse=True)[:6]:
            print(f"   L={L:<3} {evid[L]:.2f}")
        print(f"Candidatos a testar: {candidatos}\n")

    # Testa cada candidato em cada idioma; guarda a chave e o custo.
    tentativas = []
    for nome, freq in [('portugues', FREQ_PT), ('ingles', FREQ_EN)]:
        for L in candidatos:
            letras = [quebra_coluna(ct[i::L], freq) for i in range(L)]
            chave = "".join(c for c, _ in letras)
            custo = sum(x for _, x in letras) / L
            tentativas.append((custo, L, chave, nome))

    tentativas.sort()
    if verboso:
        print("Hipoteses testadas:")
        for custo, L, chave, nome in tentativas[:6]:
            print(f"   {nome:<10} L={L:<3} {chave:<20} X2={custo:.3f}")
        print()

    # Uma chave e suas repeticoes decifram o mesmo texto e empatam em custo.
    # Entre empates (5%), fica a mais curta, que e a chave real.
    limite = tentativas[0][0] * 1.05
    custo, L, chave, idioma = min((t for t in tentativas if t[0] <= limite),
                                  key=lambda t: t[1])
    return chave, decifra(ct, chave), idioma


if __name__ == "__main__":
    chave_real = "SEGURANCA"
    msg = normaliza("""
        A cifra de Vigenere foi descrita pela primeira vez por Giovan Battista
        Bellaso no seculo dezesseis, mas acabou recebendo o nome de Blaise de
        Vigenere. Durante trezentos anos ela foi considerada indecifravel. O
        metodo consiste em aplicar uma sequencia de cifras de Cesar diferentes
        ao longo da mensagem, determinadas pelas letras de uma palavra chave que
        se repete. Essa construcao elimina a assinatura estatistica simples que
        permite quebrar uma cifra monoalfabetica. O ataque moderno explora a
        periodicidade da chave para reduzir o problema a varias cifras
        monoalfabeticas independentes, resolvidas por analise de frequencia.
        Friedrich Kasiski publicou o metodo em mil oitocentos e sessenta e tres,
        observando que sequencias repetidas no texto claro cifradas pelo mesmo
        trecho da chave produzem sequencias repetidas no criptograma.
        """)

    # Cifra a mensagem para gerar o criptograma de teste.
    ct = "".join(ALFABETO[(ALFABETO.index(c) + ALFABETO.index(chave_real[i % len(chave_real)])) % 26]
                 for i, c in enumerate(msg))

    print(f"criptograma: {ct[:60]}...\n")
    chave, texto, idioma = ataque(ct)
    print(f"chave recuperada: {chave}   (real: {chave_real})")
    print(f"idioma detectado: {idioma}")
    print(f"texto decifrado : {texto[:60]}...")
