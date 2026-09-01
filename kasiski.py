#!/usr/bin/env python3
# Ataque a cifra de Vigenere: exame de Kasiski + teste do qui-quadrado.
#
# Kasiski estima o tamanho da chave pelas distancias entre trechos repetidos
# no criptograma. O qui-quadrado quebra cada coluna comparando a distribuicao
# de letras com a frequencia esperada do idioma.
#
# O alfabeto e parametro: ele define o modulo da aritmetica da cifra, entao
# precisa ser o mesmo usado na cifragem.

import unicodedata
from collections import Counter

ALFABETO_26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Alfabeto estendido, o mesmo de ciphers.py e do ataque por IoC.
ALFABETO_98 = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
               "ÁÀÂÃÄÉÈÊËÍÌÎÏÓÒÔÕÖÚÙÛÜÇáàâãäéèêëíìîïóòôõöúùûüç")

# Portugues do Brasil, em % — B. R. Braga, "Analise de Frequencias de Linguas",
# RAVEL/COPPE/UFRJ, 2003. Corpus de 1,1 MB de textos de autores brasileiros;
# o estudo desconsidera acentos e trata C-cedilha como C, mesma normalizacao
# que aplicamos no alfabeto de 26 letras.
FREQ_PT = {'A': 14.64, 'B': 1.16, 'C': 3.76, 'D': 4.97, 'E': 12.70, 'F': 1.02,
           'G': 1.29, 'H': 1.42, 'I': 5.90, 'J': 0.32, 'K': 0.01, 'L': 2.95,
           'M': 4.71, 'N': 4.85, 'O': 10.78, 'P': 2.58, 'Q': 1.09, 'R': 6.88,
           'S': 7.97, 'T': 4.26, 'U': 4.42, 'V': 1.68, 'W': 0.01, 'X': 0.23,
           'Y': 0.01, 'Z': 0.42}

# Ingles, em % — H. Beker e F. Piper, "Cipher Systems", Wiley, 1982, p. 397.
# Amostra de 100.362 caracteres de jornais e romances.
FREQ_EN = {'A': 8.17, 'B': 1.49, 'C': 2.78, 'D': 4.25, 'E': 12.70, 'F': 2.23,
           'G': 2.02, 'H': 6.09, 'I': 6.97, 'J': 0.15, 'K': 0.77, 'L': 4.03,
           'M': 2.41, 'N': 6.75, 'O': 7.51, 'P': 1.93, 'Q': 0.10, 'R': 5.99,
           'S': 6.33, 'T': 9.06, 'U': 2.76, 'V': 0.98, 'W': 2.36, 'X': 0.15,
           'Y': 1.97, 'Z': 0.07}

# Nao existe tabela publicada cobrindo maiusculas e acentuadas. Para alfabetos
# estendidos, contamos as letras nestas amostras em vez de estimar pesos.
AMOSTRA_PT = """A criptografia é a prática de técnicas para comunicação segura na
presença de terceiros. A segurança da informação moderna está ligada à matemática,
à ciência da computação e à engenharia. As aplicações incluem o comércio eletrônico,
os cartões de pagamento e as comunicações militares. Antes da era moderna era
sinônimo de codificação: a conversão de informação de um estado legível para um
aparente absurdo. Análises estatísticas permitem quebrar cifras clássicas."""

AMOSTRA_EN = """The cryptographic system must remain secure even when the adversary
knows everything about the design except the secret key. This principle is known as
Kerckhoffs maxim. Many systems have failed because they relied on obscurity instead
of sound key management. The modern practice is to publish algorithms openly so that
researchers can attack them and expose weaknesses before deployment."""


def tabela_frequencias(alfabeto, idioma):
    """Frequencia esperada (%) de cada simbolo do alfabeto."""
    if alfabeto == ALFABETO_26:
        return FREQ_PT if idioma == "portugues" else FREQ_EN
    amostra = AMOSTRA_PT if idioma == "portugues" else AMOSTRA_EN
    cont = Counter(c for c in amostra if c in alfabeto)
    total = sum(cont.values())
    # O 0.01 evita probabilidade zero para simbolos ausentes da amostra.
    return {c: cont.get(c, 0) / total * 100 + 0.01 for c in alfabeto}


def normaliza(texto, alfabeto=ALFABETO_26):
    """
    Reduz o texto ao alfabeto de trabalho.

    Em A-Z remove acentos e converte para maiuscula. Em alfabetos estendidos
    apenas descarta o que nao pertence a eles, pois ali maiuscula e acento
    sao simbolos distintos.
    """
    if alfabeto == ALFABETO_26:
        d = unicodedata.normalize("NFD", texto)
        d = "".join(c for c in d if unicodedata.category(c) != "Mn")
        return "".join(c for c in d.upper() if c in alfabeto)
    return "".join(c for c in texto if c in alfabeto)


def cifra(msg, chave, alfabeto=ALFABETO_26):
    n = len(alfabeto)
    return "".join(alfabeto[(alfabeto.index(c)
                             + alfabeto.index(chave[i % len(chave)])) % n]
                   for i, c in enumerate(msg))


def decifra(ct, chave, alfabeto=ALFABETO_26):
    n = len(alfabeto)
    return "".join(alfabeto[(alfabeto.index(c)
                             - alfabeto.index(chave[i % len(chave)])) % n]
                   for i, c in enumerate(ct))


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
        return [], {}

    evid = {L: sum(1 for d in dists if d % L == 0) / len(dists) * L
            for L in range(2, max_tam + 1)}

    maior = max(evid.values())
    fortes = [L for L, e in evid.items() if e >= 0.6 * maior]

    tamanhos = set(fortes)
    for L in fortes:
        tamanhos.update(d for d in range(2, L) if L % d == 0)
    return sorted(tamanhos)[:8], evid


def quebra_coluna(coluna, freq, alfabeto):
    """
    Testa todos os deslocamentos e devolve a letra de menor qui-quadrado.

        X2 = (1/n) * soma de (O - E)^2 / E,  com E = p*n + 0.2

    A divisao por n torna o valor comparavel entre tamanhos de chave
    diferentes (colunas de chaves longas tem menos amostras). O 0.2 evita
    que uma unica ocorrencia de letra rara reprove o deslocamento correto.
    """
    n, tam = len(coluna), len(alfabeto)
    esperado = [freq[c] / 100 * n + 0.2 for c in alfabeto]
    melhor, melhor_x2 = alfabeto[0], float('inf')
    for s in range(tam):
        obs = Counter((alfabeto.index(c) - s) % tam for c in coluna)
        x2 = sum((obs.get(i, 0) - e) ** 2 / e for i, e in enumerate(esperado)) / n
        if x2 < melhor_x2:
            melhor, melhor_x2 = alfabeto[s], x2
    return melhor, melhor_x2


def ataque(ct, alfabeto=ALFABETO_26, verboso=True):
    """Roda o ataque completo e devolve (chave, texto_claro, idioma)."""
    ct = normaliza(ct, alfabeto)   # aceita texto cru, com quebras de linha
    if len(ct) < 20:
        raise ValueError("Criptograma curto demais (menos de 20 simbolos).")

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
    for idioma in ("portugues", "ingles"):
        freq = tabela_frequencias(alfabeto, idioma)
        for L in candidatos:
            letras = [quebra_coluna(ct[i::L], freq, alfabeto) for i in range(L)]
            chave = "".join(c for c, _ in letras)
            custo = sum(x for _, x in letras) / L
            tentativas.append((custo, L, chave, idioma))

    tentativas.sort()
    if verboso:
        print("Hipoteses testadas:")
        for custo, L, chave, idioma in tentativas[:6]:
            print(f"   {idioma:<10} L={L:<3} {chave:<20} X2={custo:.3f}")
        print()

    # Uma chave e suas repeticoes decifram o mesmo texto e empatam em custo.
    # Entre empates (5%), fica a mais curta, que e a chave real.
    limite = tentativas[0][0] * 1.05
    custo, L, chave, idioma = min((t for t in tentativas if t[0] <= limite),
                                  key=lambda t: t[1])
    return chave, decifra(ct, chave, alfabeto), idioma


if __name__ == "__main__":
    # Troque para ALFABETO_98 e uma chave com acentos/minusculas para testar
    # o alfabeto estendido.
    ALFABETO = ALFABETO_26
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
        """, ALFABETO)

    ct = cifra(msg, chave_real, ALFABETO)
    print(f"criptograma: {ct[:60]}...\n")

    chave, texto, idioma = ataque(ct, ALFABETO)
    print(f"chave recuperada: {chave}   (real: {chave_real})")
    print(f"idioma detectado: {idioma}")
    print(f"texto decifrado : {texto[:60]}...")
