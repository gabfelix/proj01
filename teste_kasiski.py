#!/usr/bin/env python3
"""
Validacao do ataque de Kasiski + qui-quadrado (kasiski.py).

Cifra textos conhecidos com chaves conhecidas e verifica se o ataque recupera a
chave. Os numeros produzidos aqui alimentam a secao de resultados do relatorio.

    python3 teste_kasiski.py
"""

from itertools import cycle, islice

from kasiski import (
    ALFABETO_26, ALFABETO_98,
    normaliza, ataque, decifra, candidatos_tamanho_chave, melhores_candidatos,
)

# ---------------------------------------------------------------------------
# Textos de teste
# ---------------------------------------------------------------------------

TEXTO_PT = """
A cifra de Vigenere foi descrita pela primeira vez por Giovan Battista Bellaso no seculo
dezesseis, mas acabou recebendo o nome de Blaise de Vigenere devido a uma atribuicao
incorreta feita no seculo dezenove. Durante trezentos anos ela foi considerada indecifravel
e recebeu a alcunha de cifra indecifravel. O metodo consiste em aplicar uma sequencia de
cifras de Cesar diferentes ao longo da mensagem, determinadas pelas letras de uma palavra
chave que se repete. Essa construcao elimina a assinatura estatistica simples que permite
quebrar uma cifra monoalfabetica, porque cada posicao da mensagem pode ser deslocada por um
valor distinto. O ataque moderno explora justamente a periodicidade da chave para reduzir o
problema a varias cifras monoalfabeticas independentes que podem ser resolvidas
separadamente por analise de frequencia. Charles Babbage quebrou a cifra em segredo por
volta de mil oitocentos e cinquenta e quatro, e Friedrich Kasiski publicou de forma
independente um metodo geral alguns anos depois. A tecnica de Kasiski observa que sequencias
repetidas no texto claro cifradas pelo mesmo trecho da chave produzem sequencias repetidas
no criptograma, e a distancia entre essas repeticoes e um multiplo do tamanho da chave.
"""

TEXTO_EN = """
The Vigenere cipher is a method of encrypting alphabetic text by using a series of
interwoven Caesar ciphers, based on the letters of a keyword. It is a form of polyalphabetic
substitution. First described by Giovan Battista Bellaso in fifteen fifty three, the cipher
is easy to understand and implement, but it resisted all attempts to break it for three
centuries, which earned it the description the indecipherable cipher. Many people have tried
to implement encryption schemes that are essentially Vigenere ciphers, and many have been
broken. The primary weakness of the Vigenere cipher is the repeating nature of its key. If a
cryptanalyst correctly guesses the length of the key, then the cipher text can be treated as
interwoven Caesar ciphers, which can easily be broken individually. The Kasiski examination
and the Friedman test can help determine the key length by looking for repeated groups of
letters in the cipher text and measuring the index of coincidence of the resulting columns.
"""

TEXTO_PT_ACENTUADO = (TEXTO_PT
    .replace("Vigenere", "Vigenère").replace("seculo", "século")
    .replace("atribuicao", "atribuição").replace("indecifravel", "indecifrável")
    .replace("metodo", "método").replace("sequencia", "sequência")
    .replace("Cesar", "César").replace("construcao", "construção")
    .replace("estatistica", "estatística").replace("monoalfabetica", "monoalfabética")
    .replace("posicao", "posição").replace("varias", "várias")
    .replace("monoalfabeticas", "monoalfabéticas").replace("analise", "análise")
    .replace("frequencia", "frequência").replace("tecnica", "técnica")
    .replace("distancia", "distância").replace("repeticoes", "repetições")
    .replace("multiplo", "múltiplo").replace("sequencias", "sequências"))


def cifra(plaintext, chave, alfabeto):
    """Cifragem de Vigenere, usada apenas para gerar os casos de teste."""
    indice = {c: i for i, c in enumerate(alfabeto)}
    tamanho = len(alfabeto)
    k = "".join(islice(cycle(chave), len(plaintext)))
    return "".join(
        alfabeto[(indice[p] + indice[q]) % tamanho] for p, q in zip(plaintext, k)
    )


# ---------------------------------------------------------------------------

def cabecalho(titulo):
    print()
    print("=" * 74)
    print(titulo)
    print("=" * 74)


def caso(texto, chave, alfabeto, idioma, rotulo, tamanho_max=20):
    """Cifra, ataca e compara com a chave real."""
    pt = normaliza(texto, alfabeto)
    ct = cifra(pt, chave, alfabeto)
    r = ataque(ct, alfabeto=alfabeto, tamanho_max=tamanho_max)
    m = r['melhor']

    chave_ok = m['chave'] == chave
    texto_ok = m['plaintext'] == pt
    # Uma chave repetida (LIMA -> LIMALIMA) decifra igual: conta como sucesso.
    equivalente = (not chave_ok) and texto_ok

    status = "OK " if texto_ok else "FALHA"
    print(f"  [{status}] {rotulo:<34} chave real: {chave:<16} "
          f"recuperada: {m['chave']:<16} idioma: {m['idioma']}"
          + ("  (equivalente)" if equivalente else ""))
    return texto_ok


def main():
    resultados = []

    cabecalho("1. Portugues, alfabeto de 26 simbolos")
    for chave in ["LIMA", "LIMAO", "SEGURANCA", "CRIPTOGRAFIA"]:
        resultados.append(caso(TEXTO_PT, chave, ALFABETO_26, 'pt', f"chave de {len(chave)} letras"))
    # Chave mais longa que o teto padrao: exige elevar --tamanho-max.
    resultados.append(caso(TEXTO_PT, "UNIVERSIDADEDEBRASILIA", ALFABETO_26, 'pt',
                           "chave de 22 letras (max=25)", tamanho_max=25))

    cabecalho("2. Ingles, alfabeto de 26 simbolos")
    for chave in ["KEY", "SECRET", "CRYPTOGRAPHY", "COMPUTERSECURITY"]:
        resultados.append(caso(TEXTO_EN, chave, ALFABETO_26, 'en', f"chave de {len(chave)} letras"))

    cabecalho("3. Portugues com acentos, alfabeto de 98 simbolos (o de crypt.py)")
    for chave in ["Limao", "Seguranca", "Criptografia"]:
        resultados.append(caso(TEXTO_PT_ACENTUADO, chave, ALFABETO_98, 'pt',
                               f"chave de {len(chave)} letras"))

    # Esta secao NAO e um teste de aprovacao: mede onde o metodo deixa de
    # funcionar. As linhas marcadas [-] sao a limitacao esperada, nao defeitos.
    cabecalho("4. Limite: ate onde o ciphertext pode encurtar")
    pt = normaliza(TEXTO_PT, ALFABETO_26)
    chave = "SEGURANCA"
    for tam in [100, 200, 400, 800, len(pt)]:
        ct = cifra(pt[:tam], chave, ALFABETO_26)
        try:
            r = ataque(ct, alfabeto=ALFABETO_26, idioma='pt')
            m = r['melhor']
            ok = m['plaintext'] == pt[:tam]
            print(f"  [{'v' if ok else '-'}] {tam:>5} simbolos "
                  f"({tam//len(chave):>3}/coluna)  ->  {m['chave']}"
                  + ("" if ok else "   (degradado)"))
        except ValueError as e:
            print(f"  [-] {tam:>5} simbolos  ->  {e}")

    cabecalho("5. O caso que o IoC errou: chave 'LIMA' superestimada")
    pt = normaliza(TEXTO_PT, ALFABETO_26)
    ct = cifra(pt, "LIMA", ALFABETO_26)
    ranking, n_dist, n_rep = candidatos_tamanho_chave(ct)
    print(f"  Ranking de Kasiski (evidencia 1.00 = acaso):")
    for item in sorted(ranking, key=lambda x: x['razao'], reverse=True)[:5]:
        print(f"    tamanho {item['tamanho']:>2}: fracao {item['fracao']:.3f}  "
              f"evidencia {item['razao']:.2f}")
    escolhidos = [c['tamanho'] for c in melhores_candidatos(ranking)]
    print(f"  Candidatos apos a regra do menor multiplo: {escolhidos}")
    r = ataque(ct, alfabeto=ALFABETO_26, idioma='pt')
    print(f"  Chave recuperada: {r['melhor']['chave']}  (real: LIMA)")

    cabecalho("RESUMO")
    print(f"  {sum(resultados)}/{len(resultados)} casos recuperaram o plaintext correto.")
    return 0 if all(resultados) else 1


if __name__ == '__main__':
    raise SystemExit(main())
