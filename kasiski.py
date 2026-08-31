#!/usr/bin/env python3
"""
Ataque de recuperacao de chave contra a cifra de Vigenere.

Metodo: exame de Kasiski (estimativa do tamanho da chave a partir de repeticoes
no ciphertext) seguido de teste do qui-quadrado (recuperacao de cada letra da
chave por distancia entre distribuicoes de frequencia).

Este e um caminho INDEPENDENTE do teste de Friedman/IoC implementado em
ataque_friedman: Kasiski usa combinatoria de repeticoes, nao estatistica de
concentracao. Rodar os dois no mesmo ciphertext da validacao cruzada.

As sete etapas pedidas no item 3 do enunciado estao marcadas no codigo como
[ETAPA 1] .. [ETAPA 7].

Uso:
    python3 kasiski.py -a ciphertext.txt
    python3 kasiski.py -a ciphertext.txt --idioma pt --verboso
    echo "SGOZIAQGV..." | python3 kasiski.py

Sem dependencias externas: apenas a biblioteca padrao.
"""

import argparse
import sys
import unicodedata
from collections import Counter

# ---------------------------------------------------------------------------
# Alfabetos
# ---------------------------------------------------------------------------
# O alfabeto define o modulo da aritmetica da cifra. Um ciphertext gerado com
# 26 simbolos NAO pode ser atacado com aritmetica mod 98 (e vice-versa): as
# operacoes de wrap-around sao diferentes e o resultado e ruido.

ALFABETO_26 = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

# Mesmo alfabeto estendido usado em crypt.py, para interoperar com a Parte I.
ALFABETO_98 = list(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "ÁÀÂÃÄÉÈÊËÍÌÎÏÓÒÔÕÖÚÙÛÜÇ"
    "áàâãäéèêëíìîïóòôõöúùûüç"
)

# ---------------------------------------------------------------------------
# Distribuicoes de frequencia de referencia (%)
# Fonte: https://pt.wikipedia.org/wiki/Frequência_de_letras (indicada no item 4)
# ---------------------------------------------------------------------------

FREQ_PT = {
    'A': 14.63, 'B': 1.04, 'C': 3.88, 'D': 4.99, 'E': 12.57, 'F': 1.02,
    'G': 1.30, 'H': 1.28, 'I': 6.18, 'J': 0.40, 'K': 0.02, 'L': 2.78,
    'M': 4.74, 'N': 5.05, 'O': 10.73, 'P': 2.52, 'Q': 1.20, 'R': 6.53,
    'S': 7.81, 'T': 4.34, 'U': 4.63, 'V': 1.67, 'W': 0.01, 'X': 0.21,
    'Y': 0.01, 'Z': 0.47,
}

FREQ_EN = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702, 'F': 2.228,
    'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153, 'K': 0.772, 'L': 4.025,
    'M': 2.406, 'N': 6.749, 'O': 7.507, 'P': 1.929, 'Q': 0.095, 'R': 5.987,
    'S': 6.327, 'T': 9.056, 'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150,
    'Y': 1.974, 'Z': 0.074,
}

TABELAS = {'pt': FREQ_PT, 'en': FREQ_EN}


# ---------------------------------------------------------------------------
# Preparacao do texto
# ---------------------------------------------------------------------------

def letra_base(caractere):
    """Remove acento e devolve a letra A-Z correspondente ('ç' -> 'C')."""
    decomposto = unicodedata.normalize("NFD", caractere)
    sem_acento = "".join(c for c in decomposto if unicodedata.category(c) != "Mn")
    return sem_acento.upper()[:1]


def normaliza(texto, alfabeto):
    """
    Reduz o texto ao alfabeto de trabalho.

    Para o alfabeto de 26 simbolos: remove acentos, converte para maiuscula e
    descarta tudo que nao for letra (espacos, digitos, pontuacao, quebras).
    Para alfabetos maiores: apenas descarta o que nao pertence ao alfabeto,
    preservando caixa e acentuacao, que sao simbolos distintos ali.
    """
    conjunto = set(alfabeto)
    if alfabeto == ALFABETO_26:
        return "".join(c for c in (letra_base(ch) for ch in texto) if c in conjunto)
    return "".join(c for c in texto if c in conjunto)


def tabela_esperada(alfabeto, idioma):
    """
    Distribuicao esperada (probabilidades somando 1) sobre o alfabeto de trabalho.

    No alfabeto de 26 e a tabela da lingua diretamente. Em alfabetos estendidos
    a frequencia de cada letra base e distribuida entre suas variantes: a forma
    minuscula sem acento concentra a maior parte, a maiuscula e as acentuadas
    ficam com fatias pequenas. Nao e uma medicao de corpus, e uma aproximacao —
    mas basta para o qui-quadrado, porque o sinal dominante e que simbolos raros
    (maiusculas acentuadas) praticamente nao aparecem em texto real.

    LIMITACAO CONHECIDA: essa aproximacao recupera a chave corretamente no
    alfabeto de 98, mas os pesos fixos achatam a diferenca entre portugues e
    ingles, entao a DETECCAO AUTOMATICA DE IDIOMA fica pouco confiavel ali.
    Ao atacar um ciphertext em alfabeto estendido, informe --idioma. No alfabeto
    de 26 a deteccao usa as tabelas reais e funciona.
    """
    base = TABELAS[idioma]

    if alfabeto == ALFABETO_26:
        total = sum(base.values())
        return [base[c] / total for c in alfabeto]

    # Agrupa os simbolos do alfabeto por letra base e por "classe" de raridade.
    PESO = {'minuscula': 0.93, 'maiuscula': 0.03, 'acentuada': 0.04}

    def classe(ch):
        acentuado = len(unicodedata.normalize("NFD", ch)) > 1
        if acentuado:
            return 'acentuada'
        return 'maiuscula' if ch.isupper() else 'minuscula'

    grupos = {}
    for ch in alfabeto:
        grupos.setdefault(letra_base(ch), {}).setdefault(classe(ch), []).append(ch)

    esperado = {ch: 0.0 for ch in alfabeto}
    for letra, por_classe in grupos.items():
        freq = base.get(letra, 0.01)
        for nome, membros in por_classe.items():
            fatia = freq * PESO[nome] / len(membros)
            for ch in membros:
                esperado[ch] = fatia

    total = sum(esperado.values())
    return [esperado[ch] / total for ch in alfabeto]


# ---------------------------------------------------------------------------
# [ETAPA 1] Estimativa do tamanho da chave — exame de Kasiski
# ---------------------------------------------------------------------------
# Ideia: se um trecho do plaintext se repete e cai alinhado com o mesmo trecho
# da chave, produz o mesmo trecho no ciphertext. Logo a distancia entre duas
# ocorrencias de um n-grama repetido tende a ser MULTIPLA do tamanho da chave.

def encontra_repeticoes(ct, n):
    """Mapeia cada n-grama que aparece 2+ vezes para a lista de suas posicoes."""
    posicoes = {}
    for i in range(len(ct) - n + 1):
        posicoes.setdefault(ct[i:i + n], []).append(i)
    return {grama: pos for grama, pos in posicoes.items() if len(pos) > 1}


def distancias_entre_repeticoes(repeticoes):
    """Distancias entre todos os pares de ocorrencias de cada n-grama repetido."""
    distancias = []
    for posicoes in repeticoes.values():
        for i in range(len(posicoes)):
            for j in range(i + 1, len(posicoes)):
                distancias.append(posicoes[j] - posicoes[i])
    return distancias


def candidatos_tamanho_chave(ct, n_min=3, n_max=5, tamanho_max=20):
    """
    Ranqueia tamanhos de chave candidatos.

    Para cada tamanho L, conta que fracao das distancias observadas e divisivel
    por L. Um L ao acaso divide cerca de 1/L das distancias; o L verdadeiro
    divide quase todas. A razao entre o observado e esse acaso mede a evidencia.

    ATENCAO: multiplos do tamanho verdadeiro obtem razao parecida (se L=6 e o
    certo, L=12 divide metade das distancias e a razao empata). Por isso o
    desempate correto e preferir o MENOR tamanho com evidencia forte — e por
    isso Kasiski nao sofre do problema de superestimar a chave que o IoC
    apresentou ao quebrar "lima" como "limalimalima".
    """
    distancias = []
    total_repeticoes = 0
    for n in range(n_min, n_max + 1):
        repeticoes = encontra_repeticoes(ct, n)
        total_repeticoes += len(repeticoes)
        distancias.extend(distancias_entre_repeticoes(repeticoes))

    if not distancias:
        return [], 0, 0

    ranking = []
    for L in range(2, tamanho_max + 1):
        divisiveis = sum(1 for d in distancias if d % L == 0)
        fracao = divisiveis / len(distancias)
        ranking.append({
            'tamanho': L,
            'divisiveis': divisiveis,
            'fracao': fracao,
            'razao': fracao * L,   # 1.0 = compativel com acaso; alto = evidencia
        })

    ranking.sort(key=lambda r: r['razao'], reverse=True)
    return ranking, len(distancias), total_repeticoes


def melhores_candidatos(ranking, quantos=6, fator=0.6):
    """
    Seleciona os tamanhos que serao efetivamente testados na etapa 7.

    A metrica de evidencia (fracao x L) se comporta assim:

      - Um DIVISOR d do tamanho verdadeiro L divide todas as distancias, entao
        sua fracao e ~1 e sua evidencia vale ~d, MENOR que a de L.
      - Um MULTIPLO kL divide cerca de 1/k das distancias, entao sua evidencia
        vale ~(1/k)(kL) = L: praticamente EMPATA com a de L.

    Ou seja, a evidencia NAO consegue separar L de seus multiplos, e em textos
    curtos com repeticoes concentradas ela chega a preferir um multiplo (um
    punhado de distancias iguais a 48 faz 12 e 16 dispararem sobre o 4 real).
    Por isso esta funcao apenas PROPOE candidatos, nunca elimina: junto com cada
    tamanho forte entram seus divisores, e quem decide e o qui-quadrado na etapa
    7, que compara o encaixe com a lingua e desempata pela chave mais curta.
    """
    if not ranking:
        return []

    maior = max(r['razao'] for r in ranking)
    fortes = [r['tamanho'] for r in ranking if r['razao'] >= fator * maior]

    # Um tamanho forte pode ser multiplo do verdadeiro; os divisores entram junto.
    divisores = set()
    for L in fortes:
        divisores.update(d for d in range(2, L) if L % d == 0)

    # O corte por `quantos` nunca pode descartar um tamanho forte: sao eles que
    # carregam a evidencia. Os divisores preenchem o espaco restante.
    vagas = max(0, quantos - len(fortes))
    tamanhos = set(fortes) | set(sorted(divisores)[:vagas])

    por_tamanho = {r['tamanho']: r for r in ranking}
    return [por_tamanho[L] for L in sorted(tamanhos) if L in por_tamanho]


# ---------------------------------------------------------------------------
# [ETAPA 2] Separacao do ciphertext em subconjuntos
# ---------------------------------------------------------------------------

def separa_em_colunas(ct, tamanho_chave):
    """
    Divide o ciphertext em `tamanho_chave` colunas.

    A coluna i reune as posicoes i, i+L, i+2L, ... — ou seja, todas as letras
    cifradas pela MESMA letra da chave. Cada coluna e, portanto, uma cifra de
    Cesar independente.
    """
    return [ct[i::tamanho_chave] for i in range(tamanho_chave)]


# ---------------------------------------------------------------------------
# [ETAPA 3] Analise de frequencia de cada subconjunto
# [ETAPA 4] Comparacao com a distribuicao esperada da lingua
# [ETAPA 5] Candidatos para cada caractere da chave
# ---------------------------------------------------------------------------

def frequencias(coluna, alfabeto):
    """Contagem absoluta de cada simbolo do alfabeto na coluna. [ETAPA 3]"""
    contagem = Counter(coluna)
    return [contagem.get(ch, 0) for ch in alfabeto]


def qui_quadrado(observado, esperado_prob, n):
    """
    Distancia do qui-quadrado entre a distribuicao observada e a esperada. [ETAPA 4]

        X2 = sum_i (O_i - E_i)^2 / E_i,   com E_i = p_i * n

    Quanto MENOR, melhor o encaixe. Simbolos de probabilidade esperada nula que
    aparecem no texto recebem penalidade fixa (nao ha divisao por zero possivel).

    O valor e dividido por n antes de ser devolvido. Isso e essencial: o
    qui-quadrado bruto cresce com o tamanho da amostra, entao comparar o custo de
    uma chave de tamanho 4 (colunas longas) com o de uma de tamanho 12 (colunas
    curtas) sem normalizar favoreceria sistematicamente a chave mais longa. E
    justamente esse vies que faz um ataque ingenuo reportar "LIMALIMALIMA" no
    lugar de "LIMA". Normalizado, o custo vira uma medida por simbolo e os
    tamanhos ficam comparaveis entre si.
    """
    if n == 0:
        return float('inf')
    total = 0.0
    for obs, prob in zip(observado, esperado_prob):
        esp = prob * n
        if esp > 0:
            total += (obs - esp) ** 2 / esp
        elif obs > 0:
            total += obs * 100.0
    return total / n


def candidatos_letra(coluna, alfabeto, esperado_prob, quantos=3):
    """
    Testa todos os deslocamentos possiveis da coluna e ranqueia. [ETAPA 5]

    Para cada deslocamento s, desfaz o Cesar (c - s) e mede o qui-quadrado
    contra a distribuicao da lingua. O s de menor qui-quadrado corresponde a
    letra da chave naquela posicao.
    """
    indice = {ch: i for i, ch in enumerate(alfabeto)}
    tamanho = len(alfabeto)
    n = len(coluna)

    resultados = []
    for s in range(tamanho):
        observado = [0] * tamanho
        for ch in coluna:
            observado[(indice[ch] - s) % tamanho] += 1
        resultados.append({
            'letra': alfabeto[s],
            'qui_quadrado': qui_quadrado(observado, esperado_prob, n),
        })

    resultados.sort(key=lambda r: r['qui_quadrado'])
    return resultados[:quantos]


# ---------------------------------------------------------------------------
# [ETAPA 6] Reconstrucao da chave e decifracao
# ---------------------------------------------------------------------------

def recupera_chave(ct, tamanho_chave, alfabeto, esperado_prob):
    """Resolve cada coluna e concatena as letras vencedoras. [ETAPA 6]"""
    chave = ""
    custo_total = 0.0
    detalhes = []
    for i, coluna in enumerate(separa_em_colunas(ct, tamanho_chave)):
        candidatos = candidatos_letra(coluna, alfabeto, esperado_prob)
        chave += candidatos[0]['letra']
        custo_total += candidatos[0]['qui_quadrado']
        detalhes.append({'coluna': i, 'amostras': len(coluna), 'candidatos': candidatos})
    return chave, custo_total / tamanho_chave, detalhes


def decifra(ct, chave, alfabeto):
    """
    Decifracao de Vigenere: p_i = (c_i - k_(i mod L)) mod |alfabeto|. [ETAPA 6]
    """
    indice = {ch: i for i, ch in enumerate(alfabeto)}
    tamanho = len(alfabeto)
    L = len(chave)
    return "".join(
        alfabeto[(indice[ch] - indice[chave[i % L]]) % tamanho]
        for i, ch in enumerate(ct)
    )


# ---------------------------------------------------------------------------
# [ETAPA 7] Avaliacao do resultado e refinamento
# ---------------------------------------------------------------------------

def ataque(ct, alfabeto=ALFABETO_26, idioma=None, tamanho_max=20, quantos_testar=8):
    """
    Executa o ataque completo e devolve o melhor resultado.

    Refinamento: em vez de confiar cegamente no candidato de tamanho mais bem
    ranqueado por Kasiski, decifra com CADA candidato forte e escolhe o que
    produz o texto mais parecido com a lingua alvo (menor qui-quadrado medio).
    Quando o idioma nao e informado, testa portugues e ingles e escolhe o melhor
    — o que tambem serve como deteccao automatica de lingua.
    """
    ranking, n_distancias, n_repeticoes = candidatos_tamanho_chave(
        ct, tamanho_max=tamanho_max
    )
    if not ranking:
        raise ValueError(
            "Nenhum n-grama repetido encontrado. O ciphertext e curto demais "
            "para o exame de Kasiski."
        )

    candidatos = melhores_candidatos(ranking, quantos=quantos_testar)
    idiomas = [idioma] if idioma else list(TABELAS)

    tentativas = []
    for lang in idiomas:
        esperado = tabela_esperada(alfabeto, lang)
        for cand in candidatos:
            chave, custo, detalhes = recupera_chave(
                ct, cand['tamanho'], alfabeto, esperado
            )
            tentativas.append({
                'idioma': lang,
                'tamanho': cand['tamanho'],
                'razao_kasiski': cand['razao'],
                'chave': chave,
                'custo': custo,
                'detalhes': detalhes,
                'plaintext': decifra(ct, chave, alfabeto),
            })

    tentativas.sort(key=lambda t: (t['custo'], t['tamanho']))

    # Decide em duas etapas. Primeiro a lingua: um plaintext em portugues lido
    # com a tabela do ingles produz custo visivelmente pior, entao o menor custo
    # global identifica o idioma.
    idioma_vencedor = tentativas[0]['idioma']
    do_idioma = [t for t in tentativas if t['idioma'] == idioma_vencedor]

    # Depois o tamanho. Uma chave e seus multiplos decifram o mesmo texto e por
    # isso empatam em custo; entre empates tecnicos (5%) fica a MAIS CURTA, que
    # e a chave real. Sem esta regra o ataque reportaria "LIMALIMALIMA".
    menor_custo = do_idioma[0]['custo']
    empatados = [t for t in do_idioma if t['custo'] <= menor_custo * 1.05]
    melhor = min(empatados, key=lambda t: (t['tamanho'], t['custo']))

    return {
        'melhor': melhor,
        'tentativas': tentativas,
        'ranking': ranking,
        'n_distancias': n_distancias,
        'n_repeticoes': n_repeticoes,
        'candidatos_testados': candidatos,
    }


# ---------------------------------------------------------------------------
# Apresentacao dos resultados
# ---------------------------------------------------------------------------

def relatorio(resultado, ct, verboso=False):
    r = resultado
    m = r['melhor']
    linhas = []
    add = linhas.append

    add("=" * 68)
    add("ATAQUE DE KASISKI + QUI-QUADRADO")
    add("=" * 68)
    add(f"Ciphertext: {len(ct)} simbolos")
    add("")

    add("[ETAPA 1] Estimativa do tamanho da chave (exame de Kasiski)")
    add(f"  n-gramas repetidos (n=3..5): {r['n_repeticoes']}")
    add(f"  distancias analisadas      : {r['n_distancias']}")
    add("")
    add(f"  {'tam.':>5} | {'divisiveis':>10} | {'fracao':>7} | {'evidencia':>9}")
    add(f"  {'-'*5}-+-{'-'*10}-+-{'-'*7}-+-{'-'*9}")
    for item in sorted(r['ranking'], key=lambda x: x['razao'], reverse=True)[:8]:
        marca = "  <<<" if item['tamanho'] == m['tamanho'] else ""
        add(f"  {item['tamanho']:>5} | {item['divisiveis']:>10} | "
            f"{item['fracao']:>7.3f} | {item['razao']:>9.2f}{marca}")
    add("")
    add(f"  Evidencia 1.00 = compativel com o acaso. Candidatos testados: "
        f"{[c['tamanho'] for c in r['candidatos_testados']]}")
    add("")

    add(f"[ETAPA 2] Separacao em {m['tamanho']} colunas "
        f"(~{len(ct)//m['tamanho']} simbolos cada)")
    add("")

    add("[ETAPAS 3-5] Analise de frequencia e candidatos por coluna")
    add(f"  {'col':>4} | {'amostras':>8} | 1o (X2)          2o                3o")
    add(f"  {'-'*4}-+-{'-'*8}-+-{'-'*46}")
    for d in m['detalhes']:
        c = d['candidatos']
        trio = "  ".join(f"{x['letra']} ({x['qui_quadrado']:>7.1f})" for x in c)
        add(f"  {d['coluna']:>4} | {d['amostras']:>8} | {trio}")
    add("")

    add("[ETAPAS 6-7] Chave reconstruida e verificacao")
    add(f"  idioma detectado : {m['idioma'].upper()}")
    add(f"  tamanho da chave : {m['tamanho']}")
    add(f"  CHAVE            : {m['chave']}")
    add(f"  qui-quadrado medio: {m['custo']:.2f}")
    add("")

    if verboso:
        add("  Hipoteses testadas (todas as combinacoes):")
        add(f"    {'idioma':>6} | {'tam.':>4} | {'chave':<20} | {'X2 medio':>9}")
        add(f"    {'-'*6}-+-{'-'*4}-+-{'-'*20}-+-{'-'*9}")
        for t in r['tentativas']:
            marca = "  <<<" if t is m else ""
            add(f"    {t['idioma']:>6} | {t['tamanho']:>4} | {t['chave']:<20} | "
                f"{t['custo']:>9.2f}{marca}")
        add("")

    add("-" * 68)
    add("PLAINTEXT RECUPERADO")
    add("-" * 68)
    texto = m['plaintext']
    for i in range(0, len(texto), 68):
        add(texto[i:i + 68])

    return "\n".join(linhas)


# ---------------------------------------------------------------------------
# Interface de linha de comando
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="Ataque a cifra de Vigenere por exame de Kasiski e qui-quadrado.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Se nenhum arquivo for dado, o ciphertext e lido da entrada padrao.",
    )
    p.add_argument('-a', '--arquivo', help="arquivo com o ciphertext")
    p.add_argument('--idioma', choices=['pt', 'en'],
                   help="lingua do plaintext (se omitido, detecta automaticamente)")
    p.add_argument('--alfabeto', choices=['26', '98'], default='26',
                   help="alfabeto usado na cifragem (padrao: 26)")
    p.add_argument('--tamanho-max', type=int, default=20,
                   help="maior tamanho de chave considerado (padrao: 20)")
    p.add_argument('-v', '--verboso', action='store_true',
                   help="mostra todas as hipoteses testadas")
    args = p.parse_args()

    bruto = open(args.arquivo, encoding='utf-8').read() if args.arquivo else sys.stdin.read()
    alfabeto = ALFABETO_26 if args.alfabeto == '26' else ALFABETO_98

    ct = normaliza(bruto, alfabeto)
    if len(ct) < 20:
        sys.exit(f"Erro: ciphertext com apenas {len(ct)} simbolos validos "
                 f"no alfabeto de {len(alfabeto)}. Verifique o arquivo e o --alfabeto.")

    try:
        resultado = ataque(ct, alfabeto=alfabeto, idioma=args.idioma,
                           tamanho_max=args.tamanho_max)
    except ValueError as e:
        sys.exit(f"Erro: {e}")

    print(relatorio(resultado, ct, verboso=args.verboso))


if __name__ == '__main__':
    main()
