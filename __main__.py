#!/usr/bin/env python3
"""
Ataque à cifra de Vigenère por Índice de Coincidência (teste de Friedman).

Estima o tamanho da chave pelo IoC e, para cada coluna (que é uma cifra de
César), escolhe a letra da chave cuja decifração melhor encaixa na
distribuição de frequência esperada da língua. Testa português e inglês e
fica com o resultado de melhor encaixe -- o que também identifica o idioma.

Opera sobre o alfabeto estendido de 98 símbolos definido em ciphers.py.
"""

from collections import Counter

from ciphers import VigenereCipher, ALFABETO_98 as CUSTOM_ALFABETO, FREQ_PT, FREQ_EN

cipher = VigenereCipher(CUSTOM_ALFABETO)

# As tabelas de ciphers.py são indexadas por A-Z. O texto claro esperado é
# minúsculo; indexamos por minúscula e NÃO normalizamos a caixa ao pontuar --
# neste alfabeto de 98 símbolos maiúscula e minúscula são deslocamentos
# distintos, e uma decifração que cai em maiúsculas indica chave errada.
FREQ = {
    "pt": {c.lower(): v for c, v in FREQ_PT.items()},
    "en": {c.lower(): v for c, v in FREQ_EN.items()},
}


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


def estimate_key_length(ct: str, limite: int = 20) -> int:
    filtered_ct = [c for c in ct if c in cipher.alphabet]
    iocs = []
    for length in range(1, limite + 1):
        columns = ["" for _ in range(length)]
        for i, char in enumerate(filtered_ct):
            columns[i % length] += char
        avg_ioc = sum(ioc(col) for col in columns) / length
        iocs.append((length, avg_ioc))

    # Um tamanho ao acaso deixa o IoC médio perto do valor de língua diluído;
    # o tamanho certo (e seus múltiplos) faz cada coluna virar texto de uma
    # única César, com IoC alto. Pegamos o menor acima de 1,5x a média.
    baseline = sum(ic for _, ic in iocs) / len(iocs)
    threshold = baseline * 1.5

    candidatos = [length for length, ic in iocs if ic > threshold]
    return candidatos[0] if candidatos else -1


def score_text(text: str, freqs: dict) -> float:
    """Soma os pesos de frequência da língua `freqs` para as letras de `text`."""
    return sum(freqs.get(char, 0.0) for char in text)


def crack(ct: str, key_length: int, freqs: dict) -> str:
    """Recupera a chave: em cada coluna, testa toda letra e mantém a de melhor encaixe."""
    filtered_ct = [c for c in ct if c in cipher.alphabet]
    columns = ["" for _ in range(key_length)]
    for i, char in enumerate(filtered_ct):
        columns[i % key_length] += char

    key_guess = ""
    for col in columns:
        best_char, best_score = "", -1.0
        for possible_key_char in cipher.alphabet:
            score = score_text(cipher.decrypt(col, possible_key_char), freqs)
            if score > best_score:
                best_score, best_char = score, possible_key_char
        key_guess += best_char
    return key_guess


def attack(ct: str) -> tuple[str, str, str]:
    """
    Ataque completo. Devolve (idioma, chave, texto_claro).

    Estima o tamanho da chave uma vez e resolve a chave para português e para
    inglês. O idioma verdadeiro produz o texto de maior encaixe médio na sua
    própria tabela de frequência -- é esse que retornamos.
    """
    kl = estimate_key_length(ct)
    if kl < 1:
        raise ValueError("não foi possível estimar o tamanho da chave pelo IoC")

    melhor = None
    for idioma, freqs in FREQ.items():
        chave = crack(ct, kl, freqs)
        texto = cipher.decrypt(ct, chave)
        letras = sum(1 for c in texto if c in freqs)
        encaixe = score_text(texto, freqs) / max(1, letras)
        if melhor is None or encaixe > melhor[0]:
            melhor = (encaixe, idioma, chave, texto)

    _, idioma, chave, texto = melhor
    return idioma, chave, texto


if __name__ == "__main__":
    MSG_PT = (
        "Acriptografiasemprefoiumaferramentaessencialparaahumanidadedesdeostemposantigos"
        "Odesejodeocultarinformaçõesimportantesimpulsionouodesenvolvimentodecifrascomplexas"
        "Quandoolhamosparaaevoluçãodascomunicaçõespercebemosqueanecessidadedeprivacidadeesegurança"
        "moldouatecnologiamodernaHojeemdiausamosalgoritmosmatemáticosavançadosparaproteger"
        "nossosdadospessoaisegarantirqueasmensagenscheguemapenasaosdestinatárioscorretos"
        "Acomplexidadedoalfabetoeamatemáticaportrásdacodificaçãotornamaanáliseestatística"
        "fascinanteedesafiadora"
    )
    MSG_EN = (
        "thevigenereciphersisamethodofencryptingalphabetictextwhereeachletteroftheplaintext"
        "isshiftedalongsomenumberofplacesthemethodusesaseriesofinterwovencaesarcipherschosen"
        "accordingtothelettersofakeywordfirstdescribedbygiovanbattistabellasoinfifteenfifty"
        "threethecipherwaslongthoughttobeunbreakableanditearnedthenicknametheindecipherable"
        "ciphercharlesbabbageandlaterfriedrichkasiskishowedhowtobreakitbyfindingtherepeating"
        "keylengthandthentreatingeachcolumnasasimplesubstitutionthatyieldstoletterfrequency"
        "analysistheindexofcoincidencegivesanotherwaytoestimatethekeylengthbecauseitishigher"
        "fornaturallanguagethanforrandomtext"
    )
    DEMOS = [("limaosinhoinho", "pt", MSG_PT), ("blackcat", "en", MSG_EN)]

    for chave_real, idioma_real, msg in DEMOS:
        ct = cipher.encrypt(msg, chave_real)
        idioma, chave, texto = attack(ct)
        print(f"\n=== demo {idioma_real.upper()} ===")
        print(f"  tam. chave estimado : {estimate_key_length(ct)}")
        print(f"  chave real          : {chave_real}")
        print(f"  chave recuperada    : {chave}")
        print(f"  idioma detectado    : {idioma}  ({'ok' if idioma == idioma_real else 'ERRO'})")
        print(f"  texto recuperado    : {'ok' if texto == msg else 'ERRO'}")
        print(f"  primeiros caracteres: {texto[:70]}...")
