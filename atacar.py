#!/usr/bin/env python3
# Roda os DOIS ataques sobre o mesmo criptograma e compara as estimativas.
#
#   Kasiski  - tamanho da chave pelas distancias entre trechos repetidos
#   Friedman - tamanho da chave pelo Indice de Coincidencia (__main__.py)
#
# Sao caminhos independentes: quando concordam, a estimativa e confiavel.

import contextlib, importlib.util, io, os

import kasiski

# O ataque por IoC esta em __main__.py, nome reservado pelo Python, entao
# precisa ser carregado pelo caminho do arquivo em vez de "import".
_spec = importlib.util.spec_from_file_location(
    "ioc", os.path.join(os.path.dirname(os.path.abspath(__file__)), "__main__.py"))
ioc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ioc)


def tamanho_por_ioc(ct):
    with contextlib.redirect_stdout(io.StringIO()):   # silencia prints internos
        return ioc.estimate_key_length(ct)


if __name__ == "__main__":
    chave_real = "CRIPTOGRAFIA"
    msg = kasiski.normaliza("""
        A seguranca de um sistema criptografico nunca deve depender do segredo
        do algoritmo, mas apenas do segredo da chave. Este principio ficou
        conhecido como a maxima de Kerckhoffs. Um sistema que depende do
        segredo do algoritmo para se manter seguro sera quebrado assim que o
        algoritmo vazar, e algoritmos sempre vazam com o tempo. Por isso os
        padroes modernos de criptografia sao publicados abertamente e
        submetidos ao escrutinio da comunidade cientifica. A confianca em um
        algoritmo nasce do fato de que muitos pesquisadores tentaram quebra-lo
        e nao conseguiram. Um algoritmo secreto nunca passou por esse teste.
        """)
    ct = "".join(kasiski.ALFABETO[(kasiski.ALFABETO.index(c)
                 + kasiski.ALFABETO.index(chave_real[i % len(chave_real)])) % 26]
                 for i, c in enumerate(msg))

    print(f"criptograma: {len(ct)} letras\n")

    candidatos, _ = kasiski.candidatos_tamanho(ct)
    tam_ioc = tamanho_por_ioc(ct)

    print("Estimativa do tamanho da chave:")
    print(f"   Kasiski  : {candidatos}")
    print(f"   Friedman : {tam_ioc}")
    if tam_ioc in candidatos:
        print(f"   -> concordam: {tam_ioc} esta entre os candidatos do Kasiski\n")
    else:
        print(f"   -> divergem: o criptograma pode estar curto demais\n")

    chave, texto, idioma = kasiski.ataque(ct, verboso=False)
    print(f"chave recuperada: {chave}   (real: {chave_real})")
    print(f"idioma detectado: {idioma}")
    print(f"texto decifrado : {texto[:60]}...")
