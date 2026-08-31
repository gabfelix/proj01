#!/usr/bin/env python3
# Programa interativo: cifra, decifra e ataca a cifra de Vigenere.
#
#     python3 programa.py

import contextlib
import importlib.util
import io
import os

from ciphers import VigenereCipher
from kasiski import (ALFABETO_26, ALFABETO_98, ataque, candidatos_tamanho,
                     normaliza)

# O ataque por IoC esta em __main__.py, nome reservado pelo Python, entao
# precisa ser carregado pelo caminho do arquivo em vez de "import".
_spec = importlib.util.spec_from_file_location(
    "ioc", os.path.join(os.path.dirname(os.path.abspath(__file__)), "__main__.py"))
ioc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ioc)


def estima_por_ioc(ct):
    """Tamanho da chave estimado pelo Indice de Coincidencia."""
    with contextlib.redirect_stdout(io.StringIO()):   # silencia prints internos
        return ioc.estimate_key_length(ct)


def chave_por_ioc(ct, tamanho):
    """
    Chave recuperada por analise de frequencia (media ponderada).

    crack() no modulo de IoC le a variavel global `ciphertext` em vez do proprio
    parametro, entao definimos a global antes de chamar. Corrigindo aquela linha
    para usar `ct`, esta atribuicao deixa de ser necessaria.
    """
    ioc.ciphertext = ct
    with contextlib.redirect_stdout(io.StringIO()):
        return ioc.crack(ct, tamanho)


def escolhe_alfabeto():
    print("\nAlfabeto:")
    print("  1) 26 letras (A-Z, sem acentos)")
    print("  2) 98 simbolos (maiusculas, minusculas e acentuadas)")
    while True:
        op = input("Escolha [1]: ").strip() or "1"
        if op == "1":
            return ALFABETO_26
        if op == "2":
            return ALFABETO_98
        print("  Opcao invalida.")


def pede_chave(alfabeto):
    """Le a chave e valida que todas as letras existem no alfabeto."""
    while True:
        chave = input("Chave: ").strip()
        if not chave:
            print("  A chave nao pode ser vazia.")
            continue
        invalidos = sorted(set(c for c in chave if c not in alfabeto))
        if invalidos:
            print(f"  Estes caracteres nao existem no alfabeto: {' '.join(invalidos)}")
            if alfabeto == ALFABETO_26:
                print("  No alfabeto de 26 a chave precisa ser so letras MAIUSCULAS sem acento.")
            continue
        return chave


def pede_texto(rotulo):
    print(f"{rotulo} (linha vazia para terminar):")
    linhas = []
    while True:
        linha = input()
        if not linha:
            break
        linhas.append(linha)
    return "\n".join(linhas)


def prepara(texto, alfabeto, rotulo):
    """
    Ajusta o texto ao alfabeto e avisa o que mudou.

    No alfabeto de 26 as minusculas nao existem, entao um texto digitado
    normalmente passaria quase inteiro sem ser cifrado. Convertemos para
    maiusculas e removemos acentos e pontuacao antes de cifrar.
    """
    if alfabeto == ALFABETO_26:
        pronto = normaliza(texto, alfabeto)
        if pronto != texto:
            print(f"\n{rotulo} ajustado ao alfabeto de 26 letras:")
            print(f"  {pronto}")
        return pronto
    return texto


def cifrar():
    alfabeto = escolhe_alfabeto()
    cifra = VigenereCipher(list(alfabeto))
    chave = pede_chave(alfabeto)
    msg = pede_texto("Mensagem")
    if not msg.strip():
        print("Mensagem vazia.")
        return
    msg = prepara(msg, alfabeto, "Texto")
    print("\nCriptograma:")
    print(cifra.encrypt(msg, chave))


def decifrar():
    alfabeto = escolhe_alfabeto()
    cifra = VigenereCipher(list(alfabeto))
    chave = pede_chave(alfabeto)
    ct = pede_texto("Criptograma")
    if not ct.strip():
        print("Criptograma vazio.")
        return
    ct = prepara(ct, alfabeto, "Criptograma")
    print("\nMensagem:")
    print(cifra.decrypt(ct, chave))


def atacar():
    alfabeto = escolhe_alfabeto()
    ct = pede_texto("Criptograma (sem informar a chave)")

    util = normaliza(ct, alfabeto)
    if len(util) < 20:
        print(f"\nSo {len(util)} simbolos validos neste alfabeto. Curto demais,")
        print("ou o criptograma foi gerado com outro alfabeto.")
        return
    print(f"\n{len(util)} simbolos para analisar.")

    # Etapa 1, pelos dois caminhos independentes.
    candidatos, _ = candidatos_tamanho(util)
    tam_ioc = estima_por_ioc(util)

    print("\n--- Tamanho da chave ---")
    print(f"  Kasiski (repeticoes)  : {candidatos or 'nenhuma repeticao'}")
    print(f"  Friedman (IoC)        : {tam_ioc if tam_ioc > 0 else 'nenhuma estimativa'}")
    if tam_ioc > 0 and tam_ioc in candidatos:
        print(f"  -> os dois metodos concordam em {tam_ioc}")
    elif tam_ioc > 0 and candidatos:
        multiplos = [c for c in candidatos if tam_ioc % c == 0]
        if multiplos:
            print(f"  -> compativeis: {tam_ioc} e multiplo de {multiplos}")
        else:
            print(f"  -> divergem; o criptograma pode estar no limite dos metodos")

    # Etapa 2: recuperacao da chave.
    print("\n--- Chave ---")
    try:
        chave, texto, idioma = ataque(ct, alfabeto, verboso=False)
        print(f"  Kasiski + qui-quadrado : {chave}   (idioma: {idioma})")
    except ValueError as e:
        print(f"  Kasiski + qui-quadrado : nao foi possivel ({e})")
        return

    # O ataque por IoC opera sobre o alfabeto de 98; no de 26 ele estima o
    # tamanho, mas nao consegue recuperar as letras, por incompatibilidade
    # de aritmetica.
    if alfabeto == ALFABETO_98 and tam_ioc > 0:
        print(f"  Friedman + media pond. : {chave_por_ioc(util, tam_ioc)}")
    else:
        print(f"  Friedman + media pond. : nao aplicavel no alfabeto de 26")

    print(f"\nTexto decifrado:\n{texto}")


if __name__ == "__main__":
    acoes = {"1": cifrar, "2": decifrar, "3": atacar}
    while True:
        print("\n" + "=" * 50)
        print("CIFRA DE VIGENERE")
        print("=" * 50)
        print("  1) Cifrar uma mensagem")
        print("  2) Decifrar (com a chave)")
        print("  3) Atacar (descobrir a chave)")
        print("  0) Sair")
        op = input("\nOpcao: ").strip()
        if op == "0":
            break
        if op in acoes:
            acoes[op]()
        else:
            print("  Opcao invalida.")
