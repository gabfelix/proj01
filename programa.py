#!/usr/bin/env python3
# Programa interativo: cifra, decifra e ataca a cifra de Vigenere.
#
#     python3 programa.py

from ciphers import VigenereCipher
from kasiski import ALFABETO_26, ALFABETO_98, ataque, normaliza


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
    print(f"\n{len(util)} simbolos para analisar...\n")

    try:
        chave, texto, idioma = ataque(ct, alfabeto)
    except ValueError as e:
        print(f"Nao foi possivel atacar: {e}")
        return

    print(f"\nCHAVE ENCONTRADA : {chave}")
    print(f"Idioma detectado : {idioma}")
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
