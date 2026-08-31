# Projeto 1 — Cifra de Vigenère

CIC0201 · Segurança Computacional · UnB

Implementação da cifra de Vigenère e de dois ataques independentes de
recuperação de chave. Requer Python 3.12+, sem dependências externas.

## Arquivos

| Arquivo | Conteúdo |
|---|---|
| `ciphers.py` | Classe `VigenereCipher` — cifração e decifração |
| `__main__.py` | Ataque 1: Índice de Coincidência (teste de Friedman) |
| `kasiski.py` | Ataque 2: exame de Kasiski + qui-quadrado |
| `teste_kasiski.py` | Testes do ataque 2 com chaves conhecidas |
| `atacar.py` | Roda os dois ataques e compara as estimativas |

## Como rodar

```bash
python3 __main__.py        # ataque por Índice de Coincidência
python3 kasiski.py         # ataque por Kasiski
python3 teste_kasiski.py   # testes
python3 atacar.py          # os dois, lado a lado
```

Cada arquivo traz uma mensagem e uma chave de exemplo no bloco `__main__` —
basta editá-las para testar outros casos.

## Cifrar e decifrar

```python
from ciphers import VigenereCipher

cifra = VigenereCipher("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
ct = cifra.encrypt("ATACARBASESUL", "LIMAO")
pt = cifra.decrypt(ct, "LIMAO")
```

Caracteres fora do alfabeto passam sem alteração e não consomem letra da chave.

## Alfabetos

O alfabeto define o módulo da aritmética da cifra: um criptograma gerado sobre
26 símbolos não pode ser decifrado com aritmética de 98 símbolos, nem o
contrário, mesmo com a chave correta. Por isso o ataque precisa usar o mesmo
alfabeto da cifragem.

`kasiski.py` aceita os dois: `ALFABETO_26` (A–Z, remove acentos e pontuação) e
`ALFABETO_98` (o mesmo estendido de `ciphers.py`, com maiúsculas e acentuadas).

```python
from kasiski import ALFABETO_98, ataque
chave, texto, idioma = ataque(criptograma, ALFABETO_98)
```

Para A–Z são usadas as tabelas de frequência publicadas. Para o alfabeto
estendido, que não tem tabela publicada, as frequências são contadas em uma
amostra de texto incluída no arquivo.
