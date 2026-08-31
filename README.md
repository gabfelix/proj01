# Projeto 1 — Cifra de Vigenère

CIC0201 · Segurança Computacional · UnB

Implementação da cifra de Vigenère e de **dois ataques independentes** de
recuperação de chave.

## Requisitos

Python 3.12 ou superior. Sem dependências externas — apenas a biblioteca padrão.

```bash
python3 --version   # precisa ser >= 3.12
```

## Arquivos

| Arquivo | Conteúdo |
|---|---|
| `ciphers.py` | Classe `VigenereCipher` — cifração e decifração |
| `__main__.py` | Ataque por Índice de Coincidência (teste de Friedman) |
| `kasiski.py` | Ataque por exame de Kasiski + qui-quadrado |
| `teste_kasiski.py` | Suíte de validação do ataque de Kasiski |
| `exemplo_ct.txt` | Criptograma de exemplo (chave `SEGURANCA`, português) |

## Parte I — Cifrar e decifrar

```python
from ciphers import VigenereCipher

cifra = VigenereCipher("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
ct = cifra.encrypt("ATACARBASESUL", "LIMAO")
pt = cifra.decrypt(ct, "LIMAO")
```

Caracteres fora do alfabeto passam sem alteração e não consomem letra da chave.
Use `strict=True` para que eles gerem erro em vez de passar.

## Parte II — Ataque por Índice de Coincidência

```bash
python3 __main__.py
```

Estima o tamanho da chave pelo IoC (teste de Friedman) e recupera cada letra por
média ponderada de frequências. Opera sobre o alfabeto estendido de 98 símbolos.

## Parte II — Ataque por exame de Kasiski

```bash
python3 kasiski.py -a exemplo_ct.txt --verboso
```

Estima o tamanho da chave pelas distâncias entre n-gramas repetidos e recupera
cada letra pelo teste do qui-quadrado. Detecta o idioma automaticamente.

Opções:

```
-a, --arquivo ARQ     arquivo com o criptograma (padrão: entrada padrão)
    --idioma pt|en    força o idioma (padrão: detecta)
    --alfabeto 26|98  alfabeto usado na cifragem (padrão: 26)
    --tamanho-max N   maior tamanho de chave considerado (padrão: 20)
-v, --verboso         mostra todas as hipóteses testadas
```

Também aceita entrada padrão:

```bash
cat criptograma.txt | python3 kasiski.py --idioma pt
```

### Validação

```bash
python3 teste_kasiski.py
```

Cifra textos conhecidos com chaves conhecidas e verifica a recuperação. Cobre
português e inglês, os dois alfabetos, chaves de 3 a 22 letras, e mede a
degradação com criptogramas curtos.

## Nota sobre o alfabeto

O alfabeto define o módulo da aritmética da cifra. Um criptograma gerado sobre 26
símbolos **não** pode ser atacado com aritmética de 98 símbolos, nem o contrário —
as operações de transbordo diferem e o resultado é ruído, mesmo com a chave
correta. Ao atacar um criptograma de origem externa, confirme em que alfabeto ele
foi gerado e use `--alfabeto` de acordo.
