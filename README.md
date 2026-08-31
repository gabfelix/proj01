# Projeto 1 — Cifra de Vigenère

CIC0201 · Segurança Computacional · UnB

Implementação da cifra de Vigenère e de dois ataques independentes de
recuperação de chave. Requer Python 3.10 ou superior (testado em 3.11, 3.12 e
3.13), sem dependências externas.

## Arquivos

| Arquivo | Conteúdo |
|---|---|
| `ciphers.py` | Classe `VigenereCipher` — cifração e decifração |
| `__main__.py` | Ataque 1: Índice de Coincidência (teste de Friedman) |
| `kasiski.py` | Ataque 2: exame de Kasiski + qui-quadrado |
| `teste_kasiski.py` | Testes do ataque 2 com chaves conhecidas |
| `programa.py` | Programa interativo: cifrar, decifrar e atacar |

## Como rodar

Para escolher a mensagem e a chave na hora:

```bash
python3 programa.py
```

Menu com três opções — cifrar, decifrar e atacar — perguntando o alfabeto, a
chave e o texto, com validação das entradas. A opção de ataque roda **os dois
métodos** sobre o mesmo criptograma e compara as estimativas de tamanho da
chave, que é a validação cruzada entre eles.

Para as demonstrações automáticas:

```bash
python3 __main__.py        # ataque por Índice de Coincidência
python3 kasiski.py         # ataque por Kasiski
python3 teste_kasiski.py   # testes
```

Cada uma traz mensagem e chave de exemplo no bloco `__main__` — basta editá-las
para testar outros casos.

## Roteiro de teste

Um percurso completo: cifrar uma mensagem, decifrá-la de volta e depois atacar
o mesmo criptograma sem informar a chave.

```bash
python3 programa.py
```

### 1. Cifrar

| Prompt | Digite |
|---|---|
| `Opcao:` | `1` |
| `Escolha [1]:` | `1` |
| `Chave:` | `LIMAO` |
| `Mensagem` | o parágrafo abaixo |
| linha vazia | Enter |

```
A criptografia sempre foi uma ferramenta essencial para a humanidade desde os tempos antigos. O desejo de ocultar informacoes importantes impulsionou o desenvolvimento de cifras cada vez mais complexas ao longo dos seculos. Quando olhamos para a evolucao das comunicacoes percebemos que a necessidade de privacidade e seguranca moldou a tecnologia moderna de maneira profunda. Hoje usamos algoritmos matematicos avancados para proteger nossos dados pessoais e garantir que as mensagens cheguem apenas aos destinatarios corretos.
```

O criptograma começa em `LKDIDEWSROQQ...`. **Copie-o**, ele é usado nos passos
seguintes.

### 2. Decifrar de volta

Opção `2`, alfabeto `1`, chave `LIMAO`, e cole o criptograma. O texto original
volta em maiúsculas e sem pontuação.

### 3. Atacar sem a chave

Opção `3`, alfabeto `1`, e cole o mesmo criptograma. Agora **não** informe a
chave:

```
--- Tamanho da chave ---
  Kasiski (repeticoes)  : [2, 3, 4, 5, 10, 15, 20]
  Friedman (IoC)        : 20
  -> os dois metodos concordam em 20

--- Chave ---
  Kasiski + qui-quadrado : LIMAO   (idioma: portugues)
```

Repare que o Friedman estimou 20, um múltiplo do tamanho real. É a
superestimação discutida no relatório: uma chave e suas repetições decifram o
mesmo texto, e o qui-quadrado desempata pela mais curta.

### 4. Validação de entrada

Repita o passo 1 digitando a chave em minúsculas (`limao`). Ela é recusada, com
os caracteres inválidos listados.

### 5. O limite do método

Cifre apenas `Atacar a base sul` com a chave `LIMAO` — saem 14 letras,
`LBMCOCINAGPAGL` — e tente atacar o resultado. O ataque recusa em vez de
inventar uma chave:

```
Criptograma curto demais (menos de 20 simbolos).
```

O método precisa de cerca de **25 letras por letra da chave** — chave de 5 quer
125 letras de texto, chave de 12 quer 300. Não é limitação da implementação, é
estatística: com poucas amostras não há distribuição a reconhecer. É por isso
que a cifra de Vigenère resistiu três séculos: ela é segura para mensagens
curtas, e só cede quando muito texto é cifrado com a mesma chave.

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
