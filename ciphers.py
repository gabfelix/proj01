class VigenereCipher:
    def __init__(self, alphabet: list[str] | str):
        if not alphabet:
            raise ValueError("Alphabet cannot be empty.")
        if len(set(alphabet)) != len(alphabet):
            raise ValueError("Alphabet contains duplicate characters.")
        
        self.alphabet = list(alphabet)
        self._alphabet_set = set(self.alphabet)
        self.alphabet_size = len(self.alphabet)

    def encrypt(self, plaintext: str, key: str, strict: bool = False) -> str:
        """Encrypts text. strict=True raises ValueError on unknown characters."""
        return self._process(plaintext, key, direction=1, strict=strict)

    def decrypt(self, ciphertext: str, key: str, strict: bool = False) -> str:
        """Decrypts text. strict=True raises ValueError on unknown characters."""
        return self._process(ciphertext, key, direction=-1, strict=strict)

    def _process(self, text: str, key: str, direction: int, strict: bool) -> str:
        if not text or not key:
            raise ValueError("Text and key must not be empty.")

        # Sanitize key: drop characters not in the alphabet
        valid_key = [c for c in key if c in self._alphabet_set]
        if not valid_key:
            raise ValueError("Key contains no valid alphabet characters.")
        
        key_len = len(valid_key)
        key_idx = 0
        result = []

        for char in text:
            if char in self._alphabet_set:
                p_num = self.alphabet.index(char)
                k_num = self.alphabet.index(valid_key[key_idx % key_len])
                
                # Apply shift
                c_num = (p_num + (direction * k_num)) % self.alphabet_size
                result.append(self.alphabet[c_num])
                
                # Advance key ONLY when a valid character is processed
                key_idx += 1
            else:
                if strict:
                    raise ValueError(f"Character '{char}' not in defined alphabet.")
                # Pass through ignored characters
                result.append(char)

        return "".join(result)


# Alfabetos padrão do projeto. Definidos junto do cifrador para o ataque por
# IoC (__main__.py) usar o mesmo módulo aritmético da cifragem.

ALFABETO_26 = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

ALFABETO_98 = list(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "ÁÀÂÃÄÉÈÊËÍÌÎÏÓÒÔÕÖÚÙÛÜÇ"
    "áàâãäéèêëíìîïóòôõöúùûüç"
)


# Frequência esperada das letras (%), por idioma. Usadas pelos dois ataques
# para comparar cada coluna com a distribuição da língua.

# Português do Brasil — B. R. Braga, "Análise de frequências de línguas",
# RAVEL/COPPE/UFRJ, 2003. Medido sobre 1,1 MB de textos de autores brasileiros.
# O estudo desconsidera acentos e trata Ç como C, mesma normalização que
# aplicamos ao reduzir o texto ao alfabeto de 26 letras.
FREQ_PT = {
    'A': 14.64, 'B': 1.16, 'C': 3.76, 'D': 4.97, 'E': 12.70, 'F': 1.02,
    'G': 1.29, 'H': 1.42, 'I': 5.90, 'J': 0.32, 'K': 0.01, 'L': 2.95,
    'M': 4.71, 'N': 4.85, 'O': 10.78, 'P': 2.58, 'Q': 1.09, 'R': 6.88,
    'S': 7.97, 'T': 4.26, 'U': 4.42, 'V': 1.68, 'W': 0.01, 'X': 0.23,
    'Y': 0.01, 'Z': 0.42,
}

# Inglês — H. Beker e F. Piper, "Cipher Systems: The Protection of
# Communications", Wiley, 1982, p. 397. Amostra de 100.362 caracteres.
FREQ_EN = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702, 'F': 2.228,
    'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153, 'K': 0.772, 'L': 4.025,
    'M': 2.406, 'N': 6.749, 'O': 7.507, 'P': 1.929, 'Q': 0.095, 'R': 5.987,
    'S': 6.327, 'T': 9.056, 'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150,
    'Y': 1.974, 'Z': 0.074,
}
