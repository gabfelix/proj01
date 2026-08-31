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


# Frequência esperada das letras (%), por idioma, para comparar cada coluna
# com a distribuição da língua no ataque por IoC.
# Fonte: https://pt.wikipedia.org/wiki/Frequência_de_letras (item 4 do enunciado)

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
