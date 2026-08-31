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