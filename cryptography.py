def caesar_encrypt(message, shift):
    """
    Encrypts a message using the Caesar cipher with the given shift.
    """
    encrypted_message = ""
    for char in message:
        if char.isalpha():
            # Shift the character by the specified amount
            encrypted_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
        else:
            encrypted_char = char
        encrypted_message += encrypted_char
    return encrypted_message

def caesar_decrypt(message, shift):
    """
    Decrypts a message encrypted with the Caesar cipher with the given shift.
    """
    return caesar_encrypt(message, -shift)

def vigenere_encrypt(message, key):
    """
    Encrypts a message using the Vigenere cipher with the given key.
    """
    encrypted_message = ""
    key_index = 0
    for char in message:
        if char.isalpha():
            # Shift the character by the letter value of the key character
            key_char = key[key_index % len(key)]
            shift = ord(key_char.lower()) - ord('a')
            encrypted_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            key_index += 1
        else:
            encrypted_char = char
        encrypted_message += encrypted_char
    return encrypted_message

def vigenere_decrypt(message, key):
    """
    Decrypts a message encrypted with the Vigenere cipher with the given key.
    """
    decrypted_message = ""
    key_index = 0
    for char in message:
        if char.isalpha():
            # Shift the character by the letter value of the key character
            key_char = key[key_index % len(key)]
            shift = ord(key_char.lower()) - ord('a')
            decrypted_char = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            key_index += 1
        else:
            decrypted_char = char
        decrypted_message += decrypted_char
    return decrypted_message