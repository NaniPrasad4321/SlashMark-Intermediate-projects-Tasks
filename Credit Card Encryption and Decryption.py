from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
import base64

# Function to encrypt credit card information
def encrypt_credit_card(card_number, expiration_date, cvv, key):
    # Concatenate card details into a single string
    plaintext = f"{card_number},{expiration_date},{cvv}"
    
    # Generate a random salt
    salt = get_random_bytes(16)
    
    # Derive a key using scrypt
    derived_key = scrypt(key.encode(), salt, key_len=32, N=2**14, r=8, p=1)
    
    # Create AES cipher object
    cipher = AES.new(derived_key, AES.MODE_CBC)
    
    # Encrypt the plaintext and prepend the IV
    ciphertext = cipher.iv + cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    
    # Encode ciphertext and salt as base64 strings
    encoded_ciphertext = base64.b64encode(ciphertext).decode()
    encoded_salt = base64.b64encode(salt).decode()
    
    return encoded_ciphertext, encoded_salt

# Function to decrypt credit card information
def decrypt_credit_card(encoded_ciphertext, encoded_salt, key):
    # Decode ciphertext and salt from base64 strings
    ciphertext = base64.b64decode(encoded_ciphertext)
    salt = base64.b64decode(encoded_salt)
    
    # Derive key using scrypt
    derived_key = scrypt(key.encode(), salt, key_len=32, N=2**14, r=8, p=1)
    
    # Extract IV from ciphertext
    iv = ciphertext[:16]
    
    # Create AES cipher object
    cipher = AES.new(derived_key, AES.MODE_CBC, iv=iv)
    
    # Decrypt the ciphertext and remove padding
    decrypted_plaintext = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size).decode()
    
    # Split decrypted plaintext into card details
    card_number, expiration_date, cvv = decrypted_plaintext.split(',')
    
    return card_number, expiration_date, cvv

# Example usage
if __name__ == "__main__":
    # Sample credit card details
    card_number = "1234567890123456"
    expiration_date = "12/25"
    cvv = "123"
    
    # Secret key for encryption
    key = "super_secret_key"
    
    # Encrypt credit card information
    encoded_ciphertext, encoded_salt = encrypt_credit_card(card_number, expiration_date, cvv, key)
    print("Encrypted Credit Card Information:")
    print("Encoded Ciphertext:", encoded_ciphertext)
    print("Encoded Salt:", encoded_salt)
    
    # Decrypt credit card information
    decrypted_card_number, decrypted_expiration_date, decrypted_cvv = decrypt_credit_card(encoded_ciphertext, encoded_salt, key)
    print("\nDecrypted Credit Card Information:")
    print("Card Number:", decrypted_card_number)
    print("Expiration Date:", decrypted_expiration_date)
    print("CVV:", decrypted_cvv)
