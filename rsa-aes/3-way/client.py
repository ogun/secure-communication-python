from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


def send_encrypted(recipient_key: RSA.RsaKey, text: str):
    session_key = get_random_bytes(32)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the text with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    cipher_text, tag = cipher_aes.encrypt_and_digest(text.encode("utf-8"))

    nonce = cipher_aes.nonce

    return enc_session_key, nonce, tag, cipher_text
