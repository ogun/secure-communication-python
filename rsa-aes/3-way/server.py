from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

RSA_KEY = RSA.generate(2048)


def send_public_key():
    return RSA_KEY.publickey()


def get_decrypted(enc_session_key: bytes, nonce, tag, cipher_text):
    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(RSA_KEY)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(cipher_text, tag)

    return data.decode("utf-8")

