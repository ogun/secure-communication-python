import server
import client


def main():
    text = "hello world"

    public_key = server.send_public_key()
    enc_session_key, nonce, tag, cipher_text = client.send_encrypted(public_key, text)
    decrypted_text = server.get_decrypted(enc_session_key, nonce, tag, cipher_text)

    print(decrypted_text)


main()
