import streamlit as st
import rsa
from Crypto.Util import number

st.set_page_config(
        page_title="Asymmetric Encryption",
        page_icon="🔑",
    )

st.write("# WELCOME TO ASYMMETRIC ENCRYPTION!:sunglasses::fire:")

encryption_type = st.selectbox("Select Encryption Algorithm", ["Diffie-Hellman", "RSA"])

if encryption_type == "RSA":

    
    st.write("""
        #### HOW IT WORKS?
        1. Generate RSA public and private keys.
        2. Enter the plaintext message.
        3. Encrypt the message using the recipient's public key.
        4. Decrypt the message using the recipient's private key.
        """)
    
    publickey, privatekey = rsa.newkeys(1024)
    text = st.text_area("Enter your message: ").encode('utf8')

    if st.button("Encrypt"):
        st.write("## Encrypted text in bytes:")
        ciphertext = rsa.encrypt(text, publickey)
        st.code(ciphertext)
        st.write("## Encrypted text in hex:")
        st.code(ciphertext.hex())

        decrypted = rsa.decrypt(ciphertext, privatekey)
        st.write("## Decrypted text:")
        st.code(decrypted.decode('utf8'))

elif encryption_type == "Diffie-Hellman":
        
    st.write("""
        #### HOW IT WORKS?
        1. Choose a prime number (p) and a generator (g).
        2. Choose private keys (a and b).
        3. Generate shared secret keys for Alice and Bob using the Diffie-Hellman key exchange algorithm.
        4. Encrypt and decrypt messages using the shared secret key.
        """)

    def modexp(b, e, m):
        """Efficient modular exponentiation"""
        result = 1
        b = b % m
        while e > 0:
            if e % 2 == 1:
                result = (result * b) % m
            e = e >> 1
            b = (b * b) % m
        return result

    def generate_shared_secret(p, g, a, b):
        """Generate shared secret using Diffie-Hellman key exchange"""
        A = modexp(g, a, p)
        B = modexp(g, b, p)
        secret_A = modexp(B, a, p)
        secret_B = modexp(A, b, p)
        if secret_A == secret_B:
            return secret_A
        else:
            return None

    def encrypt(text, key):
        """Encrypt plaintext using a key"""
        return ''.join([chr((ord(char) + key) % 256) for char in text])

    def decrypt(text, key):
        """Decrypt ciphertext using a key"""
        return ''.join([chr((ord(char) - key) % 256) for char in text])

    st.write("## Diffie-Hellman Encryption and Decryption")
    col1, col2 = st.columns(2)

    with col1:
        p = st.number_input("Enter a prime number (p):", min_value=2, step=1)
        g = st.number_input("Enter a generator (g):", min_value=2, step=1)

    with col2:
        a = st.number_input("A private key (a):", min_value=1, step=1)
        b = st.number_input("B private key (b):", min_value=1, step=1)

    shared_secret = generate_shared_secret(p, g, a, b)

    if shared_secret:
        st.write(f"Shared Secret Key: {shared_secret}")

        plaintext = st.text_input("Enter the plaintext:")
        if st.button("Encrypt"):
            encrypted_text = encrypt(plaintext, shared_secret)
            st.write(f"## :green[Encrypted text]: {encrypted_text}")
            
            decrypted_text = decrypt(encrypted_text, shared_secret)
            st.write(f"## :red[Decrypted text]: {decrypted_text}")

    else:
        st.write("Invalid private keys. Please choose different private keys.")
