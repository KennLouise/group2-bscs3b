import streamlit as st

st.set_page_config(
        page_title="XOR Cypher",
        page_icon="🔑",
    )

st.write("# WELCOME TO XOR_CIPHER!:sunglasses::fire:")

  
st.write("""
        #### HOW IT WORKS?
        1. Convert the plaintext and the key to bytes.
        2. Iterate through each byte of the plaintext.
        3. XOR each byte of the plaintext with the corresponding byte of the key.
        4. Append the result to the ciphertext.
        5. Decryption is the same as encryption.
        """)

def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key, printing bits involved."""
    ciphertext = bytearray()
    for i in range(len(plaintext)):
        plaintext_byte = plaintext[i]
        key_byte = key[i % len(key)]
        cipher_byte = plaintext_byte ^ key_byte
        st.write(f"Plaintext byte: {format(plaintext_byte, '08b')} = {chr(plaintext_byte)}")
        st.write(f"Key byte:       {format(key_byte, '08b')} = {chr(key_byte)}")
        st.write(f"XOR result:     {format(cipher_byte, '08b')} = {chr(cipher_byte)}")
        st.write("-" * 20)
        ciphertext.append(cipher_byte)
    return ciphertext

def xor_decrypt(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key.
    
    Args:
        ciphertext (bytes): The ciphertext to decrypts.
        key (bytes): The key used for encryption.
        
    Returns:
        bytes: The decrypted plaintext.
    """
    return xor_encrypt(ciphertext, key)

plaintext = bytes(st.text_area("Plaintext:").encode())
key = bytes(st.text_area("Key:").encode())

if st.button("Submit"):
    if plaintext != key:
        if len(plaintext.decode()) >= len(key.decode()):
            try:
                ciphertext = xor_encrypt(plaintext, key)
                st.write("Ciphertext:", ciphertext.decode())
                decrypted = xor_decrypt(ciphertext, key)
                st.write("Decrypted:", decrypted.decode())
            except:
                st.error("Invalid key!")
        else:
            st.error(f"Plaintext lenght should be equal or greater than the lenght of key")
    else:
        st.error(f"Plaintext should not be equal to the key")