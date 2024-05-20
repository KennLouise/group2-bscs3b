import streamlit as st
import streamlit.components.v1 as components
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os

st.set_page_config(
        page_title="Symmetric Encryption",
        page_icon="🔑",
    )

st.write("# Symmetric Encryption")

encryption_type = st.selectbox("Select Encryption Algorithm", ["XOR Cipher", "Caesar Cipher","AES"])

st.divider()

if encryption_type == "XOR Cipher":

    def xor_encrypt(plaintext, key):
        """Encrypts plaintext using XOR cipher with the given key."""
        ciphertext = bytearray()
        for i in range(len(plaintext)):
            plaintext_byte = plaintext[i]
            key_byte = key[i % len(key)]
            cipher_byte = plaintext_byte ^ key_byte
            ciphertext.append(cipher_byte)
        return ciphertext

    def xor_decrypt(ciphertext, key):
        """Decrypts ciphertext using XOR cipher with the given key."""
        return xor_encrypt(ciphertext, key)  # XOR decryption is the same as encryption

    # Example usage:
    st.markdown("<h4>XOR Cipher:</h4><p style='text-align: justify;'>The XOR cipher, also known as the Vernam cipher or the one-time pad, is a symmetric encryption algorithm. It operates by taking the plaintext and a secret key of the same length and performing a bitwise XOR operation between each bit of the plaintext and the corresponding bit of the key.</p>", unsafe_allow_html=True)
    
    st.write("""
        #### Process:
        1. Convert the plaintext and the key to bytes.
        2. Iterate through each byte of the plaintext.
        3. XOR each byte of the plaintext with the corresponding byte of the key.
        4. Append the result to the ciphertext.
        5. Decryption is the same as encryption.
        """)
    option = st.radio("Select Input Type:", ("Text", "File"))

    if option == "Text":
        plaintext = bytes(st.text_area("Text:").encode())
        key = bytes(st.text_area("Key:").encode())
        if st.button("Encrypt"):
            col1, col2 = st.columns(2)
            if plaintext == key:
                st.write("Plaintext should not be equal to the key")
            elif len(plaintext.decode()) < len(key.decode()):
                st.write("Plaintext length should be greater than or equal to the key length")
            else:
                with col1:
                    encrypted_text = xor_encrypt(plaintext, key)
                    st.write("Encrypted Text:", encrypted_text.decode())
                with col2:
                    decrypted_text = xor_decrypt(encrypted_text, key)
                    st.write("Decrypted Text:", decrypted_text.decode())

    elif option == "File":
        uploaded_file = st.file_uploader("Upload a file")
        if uploaded_file is not None:
            filetype = os.path.splitext(uploaded_file.name)[-1][1:]
            if filetype == "enc":  # If uploaded file is encrypted
                key = bytes(st.text_area("Key:").encode())
                if st.button("Decrypt"):
                    file_contents = uploaded_file.read()
                    decrypted_file_contents = xor_decrypt(file_contents, key)
                    st.write("File Decrypted")
                    
                    # Get the original file extension
                    original_filename = uploaded_file.name[:-4]
                    st.download_button(
                        label="Download Decrypted File",
                        data=bytes(decrypted_file_contents),  # Convert to bytes
                        file_name=original_filename,
                        mime="application/octet-stream"
                    )
            else:  # If uploaded file is not encrypted
                key = bytes(st.text_area("Key:").encode())
                if st.button("Encrypt"):
                    file_contents = uploaded_file.read()
                    encrypted_file_contents = xor_encrypt(file_contents, key)
                    st.write("File Encrypted")
            
                    st.download_button(
                        label="Download Encrypted File",
                        data=bytes(encrypted_file_contents),  # Convert to bytes
                        file_name=f"{uploaded_file.name}.enc",
                        mime="application/octet-stream"
                    )

elif encryption_type == "Caesar Cipher":

    def encrypt_decrypt_text(text, shift_keys, ifdecrypt):

        result = ""
        
        for n, char in enumerate(text):
            if isinstance(char, int):
                result += chr(char)
            else:
                shift_key = shift_keys[n % len(shift_keys)] 
                if 32 <= ord(char) <= 126:
                    if ifdecrypt:
                        new_char = chr((ord(char) - shift_key - 32 ) % 94 + 32)
                    else:
                        new_char = chr((ord(char) + shift_key - 32 ) % 94 + 32 )
                    result += new_char
                
                else:
                    result += char
        return result

    def encrypt_decrypt_file(file, shift_keys, ifdecrypt):
        result = ""
        file_contents = file.read()
        result = encrypt_decrypt_text(file_contents, shift_keys, ifdecrypt)
        return result

    st.write("<h4>Caesar Cipher:</h4><p style='text-align: justify;'>The Caesar cipher is one of the simplest and most widely known encryption techniques. It is a type of substitution cipher where each letter in the plaintext is shifted a certain number of places down or up the alphabet.</p>", unsafe_allow_html=True)
    
    st.write("""
        #### Process:
        1. Convert each character of the plaintext to its ASCII value.
        2. Shift the ASCII value by the given key value.
        3. If the ASCII value goes beyond the printable ASCII range, wrap around.
        4. Convert the new ASCII value back to its corresponding character.
        """)

    option = st.radio("Select Input Type:", ("Text", "File"))
    text = ""
    file = ""
    if option == "Text":
        text = st.text_area("Plaintext:")
        shift_keys = list(map(int, st.text_area("Shift Keys:").split()))
        if st.button("Encrypt"):
            encrypt = encrypt_decrypt_text(text, shift_keys, ifdecrypt=False)
            decrypt = encrypt_decrypt_text(encrypt, shift_keys, ifdecrypt=True)
            st.write("Encrypted Text:", encrypt)
            st.write("Decrypted text:", decrypt)


    elif option == "File":
        upfile = st.file_uploader("Upload a file")
        if upfile is not None:
            filetype = os.path.splitext(upfile.name)[-1][1:]
            if filetype == "enc":  # If uploaded file is encrypted
                shift_keys = list(map(int, st.text_area("Shift Keys:").split()))
                if st.button("Decrypt"):
                    decrypted_file_contents = encrypt_decrypt_file(upfile, shift_keys, ifdecrypt=True)
                    st.write("File Decrypted")
                    
                    # Get the original file extension
                    original_filename = upfile.name[:-4]
                    st.download_button(
                        label="Download Decrypted File",
                        data=bytes(decrypted_file_contents.encode()),  # No need to convert to bytes
                        file_name=original_filename,
                        mime="application/octet-stream"
                    )
            else:
                shift_keys = list(map(int, st.text_area("Shift Keys:").split()))
                if st.button("Encrypt"):
                    encrypted_file_contents = encrypt_decrypt_file(upfile, shift_keys, ifdecrypt=False)
                    st.write("File Encrypted")
                    
                    # Get the original file extension
                    
                    st.download_button(
                        label="Download Encrypted File",
                        data=bytes(encrypted_file_contents.encode()),
                        file_name=f"{upfile.name}.enc",
                        mime="application/octet-stream"
                    )

elif encryption_type == "AES":

    #  encrypt plaintext
    def encrypt_text(plaintext, key):
        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        return base64.b64encode(cipher.iv + ciphertext)

    #  decrypt ciphertext
    def decrypt_text(ciphertext, key):
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
        return plaintext.decode()

    #  encrypt file
    def encrypt_file(file, key):
        with open(file, "rb") as f:
            plaintext = f.read()
        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.iv + cipher.encrypt(pad(plaintext, AES.block_size))
        encrypted_file_path = file + ".enc"
        with open(encrypted_file_path, "wb") as f:
            f.write(ciphertext)
        return encrypted_file_path

    #  decrypt file
    def decrypt_file(file, key):
        with open(file, "rb") as f:
            ciphertext = f.read()
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
        decrypted_file_path = os.path.splitext(file)[0]
        with open(decrypted_file_path, "wb") as f:
            f.write(plaintext)
        return decrypted_file_path

    st.markdown("<h4>AES Encryption and Decryption:</h4><p style='text-align: justify;'>AES (Advanced Encryption Standard) is a symmetric encryption algorithm used to secure sensitive data. It was established as the standard for encryption by the U.S. National Institute of Standards and Technology (NIST) in 2001. AES operates on blocks of data, and it supports key sizes of 128, 192, or 256 bits.</p>", unsafe_allow_html=True)

    st.write("""
        #### Process:
        1. Choose a key with a length of 16, 24, or 32 bytes.
        2. Enter plaintext for encryption or ciphertext for decryption.
        3. Encrypt or decrypt the text using AES algorithm.
        """)

    option = st.radio("Select Input Type:", ("Text", "File"))

    if option == "Text":
        # Input plaintext
        plaintext = st.text_area("Enter plaintext:", "")

        # Input key
        key = st.text_area("Enter encryption key (16, 24, or 32 bytes):", "")

        if st.button("Encrypt"):
            if plaintext and key:
                try:
                    ciphertext = encrypt_text(plaintext, key.encode())
                    st.success("Ciphertext: " + ciphertext.decode())
                except Exception as e:
                    st.error(f"Encryption failed: {e}")
            else:
                st.warning("Please enter plaintext and encryption key.")

        ciphertext = st.text_input("Enter ciphertext:", "")
        if st.button("Decrypt Text"):
            if ciphertext and key:
                try:
                    plaintext = decrypt_text(ciphertext, key.encode())
                    st.success("Decrypted plaintext: " + plaintext)
                except Exception as e:
                    st.error(f"Decryption failed: {e}")
            else:
                st.warning("Please enter ciphertext and decryption key.")

    elif option == "File":
        uploaded_file = st.file_uploader("Upload a file")
        if uploaded_file is not None:
            filetype = os.path.splitext(uploaded_file.name)[-1][1:]
            if filetype == "enc":  # If uploaded file is encrypted
                key = st.text_input("Enter decryption key (16, 24, or 32 bytes):", "")
                if st.button("Decrypt"):
                    if key:
                        try:
                            with open("temp_file", "wb") as f:
                                f.write(uploaded_file.getvalue())
                            decrypted_file_path = decrypt_file("temp_file", key.encode())
                            st.success("File decrypted successfully!")

                            st.download_button(
                                label="Download Decrypted File",
                                data=open(decrypted_file_path, "rb").read(),
                                file_name=os.path.basename(uploaded_file.name)[:-4],
                                mime="application/octet-stream"
                            )
                        except Exception as e:
                            st.error(f"Decryption failed: {e}")
                        finally:
                            os.remove("temp_file")
                    else:
                        st.warning("Please enter decryption key.")
            else:  # If uploaded file is not encrypted
                key = st.text_input("Enter encryption key (16, 24, or 32 bytes):", "")
                if st.button("Encrypt"):
                    if key:
                        try:
                            with open("temp_file", "wb") as f:
                                f.write(uploaded_file.getvalue())
                            encrypted_file_path = encrypt_file("temp_file", key.encode())
                            st.success("File encrypted successfully!")

                            st.download_button(
                                label="Download Encrypted File",
                                data=open(encrypted_file_path, "rb").read(),
                                file_name=os.path.basename(uploaded_file.name) + ".enc",
                                mime="application/octet-stream"
                            )
                        except Exception as e:
                            st.error(f"Encryption failed: {e}")
                        finally:
                            os.remove("temp_file")
                    else:
                        st.warning("Please enter encryption key.")

