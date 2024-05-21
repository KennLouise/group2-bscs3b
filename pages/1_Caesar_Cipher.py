import streamlit as st

st.header("WELCOME TO CAESAR_CIPHER!:sunglasses::fire:")

encryption_type == "Caesar Cipher"

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