import streamlit as st
import hashlib

st.set_page_config(
        page_title="Hashing Encryption",
        page_icon="🔑",
    )

st.write("# Hashing Functions")

hash_type = st.selectbox("Select Hashing Algorithm", ["MD5", "SHA1", "SHA256", "SHA512"])



st.write("""
    #### HOW IT WORKS?
    1. If the input is text, encode the text using UTF-8.
    2. Use the selected hashing algorithm to generate the hash value.
    3. Display the hash value.
    """)

option = st.radio("Choose Input Option", ("Enter Text", "Upload File"))

if option == "Enter Text":
    user_input = st.text_area("Enter TEXT: ")
    if st.button("Encrypt!"):
        if hash_type == "MD5":
            result = hashlib.md5(user_input.encode()).hexdigest()
            st.write("MD5 Hash:", result)
        elif hash_type == "SHA1":
            result = hashlib.sha1(user_input.encode()).hexdigest()
            st.write("SHA1 Hash:", result)
        elif hash_type == "SHA256":
            result = hashlib.sha256(user_input.encode()).hexdigest()
            st.write("SHA256 Hash:", result)
        elif hash_type == "SHA512":
            result = hashlib.sha512(user_input.encode()).hexdigest()
            st.write("SHA512 Hash:", result)

elif option == "Upload File":
    uploaded_file = st.file_uploader("Choose a file", type=None)
    if uploaded_file is not None:
        file_content = uploaded_file.getvalue()
        if hash_type == "MD5":
            result = hashlib.md5(file_content).hexdigest()
            st.write("MD5 Hash:", result)
        elif hash_type == "SHA1":
            result = hashlib.sha1(file_content).hexdigest()
            st.write("SHA1 Hash:", result)
        elif hash_type == "SHA256":
            result = hashlib.sha256(file_content).hexdigest()
            st.write("SHA256 Hash:", result)
        elif hash_type == "SHA512":
            result = hashlib.sha512(file_content).hexdigest()
            st.write("SHA512 Hash:", result)
        else:
            user_input = file_content.decode("utf-8")

