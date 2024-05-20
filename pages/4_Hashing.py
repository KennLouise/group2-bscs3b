import streamlit as st
import hashlib

st.set_page_config(
        page_title="Hashing Encryption",
        page_icon="💼",
    )

st.write("# Hashing Functions")

hash_type = st.selectbox("Select Hashing Algorithm", ["MD5", "SHA1", "SHA256", "SHA512"])

if hash_type == "MD5":
    st.write("""
        ### MD5 Hash:
        MD5 (Message Digest Algorithm 5) is a widely used cryptographic hash function that produces a 128-bit (16-byte) hash value. It is commonly used to verify the integrity of data. However, MD5 is not collision-resistant and is not suitable for use in cryptographic applications that rely on this property.
        """)
elif hash_type == "SHA1":
    st.write("""
    ### SHA1 Hash:
    SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function that produces a 160-bit (20-byte) hash value. Like MD5, SHA-1 is also widely used to verify data integrity. However, SHA-1 is also not collision-resistant and is considered to be less secure than SHA-256 and SHA-512.
    """)
elif hash_type == "SHA256":
    st.write("""
    ### SHA256 Hash:
    SHA-256 (Secure Hash Algorithm 256-bit) is a cryptographic hash function that produces a 256-bit (32-byte) hash value. It is a part of the SHA-2 family of hashing algorithms and is considered to be more secure than MD5 and SHA-1.
    """)
elif hash_type == "SHA512":
    st.write("""
    ### SHA512 Hash:
    SHA-512 (Secure Hash Algorithm 512-bit) is a cryptographic hash function that produces a 512-bit (64-byte) hash value. It is also a part of the SHA-2 family and is more secure than SHA-256, especially for longer messages.
    """)

st.write("""
    #### Process:
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

