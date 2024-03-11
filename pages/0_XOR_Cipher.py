import streamlit as st

st.header("WELCOME TO XOR_CIPHER!:sunglasses::fire:")
st.write("What is your name?")

txt_FNAME = st.text_input("FIRST NAME:")
txt_LNAME = st.text_input("LAST NAME:")

btn_submit = st.button("SUBMIT")

if btn_submit:
    st.success(f"Hello {txt_FNAME} {txt_LNAME}!")