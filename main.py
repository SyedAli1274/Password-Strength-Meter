import re
import random
import string
import math
import streamlit as st

# List of common weak passwords to blacklist
COMMON_PASSWORDS = ["password", "123456", "qwerty", "admin", "letmein", "welcome", "password123"]

# Password history (for demonstration purposes only)
if "password_history" not in st.session_state:
    st.session_state.password_history = []

def calculate_entropy(password):
    """
    Calculate the entropy of a password in bits.
    """
    if not password:
        return 0

    # Determine the pool of characters used in the password
    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"\d", password):
        pool_size += 10
    if re.search(r"[!@#$%^&*]", password):
        pool_size += 8

    # Calculate entropy
    entropy = len(password) * math.log2(pool_size) if pool_size else 0
    return entropy

def check_password_strength(password):
    """
    Evaluates the strength of a password based on length, character types, and patterns.
    Provides feedback to improve weak passwords.
    """
    score = 0
    feedback = []

    # Length Check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("❌ Password should be at least 8 characters long (12+ recommended).")

    # Upper & Lowercase Check
    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("❌ Include both uppercase and lowercase letters.")

    # Digit Check
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("❌ Add at least one number (0-9).")

    # Special Character Check
    if re.search(r"[!@#$%^&*]", password):
        score += 1
    else:
        feedback.append("❌ Include at least one special character (!@#$%^&*).")

    # Blacklist Check
    if password.lower() in COMMON_PASSWORDS:
        score = 0
        feedback.append("❌ Password is too common and easily guessable.")

    # Advanced Pattern Detection
    if re.search(r"(.)\1{2,}", password):  # Repeated characters
        feedback.append("❌ Avoid repeated characters (e.g., 'aaa').")
    if re.search(r"(abc|123|qwerty)", password.lower()):  # Sequential patterns
        feedback.append("❌ Avoid common sequential patterns (e.g., '123', 'abc').")

    # Strength Rating
    if score >= 5:
        st.success("✅ Strong Password! Great job!")
    elif score >= 3:
        st.warning("⚠️ Moderate Password - Consider adding more security features.")
    else:
        st.error("❌ Weak Password - Improve it using the suggestions below.")

    # Provide feedback
    if feedback:
        st.write("### Feedback:")
        for suggestion in feedback:
            st.write(suggestion)

    # Display strength score as a progress bar
    st.write("### Password Strength Score")
    st.progress(score / 5)

    # Calculate and display entropy
    entropy = calculate_entropy(password)
    st.write("### Password Entropy")
    st.write(f"Entropy: `{entropy:.2f} bits`")
    if entropy < 40:
        st.warning("⚠️ Low entropy - Password is predictable.")
    elif entropy < 80:
        st.info("ℹ️ Medium entropy - Password is moderately secure.")
    else:
        st.success("✅ High entropy - Password is highly secure.")

def generate_strong_password(length=12, include_uppercase=True, include_digits=True, include_special=True):
    """
    Generates a strong password with customizable options.
    """
    characters = string.ascii_lowercase
    if include_uppercase:
        characters += string.ascii_uppercase
    if include_digits:
        characters += string.digits
    if include_special:
        characters += "!@#$%^&*"

    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def main():
    """
    Main function to run the Streamlit app.
    """
    st.set_page_config(page_title="🔐 Advanced Password Strength Meter", layout="wide")

    # Dark mode / Light mode toggle
    st.sidebar.header("Settings")
    theme = st.sidebar.selectbox("Choose Theme", ["Light", "Dark"])
    if theme == "Dark":
        st.markdown(
            """
            <style>
            .stApp {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            </style>
            """,
            unsafe_allow_html=True,
        )

    # Sidebar for options
    st.sidebar.header("Options")
    option = st.sidebar.radio("Choose an option:", ["Check Password Strength", "Generate Strong Password", "Password History"])

    if option == "Check Password Strength":
        st.header("Check Password Strength")
        password = st.text_input("Enter your password:", type="password", key="password_input")
        if password:
            check_password_strength(password)

    elif option == "Generate Strong Password":
        st.header("Generate Strong Password")
        length = st.number_input("Enter password length:", min_value=8, max_value=50, value=12)
        include_uppercase = st.checkbox("Include Uppercase Letters", value=True)
        include_digits = st.checkbox("Include Digits", value=True)
        include_special = st.checkbox("Include Special Characters", value=True)

        if st.button("Generate Password"):
            password = generate_strong_password(length, include_uppercase, include_digits, include_special)
            st.success(f"✅ Generated Strong Password: `{password}`")
            st.session_state.password_history.append(password)
            st.write("### Password Strength Check:")
            check_password_strength(password)

    elif option == "Password History":
        st.header("Password History")
        if st.session_state.password_history:
            st.write("### Previously Generated Passwords")
            for idx, pwd in enumerate(st.session_state.password_history, 1):
                st.write(f"{idx}. `{pwd}`")
            if st.button("Clear History"):
                st.session_state.password_history.clear()
                st.success("Password history cleared!")
        else:
            st.info("No passwords generated yet.")

if __name__ == "__main__":
    main()