import streamlit as st
import json
import os
from cryptography.fernet import Fernet
import hashlib
import time
import base64

# ----------------------------- UI Styling -----------------------------
def get_base64_image(image_path):
    with open(image_path, "rb") as img_file:
        return base64.b64encode(img_file.read()).decode()

def custom_ui():
    img_base64 = get_base64_image("bgg.jpeg")
    st.markdown(f"""
    <style>
    html, body, .stApp {{
        height: 100%;
        margin: 0;
        padding: 0;
        background-image: url("data:image/jpeg;base64,{img_base64}");
        background-size: cover;
        background-position: center;
        background-repeat: no-repeat;
        color: white;
        font-family: 'Segoe UI', sans-serif;
    }}
    .title {{
        font-size: 2.5rem;
        text-align: center;
        margin-bottom: 1rem;
        color: white;
        font-weight: bold;
        animation: fadeIn 2s ease-in-out;
    }}
    .main-container {{
        background: rgba(255, 255, 255, 0.1);
        padding: 2rem;
        border-radius: 15px;
        box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
        backdrop-filter: blur(7px);
        -webkit-backdrop-filter: blur(7px);
        width: 90%;
        max-width: 500px;
        margin: 0 auto;
        margin-top: 3rem;
        animation: slideUp 1s ease-in-out;
    }}
    .stTextInput > div > input,
    .stPasswordInput > div > input {{
        background-color: rgba(255,255,255,0.05);
        color: white;
        border-radius: 10px;
        padding: 0.5rem;
    }}
    .stButton button {{
        background-color: #60a5fa;
        color: white;
        border: none;
        border-radius: 10px;
        padding: 0.5rem 1rem;
        font-weight: bold;
        width: 100%;
        max-width: 400px;
        transition: background-color 0.3s;
    }}
    .stButton button:hover {{
        background-color: #3b82f6;
    }}
    .stAlert {{
        padding: 0.75rem 1.25rem;
        margin-top: 1rem;
        border-radius: 8px;
        animation: fadeIn 0.5s ease-in-out;
    }}
    .stAlert.success {{ background-color: #28a745; }}
    .stAlert.error {{ background-color: #dc3545; }}
    .stAlert.warning {{ background-color: #ffc107; color: black; }}

    @keyframes fadeIn {{
        from {{ opacity: 0; transform: translateY(-10px); }}
        to {{ opacity: 1; transform: translateY(0); }}
    }}
    @keyframes slideUp {{
        from {{ transform: translateY(50px); opacity: 0; }}
        to {{ transform: translateY(0); opacity: 1; }}
    }}
    </style>
    """, unsafe_allow_html=True)

# ----------------------------- Security Functions -----------------------------
users_file = "users.json"
secrets_file = "secrets.json"
key_file = "secret.key"
lockout_time = 30  # seconds

if not os.path.exists(key_file):
    with open(key_file, 'wb') as f:
        f.write(Fernet.generate_key())

def load_key():
    with open(key_file, 'rb') as f:
        return f.read()

def load_data(file):
    if os.path.exists(file):
        with open(file, 'r') as f:
            return json.load(f)
    return {}

def save_data(data, file):
    with open(file, 'w') as f:
        json.dump(data, f, indent=4)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ----------------------------- App Logic -----------------------------
def register():
    st.subheader("Register")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Register"):
        if username and password:
            users = load_data(users_file)
            if username in users:
                st.warning("User already exists!")
            else:
                users[username] = {
                    "password": hash_password(password),
                    "attempts": 0,
                    "lockout": 0
                }
                save_data(users, users_file)
                st.success("User registered successfully!")
        else:
            st.warning("Fill all fields.")

def login():
    st.subheader("Login")
    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type="password", key="login_password")

    if st.button("Login"):
        users = load_data(users_file)
        if username in users:
            user = users[username]
            if time.time() < user.get("lockout", 0):
                st.error("Account locked. Try again later.")
            elif user["password"] == hash_password(password):
                user["attempts"] = 0
                user["lockout"] = 0
                save_data(users, users_file)
                st.session_state["user"] = username
                st.success("Logged in successfully!")
            else:
                user["attempts"] += 1
                if user["attempts"] >= 3:
                    user["lockout"] = time.time() + lockout_time
                    st.error("Too many attempts. Locked for 30 seconds.")
                else:
                    st.warning("Incorrect password.")
                save_data(users, users_file)
        else:
            st.warning("User does not exist.")

def encrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.decrypt(data.encode()).decode()

def secret_manager():
    st.subheader("Encrypt & Decrypt Secrets")
    secrets = load_data(secrets_file)
    key = load_key()
    
    user_secrets = secrets.get(st.session_state["user"], {})
    
    secret_input = st.text_input("Enter Secret")
    if st.button("Encrypt & Save"):
        encrypted = encrypt_data(secret_input, key)
        user_secrets[str(len(user_secrets)+1)] = encrypted
        secrets[st.session_state["user"]] = user_secrets
        save_data(secrets, secrets_file)
        st.success("Secret saved securely.")

    st.subheader("Manual Decryption")
    decrypt_input = st.text_input("Enter Encrypted Text")
    if st.button("Decrypt"):
        try:
            decrypted = decrypt_data(decrypt_input, key)
            st.success(f"Decrypted Data: {decrypted}")
        except Exception:
            st.error("Invalid encrypted string.")

    if user_secrets:
        st.write("### Your Secrets:")
        for k, v in user_secrets.items():
            with st.expander(f"Secret {k}"):
                st.code(decrypt_data(v, key))

def main():
    custom_ui()
    st.markdown("<div class='title'>🔐 Secure Data Encryption System</div>", unsafe_allow_html=True)

    if "user" not in st.session_state:
        st.markdown("<div class='main-container'>", unsafe_allow_html=True)
        menu = st.radio("Choose an option:", ["Login", "Register"])
        if menu == "Login":
            login()
        else:
            register()
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.markdown("<div class='main-container'>", unsafe_allow_html=True)
        st.success(f"Welcome, {st.session_state['user']}!")
        secret_manager()
        if st.button("Logout"):
            st.session_state.pop("user")
        st.markdown("</div>", unsafe_allow_html=True)

if __name__ == "__main__":
    main()
