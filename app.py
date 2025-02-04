import os
import pandas as pd
import streamlit as st
import google.generativeai as genai
from dotenv import load_dotenv
import re
import time
import bcrypt
from streamlit_authenticator import Authenticate
import yaml
from datetime import datetime

# Configuración inicial
load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("gemini-1.5-flash")

# 1. Configuración de Autenticación (Archivo YAML)
auth_config = {
    "credentials": {
        "usernames": {
            "admin": {  # Usuario demo
                "email": "admin@demo.com",
                "name": "Admin",
                "password": bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode()
            }
        }
    },
    "cookie": {
        "expiry_days": 1,
        "key": "codigos_auth",
        "name": "session_codigos"
    }
}

# Guardar/Leer configuración
AUTH_FILE = "auth.yaml"

def load_auth():
    try:
        with open(AUTH_FILE) as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        with open(AUTH_FILE, "w") as file:
            yaml.dump(auth_config, file)
        return auth_config

auth_data = load_auth()
authenticator = Authenticate(
    auth_data["credentials"],
    auth_data["cookie"]["name"],
    auth_data["cookie"]["key"],
    auth_data["cookie"]["expiry_days"]
)

# 2. Sistema de Logs (Archivo CSV)
LOG_FILE = "usage_logs.csv"

def log_action(username, action):
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "username": username,
        "action": action
    }
    
    try:
        logs = pd.read_csv(LOG_FILE)
    except FileNotFoundError:
        logs = pd.DataFrame(columns=log_entry.keys())
    
    logs = pd.concat([logs, pd.DataFrame([log_entry])], ignore_index=True)
    logs.to_csv(LOG_FILE, index=False)

# 3. Interfaz de Autenticación
def auth_flow():
    name, auth_status, username = authenticator.login("Inicio de Sesión", "main")
    
    if not auth_status:
        # Sección de Registro
        with st.expander("🔐 Registro de Nuevos Usuarios (Solo Admin)"):
            if st.session_state.get("username") == "admin":
                new_user = st.text_input("Nuevo usuario")
                new_pass = st.text_input("Contraseña", type="password")
                if st.button("Crear usuario"):
                    hashed_pw = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt()).decode()
                    auth_data["credentials"]["usernames"][new_user] = {
                        "email": f"{new_user}@demo.com",
                        "name": new_user,
                        "password": hashed_pw
                    }
                    with open(AUTH_FILE, "w") as file:
                        yaml.dump(auth_config, file)
                    st.success("Usuario creado")
            else:
                st.warning("Solo el admin puede crear usuarios")
        
        st.stop()
    
    log_action(username, "login")
    return username

# 4. Tu aplicación principal (sin cambios)
def main_app(username):
    log_action(username, "app_access")
    
    # ... [Todo tu código original aquí] ...
    # Solo cambia la primera línea del main original por:
    st.title(f"📚 Generador de Libros de Códigos - Bienvenido {username}")

# Punto de entrada
if __name__ == "__main__":
    username = auth_flow()
    main_app(username)
    authenticator.logout("Cerrar Sesión", "sidebar")
