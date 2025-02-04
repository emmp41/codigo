import os
import pandas as pd
import streamlit as st
import google.generativeai as genai
from dotenv import load_dotenv
import re
import time
from supabase import create_client

# Configuración inicial
load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("gemini-1.5-flash")

# Configura Supabase
@st.cache_resource
def init_supabase():
    return create_client(
        st.secrets["SUPABASE_URL"],
        st.secrets["SUPABASE_KEY"]
    )

supabase = init_supabase()

# Sistema de autenticación
def handle_auth():
    if "user" not in st.session_state:
        st.session_state.user = None

    if not st.session_state.user:
        st.title("🔒 Acceso a la Plataforma")
        tab1, tab2 = st.tabs(["Iniciar Sesión", "Registro"])

        with tab1:
            email = st.text_input("Email")
            password = st.text_input("Contraseña", type="password")
            if st.button("Ingresar"):
                try:
                    user = supabase.auth.sign_in_with_password({
                        "email": email,
                        "password": password
                    })
                    st.session_state.user = user
                    log_usage("login")
                    st.rerun()
                except Exception as e:
                    st.error("Credenciales incorrectas")

        with tab2:
            new_email = st.text_input("Nuevo Email")
            new_pass = st.text_input("Nueva Contraseña", type="password")
            if st.button("Crear cuenta"):
                try:
                    user = supabase.auth.sign_up({
                        "email": new_email,
                        "password": new_pass
                    })
                    st.success("Cuenta creada! Verifica tu email.")
                    log_usage("signup")
                except Exception as e:
                    st.error(f"Error: {str(e)}")

        st.stop()

# Monitoreo de uso
def log_usage(action):
    if st.session_state.user:
        supabase.table("usage_logs").insert({
            "user_id": st.session_state.user.user.id,
            "action": action
        }).execute()

# Tus funciones existentes (generar_codigos, parsear_tabla, etc.)
# ... [Mantén todo tu código actual sin cambios] ...

def main():
    handle_auth()  # Primera línea modificada
    
    # Registra acceso a la app
    log_usage("app_access")
    
    st.title("📚 Generador de Libros de Códigos")
    
    # ... [Resto de tu código original] ...

if __name__ == "__main__":
    main()
