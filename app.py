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

# =============================================
# CONFIGURACIÓN INICIAL Y AUTENTICACIÓN
# =============================================

# Cargar variables de entorno
load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("gemini-1.5-flash")

# Configuración de autenticación
AUTH_FILE = "auth.yaml"
LOG_FILE = "usage_logs.csv"

# 1. Configuración inicial de autenticación
auth_config = {
    "credentials": {
        "usernames": {
            "admin": {
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

# 2. Sistema de logs
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

# 3. Flujo de autenticación
def auth_flow():
    # Línea corregida con parámetros nombrados
    name, auth_status, username = authenticator.login("Inicio de Sesión","main")
    
    if not auth_status:
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

# =============================================
# FUNCIONALIDAD PRINCIPAL DE LA APLICACIÓN
# =============================================

def generar_codigos(respuestas):
    prompt = f"""Genera un libro de códigos exhaustivo con estas REGLAS:
1. Códigos en formato C## (C01, C02...)
2. Mínimo 12 categorías principales
3. Cada categoría debe cubrir al menos 5% de las respuestas
4. PROHIBIDO usar 'Otros'
5. Incluir 5 ejemplos reales por categoría

Ejemplo de formato REQUERIDO (Markdown):
| Código | Descripción | Ejemplos | Criterios |
|--------|-------------|----------|-----------|
| C01 | Satisfacción general | "Buen servicio", "Contento" | Respuestas positivas genéricas |

Respuestas a clasificar:
{chr(10).join(respuestas[:200])}"""

    response = model.generate_content(prompt)
    return parsear_tabla(response.text)

def parsear_tabla(texto):
    filas = []
    for linea in texto.split('\n'):
        if re.match(r'^\|.*C\d{2}.*\|', linea):
            celdas = [celda.strip() for celda in linea.split('|')[1:-1]]
            if len(celdas) == 4:
                filas.append(celdas)
    return pd.DataFrame(filas, columns=['Código', 'Descripción', 'Ejemplos', 'Criterios'])

def procesar_respuestas(respuestas, codigos_df, lote_size=20):
    codigos = []
    schema = codigos_df.to_markdown()
    
    for i in range(0, len(respuestas), lote_size):
        lote = respuestas[i:i+lote_size]
        current_size = len(lote)
        
        prompt = f"""Asigna códigos a estas {current_size} respuestas usando ESTA TABLA:
{schema}

Formato REQUERIDO:
1 | C01 | Razón breve
2 | C02 | Razón específica
...
{current_size} | CXX | Razón

Respuestas:
{chr(10).join(f"{n+1}. {r}" for n,r in enumerate(lote))}"""

        try:
            response = model.generate_content(prompt)
            codigos_lote = parsear_respuesta(response.text, codigos_df, current_size)
            codigos.extend(codigos_lote)
            time.sleep(2)
        except Exception as e:
            codigos.extend([None]*current_size)
            st.error(f"Error en lote {i//lote_size}: {str(e)}")
    
    return codigos

def parsear_respuesta(texto, codigos_df, expected):
    codigos = []
    validos = codigos_df['Código'].tolist()
    
    for linea in texto.split('\n'):
        if re.match(r'^\d+\s*\|', linea):
            partes = linea.split('|')
            if len(partes) >= 3:
                codigo = re.search(r'(C\d{2})', partes[1].strip())
                if codigo and codigo.group(0) in validos:
                    codigos.append(codigo.group(0))
                else:
                    codigos.append(None)
    
    if len(codigos) < expected:
        codigos += [None]*(expected - len(codigos))
    elif len(codigos) > expected:
        codigos = codigos[:expected]
    
    return codigos

# =============================================
# INTERFAZ PRINCIPAL INTEGRADA
# =============================================

def main_app(username):
    log_action(username, "app_access")
    # ... (tu código actual)
    
    # =============================================
    # PANEL DE ADMINISTRACIÓN (Solo visible para admin)
    # =============================================
    if username == "admin":
        with st.sidebar.expander("🔧 Panel de Administración"):
            st.subheader("Gestión de Usuarios")
            
            # 1. Crear nuevos usuarios
            with st.form("nuevo_usuario"):
                nuevo_user = st.text_input("Nuevo usuario")
                nuevo_pass = st.text_input("Contraseña", type="password")
                if st.form_submit_button("Crear usuario"):
                    hashed_pw = bcrypt.hashpw(nuevo_pass.encode(), bcrypt.gensalt()).decode()
                    auth_data["credentials"]["usernames"][nuevo_user] = {
                        "email": f"{nuevo_user}@empresa.com",
                        "name": nuevo_user,
                        "password": hashed_pw
                    }
                    with open(AUTH_FILE, "w") as file:
                        yaml.dump(auth_data, file)
                    st.success(f"Usuario {nuevo_user} creado")
                    log_action(username, f"crear_usuario: {nuevo_user}")

            # 2. Eliminar usuarios existentes
            usuarios = list(auth_data["credentials"]["usernames"].keys())
            usuarios.remove("admin")  # Prevenir auto-eliminación
            usuario_a_eliminar = st.selectbox("Seleccionar usuario para eliminar", usuarios)
            if st.button("Eliminar usuario"):
                del auth_data["credentials"]["usernames"][usuario_a_eliminar]
                with open(AUTH_FILE, "w") as file:
                    yaml.dump(auth_data, file)
                st.warning(f"Usuario {usuario_a_eliminar} eliminado")
                log_action(username, f"eliminar_usuario: {usuario_a_eliminar}")

            # 3. Cambiar contraseña de admin
            with st.form("cambiar_pass_admin"):
                current_pass = st.text_input("Contraseña actual", type="password")
                new_pass = st.text_input("Nueva contraseña", type="password")
                confirm_pass = st.text_input("Confirmar nueva contraseña", type="password")
                if st.form_submit_button("Actualizar contraseña"):
                    # Verificar contraseña actual
                    if bcrypt.checkpw(current_pass.encode(), auth_data["credentials"]["usernames"]["admin"]["password"].encode()):
                        if new_pass == confirm_pass:
                            hashed_new = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt()).decode()
                            auth_data["credentials"]["usernames"]["admin"]["password"] = hashed_new
                            with open(AUTH_FILE, "w") as file:
                                yaml.dump(auth_data, file)
                            st.success("Contraseña actualizada")
                            log_action(username, "cambio_pass_admin")
                        else:
                            st.error("Las contraseñas nuevas no coinciden")
                    else:
                        st.error("Contraseña actual incorrecta")
    st.title(f"📚 Generador de Libros de Códigos - Bienvenido {username}")
    
    archivo = st.file_uploader("Sube tu archivo Excel", type=["xlsx", "xls"])
    
    if archivo:
        df = pd.read_excel(archivo)
        columna = st.selectbox("Selecciona la columna a codificar", df.columns)
        
        if st.button("Generar Codificación"):
            mask = df[columna].notna()
            respuestas = df.loc[mask, columna].astype(str).tolist()
            
            with st.spinner("Generando libro de códigos..."):
                codigos_df = generar_codigos(respuestas)
                st.dataframe(codigos_df)
            
            with st.spinner(f"Codificando {len(respuestas)} respuestas..."):
                codigos = procesar_respuestas(respuestas, codigos_df)
                
                df['Código'] = None
                df.loc[mask, 'Código'] = codigos
                
                df = df.merge(codigos_df[['Código', 'Descripción']], 
                            on='Código', how='left', suffixes=('', '_desc'))
                
                with pd.ExcelWriter("resultados.xlsx") as writer:
                    codigos_df.to_excel(writer, sheet_name="Libro de Códigos", index=False)
                    df.to_excel(writer, sheet_name="Datos Codificados", index=False)
                
                st.success("Proceso completado!")
                st.download_button("Descargar resultados", 
                                 open("resultados.xlsx", "rb"), 
                                 "codificacion_final.xlsx")

# =============================================
# PUNTO DE ENTRADA PRINCIPAL
# =============================================

if __name__ == "__main__":
    username = auth_flow()
    main_app(username)
    authenticator.logout("Cerrar Sesión", "sidebar") 
