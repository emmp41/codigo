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

load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("gemini-1.5-flash")

# Configuración de autenticación
AUTH_FILE = "auth.yaml"
LOG_FILE = "usage_logs.csv"

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

def auth_flow():
    name, auth_status, username = authenticator.login("Inicio de Sesión", "main")
    
    # Eliminar todo el bloque de registro anterior
    if not auth_status:
        st.stop()  # Solo muestra login
    
    log_action(username, "login")
    return username

# =============================================
# FUNCIONALIDAD PRINCIPAL CORREGIDA
# =============================================

def generar_codigos(respuestas):
    prompt = f"""Genera un libro de códigos exhaustivo para estas {len(respuestas)} respuestas siguiendo REGLAS ESTRICTAS:
    
    1. Códigos en formato C## (C01, C02...)
    2. Mínimo 5 categorías, máximo 15
    3. Cada categoría debe cubrir al menos 3 respuestas
    4. Todas las respuestas DEBEN ser clasificadas
    5. PROHIBIDO usar 'Otros' o categorías residuales
    6. Incluir 3 ejemplos reales por categoría
    
    Formato REQUERIDO (Markdown):
    | Código | Descripción | Ejemplos | Criterios |
    |--------|-------------|----------|-----------|
    | C01 | Diseño innovador | "Forma única", "Colores vibrantes" | Respuestas sobre características visuales |
    
    Respuestas a clasificar:
    {chr(10).join(respuestas[:200])}"""

    try:
        response = model.generate_content(prompt, request_options={"timeout": 300})
        return parsear_tabla(response.text)
    except Exception as e:
        st.error(f"Error generando códigos: {str(e)}")
        return pd.DataFrame()

def parsear_tabla(texto):
    filas = []
    for linea in texto.split('\n'):
        if re.match(r'^\|.*C\d{2}.*\|', linea):
            celdas = [celda.strip() for celda in linea.split('|')[1:-1]]
            if len(celdas) == 4:
                filas.append(celdas)
    return pd.DataFrame(filas, columns=['Código', 'Descripción', 'Ejemplos', 'Criterios'])

def analizar_sentimiento(respuestas):
    sentimientos = ['Neutral'] * len(respuestas)
    lote_size = 10
    
    for i in range(0, len(respuestas), lote_size):
        lote = respuestas[i:i+lote_size]
        try:
            prompt = f"""Clasifica el sentimiento de estas {len(lote)} respuestas:
            - Positivo: Expresa satisfacción o aspectos positivos
            - Negativo: Menciona problemas o insatisfacción
            - Neutral: No expresa claramente sentimiento
            
            Formato REQUERIDO (1 por línea):
            NÚMERO | SENTIMIENTO
            
            Respuestas:
            {chr(10).join(f"{n+1}. {r}" for n,r in enumerate(lote))}"""

            response = model.generate_content(prompt, request_options={"timeout": 180})
            
            for line in response.text.split('\n'):
                if '|' in line:
                    parts = line.split('|')
                    if len(parts) >= 2:
                        try:
                            idx = int(parts[0].strip()) - 1
                            if 0 <= idx < len(lote):
                                sentimiento = parts[1].strip().capitalize()
                                if sentimiento in ['Positivo', 'Negativo']:
                                    sentimientos[i + idx] = sentimiento
                        except: pass
            time.sleep(3)
        except Exception as e:
            st.error(f"Error en lote {i//lote_size}: {str(e)}")
            time.sleep(10)
    
    return sentimientos

def procesar_respuestas(respuestas, codigos_df):
    codigos = []
    schema = codigos_df.to_markdown()
    validos = codigos_df['Código'].tolist()
    total = len(respuestas)
    lote_size = 5  # Lotes más pequeños para mejor precisión
    
    for i in range(0, total, lote_size):
        lote = respuestas[i:i+lote_size]
        current_size = len(lote)
        
        try:
            prompt = f"""Asigna códigos a estas respuestas usando EXCLUSIVAMENTE la tabla siguiente:
{schema}

Formato REQUERIDO (1 por línea):
NÚMERO | CÓDIGO

Respuestas:
{chr(10).join(f"{n+1}. {r}" for n,r in enumerate(lote))}"""

            response = model.generate_content(
                prompt,
                request_options={"timeout": 300},
                generation_config={"temperature": 0.0}
            )
            
            # Procesamiento mejorado
            lote_codigos = [None] * current_size
            for line in response.text.split('\n'):
                if '|' in line:
                    parts = line.split('|')
                    if len(parts) >= 2:
                        try:
                            idx = int(parts[0].strip()) - 1
                            codigo = re.search(r'(C\d{2})', parts[1].strip()).group(0)
                            if 0 <= idx < current_size and codigo in validos:
                                lote_codigos[idx] = codigo
                        except: pass
            
            codigos.extend(lote_codigos)
            st.write(f"Lote {i//lote_size + 1} procesado: {lote_codigos}")  # Debug
            time.sleep(5)
            
        except Exception as e:
            codigos.extend([None] * current_size)
            st.error(f"Error en lote {i//lote_size}: {str(e)}")
            time.sleep(15)
    
    # Validación final
    if len(codigos) != total:
        codigos = codigos[:total] + [None] * (total - len(codigos))
    
    return codigos

# =============================================
# INTERFAZ PRINCIPAL MEJORADA
# =============================================

def main_app(username):
    log_action(username, "app_access")
    
def main_app(username):
    log_action(username, "app_access")
    
    # Panel de Administración solo para admin
    if username == "admin":
        with st.sidebar.expander("🔧 Panel de Administración"):
            st.subheader("Gestión de Usuarios")
            
            # 1. Crear nuevos usuarios
            with st.form("nuevo_usuario_form"):
                st.write("### Crear Nuevo Usuario")
                new_user = st.text_input("Nombre de usuario")
                new_pass = st.text_input("Contraseña", type="password")
                if st.form_submit_button("Crear"):
                    hashed_pw = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt()).decode()
                    auth_data["credentials"]["usernames"][new_user] = {
                        "email": f"{new_user}@empresa.com",
                        "name": new_user,
                        "password": hashed_pw
                    }
                    with open(AUTH_FILE, "w") as file:
                        yaml.dump(auth_data, file)
                    st.success("Usuario creado exitosamente")
                    st.rerun()
            
            # 2. Eliminar usuarios
            usuarios = list(auth_data["credentials"]["usernames"].keys())
            if len(usuarios) > 1:
                st.write("### Eliminar Usuario")
                usuario_a_eliminar = st.selectbox("Seleccionar usuario:", [u for u in usuarios if u != "admin"])
                if st.button("Eliminar"):
                    del auth_data["credentials"]["usernames"][usuario_a_eliminar]
                    with open(AUTH_FILE, "w") as file:
                        yaml.dump(auth_data, file)
                    st.success(f"Usuario {usuario_a_eliminar} eliminado")
                    st.rerun()
            
            # 3. Cambiar contraseña de admin
            with st.form("cambiar_pass_admin_form"):
                st.write("### Cambiar Contraseña de Admin")
                current_pass = st.text_input("Contraseña actual", type="password")
                new_pass = st.text_input("Nueva contraseña", type="password")
                confirm_pass = st.text_input("Confirmar nueva contraseña", type="password")
                if st.form_submit_button("Actualizar"):
                    if bcrypt.checkpw(current_pass.encode(), auth_data["credentials"]["usernames"]["admin"]["password"].encode()):
                        if new_pass == confirm_pass:
                            hashed_new = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt()).decode()
                            auth_data["credentials"]["usernames"]["admin"]["password"] = hashed_new
                            with open(AUTH_FILE, "w") as file:
                                yaml.dump(auth_data, file)
                            st.success("Contraseña actualizada exitosamente")
                            st.rerun()
                        else:
                            st.error("Las contraseñas nuevas no coinciden")
                    else:
                        st.error("Contraseña actual incorrecta")
    st.title(f"📚 Generador de Libros de Códigos - Bienvenido {username}")
    
    archivo = st.file_uploader("Sube tu archivo Excel", type=["xlsx", "xls"])
    
    if archivo:
        df = pd.read_excel(archivo)
        original_columns = df.columns.tolist()
        columna = st.selectbox("Selecciona la columna a codificar", df.columns)
        analisis_sentimiento = st.checkbox("Incluir análisis de sentimiento")
        
        if st.button("Generar Codificación"):
            mask = df[columna].notna()
            respuestas = df.loc[mask, columna].astype(str).tolist()
            
            with st.status("Procesando...", expanded=True) as status:
                try:
                    # Generar libro de códigos
                    st.write("📖 Generando categorías...")
                    codigos_df = generar_codigos(respuestas)
                    if codigos_df.empty:
                        st.error("Error crítico: No se generaron códigos")
                        return
                    
                    st.write(f"✅ Códigos generados: {len(codigos_df)} categorías")
                    st.dataframe(codigos_df)
                    
                    # Procesar codificación
                    st.write("🔢 Asignando códigos...")
                    codigos = procesar_respuestas(respuestas, codigos_df)
                    st.write("🔍 Resultados parciales:", codigos[:10])  # Debug
                    
                    # Validar asignación
                    asignados = sum(1 for c in codigos if c is not None)
                    if asignados == 0:
                        st.error("Error crítico: Ningún código fue asignado")
                        st.stop()
                    
                    # Procesar sentimiento
                    sentimientos = []
                    if analisis_sentimiento:
                        st.write("😊 Analizando sentimientos...")
                        sentimientos = analizar_sentimiento(respuestas)
                    
                    # Integrar resultados
                    st.write("💾 Guardando resultados...")
                    df_resultado = df.copy()
                    df_resultado['Código'] = None
                    df_resultado.loc[mask, 'Código'] = codigos
                    
                    df_resultado = df_resultado.merge(
                        codigos_df[['Código', 'Descripción']],
                        on='Código',
                        how='left'
                    )
                    
                    if analisis_sentimiento:
                        df_resultado['Sentimiento'] = None
                        df_resultado.loc[mask, 'Sentimiento'] = sentimientos
                    
                    # Ordenar columnas
                    columnas_finales = original_columns + ['Código', 'Descripción']
                    if analisis_sentimiento:
                        columnas_finales.append('Sentimiento')
                    
                    df_resultado = df_resultado[columnas_finales]
                    
                    # Guardar
                    with pd.ExcelWriter("resultados.xlsx") as writer:
                        codigos_df.to_excel(writer, sheet_name="Libro de Códigos", index=False)
                        df_resultado.to_excel(writer, sheet_name="Datos Codificados", index=False)
                    
                    status.update(label="Proceso completado!", state="complete")
                    nombre_original = archivo.name.replace('.xlsx', '')  # Elimina la extensión
                    nombre_final = f"{nombre_original}_codificacion.xlsx"
                    st.download_button("Descargar resultados", 
                                    open("resultados.xlsx", "rb"), 
                                    nombre_final)
                
                except Exception as e:
                    status.update(label="Error en el proceso", state="error")
                    st.error(f"Error crítico: {str(e)}")
                    st.stop()

# =============================================
# EJECUCIÓN PRINCIPAL
# =============================================

if __name__ == "__main__":
    username = auth_flow()
    main_app(username)
    authenticator.logout("Cerrar Sesión", "sidebar")
