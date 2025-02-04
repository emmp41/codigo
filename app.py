import os
import pandas as pd
import streamlit as st
import google.generativeai as genai
from dotenv import load_dotenv
import re
import time

# Configuración inicial
load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("gemini-1.5-flash")

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
    
    # Asegurar longitud exacta
    if len(codigos) < expected:
        codigos += [None]*(expected - len(codigos))
    elif len(codigos) > expected:
        codigos = codigos[:expected]
    
    return codigos

def main():
    st.title("📚 Generador de Libros de Códigos")
    
    archivo = st.file_uploader("Sube tu archivo Excel", type=["xlsx", "xls"])
    
    if archivo:
        df = pd.read_excel(archivo)
        columna = st.selectbox("Selecciona la columna a codificar", df.columns)
        
        if st.button("Generar Codificación"):
            # Filtrar y limpiar respuestas
            mask = df[columna].notna()
            respuestas = df.loc[mask, columna].astype(str).tolist()
            
            with st.spinner("Generando libro de códigos..."):
                codigos_df = generar_codigos(respuestas)
                st.dataframe(codigos_df)
            
            with st.spinner(f"Codificando {len(respuestas)} respuestas..."):
                codigos = procesar_respuestas(respuestas, codigos_df)
                
                # Asignar códigos solo a las filas válidas
                df['Código'] = None
                df.loc[mask, 'Código'] = codigos
                
                # Unir descripciones
                df = df.merge(codigos_df[['Código', 'Descripción']], 
                            on='Código', how='left', suffixes=('', '_desc'))
                
                # Exportar
                with pd.ExcelWriter("resultados.xlsx") as writer:
                    codigos_df.to_excel(writer, sheet_name="Libro de Códigos", index=False)
                    df.to_excel(writer, sheet_name="Datos Codificados", index=False)
                
                st.success("Proceso completado!")
                st.download_button("Descargar resultados", 
                                 open("resultados.xlsx", "rb"), 
                                 "codificacion_final.xlsx")

if __name__ == "__main__":
    main()