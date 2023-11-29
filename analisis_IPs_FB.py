import requests
import json
import socket

def verificar_virustotal(api_key, ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {'x-apikey': api_key}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        resultado = response.json()
        return resultado
    except requests.exceptions.RequestException as e:
        print(f"Error en la verificación de VirusTotal: {e}")
        return None

def verificar_abuseipdb(api_key, ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Key': api_key}

    try:
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()
        resultado = response.json()
        return resultado
    except requests.exceptions.RequestException as e:
        print(f"Error en la verificación de AbuseIPDB: {e}")
        return None

def verificar_ipvoid(api_key, ip):
    url = f'https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key={api_key}&ip={ip}'
    params = {'key': api_key}

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        resultado = response.json()
        return resultado
    except requests.exceptions.RequestException as e:
        print(f"Error en la verificación de IPVoid: {e}")
        return None

def obtener_dominio(ip):
    try:
        # Establecer un tiempo de espera para la operación de resolución de nombres
        socket.setdefaulttimeout(5)
        
        dominio = socket.gethostbyaddr(ip)[0]
        return dominio
    except socket.herror:
        return None
    except socket.timeout:
        print(f"Tiempo de espera agotado para la IP {ip}. No se pudo obtener el dominio.")
        return None

def obtener_pais_desde_respuestas(resultado_virustotal, resultado_abuseipdb, resultado_ipvoid):
    pais_virustotal = resultado_virustotal.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('country', 'N/A') or 'N/A'
    pais_abuseipdb = resultado_abuseipdb.get('data', {}).get('countryCode', 'N/A') or 'N/A'
    pais_ipvoid = resultado_ipvoid.get('data', {}).get('country_code', 'N/A') or 'N/A'
    
    return pais_virustotal, pais_abuseipdb, pais_ipvoid

#PONER TUS APIS KEYS DESDE LAS PLATAFORMAS OFICIALES CREANDOTE UNA CUENTA PERSONAL
def verificar_reputacion_ip(ip):
    clave_virustotal = 'API_VIRUSTOTAL'
    clave_abuseipdb = 'API_ABUSE'
    clave_ipvoid = 'API_IPVOID'

    resultado_whitelist = "La IP está en la lista blanca."

    # Leer la whitelist desde el archivo
    with open("whitelist.txt", "r") as archivo:
        lista_whitelist = archivo.read().splitlines()

    # Verificar si la IP está en la lista blanca
    if ip in lista_whitelist:
        print(resultado_whitelist)
    else:
        print(f"La IP {ip} NO está en la lista blanca.")
        print("Ahora se procederá a verificar la reputación de la IP aportada...")

        # Verificar la reputación utilizando las funciones anteriores
        resultado_virustotal = verificar_virustotal(clave_virustotal, ip)
        resultado_abuseipdb = verificar_abuseipdb(clave_abuseipdb, ip)
        resultado_ipvoid = verificar_ipvoid(clave_ipvoid, ip)

        # Obtener el dominio asociado a la IP
        dominio = obtener_dominio(ip)

        # Obtener el país de la IP
        pais_virustotal, pais_abuseipdb, pais_ipvoid = obtener_pais_desde_respuestas(resultado_virustotal, resultado_abuseipdb, resultado_ipvoid)

        # Imprimir información relevante en columnas
        print(f"{'Servicio': <15}{'Blacklist': <10}{'País': <10}{'Dominio': <20}")
        print("-" * 60)
        print(f"{f'VirusTotal': <15}{resultado_virustotal.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) or 'N/A': <10}{pais_virustotal: <10}{dominio or 'N/A': <20}")
        print(f"{f'AbuseIPDB': <15}{resultado_abuseipdb.get('data', {}).get('abuseConfidenceScore', 0) or 'N/A': <10}{pais_abuseipdb: <10}")
        print(f"{f'IPVoid': <15}{1 if resultado_ipvoid.get('data', {}).get('malicious') or resultado_ipvoid.get('data', {}).get('total_reports') or resultado_ipvoid.get('data', {}).get('detections') else 0: <10}{pais_ipvoid: <10}")

        # Verificar si la IP es española y está reportada
        if pais_abuseipdb == 'ES':
            print(f"\nLa IP {ip} está reportada en AbuseIPDB como española. Se recomienda bloquearla por dos horas.")
            # Agregar aquí la lógica para bloquear la IP por dos horas

# Pide la ruta del archivo que contiene las IP
ruta_archivo = input("Ingrese la ruta del archivo que contiene las IPs para analizar: ")

# Lee las IP desde el archivo
with open(ruta_archivo, "r") as archivo_ips:
    lista_ips = archivo_ips.read().splitlines()

# Itera sobre las IPs y realiza la verificación de reputación
for ip_a_verificar in lista_ips:
    print(f"\nVerificando la IP: {ip_a_verificar}")
    verificar_reputacion_ip(ip_a_verificar)

print("Proceso completo.")