import requests
import json

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
# PONER TUS APIS_KEYS TRAS REGISTRARSE EN LAS PLATAFORMAS
def verificar_reputacion_ip(ip, generar_informe=False):
    clave_virustotal = 'API_VIRUSTOTAL'
    clave_abuseipdb = 'API_ABUSEIP'
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

        # Generar informe si se requiere
        if generar_informe:
            with open("informe.txt", "w") as informe:
                informe.write(f"Informe de la IP: {ip}\n")
                informe.write(f"Resultado de VirusTotal: {json.dumps(resultado_virustotal, indent=2)}\n")
                informe.write(f"Resultado de AbuseIPDB: {json.dumps(resultado_abuseipdb, indent=2)}\n")
                informe.write(f"Resultado de IPVoid: {json.dumps(resultado_ipvoid, indent=2)}\n")

# Ingresa la IP que deseas verificar
ip_a_verificar = input("Ingrese la dirección IP a verificar: ")

# Pregunta si se desea generar el informe
generar = input("¿Desea generar un informe de los resultados? (sí/no): ")

# Llama a la función principal
verificar_reputacion_ip(ip_a_verificar, generar_informe=generar.lower() == 'si')

# Muestra el informe si se generó
if generar.lower() == 'si':
    with open("informe.txt", "r") as informe:
        print(informe.read())
