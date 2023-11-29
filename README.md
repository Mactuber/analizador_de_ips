# analizador_de_ips
El siguiente proyecto ha sido diseñado para el empleo de un equipo de analistas de un SIEM cuando observan comportamiento anómalo por parte de IPs. Os adjunto un vídeo en mi Linkedin personal para su buen uso y se descarguen sus dependencias correspondientes.

1) Instalar python 3.12 (versión estable) para la ejecución.

2) Instalar pip para instalar dependencias

3) Dependencias instalables con pip:

pip install requests
pip install socket
pip install ipaddress

4) Crearte una cuenta personal en las siguientes plataformas y guardarte las APIS_KEYS generadas:

https://www.virustotal.com/gui/home/upload
https://www.abuseipdb.com/
https://www.ipvoid.com/ip-blacklist-check/

5)Introducir las claves personales en el código de reputacion_ip_informe y analisis_IPs_FB.py
# PONER TUS APIS_KEYS TRAS REGISTRARSE EN LAS PLATAFORMAS
def verificar_reputacion_ip(ip, generar_informe=False):
    clave_virustotal = 'API_VIRUSTOTAL'
    clave_abuseipdb = 'API_ABUSEIP'
    clave_ipvoid = 'API_IPVOID'

6) Solo con eso ya podrás ejecutar tus scripts siempre que quieras para analizar IPs individuales o por lotes en el LISTADO_IP.txt

