import ipaddress

def verificar_ip(ip):
    # Verificar si es una IP de agregador
    with open('agregador.txt', 'r') as agregador:
        for linea in agregador:
            linea = linea.strip()
            try:
                red = ipaddress.ip_network(linea)
                if ipaddress.ip_address(ip) in red:
                    return "Está en la lista de agregadores"
            except ValueError:
                pass

    # Verificar si es una IP privada
    if ipaddress.ip_address(ip).is_private:
        return "Es una IP privada"

    # Verificar si está en la lista blanca
    with open('whitelist.txt', 'r') as lista_blanca:
        for linea in lista_blanca:
            linea = linea.strip()
            try:
                red = ipaddress.ip_network(linea)
                if ipaddress.ip_address(ip) in red:
                    return "Está en la lista blanca"
            except ValueError:
                pass

    return "No se encontró coincidencia en ninguna lista"

# Ejemplo de uso:
ip = input("Por favor, introduce una dirección IP: ")
resultado = verificar_ip(ip)
print(resultado)