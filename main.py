from termcolor import colored
from Modules.honeypot_ssh import start_honeypot
from Modules.modules_api import search_vulnerabilities, suspicious_ip
from Modules.analyze_connections import analyze_connections
from Modules.suspicious_services import suspicious_services

#APIKEY for shodan suggested: skoTKeGUubhAIZbKPZEBpEeEiuk8o5Wu
#APIKEY for IPAbuseDB suggested: 51bffcedf179e67ae15996a1160b04cacb0e23f49841aa355b2602e8335e2cf692c698c93033e9a6

def format_menu():
    """This function contains the format of the menu."""
    msg = "-"*50+"""
        MENU
    [0]. Salir
    [1]. Iniciar SSH Honeypot
    [2]. Consultar API Shodan
    [3]. Consultar API IPAbuseD
    [4]. Analizar conexiones
    [5]. Servicios sospechosos
"""
    print(msg)

if __name__ == "__main__":
    while True:
        try:
            format_menu()
            option = int(input("Seleccione una opcion: "))
            
            if option == 1: 
                port = input("Puerto para vincular el servidor SSH (default 2222): ")
                
                #Validate the port.
                while True:
                    try: 
                        if port == "":
                            port = 2222
                            break 
                        else: 
                            port = int(port)
                            while port < 1024 or port > 65535:
                                port = int(input("Ingrese el puerto en un rango de 1024-65535: "))
                            break 
                    except ValueError: 
                        port = input("Es un dato numérico, si no desea ingresar un puerto presione enter: ")
                start_honeypot(port)
                
            elif option == 2:
                APIKEY=input("Ingrese la API key que se usara para conectarse a la API de shodan")
                ports=input("Ingrese los puertos que quiera ver, en caso de ser mas de uno separarlos por una coma y un espacio")
                port_shodan="port: "+str(ports)
                search_vulnerabilities(APIKEY,port_shodan)
                
            elif option == 3:
                APIKEY=input("Ingrese la API key que se usara para conectarse a la API de IPAbuseDB")
                suspicious_ip(APIKEY)
                
            elif option == 4:
                try:
                    opcion_nombre=int(input("Desea editar el nombre del archivo en donde se guardará el reporte (suspicious_connections_report.txt)? 1-Si 2-No: "))
                    while (opcion_nombre <=0 or opcion_nombre>2):
                        opcion_nombre = int(input("Opicón no válida, intente nuevamente: "))
                    if opcion_nombre == 1:
                        nombre_reporte=input("Ingrese el nombre con el que se guardará el reporte (incluya la extensión .txt): ")
                        analyze_connections(nombre_reporte)
                    else:
                        analyze_connections()
                except Exception: 
                    print("Ha ocurrido un error, intente nuevamente")

            elif option == 5:
                try:
                    opcion_generar_excel = int(input("Deseas conservar el excel con los procesos activos? 1-Sí 2-No: "))
                    while opcion_generar_excel<1 or opcion_generar_excel>2:
                        opcion_generar_excel = int(input("Opción no válida, vuleve a ingresarla: "))
                    suspicious_services(opcion_generar_excel)
                except Exception:
                    print("Ha ocurrido un error, intentalo de nuevo")
                
            elif option == 0:
                print("Saliendo...")
                break
            else:   
                print(colored("Opcion incorrecta.", 'red'))
        except ValueError:
            print(colored("Ingrese un valor de tipo numerico.", 'red'))
