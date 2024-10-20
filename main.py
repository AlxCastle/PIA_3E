import argparse
from termcolor import colored
from honeypot_ssh import start_honeypot
from Modules.Module_shodan import *

#APIKEY for shodan suggested: skoTKeGUubhAIZbKPZEBpEeEiuk8o5Wu
#APIKEY for IPAbuseDB suggested: 51bffcedf179e67ae15996a1160b04cacb0e23f49841aa355b2602e8335e2cf692c698c93033e9a6

def menu():
    """Esta funcion contiene el formato del menu."""
    msg = "-"*50+"""
        MENU
    [0]. Salir
    [1]. SSH Honeypot
    [2]. Consume API Shodan
    [3]. Consume API IPAbuseD
    [4].
"""
    print(msg)

if __name__ == "__main__":
    while True:
        try:
            menu()
            option = int(input("Seleccione una opcion: "))
            if option == 1: 
                port = input("Port to bind the SSH server (default 2222): ")
                
                # Validar el puerto
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

                # Inicia el honeypot
                start_honeypot(port)

            elif option == 2:
                pass
            elif option == 3:
                pass
            elif option == 4:
                pass
            elif option == 5:
                pass
            elif option == 0:
                print("Saliendo...")
                break
            else:   
                print(colored("Opcion incorrecta.", 'red'))
        except ValueError:
            print(colored("Ingrese un valor de tipo numerico.", 'red'))
