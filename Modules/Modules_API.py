import shodan
import logging
import requests
import json

#Function to search for vulnerabilities in different ports for different IPS

def Search_Vulnerabilities(APIKEY,Port_shodan):
    logging.basicConfig(filename='module_shodan.log', level=logging.INFO)
    try:
        logging.info("Se intenta entrar en la api con la apikey: %s" % APIKEY)
        shodan_api=shodan.Shodan(APIKEY)

    except Exception as e:
        logging.error("Se crea un error debido a que la API KEY es invalida o no tiene los permisos requeridos")
        print("Hubo un error con la apikey\n", e)
        exit()

    else:

        try:
            logging.info("Se intenta buscar IPs con los puertos antes determinados: %s" % Port_shodan)
            result=shodan_api.search(Port_shodan)

        except Exception as e:
            logging.error("Error al poner los puertos")
            print("Hubo un error con la búsqueda\n", e)
            exit()

        else:
            logging.info("Se elige si se desea ver los resultados o guardarlos en un archivo")
            print("Presione [1]-Para ver en pantalla los resultados\n[2]-Para generar un reporte de texto")
            op=int(input())

            while op!=1 and op!=2:
            
                #A loop is created until I get a correct option.
            
                logging.error("Se genera un error cuando la opcion es diferente a 1 o 2")
                print("Elija una opcion valida")
                print("Presione [1]-Para ver en pantalla los resultados\n[2]-Para generar un reporte de texto")
                op=int(input())

            if op==1:            
                logging.info("Se muestran en pantalla los resultados")
                for match in result["matches"]:
                
                    #The IP, port, vulnerabilities, and city are identified

                    if match["ip_str"] is not None:
                        print("IP:", match['ip_str'])
                        print("Puerto:", match['port'])

                        if 'vulns' in match:

                            #We look for vulnerabilities; if they do not exist, a message will be printed.

                            print("Vulnerabilidades encontradas:")

                            for vuln in match["vulns"]:
                                print("Este es el codigo de vulnerabilidad:", vuln, \
                                    "esta es el resumen del codigo:",match["vulns"][vuln]["summary"])
                                
                        else:
                            print("No se encontraron vulnerabilidades.")
                        
                        if match["location"]["city"] is not None:
                            
                            #The city of the found IP is searched

                            print("Ciudad de la IP:", match["location"]["city"])
                
                        print("-" * 50)

            else:
                logging.info("Se pide el nombre del archivo para generarlo")
                file_name=input("Ingrese el nombre del reporte junto con su extensión \".txt\"")

                try:
                    logging.info("Se intenta crear el archivo")
                    with open(file_name,"w") as file:
                        for match in result["matches"]:

                            #the same thing is searched but instead of printing everything \
                            # it will be saved in a text file

                            if match["ip_str"] is not None:
                                file.write("IP: "+str(match['ip_str']))
                                file.write("Puerto: "+str(match['port']))

                                if 'vulns' in match:
                                    file.write("Vulnerabilidades encontradas:")
                                    for vuln in match["vulns"]:
                                        file.write("Este es el codigo de vulnerabilidad: "\
                                                +str(vuln)+"esta es el resumen del codigo:"+\
                                                    str(match["vulns"][vuln]["summary"]))
                                        
                                else:
                                    file.write("No se encontraron vulnerabilidades.")

                                if match["location"]["city"] is not None:
                                    file.write("Ciudad de la IP: "+str(match["location"]["city"]))
                                file.write("-" * 50)

                except Exception as e:
                    logging.error("Se creo un error debido a que el nombre no es valido")
                    print("Hubo un problema al hacer el archivo\n", e)
    finally:
        print("La funcion ha terminado de ejecutarse")
