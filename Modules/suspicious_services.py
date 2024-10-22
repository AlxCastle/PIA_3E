#Import all the modules required
import subprocess
import csv
from openpyxl import Workbook
import os
import logging



def suspicious_services(generar_excel):
    #Configure log to keep a log of the actions performed
    log = logging.getLogger('suspicious_services')
    log.setLevel(logging.INFO)

    # Configurar el formato del logging
    file_handler = logging.FileHandler('suspicious_services.log')
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)

    # Añadir el manejador al logger
    log.addHandler(file_handler)
    
    #This is the command that obtain the Services
    powershell_command = 'Get-Service | Select-Object Name, DisplayName, Status, StartType | Export-Csv -Path "services.csv" -NoTypeInformation'
    try:
        #Execute the PowerShell script directly from python
        result = subprocess.run(["powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", powershell_command], capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Error ejecutando el comando: {result.stderr}")
        csv_file = "services.csv"
        log.info("El comando de PowerShell se ejecutó correctamente y el archivo CSV fue generado.")
    except Exception as e:
        log.error(f"Ocurrió un error mientras se ejecutaba el comando de PowerShell: {e}")
        return
    
    if csv_file:
    #Converts the CSV to an Excel file
        excel_file = "services.xlsx"
        try:
            workbook = Workbook()
            sheet = workbook.active
            sheet.title = "Services"

            #Read the CSV file and write it into the Excel file
            with open(csv_file, newline='', encoding='utf-8') as csvfile:
                reader = csv.reader(csvfile)
                for row in reader:
                    sheet.append(row)

            #Save the Excel file
            workbook.save(excel_file)
            if generar_excel == 1:
                print(f"Los servicios han sido guardados en {excel_file}.")
            log.info(f"El archivo Excel {excel_file} fue generado correctamente.")
        except Exception as e:
            log.error(f"Ocurrió un error procesando el archivo CSV o guardando el archivo de Excel: {e}")

        #Analyze the services and save suspicious ones in a text file named "suspicious_services_report.txt"
        suspicious_services_file = "suspicious_services_report.txt"
        try:
            suspicious_services = []
        
            #Read the CSV file and search for suspicious services
            with open(csv_file, newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                #Condition in order to be considered as suspicious: services that are disabled or not running
                    if row['Status'] != 'Running' or row['StartType'] == 'Disabled':
                        suspicious_services.append(f"{row['Name']} - {row['DisplayName']} (Status: {row['Status']}, StartType: {row['StartType']})") #Saves the services that fit with the conditions 

            #Write the suspicious services into a text file
            with open(suspicious_services_file, "w") as f:
                if suspicious_services:
                    f.write("Servicios sospechosos encontrados:\n")
                    for service in suspicious_services:
                        f.write(service + "\n")
                else:
                    f.write("No se encontraron servicios sospechosos.\n")

            print(f"El reporte de los servicios sospechosos ha sido generado en {suspicious_services_file}.")
            log.info(f"El reporte de los servicios sospechosos ha sido generado en {suspicious_services_file}.")
        except Exception as e:
            log.error(f"Ocurrió un error mientras se analizaban los servicios: {e}")
    
        #Delete the temporary CSV file since the excel it's already saved
        if os.path.exists(csv_file):
            os.remove(csv_file)
            log.info(f"El archivo CSV temporal {csv_file} ha sido eliminado.")
            if generar_excel == 2:
                os.remove(excel_file)
                log.info(f"El archivo Excel {excel_file} ha sido eliminado.")
