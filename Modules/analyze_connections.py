import subprocess
import re
import logging


#Function to execute the entire connection analysis, save a report, and log the process
def analyze_connections(output_file="suspicious_connections_report.txt"):
    try:
        #Configuring logging to keep a log of the actions performed
        log = logging.getLogger('analyze_connectionst')
        log.setLevel(logging.INFO)

        file_handler = logging.FileHandler('connection_analysis.log')
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)

        log.addHandler(file_handler)

        #Standard ports that we are going to check
        standard_ports = {22, 25, 80, 465, 587, 8080}
        
        #Execute the PowerShell command to retrieve active TCP connections in "Established" state
        result = subprocess.run(["powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", "Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' }"], capture_output=True, text=True)
        result.check_returncode() #Ensure the command was executed successfully
        connections_output = result.stdout
        log.info("Conexiones TCP obtenidas exitosamente.")

        suspicious_connections=[]
        #This regular expression is in charge of extracting the port from the netstat output
        port_regex = re.compile(r':(\d+)') #Finds the numeric ports

        #Analyze connections in case for suspicious ports
        for line in connections_output.splitlines(): #Split the output in different lines
            found_ports = port_regex.findall(line) #Find all ports in the line
            if found_ports:
                #Check if any of the ports is not standard
                for port in found_ports:
                    if int(port) not in standard_ports:
                        suspicious_connections.append(line) #Save the suspicious connection
                        break #If the line is suspicious, stop analyzing the other ports in the line
        log.info(f"Total de conexiones sospechosas encontradas: {len(suspicious_connections)}")

        #Save the report to the file
        with open(output_file, "w") as f: #Open the file to write the results
            if suspicious_connections:
                f.write("Conexiones sospechosas encontradas:\n") #Write the suspicious connections to the file
                for connection in suspicious_connections:
                    f.write(connection + "\n")
            else:
                f.write("No se han encontrado conexiones sospechosas.\n") #In case there are no suspicious connections
        log.info(f"Reporte generado en {output_file}")
        print(f"Reporte generado en {output_file}")

    except subprocess.CalledProcessError as e:
        log.error(f"Ha ocurrido un error mientras se ejecutaba el comando de PowerShell: {e}")
        print(f"Ha ocurrido un error mientras se ejecutaba el comando de PowerShell: {e}")
    except Exception as e:
        log.error(f"Ha ocurrido un error mientras se analizaban las conexiones: {e}")
        print(f"Ha ocurrido un error mientras se analizaban las conexiones: {e}")