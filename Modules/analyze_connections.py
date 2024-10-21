import subprocess
import re
import logging


#Function to execute the entire connection analysis, save a report, and log the process
def analyze_connections(output_file="suspicious_connections_report.txt"):
    try:
        #Configuring logging to keep a log of the actions performed
        logging.basicConfig(filename='connection_analysis.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

        #Standard ports that we are going to check
        standard_ports = {22, 25, 80, 465, 587, 8080}
        
        #Execute the PowerShell command to retrieve active TCP connections in "Established" state
        result = subprocess.run(["powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", "Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' }"], capture_output=True, text=True)
        result.check_returncode() #Ensure the command was executed successfully
        connections_output = result.stdout
        logging.info("Successfully retrieved TCP connections.")

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
        logging.info(f"Total suspicious connections found: {len(suspicious_connections)}")

        #Save the report to the file
        with open(output_file, "w") as f: #Open the file to write the results
            if suspicious_connections:
                f.write("Suspicious connections found:\n") #Write the suspicious connections to the file
                for connection in suspicious_connections:
                    f.write(connection + "\n")
            else:
                f.write("No suspicious connections found.\n") #In case there are no suspicious connections
        logging.info(f"Report generated in {output_file}")
        print(f"Report generated in {output_file}")

    except subprocess.CalledProcessError as e:
        logging.error(f"Error while executing the PowerShell command: {e}")
        print(f"Error while executing the PowerShell command: {e}")
    except Exception as e:
        logging.error(f"An error occurred during connection analysis: {e}")
        print(f"An error occurred during connection analysis: {e}")
