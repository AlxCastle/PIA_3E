import threading
import socket
import time
import logging
import paramiko
from termcolor import colored
from datetime import datetime

# Get the local IP address
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))  # Use a public DNS to obtain the local IP
        local_ip = s.getsockname()[0]
    except Exception as e:
        logging.error(f"Error obtaining local IP: {e}")
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip

# Generate and save the RSA private key
private_key = paramiko.RSAKey.generate(2048)
private_key.write_private_key_file('server.key')
HOST_KEY = paramiko.RSAKey(filename='server.key')
SSH_BANNER = "SSH-2.0-OpenSSH_8.7p1 Debian-3ubuntu0.1"

# Basic logging configuration
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    filename='ssh_honeypot.log'
)
    
class Honeypot(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()
        self.username = None

    def check_channel_request(self, kind, chanid):
        if kind in ['session', 'shell']:  # Permitir sesiones y shell
            logging.info(f'Channel request: {self.client_ip} ({kind})')
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        logging.info(f'Auth requested: {self.client_ip} (user: {username})')
        return "password"

    def check_auth_password(self, username, password):
        logging.info(f'Password attempt: {self.client_ip} (user: {username}, password: {password})')
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()  # Señalar que se ha solicitado un shell
        return True  # Permitir la asignación de un PTY


# Command handling
def handle_command(command, msg, user):
    response = ""
    #valid_commands = ["ls", "pwd", "whoami", "date", "echo", "cat"] 
    
    if command == "ls":
        response = colored(f"Desktop    Downloads   Documents    Music    Pictures   \r\n", 'blue', attrs=['bold'])
    elif command == "pwd":
        response = f"/home/{user}\r\n"
    elif command == "whoami":
        response = f"{user}\r\n"
    elif command == "date":
        response = datetime.now().strftime("%a %b %d %I:%M:%S %p %Z %Y") + "\r\n"
    elif ("echo") in command:
        command = str(command)
        command_parts = command.split() 
        if len(command_parts) > 1:
            response = " ".join(command_parts[1:]) + "\r\n"
        else:
            response = "\r\n"  # If no message, just return a new line
    elif ("cat") in command:
        command = str(command)
        command_parts = command.split() 
        if len(command_parts) > 1:
            response = f"This is just a test.\r\n"
        else:
            response = "cat: missing operand\r\n"
    else: 
        response = f"{command}: Command not found\r\n"

    msg.send(response.encode("utf-8"))  # Send response as bytes

# Handle incoming connections
def handle_connection(client, addr):
    client_ip = addr[0]
    logging.info(f'New connection from: {client_ip}')

    transport = paramiko.Transport(client)
    transport.add_server_key(HOST_KEY)
    transport.local_version = SSH_BANNER
    server = Honeypot(client_ip)

    try:
        transport.start_server(server=server)
        msg = transport.accept(20)  
        if msg is None:
            logging.info(f'No channel request from {client_ip}')
            return
        time.sleep(1)
        date = datetime.now().strftime("%a %b %d %I:%M:%S %p %Z %Y") + "\r\n"
        msg.send(f"Welcome to the Kali Linux SSH server\r\nLast login: {date}".encode("utf-8"))  # Welcome message

        time.sleep(5)
        while True:
            # Get the username after successful authentication
            user = server.username
            
            txt_part1 = colored("┌──(", 'light_green')
            txt_part2 = colored(f"{user}㉿kali", 'blue', attrs=['bold'])  
            txt_part3 = colored(")-[~]", 'light_green')
            txt_part4 = colored("└─$ ", 'light_green')
            format_prompt = f"{txt_part1}{txt_part2}{txt_part3}\n{txt_part4}"
            msg.send(format_prompt.encode("utf-8"))  # Send prompt
            
            try:
                command = msg.recv(1024).decode("utf-8").strip()  # Receive command from the client
                if command == "exit":
                    logging.info(f'Command from {client_ip}: {command}')
                    break
                else:
                    logging.info(f'Command from {client_ip}: {command}')
                    handle_command(command, msg, user)  # Process the command
            
            except Exception as e:
                logging.error(f'Error processing command from {client_ip}: {e}')
                msg.send(f"Error processing command: {e}\r\n".encode("utf-8"))

            
    
    except Exception as err:
        logging.error(f'Error handling connection from {client_ip}: {err}')
        if msg:
            msg.send("An error occurred in the connection.\r\n".encode("utf-8"))
    finally:
        msg.close()
        transport.close()

# Start the SSH server
def start_server(port, bind_addr):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_addr, port))
    sock.listen(10)

    print(f"""
          **SSH HONEYPOT**
Server listening on {bind_addr} : {port} """)

    logging.info(f'Server listening on {bind_addr}:{port}')

    while True:
        try:
            client, addr = sock.accept()
            threading.Thread(target=handle_connection, args=(client, addr)).start()
        except Exception as e:
            logging.error(f'Error accepting connection: {e}')

    
