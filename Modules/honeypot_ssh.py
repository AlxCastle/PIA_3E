import threading
import socket
import time
import logging
import paramiko
from termcolor import colored
from datetime import datetime


#Configure basic logging settings
log = logging.getLogger('ssh_honeypot')
log.setLevel(logging.INFO)

file_handler = logging.FileHandler('report_ssh_honeypot.log')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
log.addHandler(file_handler)


#Global variable to control stopping the SSH honeypot
stop_server = False  

#Generate and save the RSA private key
private_key = paramiko.RSAKey.generate(2048)
private_key.write_private_key_file('server.key')
HOST_KEY = paramiko.RSAKey(filename='server.key')

#SSH banner emulating a Kali Linux server
SSH_BANNER = "SSH-2.0-OpenSSH_8.7p1 Debian-3ubuntu0.1"  


def get_local_ip():
    """Get the local IP address by connecting to a public DNS server (8.8.8.8).
    If the attempt fails, it defaults to 127.0.0.1."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(('8.8.8.8', 80))
        local_ip = sock.getsockname()[0]
    except Exception as e:
        log.error(f"Error obtaining local IP: {e}")
        local_ip = '127.0.0.1' 
    finally:
        sock.close()
    return local_ip


class SshHoneypot(paramiko.ServerInterface):
    """ssh Honeypot class that handles ssh server interactions using Paramiko.
    Logs connection attempts, authentication requests, and channel requests."""
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()
        self.username = None

    def check_channel_request(self, kind, chanid):
        """Allows 'session' or 'shell' channel requests.
        Logs the request type and client IP."""
        if kind in ['session', 'shell']:
            log.info(f'Channel request: {self.client_ip} ({kind})')
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        """Returns the allowed authentication method as 'password'.
        Logs the username and client IP for authentication attempts."""
        log.info(f'Auth requested: {self.client_ip} (user: {username})')
        return "password"

    def check_auth_password(self, username, password):
        """Logs the password attempt and simulates successful authentication."""
        log.info(f'Password attempt: {self.client_ip} (user: {username}, password: {password})')
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        """Allows shell requests and sets the event for shell access."""
        self.event.set()
        return True


def handle_command(command, msg, user):
    """Simulates responses to common Linux commands for the honeypot.
    Handles commands such as 'ls', 'pwd', 'whoami', 'date', 'echo', and 'cat'."""
    response = ""
    command = str(command)
    command_parts = command.split() 

    if command == "ls":
        response = colored("Desktop    Downloads   Documents    Music    Pictures\r\n", 'blue', attrs=['bold'])
    elif command == "pwd":
        response = f"/home/{user}\r\n"
    elif command == "whoami":
        response = f"{user}\r\n"
    elif command == "date":
        response = datetime.now().strftime("%a %b %d %I:%M:%S %p %Z %Y") + "\r\n"
    elif "echo" in command:
        text = " ".join(command_parts[1:])
        response =  (f"{text}\r\n") if len(command_parts) > 1 else "\r\n"
    elif "cat" in command:
        if len(command_parts) > 1:
            response = "This is just a text.\r\n" 
        else:
            response= "cat: missing operand\r\n"
    else:
        response = f"{command}: Command not found\r\n"
    
    msg.send(response.encode("utf-8"))  # Send response as bytes


def handle_connection(client, addr):
    """Manages incoming connections, handles authentication and commands for the honeypot.
    Logs connection attempts and simulates a shell prompt."""
    client_ip = addr[0]
    log.info(f'New connection from: {client_ip}')

    transport = paramiko.Transport(client)
    transport.add_server_key(HOST_KEY)
    transport.local_version = SSH_BANNER
    server = SshHoneypot(client_ip) 

    try:
        transport.start_server(server=server)
        msg = transport.accept(20)
        if msg is None:
            log.warning(f"No message received from {client_ip} within the timeout.")
            return

        time.sleep(1)
        date = datetime.now().strftime("%a %b %d %I:%M:%S %p %Z %Y") + "\r\n"
        msg.send(f"Welcome to the Kali Linux SSH server\r\nLast login: {date}".encode("utf-8"))

        time.sleep(5)
        while True:
            user = server.username  
            #Simulate a Linux shell prompt
            prompt_part1 = colored("┌──(", 'light_green')
            prompt_part2 = colored(f"{user}㉿kali", 'blue', attrs=['bold'])  
            prompt_part3 = colored(")-[~]", 'light_green')
            prompt_part4 = colored("└─", 'light_green')
            prompt_part5 = colored("$ ", 'blue', attrs=['bold'])
            format_prompt = (
                f"{prompt_part1}{prompt_part2}{prompt_part3}\n{prompt_part4}{prompt_part5}"
            )
            msg.send(format_prompt.encode("utf-8")) 

            try:
                command = msg.recv(1024).decode("utf-8").strip()
                if command == "exit":
                    log.info(f'Command from {client_ip}: {command}')
                    break
                else:
                    log.info(f'Command from {client_ip}: {command}')
                    handle_command(command, msg, user)
            except Exception as e:
                log.error(f'Error processing command from {client_ip}: {e}')
                msg.send(f"Error processing command: {e}\r\n".encode("utf-8"))

    except Exception as e:
        log.error(f'Error handling connection from {client_ip}: {e}')
        try: 
            if msg:
                msg.send("An error occurred in the connection.\r\n".encode("utf-8"))
                msg.close()
                transport.close()
        except:
            pass
    else:
        msg.close()
        transport.close()


def capture_user_input():
    """Waits for user input to stop the honeypot server"""
    global stop_server
    x = input("Presione Enter para detener la honeypot...")
    stop_server = True


def start_server(port, bind_addr):
    """Initializes and starts the SSH honeypot server on the specified port and address."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_addr, port))
    sock.listen(100)
    sock.settimeout(1)  

    log.info(f'Server listening on {bind_addr}:{port}')
    print(f"""
          **SSH HONEYPOT**
Servidor escuchando en {bind_addr} : {port} \n""")

    while not stop_server:
        try:
            client, addr = sock.accept()
            threading.Thread(target=handle_connection, args=(client, addr)).start()
        except socket.timeout:
            continue
        except Exception as e:
            log.error(f'Error accepting connection: {e}')

    print("Honeypot Detenida.")


def start_honeypot(port):
    """Starts the honeypot by initializing the SSH server and capturing user input to stop the server."""
    honeypot_address = get_local_ip()

    input_thread = threading.Thread(target=capture_user_input)
    input_thread.start()

    start_server(port, honeypot_address)

    input_thread.join()
