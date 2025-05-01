# libraries
import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko

SSH_BANNER = "WELCOME TO PUCCI SSH SERVER"
host_key = "server.key"

# Constants
logging_format = logging.Formatter('%(message)s')

# Loggers & Logging files
funnel_logger = logging.getLogger('Funnel_Logger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler(
    'audits.log', maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

credentials_logger = logging.getLogger('Credential_Logger')
credentials_logger.setLevel(logging.INFO)
credentials_handler = RotatingFileHandler(
    'cmd_audits.log', maxBytes=2000, backupCount=5)
credentials_handler.setFormatter(logging_format)
credentials_logger.addHandler(credentials_handler)

# Emulate Shell


def emulate_shell(channel, client_ip):
    """
    Way to send dialogue messages/strings over the SSH connection
    """
    # Log the command
    channel.send("user@honeypot$ ")
    command = b""
    current_directory = b"/home/pucci"
    
    while True:
        char = channel.recv(1)
        channel.send(char)
        if not char:
            channel.close()
        command += char

        if char == b"\r":
            stripped_command = command.strip()
            
            if stripped_command == b"whoami":
                response = b"\n" + "user" + b"\r\n"
                
            elif stripped_command == b"exit":
                response = b"\n" + "Goodbye!" + b"\n"
                channel.close()
                
            elif stripped_command.startswith("echo "):
                response = b"\n" + f"{stripped_command[5:]}\n" + b"\r\n"
                
            elif stripped_command == "ls":
                response = "\nfile1.txt  file2.txt  secret_folder\n"
                
            elif stripped_command.startswith("cat ") and current_directory == b"/home/pucci":
                if stripped_command[3:] == b"file1.txt":
                    response = b"\n" + "eW91IGhhdmUgZW50ZXJlZCBhIHNlY3JldCBmaWxlIApwYXNzd29yZDogd2FfeWFfcGFwYV9wdWNjaQ==.\n" + b"\r\n"
                elif stripped_command[3:] == b"file2.txt":
                    response = b"\n" + "dXNlcm5hbWU6IHB1Y2NpX211Y2NpCnBhc3N3b3JkOiAjJCFzMG0kMG4kI0A=\n" + b"\r\n"
                else: 
                    response = b"\n" + f"cat: {stripped_command[3:]}: No such file or directory\n" + b"\r\n"
            
            elif stripped_command == b"clear":
                response = b"\n" + "\033[H\033[J" + b"\r\n"
                
            elif stripped_command == b"cd secret_folder" and current_directory == b"/home/pucci":
                current_directory = b"/home/pucci/secret_folder"
                response = b"\n" + current_directory + b"\r\n"
            
            elif stripped_command == b"ls" and current_directory == b"/home/pucci/secret_folder":
                response = b"\n\r\n"
            
            elif stripped_command == b"cd ..":
                current_directory = b"/home/pucci"
                response = b"\n" + current_directory + b"\r\n"
                
            elif stripped_command == b"pwd":
                response = b"\n" + current_directory + b"\r\n"  
            
            else:
                response = b"\n" + f"bash: {stripped_command}: command not found\n" + b"\r\n"
            
        channel.send(response)
        channel.send(b"user@honeypot$ ")
        command = b""
        

# SSH Server + Sockets
class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, input_passwords=None):
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_passwords = input_passwords

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self) -> str:
        return "password"

    def check_auth_password(self, username: str, password: str) -> int:
        if username == "user" and password == "password":
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel) -> bool:
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command: str) -> bool:
        command = str(command)
        return True
    
    def check_channel_pty_request(channel, term, width, height, pixelwidth, pixelheight, modes):
        return True
    
def client_handler(client,addr,username,password):
    client_ip = addr[0]
    print(f"{client_ip} has connected")
    
    try:
        
        transport = paramiko.Transport()
        transport.local_version = SSH_BANNER
        server = SSHServer(client_ip=client_ip, input_username=username,input_passwords=password)
        
        transport.add_server_key(host_key)
        
        transport.start_server(server=server)
        
        channel = transport.accept(100)
        if channel is None:
            print("No channel was opened.")
    except Exception as e:
        print(f"{e}")
    finally:
        try:
            channel.close()
        except Exception as e:
            print(f"{e}")

    
# Provision SSH_based  Server