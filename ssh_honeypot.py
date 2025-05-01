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
    while True:
        char = channel.recv(1)
        channel.send(char)
        if not char:
            channel.close()
        command += char

        if char == b"\r":
            if command.strip() == b"whoami":
                response = b"\n" + "user" + b"\r\n"
            elif command.strip() == b"exit":
                response = b"\n" + "Goodbye!" + b"\n"
                channel.close()
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