# libraries
import logging
from logging.handlers import RotatingFileHandler
import socket
import threading
import paramiko

SSH_BANNER = "SSH-2.0-PucciSSH_1.0"
host_key = paramiko.RSAKey(filename="server.key")

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
    channel.send(b"user@honeypot$ ")
    command = b""
    
    while True:
        try:
            char = channel.recv(1)
            if not char:
                break
            channel.send(char)
            command += char

            if char == b"\r":
                cmd = command.strip().decode('utf-8', errors='ignore')
                if cmd == "whoami":
                    response = b"\nuser\r\n"
                elif cmd == "pwd":
                    response = b"\n/home/user\r\n"
                elif cmd == "ls":
                    response = b"\ntest.txt\r\n"
                elif cmd == "ls -la":
                    response = b"\n-rw-r--r-- 1 user user 0 Oct 12 10:37 test.txt\r\n"
                elif cmd == "cat text.txt":
                    response = b"\nThis is a test file.\r\n"
                elif cmd == "exit":
                    response = b"\nGoodbye!\n"
                    channel.send(response)
                    channel.close()
                    break
                elif cmd == "history":
                    response_str = ""
                    for index, command in enumerate(history):
                        response_str += f"{index}:\t{command}\n"
                    response = b"\n" + response_str.encode() + b"\r\n"


                else:
                    response = b"\nUnknown command\r\n"
                    
                

                channel.send(response)
                channel.send(b"user@honeypot$ ")
                command = b""
        except Exception as e:
            print(f"[{client_ip}] Error in shell: {e}")
            break

    try:
        channel.close()
    except:
        pass

# SSH Server + Sockets
class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, input_passwords=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_passwords = input_passwords

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username: str) -> str:
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
    
    def check_channel_pty_request(self,channel,term,width,height,pixelwidth,pixelheight,modes):
        return True

    
def client_handler(client,addr,username,password):
    client_ip = addr[0]
    print(f"{client_ip} has connected")
    
    try:
        
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = SSHServer(client_ip=client_ip, input_username=username,input_passwords=password)
        
        transport.add_server_key(host_key)
        
        transport.start_server(server=server)
        
        channel = transport.accept(100)
        if channel is None:
            print("No channel was opened.")
            
        standard_banner = "hello world\n\r"
        channel.send(standard_banner)
        emulate_shell(channel,client_ip=client_ip)
    except Exception as e:
        print(f"{e}")
    finally:
        try:
            channel.close()
        except Exception as e:
            print(f"{e}")

    
# Provision SSH_based  Server

def honeypot(address, port, username, password):
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address,port))
    
    socks.listen(100)
    print(f"Honeypot listening on {address}:{port}")
    
    while True:
        try:
            client, addr = socks.accept()
            client_thread = threading.Thread(target=client_handler, args=(client,addr,username,password))
            client_thread.start()
        except Exception as e:
            raise e
honeypot('127.0.0.1',2223,'user','password')



