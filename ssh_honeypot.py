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
funnel_handler = RotatingFileHandler('audits.log', maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

credentials_logger = logging.getLogger('Credential_Logger')
credentials_logger.setLevel(logging.INFO)
credentials_handler = RotatingFileHandler('cmd_audits.log', maxBytes=2000, backupCount=5)
credentials_handler.setFormatter(logging_format)
credentials_logger.addHandler(credentials_handler)

# Emulate Shell
# Emulate Shell
def emulate_shell(channel, client_ip):
    current_directory = "/home/pucci"
    history = []
    channel.send(b"user@honeypot$ ")
    command = b""

    while True:
        try:
            char = channel.recv(1)
            if not char:
                break

            # Handle backspace BEFORE echoing or storing it
            if char == b"\x7f" or char == b"\b":
                if len(command) > 0:
                    command = command[:-1]            # remove last byte
                    channel.send(b"\b \b")            # move back, erase, move back again
                continue  # skip the rest, don't echo or add char
            
            # Intercept escape sequences (like arrow keys)
            if char == b'\x1b':
                # Look ahead to see if it's part of an escape sequence
                next1 = channel.recv(1)
                next2 = channel.recv(1)
                sequence = char + next1 + next2

                # Check for arrow keys
                if sequence in [b'\x1b[A', b'\x1b[B', b'\x1b[C', b'\x1b[D']:
                    continue  # Skip them, don't send or store
                else:
                    # Unknown escape sequence, ignore or handle
                    continue
            
            # For normal characters:
            channel.send(char)       # echo the char
            command += char          # add to buffer

            if char == b"\r":
                stripped_command = command.strip().decode('utf-8', errors='ignore')
                history.append(stripped_command)  # <- Append only when full command is received

                if stripped_command == "whoami":
                    response = b"\nuser\r\n"

                elif stripped_command == "history":
                    response_lines = [f"{i}: {cmd}" for i, cmd in enumerate(history)]
                    response_str = "\n".join(response_lines)
                    response = f"\n{response_str}\n\r".encode()


                elif stripped_command == "exit":
                    response = b"\nGoodbye!\n"
                    channel.send(response)
                    channel.close()
                    break

                elif stripped_command.startswith("echo "):
                    response = ("\n" + stripped_command[5:] + "\r\n").encode()

                elif stripped_command == "ls":
                    if current_directory == "/home/pucci":
                        response = b"\nfile1.txt  file2.txt  secret_folder\r\n"
                    elif current_directory == "/home/pucci/secret_folder":
                        response = b"\n\r\n"
                    else:
                        response = b"\n\r\n"

                elif stripped_command.startswith("cat ") and current_directory == "/home/pucci":
                    file = stripped_command[4:]
                    if file == "file1.txt":
                        response = b"\neW91IGhhdmUgZW50ZXJlZCBhIHNlY3JldCBmaWxlIApwYXNzd29yZDogd2FfeWFfcGFwYV9wdWNjaQ==.\n\r\n"
                    elif file == "file2.txt":
                        response = b"\ndXNlcm5hbWU6IHB1Y2NpX211Y2NpCnBhc3N3b3JkOiAjJCFzMG0kMG4kI0A=\n\r\n"
                    else:
                        response = f"\ncat: {file}: No such file or directory\r\n".encode()

                elif stripped_command == "clear":
                    response = b"\n\033[H\033[J\r\n"

                elif stripped_command == "cd secret_folder" and current_directory == "/home/pucci":
                    current_directory = "/home/pucci/secret_folder"
                    response = b"\r\n"

                elif stripped_command == "cd ..":
                    current_directory = "/home/pucci"
                    response = b"\r\n"

                elif stripped_command == "pwd":
                    response = (f"\n{current_directory}\r\n").encode()

                else:
                    if not stripped_command:
                        response = b"\r\n"
                        pass
                    else:
                        response = f"\nbash: {stripped_command}: command not found\n\r\n".encode()

                credentials_logger.info(f"[{client_ip}] {stripped_command}")
                channel.send(response)

                # Send the shell prompt back after response
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
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

# Client Handler
def client_handler(client, addr, username, password):
    client_ip = addr[0]
    print(f"{client_ip} has connected")

    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = SSHServer(client_ip=client_ip, input_username=username, input_passwords=password)
        transport.add_server_key(host_key)
        transport.start_server(server=server)

        channel = transport.accept(100)
        if channel is None:
            print("No channel was opened.")
            return

        standard_banner = "hello world\n\r"
        channel.send(standard_banner.encode())
        emulate_shell(channel, client_ip=client_ip)

    except Exception as e:
        print(f"Exception: {e}")
    finally:
        try:
            channel.close()
        except Exception as e:
            print(f"Exception while closing: {e}")

# Provision SSH Honeypot
def honeypot(address, port, username, password):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, port))
    sock.listen(100)
    print(f"Honeypot listening on {address}:{port}")

    while True:
        try:
            client, addr = sock.accept()
            client_thread = threading.Thread(target=client_handler, args=(client, addr, username, password))
            client_thread.start()
        except Exception as e:
            print(f"Server exception: {e}")

honeypot('127.0.0.1', 2223, 'user', 'password')
