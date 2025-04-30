#libraries 
import logging
from logging.handlers import RotatingFileHandler
import socket

# Constants
logging_format=logging.Formatter('%(message)s')

# Loggers & Logging files
funnel_logger=logging.getLogger('Funnel_Logger')
funnel_logger.setLevel(logging.INFO)
funnel_handler=RotatingFileHandler('audits.log', maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

credentials_logger=logging.getLogger('Credential_Logger')
credentials_logger.setLevel(logging.INFO)
credentials_handler=RotatingFileHandler('cmd_audits.log', maxBytes=2000, backupCount=5)
credentials_handler.setFormatter(logging_format)
credentials_logger.addHandler(credentials_handler)

#anus
# Emulate Shell

def emulate_shell(channel, client_ip):
    """
    Way to send dialogue messages/strings over the SSH connection
    """
    # Log the command
    channel.send(b'corporate-jumpbox2$')
    command=b""
    while True:
        char=channel.recv(1)
        channel.send(char)
        if not char:
            channel.close()
        


# SSH Server + Sockets

# Provision SSH_based  Server