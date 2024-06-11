#!/usr/bin/env python3

import socket
import os
import json
import sys

def get_execution_environment():
    return {
        'os': os.name,
        'platform': os.sys.platform,
        'version': os.sys.version,
        'cwd': os.getcwd()
    }

def send_environment_data():
    
    if len(sys.argv) != 2:
        print("Usage: pseudo_sr.py <socket path>")
        sys.exit(1)
        
    socket_path = sys.argv[1]
    
    # Créer une socket Unix Domain de type datagram
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    except OSError as e:
        print(f"Failed to create socket: {e}")
        return 1
    
    try:
        # Envoyer un message au kernel
        env_data = get_execution_environment()
        env_data_str = bytearray(json.dumps(env_data), "utf8")
        sock.sendto(env_data_str, (socket_path))
    except OSError as e:
        print(f"Failed to send data: {e}")
    finally:
        sock.close()
    
    return 0

if __name__ == "__main__":
    # Redirect stdout and stderr to ./ux_pseudosr.log (append mode)
    sys.stdout = open("ux_pseudosr.log", "a")
    sys.stderr = open("ux_pseudosr.log", "a")
    
    # Définir une variable d'environnement pour indiquer que ce processus est le parent
    os.environ["PARENT_PROCESS"] = "1"
    sys.exit(send_environment_data())
