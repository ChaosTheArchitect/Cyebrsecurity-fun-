import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk
from cryptography.fernet import Fernet
import ssl

# Generate a random secret key for AES encryption
secret_key = Fernet.generate_key()
cipher_suite = Fernet(secret_key)

client = None


def start_server():
    global client

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="path_to_certfile.pem", keyfile="path_to_keyfile.pem")  # You'll need to generate these

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 9999))
    server.listen()

    conn, addr = server.accept()
    client = context.wrap_socket(conn, server_side=True)

    chat_log.insert(tk.END, "Connected!\n")
    chat_log.see(tk.END)


def connect_to_server():
    global client

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations('path_to_ca_cert.pem')  # Path to your CA cert

    client = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=host_entry.get())
    client.connect((host_entry.get(), 9999))

    chat_log.insert(tk.END, "Connected!\n")
    chat_log.see(tk.END)


def send_message():
    message = message_entry.get()
    if message:
        encrypted_msg = cipher_suite.encrypt(message.encode())
        client.send(encrypted_msg)
        chat_log.insert(tk.END, "You: " + message + "\n")
        chat_log.see(tk.END)
        message_entry.delete(0, tk.END)


def receive_messages():
    while True:
        try:
            encrypted_msg = client.recv(1024)
            decrypted_msg = cipher_suite.decrypt(encrypted_msg).decode()
            chat_log.insert(tk.END, "Partner: " + decrypted_msg + "\n")
            chat_log.see(tk.END)
        except Exception as e:
            chat_log.insert(tk.END, f"Error: {e}\n")
            chat_log.see(tk.END)
            break


def start_chat(hosting):
    if hosting:
        threading.Thread(target=start_server, daemon=True).start()
    else:
        connect_to_server()

    threading.Thread(target=receive_messages, daemon=True).start()


# Rest of the GUI code remains the same as previously provided...


# GUI Setup
root = tk.Tk()
root.title("Secure Chat")
root.geometry("400x500")

frame = ttk.Frame(root)
frame.pack(pady=20)

host_button = ttk.Button(frame, text="Host", command=lambda: start_chat(True))
host_button.pack(side=tk.LEFT, padx=20)

host_entry = ttk.Entry(frame, width=15)
host_entry.pack(side=tk.LEFT)
host_entry.insert(0, "192.168.1.75")

connect_button = ttk.Button(frame, text="Connect", command=lambda: start_chat(False))
connect_button.pack(side=tk.LEFT, padx=20)

chat_log = scrolledtext.ScrolledText(root, width=50, height=20)
chat_log.pack(pady=20)

message_entry = ttk.Entry(root, width=40)
message_entry.pack(pady=20)

send_button = ttk.Button(root, text="Send", command=send_message)
send_button.pack()

root.mainloop()
