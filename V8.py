import socket
import threading
import pickle
import binascii
import hashlib
import secrets
import time
import os
from tinyec import registry
from Crypto.Cipher import AES

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

curve = registry.get_curve('brainpoolP256r1')

def ecc_point_to_256_bit_key(point):
    bx = int.to_bytes(point.x, 32, 'big')
    by = int.to_bytes(point.y, 32, 'big')
    h = hashlib.sha256()
    h.update(bx)
    h.update(by)
    return h.digest()

def encrypt_AES_GCM(msg_bytes, secretKey):
    aes = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aes.encrypt_and_digest(msg_bytes)
    return ciphertext, aes.nonce, authTag

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aes = AES.new(secretKey, AES.MODE_GCM, nonce=nonce)
    return aes.decrypt_and_verify(ciphertext, authTag)

def encrypt_ECC(msg_bytes, shared_point):
    key = ecc_point_to_256_bit_key(shared_point)
    return encrypt_AES_GCM(msg_bytes, key)

def decrypt_ECC(encrypted_tuple, shared_point):
    ct, nonce, tag = encrypted_tuple
    key = ecc_point_to_256_bit_key(shared_point)
    return decrypt_AES_GCM(ct, nonce, tag, key)

def send_with_length(sock, data_bytes):
    header = len(data_bytes).to_bytes(4, 'big')
    sock.sendall(header + data_bytes)

def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            raise ConnectionError("Socket closed while receiving data")
        data += part
    return data

def recv_with_length(sock):
    header = recv_exact(sock, 4)
    length = int.from_bytes(header, 'big')
    if length == 0:
        return b''
    return recv_exact(sock, length)

def file_to_bytes(path):
    with open(path, "rb") as f:
        return f.read()

def save_bytes_to_file(data, out_path):
    with open(out_path, "wb") as f:
        f.write(data)

def run_sender_file(server_ip, server_port, file_path, log_fn):
    try:
        log_fn(f"Sender(file): loading {file_path}")
        msg_bytes = file_to_bytes(file_path)
        fname = os.path.basename(file_path).encode('utf-8')
        log_fn(f"Sender(file): size {len(msg_bytes)} bytes, filename '{fname.decode()}'")

        sender_priv = secrets.randbelow(curve.field.n)
        sender_pub = sender_priv * curve.g

        try:
            with open("S_pubkey.txt", "w") as f:
                f.write(str(sender_pub))
            log_fn("Sender: saved S_pubkey.txt")
        except Exception:
            log_fn("Sender: couldn't save S_pubkey.txt (ignore)")

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        log_fn(f"Sender: connecting to {server_ip}:{server_port} ...")
        start = time.time()
        while True:
            try:
                client.connect((server_ip, server_port))
                break
            except (ConnectionRefusedError, OSError) as e:
                if time.time() - start > 30:
                    log_fn(f"Sender: connection timed out after 30s: {e}")
                    return
                time.sleep(0.5)

        send_with_length(client, pickle.dumps(sender_pub))
        log_fn("Sender: public key sent.")

        recv_pk_bytes = recv_with_length(client)
        receiver_pub = pickle.loads(recv_pk_bytes)
        try:
            with open("S_receiver_pubkey.txt", "w") as f:
                f.write(str(receiver_pub))
            log_fn("Sender: saved S_receiver_pubkey.txt")
        except Exception:
            log_fn("Sender: couldn't save S_receiver_pubkey.txt (ignore)")

        shared = sender_priv * receiver_pub
        log_fn("Sender: shared point computed.")

        ct, nonce, tag = encrypt_ECC(msg_bytes, shared)

        try:
            with open("ciphertext_sender.txt", "w") as f:
                f.write(binascii.hexlify(ct).decode() + "\n")
                f.write(binascii.hexlify(nonce).decode() + "\n")
                f.write(binascii.hexlify(tag).decode() + "\n")
            log_fn("Sender: ciphertext saved to ciphertext_sender.txt")
        except Exception:
            log_fn("Sender: couldn't save ciphertext file (ignore)")

        payload = (
            "FILE\n"
            + binascii.hexlify(ct).decode() + "\n"
            + binascii.hexlify(nonce).decode() + "\n"
            + binascii.hexlify(tag).decode() + "\n"
        ).encode('ascii')

        send_with_length(client, payload)
        log_fn("Sender: encrypted payload (file) sent.")

        send_with_length(client, fname)
        log_fn(f"Sender: filename '{fname.decode()}' sent.")

        client.close()
        log_fn("Sender: finished and closed socket.")
    except Exception as e:
        log_fn(f"Sender(file) error: {repr(e)}")

def run_sender_text(server_ip, server_port, text_msg, log_fn):
    try:
        msg_bytes = text_msg.encode('utf-8')
        log_fn(f"Sender(text): message length {len(msg_bytes)} bytes")

        sender_priv = secrets.randbelow(curve.field.n)
        sender_pub = sender_priv * curve.g

        try:
            with open("S_pubkey.txt", "w") as f:
                f.write(str(sender_pub))
            log_fn("Sender: saved S_pubkey.txt")
        except Exception:
            pass

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        log_fn(f"Sender(text): connecting to {server_ip}:{server_port} ...")
        start = time.time()
        while True:
            try:
                client.connect((server_ip, server_port))
                break
            except (ConnectionRefusedError, OSError):
                if time.time() - start > 30:
                    log_fn("Sender(text): connection timed out after 30s")
                    return
                time.sleep(0.5)

        send_with_length(client, pickle.dumps(sender_pub))
        log_fn("Sender(text): public key sent.")

        recv_pk_bytes = recv_with_length(client)
        receiver_pub = pickle.loads(recv_pk_bytes)
        try:
            with open("S_receiver_pubkey.txt", "w") as f:
                f.write(str(receiver_pub))
            log_fn("Sender(text): saved S_receiver_pubkey.txt")
        except Exception:
            pass

        shared = sender_priv * receiver_pub

        ct, nonce, tag = encrypt_ECC(msg_bytes, shared)

        try:
            with open("ciphertext_sender_text.txt", "w") as f:
                f.write(binascii.hexlify(ct).decode() + "\n")
                f.write(binascii.hexlify(nonce).decode() + "\n")
                f.write(binascii.hexlify(tag).decode() + "\n")
            log_fn("Sender(text): ciphertext saved to ciphertext_sender_text.txt")
        except Exception:
            log_fn("Sender(text): couldn't save ciphertext file (ignore)")

        payload = (
            "TEXT\n"
            + binascii.hexlify(ct).decode() + "\n"
            + binascii.hexlify(nonce).decode() + "\n"
            + binascii.hexlify(tag).decode() + "\n"
        ).encode('ascii')

        send_with_length(client, payload)
        log_fn("Sender(text): encrypted text payload sent.")

        client.close()
        log_fn("Sender(text): finished and closed socket.")
    except Exception as e:
        log_fn(f"Sender(text) error: {repr(e)}")

def run_receiver(listen_ip, listen_port, save_as_path, log_fn, running_flag):
    server = None
    try:
        receiver_priv = secrets.randbelow(curve.field.n)
        receiver_pub = receiver_priv * curve.g
        print(receiver_priv)

        try:
            with open("R_pubkey.txt", "w") as f:
                f.write(str(receiver_pub))
            log_fn("Receiver: saved R_pubkey.txt")
        except Exception:
            pass

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((listen_ip, listen_port))
        server.listen(5)
        server.settimeout(1.0)  
        log_fn(f"Receiver: LISTENING on {listen_ip}:{listen_port}")

        while running_flag():
            try:
                try:
                    conn, addr = server.accept()
                except socket.timeout:
                    continue
                except OSError as e:
                    log_fn(f"Receiver: accept OSError: {repr(e)}")
                    break

                log_fn(f"Receiver: connection from {addr}")

                try:
                    data_pk = recv_with_length(conn)
                    if data_pk is None:
                        raise RuntimeError("Receiver: no public key received")
                    sender_pub = pickle.loads(data_pk)
                    try:
                        with open("R_sender_pubkey.txt", "w") as f:
                            f.write(str(sender_pub))
                        log_fn("Receiver: saved R_sender_pubkey.txt")
                    except Exception:
                        pass

                    send_with_length(conn, pickle.dumps(receiver_pub))
                    log_fn("Receiver: sent receiver public key.")

                    payload = recv_with_length(conn)
                    if payload is None:
                        raise RuntimeError("Receiver: empty payload")
                    try:
                        lines = payload.decode('ascii', errors='ignore').strip().splitlines()
                    except Exception:
                        raise RuntimeError("Receiver: cannot decode payload header")

                    if len(lines) < 4:
                        raise RuntimeError("Receiver: malformed payload header")

                    data_type = lines[0].strip().upper()
                    ct_hex = lines[1].strip()
                    nonce_hex = lines[2].strip()
                    tag_hex = lines[3].strip()

                    try:
                        if data_type == "TEXT":
                            with open("ciphertext_receiver_text.txt", "w") as f:
                                f.write(ct_hex + "\n" + nonce_hex + "\n" + tag_hex + "\n")
                        else:
                            with open("ciphertext_receiver.txt", "w") as f:
                                f.write(ct_hex + "\n" + nonce_hex + "\n" + tag_hex + "\n")
                        log_fn("Receiver: ciphertext saved.")
                    except Exception:
                        pass

                    ct = binascii.unhexlify(ct_hex)
                    nonce = binascii.unhexlify(nonce_hex)
                    tag = binascii.unhexlify(tag_hex)

                    shared = receiver_priv * sender_pub
                    decrypted = decrypt_ECC((ct, nonce, tag), shared)
                    log_fn(f"Receiver: decrypted {len(decrypted)} bytes.")

                    if data_type == "TEXT":
                        text_msg = decrypted.decode('utf-8', errors='replace')
                        log_fn(f"[Received TEXT] {text_msg}")
                    elif data_type == "FILE":
                        fname_bytes = recv_with_length(conn)
                        orig_name = fname_bytes.decode('utf-8', errors='replace') if fname_bytes else "received_file"
                        out_path = save_as_path or orig_name
                        try:
                            save_bytes_to_file(decrypted, out_path)
                            log_fn(f"Receiver: file saved to '{out_path}' (original name: '{orig_name}')")
                        except Exception as e:
                            log_fn(f"Receiver: error saving file: {repr(e)}")
                    else:
                        log_fn(f"Receiver: unknown data_type '{data_type}'")

                except Exception as e:
                    log_fn(f"Receiver error during connection handling: {repr(e)}")

                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    log_fn("Receiver: connection closed")

            except Exception as e:
                log_fn(f"Receiver loop unexpected error: {repr(e)}")

        log_fn("Receiver: exiting listening loop.")
    except Exception as e:
        log_fn(f"Receiver fatal error: {repr(e)}")
    finally:
        if server:
            try:
                server.close()
            except Exception:
                pass
        log_fn("Receiver: socket closed (final).")

class App:
    def __init__(self, root):
        self.root = root
        root.title("ECCDH")

        self.receiver_running = False
        self.receiver_thread = None

        top = tk.Frame(root)
        top.pack(padx=8, pady=8, fill='x')

        local_ip = self.get_local_ip()
        tk.Label(top, text=f"Local IP detected: {local_ip}", fg='blue').grid(row=0, column=0, columnspan=3, sticky='w')

        tk.Label(top, text="IP:").grid(row=1, column=0, sticky='w')
        self.ip_entry = tk.Entry(top)
        self.ip_entry.grid(row=1, column=1, sticky='we', columnspan=2)
        self.ip_entry.insert(0, "127.0.0.1")

        tk.Label(top, text="Port:").grid(row=2, column=0, sticky='w')
        self.port_entry = tk.Entry(top)
        self.port_entry.grid(row=2, column=1, sticky='we', columnspan=2)
        self.port_entry.insert(0, "65432")

        tk.Label(top, text="Mode:").grid(row=3, column=0, sticky='w')
        self.mode_var = tk.StringVar(value='send')
        tk.Radiobutton(top, text="Send", variable=self.mode_var, value='send', command=self._mode_changed).grid(row=3, column=1, sticky='w')
        tk.Radiobutton(top, text="Receive", variable=self.mode_var, value='receive', command=self._mode_changed).grid(row=3, column=2, sticky='w')

        tk.Label(top, text="Send as:").grid(row=4, column=0, sticky='w')
        self.send_type = tk.StringVar(value='text')
        tk.Radiobutton(top, text="Text", variable=self.send_type, value='text').grid(row=4, column=1, sticky='w')
        tk.Radiobutton(top, text="File", variable=self.send_type, value='file').grid(row=4, column=2, sticky='w')

        tk.Label(top, text="File to send:").grid(row=5, column=0, sticky='w')
        self.file_path_var = tk.StringVar()
        self.file_entry = tk.Entry(top, textvariable=self.file_path_var)
        self.file_entry.grid(row=5, column=1, sticky='we')
        tk.Button(top, text="Browse...", command=self.browse_file).grid(row=5, column=2)

        tk.Label(top, text="Save received as:").grid(row=6, column=0, sticky='w')
        self.out_entry = tk.Entry(top)
        self.out_entry.grid(row=6, column=1, sticky='we')
        self.out_entry.insert(0, "")
        tk.Button(top, text="Browse...", command=self.browse_out).grid(row=6, column=2)

        tk.Label(top, text="Text message:").grid(row=7, column=0, sticky='w')
        self.text_msg_entry = tk.Entry(top)
        self.text_msg_entry.grid(row=7, column=1, sticky='we', columnspan=2)

        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=(6,0))
        self.start_btn = tk.Button(btn_frame, text="Start", command=self.start_operation, width=12)
        self.start_btn.grid(row=0, column=0, padx=4)
        self.stop_btn = tk.Button(btn_frame, text="Stop", command=self.stop_receiver, width=12, state='disabled')
        self.stop_btn.grid(row=0, column=1, padx=4)

        self.log = scrolledtext.ScrolledText(root, width=100, height=20, state='disabled')
        self.log.pack(padx=8, pady=8)

        top.grid_columnconfigure(1, weight=1)

        self.log_fn(f"App ready. Local IP: {local_ip}")
        self._mode_changed()

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def browse_file(self):
        path = filedialog.askopenfilename(title="Select file to send")
        if path:
            self.file_path_var.set(path)

    def browse_out(self):
        path = filedialog.asksaveasfilename(title="Save received file as", defaultextension="")
        if path:
            self.out_entry.delete(0, tk.END)
            self.out_entry.insert(0, path)

    def log_fn(self, msg):
        timestamp = time.strftime("%H:%M:%S")
        self.log.configure(state='normal')
        self.log.insert(tk.END, f"[{timestamp}] {msg}\n")
        self.log.see(tk.END)
        self.log.configure(state='disabled')

    def _mode_changed(self):
        mode = self.mode_var.get()
        if mode == 'send':
            self.file_entry.configure(state='normal')
            self.text_msg_entry.configure(state='normal')
            self.start_btn.configure(text='Start (send)')
        else:
            self.file_entry.configure(state='disabled')
            self.text_msg_entry.configure(state='disabled')
            self.start_btn.configure(text='Start (receive)')

    def start_operation(self):
        mode = self.mode_var.get()
        ip = self.ip_entry.get().strip()
        try:
            port = int(self.port_entry.get().strip())
        except ValueError:
            messagebox.showerror("Invalid port", "Port must be an integer")
            return

        if mode == 'send':
            data_type = self.send_type.get()
            if data_type == "file":
                file_path = self.file_path_var.get().strip()
                if not file_path or not os.path.isfile(file_path):
                    messagebox.showerror("No file", "Please choose a valid file to send.")
                    return
                t = threading.Thread(target=run_sender_file, args=(ip, port, file_path, self.log_fn), daemon=True)
                t.start()
                self.log_fn("Started sender thread (file).")
            else:
                text_msg = self.text_msg_entry.get()
                if not text_msg:
                    messagebox.showerror("No text", "Please enter a text message to send.")
                    return
                t = threading.Thread(target=run_sender_text, args=(ip, port, text_msg, self.log_fn), daemon=True)
                t.start()
                self.log_fn("Started sender thread (text).")
        else:
            # Receiver mode
            if self.receiver_running:
                self.log_fn("Receiver already running.")
                return

            out_path = self.out_entry.get().strip() or None
            self.receiver_running = True
            self.start_btn.configure(state='disabled')
            self.stop_btn.configure(state='normal')
            self.log_fn("Starting receiver (looping).")

            t = threading.Thread(target=run_receiver, args=(ip, port, out_path, self.log_fn, lambda: self.receiver_running), daemon=True)
            self.receiver_thread = t
            t.start()

    def stop_receiver(self):
        if not self.receiver_running:
            self.log_fn("Receiver not running.")
            return
        self.receiver_running = False
        self.start_btn.configure(state='normal')
        self.stop_btn.configure(state='disabled')
        self.log_fn("Stop requested: trying to wake listener (if blocked) and stop.")

        try:
            wake = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            wake.settimeout(1.0)
            listen_ip = self.ip_entry.get().strip()
            listen_port = int(self.port_entry.get().strip())
            try:
                wake.connect((listen_ip, listen_port))
            except Exception:
                try:
                    wake.connect(("127.0.0.1", listen_port))
                except Exception:
                    pass
            try:
                wake.close()
            except Exception:
                pass
        except Exception:
            pass


if __name__ == '__main__':
    root = tk.Tk()
    app = App(root)
    root.mainloop()
