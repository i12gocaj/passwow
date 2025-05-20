import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog
import os
from vault.storage import load_entries, save_entries
from vault.crypto import derive_key, encrypt_data, _SALT_SIZE
from vault.session import DEFAULT_SESSION_FILE, save_session, load_session, clear_session
from pathlib import Path
import json
import time
import string
import secrets

class PasswowGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Passwow - Gestor de Contraseñas")
        self.vault_path = "vault.dat"
        self.session_key = None
        self.create_main_menu()
        self.show_welcome()

    def create_main_menu(self):
        menubar = tk.Menu(self.root)
        vault_menu = tk.Menu(menubar, tearoff=0)
        vault_menu.add_command(label="Inicializar Vault", command=self.init_vault)
        vault_menu.add_command(label="Cambiar Contraseña Maestra", command=self.change_master_password)
        vault_menu.add_separator()
        vault_menu.add_command(label="Exportar Vault", command=self.export_vault)
        vault_menu.add_command(label="Importar Vault", command=self.import_vault)
        vault_menu.add_separator()
        vault_menu.add_command(label="Borrado Seguro", command=self.delete_vault)
        menubar.add_cascade(label="Vault", menu=vault_menu)

        entry_menu = tk.Menu(menubar, tearoff=0)
        entry_menu.add_command(label="Añadir Entrada", command=self.add_entry)
        entry_menu.add_command(label="Listar Entradas", command=self.list_entries)
        entry_menu.add_command(label="Buscar Entrada", command=self.get_entry)
        entry_menu.add_command(label="Eliminar Entrada", command=self.remove_entry)
        menubar.add_cascade(label="Entradas", menu=entry_menu)

        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Comprobar Contraseña (Pwned)", command=self.check_pwned)
        menubar.add_cascade(label="Herramientas", menu=tools_menu)

        self.root.config(menu=menubar)

    def show_welcome(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        label = tk.Label(self.root, text="Bienvenido a Passwow\nGestor de contraseñas local y seguro", font=("Arial", 16), pady=20)
        label.pack()
        # Añadir botones grandes para cada acción principal
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=10)
        actions = [
            ("Inicializar Vault", self.init_vault),
            ("Añadir Entrada", self.add_entry),
            ("Listar Entradas", self.list_entries),
            ("Buscar Entrada", self.get_entry),
            ("Eliminar Entrada", self.remove_entry),
            ("Exportar Vault", self.export_vault),
            ("Importar Vault", self.import_vault),
            ("Cambiar Contraseña Maestra", self.change_master_password),
            ("Borrado Seguro", self.delete_vault),
            ("Comprobar Contraseña (Pwned)", self.check_pwned),
        ]
        for i, (text, cmd) in enumerate(actions):
            btn = tk.Button(btn_frame, text=text, width=30, height=2, command=cmd)
            btn.grid(row=i//2, column=i%2, padx=10, pady=5)

    def init_vault(self):
        # Implementación básica: pide contraseña y crea vault
        password = simpledialog.askstring("Contraseña Maestra", "Introduce una nueva contraseña maestra:", show='*')
        if not password:
            return
        if Path(self.vault_path).exists():
            messagebox.showwarning("Vault existente", f"El vault '{self.vault_path}' ya existe.")
            return
        salt = os.urandom(_SALT_SIZE)
        key = derive_key(password, salt)
        initial_data = json.dumps([]).encode()
        iv, ciphertext = encrypt_data(key, initial_data)
        with open(self.vault_path, "wb") as vault_file:
            vault_file.write(salt + iv + ciphertext)
        Path(self.vault_path).chmod(0o600)
        messagebox.showinfo("Vault creado", f"Vault inicializado correctamente en '{self.vault_path}'.")

    def change_master_password(self):
        # Cambiar la contraseña maestra
        if not Path(self.vault_path).exists():
            messagebox.showerror("Error", f"No se encontró el vault '{self.vault_path}'.")
            return
        old_pw = simpledialog.askstring("Contraseña actual", "Introduce la contraseña maestra actual:", show='*')
        if not old_pw:
            return
        try:
            entries = load_entries(self.vault_path, old_pw)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo abrir el vault: {e}")
            return
        new_pw = simpledialog.askstring("Nueva contraseña", "Introduce la nueva contraseña maestra:", show='*')
        if not new_pw:
            return
        try:
            save_entries(self.vault_path, new_pw, entries)
            messagebox.showinfo("Éxito", "Contraseña maestra cambiada correctamente.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo cambiar la contraseña: {e}")

    def export_vault(self):
        # Exportar vault a bin, JSON o CSV
        password = simpledialog.askstring("Contraseña Maestra", "Introduce la contraseña maestra:", show='*')
        if not password:
            return
        if not Path(self.vault_path).exists():
            messagebox.showerror("Error", f"No se encontró el vault '{self.vault_path}'.")
            return
        try:
            entries = load_entries(self.vault_path, password)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo abrir el vault: {e}")
            return
        export_type = simpledialog.askstring("Formato de exportación", "Formato (bin/json/csv):", initialvalue="bin")
        if not export_type or export_type not in ("bin", "json", "csv"):
            messagebox.showwarning("Formato inválido", "El formato debe ser bin, json o csv.")
            return
        dest_path = filedialog.asksaveasfilename(title="Guardar como", defaultextension=export_type)
        if not dest_path:
            return
        try:
            if export_type == "bin":
                with open(self.vault_path, "rb") as src, open(dest_path, "wb") as dst:
                    dst.write(src.read())
                Path(dest_path).chmod(0o600)
            elif export_type == "json":
                with open(dest_path, "w", encoding="utf-8") as f:
                    json.dump(entries, f, ensure_ascii=False, indent=2)
                Path(dest_path).chmod(0o600)
            elif export_type == "csv":
                import csv
                with open(dest_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=["name", "username", "password", "note", "timestamp"])
                    writer.writeheader()
                    for entry in entries:
                        writer.writerow(entry)
                Path(dest_path).chmod(0o600)
            messagebox.showinfo("Exportado", f"Vault exportado correctamente a '{dest_path}'.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo exportar: {e}")

    def import_vault(self):
        # Importar vault cifrado (bin)
        src_path = filedialog.askopenfilename(title="Selecciona el archivo a importar")
        if not src_path:
            return
        if Path(self.vault_path).exists():
            overwrite = messagebox.askyesno("Sobrescribir", f"El vault '{self.vault_path}' ya existe. ¿Sobrescribir?")
            if not overwrite:
                return
        try:
            with open(src_path, "rb") as src, open(self.vault_path, "wb") as dst:
                dst.write(src.read())
            Path(self.vault_path).chmod(0o600)
            messagebox.showinfo("Importado", f"Vault importado correctamente desde '{src_path}'.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo importar: {e}")

    def delete_vault(self):
        # Borrado seguro del vault
        if not Path(self.vault_path).exists():
            messagebox.showerror("Error", f"No se encontró el vault '{self.vault_path}'.")
            return
        confirm = simpledialog.askstring("Confirmar borrado", "Escribe BORRAR para eliminar el vault y todos sus datos:")
        if confirm != "BORRAR":
            messagebox.showinfo("Cancelado", "Operación cancelada.")
            return
        try:
            os.remove(self.vault_path)
            messagebox.showinfo("Eliminado", "Vault y datos eliminados de forma segura.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo eliminar el vault: {e}")

    def add_entry(self):
        # Añadir una nueva entrada al vault
        password = simpledialog.askstring("Contraseña Maestra", "Introduce la contraseña maestra:", show='*')
        if not password:
            return
        try:
            entries = load_entries(self.vault_path, password)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo abrir el vault: {e}")
            return
        name = simpledialog.askstring("Nombre de la entrada", "Identificador único:")
        if not name:
            return
        username = simpledialog.askstring("Usuario", "Nombre de usuario/login:")
        if not username:
            return
        note = simpledialog.askstring("Nota", "Nota opcional:")
        gen = messagebox.askyesno("Contraseña", "¿Generar contraseña segura automáticamente?")
        if gen:
            length = simpledialog.askinteger("Longitud", "Longitud de la contraseña generada:", initialvalue=20, minvalue=8, maxvalue=64)
            alphabet = string.ascii_letters + string.digits + string.punctuation
            entry_pass = ''.join(secrets.choice(alphabet) for _ in range(length))
        else:
            entry_pass = simpledialog.askstring("Contraseña", "Contraseña para la entrada:", show='*')
            if not entry_pass:
                return
        new_entry = {
            "name": name,
            "username": username,
            "password": entry_pass,
            "note": note or "",
            "timestamp": int(time.time()),
        }
        entries.append(new_entry)
        try:
            save_entries(self.vault_path, password, entries)
            messagebox.showinfo("Éxito", f"Entrada '{name}' añadida correctamente.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo guardar la entrada: {e}")

    def list_entries(self):
        # Lista todas las entradas del vault
        password = simpledialog.askstring("Contraseña Maestra", "Introduce la contraseña maestra:", show='*')
        if not password:
            return
        try:
            entries = load_entries(self.vault_path, password)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo abrir el vault: {e}")
            return
        if not entries:
            messagebox.showinfo("Entradas", "No hay entradas guardadas en el vault.")
            return
        win = tk.Toplevel(self.root)
        win.title("Entradas del Vault")
        text = tk.Text(win, width=80, height=20)
        text.pack()
        text.insert(tk.END, f"{'Nombre':<20} {'Usuario':<20} {'Creado':<20}\n")
        text.insert(tk.END, "-" * 60 + "\n")
        for e in entries:
            created = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(e['timestamp']))
            text.insert(tk.END, f"{e['name']:<20} {e['username']:<20} {created:<20}\n")
        text.config(state=tk.DISABLED)

    def get_entry(self):
        # Recupera y muestra los detalles de una entrada
        password = simpledialog.askstring("Contraseña Maestra", "Introduce la contraseña maestra:", show='*')
        if not password:
            return
        try:
            entries = load_entries(self.vault_path, password)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo abrir el vault: {e}")
            return
        name = simpledialog.askstring("Buscar Entrada", "Nombre de la entrada a recuperar:")
        if not name:
            return
        entry = next((e for e in entries if e["name"] == name), None)
        if not entry:
            messagebox.showwarning("No encontrada", f"No existe una entrada con nombre '{name}'.")
            return
        created = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(entry['timestamp']))
        details = f"Nombre: {entry['name']}\nUsuario: {entry['username']}\nContraseña: {entry['password']}\nNota: {entry['note'] or '-'}\nCreado: {created}"
        messagebox.showinfo("Detalles de la entrada", details)

    def remove_entry(self):
        # Elimina una entrada del vault
        password = simpledialog.askstring("Contraseña Maestra", "Introduce la contraseña maestra:", show='*')
        if not password:
            return
        try:
            entries = load_entries(self.vault_path, password)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo abrir el vault: {e}")
            return
        name = simpledialog.askstring("Eliminar Entrada", "Nombre de la entrada a eliminar:")
        if not name:
            return
        if not any(e["name"] == name for e in entries):
            messagebox.showwarning("No encontrada", f"No existe una entrada con nombre '{name}'.")
            return
        new_entries = [e for e in entries if e["name"] != name]
        try:
            save_entries(self.vault_path, password, new_entries)
            messagebox.showinfo("Eliminada", f"Entrada '{name}' eliminada correctamente.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo eliminar la entrada: {e}")

    def check_pwned(self):
        # Comprobar si una contraseña ha sido filtrada (HaveIBeenPwned)
        import hashlib
        import requests
        pw = simpledialog.askstring("Comprobar contraseña", "Introduce la contraseña a comprobar:", show='*')
        if not pw:
            return
        sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        try:
            resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
            if resp.status_code != 200:
                messagebox.showerror("Error", "No se pudo consultar la API de HaveIBeenPwned.")
                return
            hashes = (line.split(":") for line in resp.text.splitlines())
            for suf, count in hashes:
                if suf == suffix:
                    messagebox.showwarning("¡Comprometida!", f"Esta contraseña ha aparecido {count} veces en filtraciones.")
                    return
            messagebox.showinfo("OK", "Esta contraseña NO aparece en la base de datos de filtraciones conocidas.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo consultar la API: {e}")


def main():
    root = tk.Tk()
    app = PasswowGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
