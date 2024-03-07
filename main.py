import customtkinter as ctk
from customtkinter import *
import sqlite3
import re
import socket
from datetime import datetime
import tkinter as tk
from tkinter import ttk
import hashlib


class Start_Window(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title('Test Application')
        self.geometry("300x350")
        self.custom_font = ctk.CTkFont()
        self.custom_font.configure(size=24, family="Rubik Maps")
        self.frame = ctk.CTkFrame(self)
        self.frame.pack(pady=20, padx=12, fill='both', expand=True)
        self.buttons()

    def buttons(self):
        self.login_button = ctk.CTkButton(master=self.frame,
                                          corner_radius=30,
                                          width=200,
                                          height=50,
                                          fg_color='transparent',
                                          border_color='#2775d8', border_width=2,
                                          hover_color='#2775d8',
                                          text='Login',
                                          font=("arial", 20),
                                          command=lambda: self.open_login_window())
        self.register_button = ctk.CTkButton(master=self.frame,
                                             corner_radius=30,
                                             width=200,
                                             height=50,
                                             fg_color='transparent',
                                             border_color='#2775d8', border_width=2,
                                             hover_color='#2775d8',
                                             text='Register',
                                             font=("arial", 20),
                                             command=lambda: self.open_register_window())

        self.login_button.pack(pady=20, padx=12)
        self.register_button.pack(pady=20, padx=12)

    def open_register_window(self):
        register_window = App_register()
        register_window.after(500, self.close_window)
        register_window.mainloop()

    def open_login_window(self):
        login_window = App_login()
        login_window.after(500, self.close_window)
        login_window.mainloop()

    def close_window(self):
        self.destroy()

class App_register(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title('Register')
        self.geometry("300x350")
        self.custom_font = ctk.CTkFont()
        self.custom_font.configure(size=24, family="Rubik Maps")
        self.frame = ctk.CTkFrame(self)
        self.frame.pack(pady=20, padx=12, fill='both', expand=True)

        self.label = ctk.CTkLabel(master=self.frame,
                                  text="Register",
                                  font=self.custom_font,
                                  fg_color="transparent")
        self.label.pack(pady=12, padx=10)

        self.username_entry = self.create_entry(self.frame, "Username")
        self.email_entry = self.create_entry(self.frame, "Email")
        self.password_entry = self.create_entry(self.frame, "Password", show="*")

        self.submit_button = ctk.CTkButton(master=self.frame,
                                           corner_radius=30,
                                           width=170,
                                           height=40,
                                           fg_color='transparent',
                                           border_color='#2775d8', border_width=2,
                                           hover_color='#2775d8',
                                           text="Register",
                                           font=("arial", 20),
                                           command=self.register_user)
        self.submit_button.pack(pady=12, padx=10)

        self.result = ctk.CTkLabel(master=self.frame, text="")
        self.result.pack()

        self.create_table()

    def create_entry(self, frame, placeholder_text, show=""):
        entry = ctk.CTkEntry(master=frame,
                             corner_radius=30,
                             width=170,
                             height=35,
                             fg_color='transparent',
                             placeholder_text=placeholder_text,
                             show=show)
        entry.pack(pady=12, padx=10)
        return entry

    def create_table(self):
        with sqlite3.connect('database.db') as conn:
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS credentials
                              (id INTEGER PRIMARY KEY,
                               username TEXT,
                               email TEXT UNIQUE,
                               password TEXT,
                               datetime TEXT DEFAULT CURRENT_TIMESTAMP,
                               ip TEXT,
                               admin bool default False)''')
    def open_start_window(self):
        start_window = App_login(email=self.email_entry.get(), password=self.password_entry.get())
        start_window.after(200, self.close_window)
        self.after(200, start_window.mainloop())
    def close_window(self):
        self.destroy()
    def register_user(self):
        username = self.username_entry.get()
        email = self.email_entry.get()
        password = self.password_entry.get()
        current_datetime = datetime.now()
        formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")

        if not (username and email and password):
            self.result.configure(text="Please fill all fields.")
            return

        pattern_email = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        pattern_password = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&.])[A-Za-z\d@$!%*?&.]{8,}$"

        is_valid_email = re.match(pattern_email, email)
        is_valid_password = re.match(pattern_password, password)
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        if not (is_valid_email and is_valid_password):
            self.result.configure(text="Invalid email or password!")
            return

        with sqlite3.connect('database.db') as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("INSERT INTO credentials (username, email, password, datetime,ip) VALUES (?, ?, ?,?,?)",
                               (username, email, hashed_password, formatted_datetime  ,socket.gethostbyname(socket.gethostname())))
                self.result.configure(text="Account successfully created!")
                cursor.connection.commit()
                self.open_start_window()
            except sqlite3.IntegrityError:
                self.result.configure(text="Username or Email already exists.")

        self.clear_entries()

    def clear_entries(self):
        self.username_entry.delete(0, 'end')
        self.email_entry.delete(0, 'end')
        self.password_entry.delete(0, 'end')

class App_login(ctk.CTk):
    user_id = 0

    def __init__(self, email=None, password=None):
        super().__init__()
        self.title('Login')
        self.geometry("300x350")
        self.custom_font = ctk.CTkFont()
        self.custom_font.configure(size=24, family="Rubik Maps")
        self.frame = ctk.CTkFrame(self)
        self.frame.pack(pady=20, padx=12, fill='both', expand=True)

        self.label = ctk.CTkLabel(master=self.frame,
                                  text="Login",
                                  font=self.custom_font,
                                  fg_color="transparent")
        self.label.pack(pady=12, padx=10)

        self.email_entry = ctk.CTkEntry(master=self.frame,
                                        corner_radius=30,
                                        width=170,
                                        height=35,
                                        fg_color='transparent',
                                        placeholder_text="Email")
        self.email_entry.pack(pady=12, padx=10)
        if email:
            self.email_entry.insert(0, email)

        self.password_entry = ctk.CTkEntry(master=self.frame,
                                           corner_radius=30,
                                           width=170,
                                           height=35,
                                           fg_color='transparent',
                                           placeholder_text="Password",
                                           show="*")
        self.password_entry.pack(pady=12, padx=10)
        if password:
            self.password_entry.insert(0, password)

        self.submit_button = ctk.CTkButton(master=self.frame,
                                           corner_radius=30,
                                           width=170,
                                           height=40,
                                           fg_color='transparent',
                                           border_color='#2775d8', border_width=2,
                                           hover_color='#2775d8',
                                           text="Login",
                                           font=("arial", 20),
                                           command=lambda: self.login(self.email_entry.get(), self.password_entry.get(),
                                                                      self.email_entry, self.password_entry))
        self.submit_button.pack(pady=12, padx=10)

        self.result = ctk.CTkLabel(master=self.frame, text="")
        self.result.pack()


    def login(self, email, password, email_entry, password_entry):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        if self.user_exist(email, hashed_password):

            self.result.configure(text="Welcome")
            self.open_main_window()

        else:
            self.result.configure(text="Wrong credentials")

    def open_main_window(self):
        main_window = Main_window()
        main_window.after(1, self.close_window)
        self.after(1, main_window.mainloop())

    def close_window(self):
        self.destroy()

    def user_exist(self, email, password):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT id FROM credentials WHERE email = ? AND password = ?", (email, password))
            result = cursor.fetchone()
            if result:
                App_login.user_id = result[0]
                return True
        finally:
            cursor.close()
            conn.close()


class Main_window(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.user_id = App_login.user_id
        self.title('Welcome')
        self.geometry("1366x768")

        self.custom_font = ctk.CTkFont()
        self.custom_font.configure(size=24, family="Rubik Maps")

        self.frame_user = ctk.CTkFrame(self, fg_color='transparent')
        self.frame_user_id = ctk.CTkFrame(self.frame_user, fg_color='transparent')
        self.frame_username = ctk.CTkFrame(self.frame_user, fg_color='transparent')
        self.frame_user_admin = ctk.CTkFrame(self.frame_user, fg_color='transparent')

        self.frame_user.pack(side='top')
        self.frame_user_id.grid(row=0, column=0, ipadx=70, sticky='wn')
        self.frame_username.grid(row=0, column=1, ipadx=140, sticky='ns')
        self.frame_user_admin.grid(row=0, column=2, ipadx=100, sticky='es')

        self.frame_data_edit = ctk.CTkFrame(self, height=5,
                                            fg_color='transparent')
        self.frame_data_edit.pack(pady=5, padx=12, fill='both', side='top')

        self.frame_data_edit1 = ctk.CTkFrame(self.frame_data_edit, height=5,
                                             fg_color='transparent')
        self.frame_data_edit1.grid(column=0, row=0, padx=5)

        self.frame_data_edit2 = ctk.CTkFrame(self.frame_data_edit, height=5,
                                             fg_color='transparent')
        self.frame_data_edit2.grid(column=1, row=0, padx=140)

        self.frame_data_edit3 = ctk.CTkFrame(self.frame_data_edit, height=5,
                                             fg_color='transparent')
        self.frame_data_edit3.grid(column=2, row=0, padx=50)

        self.frame_table = ctk.CTkFrame(self, height=50, fg_color='transparent')
        self.frame_table.pack(pady=20, padx=12, fill='both')

        self.button_change_username = ctk.CTkButton(master=self.frame_data_edit1,
                                                    text="Change Username",
                                                    corner_radius=30,
                                                    command=lambda: self.change_username(self.user_id))

        self.button_change_email = ctk.CTkButton(master=self.frame_data_edit1,
                                                 text="Change Email",
                                                 corner_radius=30,
                                                 command=lambda: self.change_email(self.user_id))

        self.button_change_password = ctk.CTkButton(master=self.frame_data_edit1,
                                                    text="Change Password",
                                                    corner_radius=30,
                                                    command=lambda: self.change_password(self.user_id))

        self.button_change_username.grid(column=0, row=0, padx=9)
        self.button_change_email.grid(column=1, row=0, padx=9)
        self.button_change_password.grid(column=2, row=0, padx=9)

        self.button_make_admin = CTkSwitch(master=self.frame_data_edit3,
                                           text="Admin", corner_radius=30,
                                           command=lambda: handle_switch())

        def handle_switch():
            is_switch_on = self.button_make_admin.get()

            if is_switch_on:
                self.admin_login(self.user_id)
            else:
                self.remove_admin(self.user_id)

        self.button_make_admin.pack(side='right')

        self.textbox = ctk.CTkTextbox(master=self.frame_table,
                                      font=self.custom_font,
                                      height=350, )
        self.textbox.pack(pady=5, padx=12, fill='both', side='top')

        self.print_button = ctk.CTkButton(master=self.frame_table,
                                          corner_radius=30,
                                          text="Show Users",
                                          command=lambda: self.adminview(self.user_id))
        self.print_button.pack(pady=5, padx=12, )

        self.edit_user_id = ctk.CTkButton(master=self.frame_table,
                                          corner_radius=30,
                                          text="Edit User",
                                          command=lambda: self.edit_user_input(self.user_id))
        self.edit_user_id.pack(pady=5, padx=12)

        user_info = self.get_user_info(self.user_id)
        if user_info:
            self.label_user_id = ctk.CTkLabel(master=self.frame_user_id, text=f"User ID: {user_info['id']}",
                                              font=self.custom_font)
            self.label_user_id.pack()

            self.label_username = ctk.CTkLabel(master=self.frame_username, text=f"Username: {user_info['username']}",
                                               font=self.custom_font)
            self.label_username.pack()

            self.label_admin = ctk.CTkLabel(master=self.frame_user_admin, text=f"Admin: {user_info['admin']}",
                                            font=self.custom_font)
            self.label_admin.pack()

    def edit_user_input(self, user_id):
        user_info = self.get_user_info(user_id)

        if user_info and user_info.get("admin"):
            edit_window = ctk.CTkInputDialog(text="Type in user ID:", title="Enter User ID")
            self.entered_id = edit_window.get_input()

            if self.edit_user_window(self.entered_id):

                return True
            else:
                return False
        else:
            table_string = "Access denied. User is not an admin."
            self.textbox.delete(1.0, ctk.END)
            self.textbox.insert(ctk.END, table_string)
            return False

    def edit_user_window(self, user_id):
        user_info = self.get_full_user_info(user_id)

        if user_info:
            toplevel = tk.Toplevel(self)
            toplevel.geometry("800x60")
            toplevel.title("Editor")
            toplevel.focus_set()

            data_tree = ttk.Treeview(toplevel, columns=("id", "username", "email", "password", "admin"),
                                     show="headings")
            data_tree.column("id", width=50, anchor='center')  # Expand the first column
            data_tree.column("username", anchor="center", width=200)
            data_tree.column("email", width=250, anchor='center')
            data_tree.column("password", width=250, anchor='center')
            data_tree.column("admin", width=50, anchor='center')

            data_tree.heading("id", text="User ID")
            data_tree.heading("username", text="Username")
            data_tree.heading("email", text="Email")
            data_tree.heading("password", text="Password")
            data_tree.heading("admin", text="Admin")
            data_tree.insert('', 'end',
                             values=tuple(user_info[key] for key in ["id", "username", "email", "password", "admin"]))
            data_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

            context_menu = tk.Menu(toplevel, tearoff=0)
            context_menu.add_command(label="Change Username", command=lambda: self.change_username(user_id))
            context_menu.add_command(label="Change Email", command=lambda: self.change_email(user_id))
            context_menu.add_command(label="Change Password", command=lambda: self.change_password(user_id))
            context_menu.add_command(label="Change Role", command=lambda: self.change_role(user_id))
            data_tree.bind("<Button-3>", lambda event: self.right_click(event, context_menu))
            return True
        else:
            table_string = "User not found"
            self.textbox.delete(1.0, ctk.END)
            self.textbox.insert(ctk.END, table_string)
            return False

    def right_click(self, event, context_menu):
        context_menu.post(event.x_root, event.y_root)

    def get_full_user_info(self, user_id):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT id, username,email, admin FROM credentials WHERE id = ?", (user_id,))
            result = cursor.fetchone()

            if result:
                user_id, username, email, password, admin = result
                return {"id": user_id, "username": username, "email": email, "admin": bool(admin)}
            else:
                return None

        finally:
            cursor.close()
            conn.close()

    def change_role(self, user_id):
        role_window = ctk.CTkInputDialog(text="Yes or No: ", title="Change role")
        new_role = role_window.get_input()
        if new_role.lower() == "yes":
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute("UPDATE credentials SET admin = ? WHERE id = ?", (1, user_id))
            conn.commit()
        else:
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute("UPDATE credentials SET admin = ? WHERE id = ?", (0, user_id))
            conn.commit()

    def get_user_info(self, user_id):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT id, username, admin FROM credentials WHERE id = ?", (user_id,))
            result = cursor.fetchone()

            if result:
                user_id, username, admin = result
                return {"id": user_id, "username": username, "admin": bool(admin)}
            else:
                # No match found
                return None

        finally:
            cursor.close()
            conn.close()

    def adminview(self, user_id):
        user_info = self.get_user_info(user_id)

        if user_info and user_info.get("admin"):
            try:
                conn = sqlite3.connect('database.db')
                cursor = conn.cursor()
                cursor.execute("SELECT id, username,email,datetime, ip, admin FROM credentials")
                rows = cursor.fetchall()
                column_names = [description[0] for description in cursor.description]
                formatted_data = []
                formatted_data.append(column_names)
                formatted_data.extend(rows)

                table_string = "\n".join([" | ".join(map(str, row)) for row in formatted_data])
                self.textbox.delete(1.0, ctk.END)
                self.textbox.insert(ctk.END, table_string)
            finally:
                if conn:
                    conn.close()
        else:
            table_string = "Access denied. User is not an admin."
            self.textbox.delete(1.0, ctk.END)
            self.textbox.insert(ctk.END, table_string)

    def admin_login(self, user_id):
        user_info = self.get_user_info(user_id)
        admin_password = "Admin123"

        if user_info and not user_info.get("admin"):
            admin_window = ctk.CTkInputDialog(text="Type in admin password:", title="Admin Login", )
            entered_password = admin_window.get_input()
            while True:
                if entered_password is None:
                    break

                if entered_password == admin_password:
                    self.set_admin(user_id)
                    self.label_admin.configure(text=f"Admin: {True}")
                    break
                else:
                    admin_window = ctk.CTkInputDialog(text="Error: Wrong password", title="Admin Login", )
                    entered_password = admin_window.get_input()

    def set_admin(self, user_id):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        try:
            cursor.execute("UPDATE credentials SET admin = ? WHERE id = ?", (1, user_id))
            conn.commit()
        finally:
            cursor.close()
            conn.close()

    def remove_admin(self, user_id):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        try:
            cursor.execute("UPDATE credentials SET admin = ? WHERE id = ?", (0, user_id))
            conn.commit()
        finally:
            self.label_admin.configure(text=f"Admin: {False}")
            cursor.close()
            conn.close()

    def is_duplicate_username(self, username):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT COUNT(*) FROM credentials WHERE username = ? ", (username,))
            count = cursor.fetchone()[0]
            return count > 0
        finally:
            cursor.close()
            conn.close()

    def change_username(self, user_id):
        admin_window = ctk.CTkInputDialog(text="Enter new username: ", title="Change username")
        new_username = admin_window.get_input()
        while True:

            if self.is_duplicate_username(new_username):
                admin_window = ctk.CTkInputDialog(
                    text="Error: Username already exists. Please choose a different username.", title="Change username")
                new_username = admin_window.get_input()
            else:

                self.set_username(new_username, user_id)
                self.label_username.configure(text=f"Username: {new_username}")
                break

    def set_username(self, new_username, user_id):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        try:
            cursor.execute("UPDATE credentials SET username = ? WHERE id = ?", (new_username, user_id))
            conn.commit()
        finally:
            cursor.close()
            conn.close()

    def is_duplicate_email(self, email):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT COUNT(*) FROM credentials WHERE email = ? ", (email,))
            count = cursor.fetchone()[0]
            return count > 0
        finally:
            cursor.close()
            conn.close()

    def change_email(self, user_id):
        admin_window = ctk.CTkInputDialog(text="Enter new email: ", title="Change email")
        new_email = admin_window.get_input()
        while True:
            if self.is_duplicate_email(new_email):
                admin_window = ctk.CTkInputDialog(text="Error: Email already exists. Please choose a different email.",
                                                  title="Change email")
                new_email = admin_window.get_input()

            elif not re.match(r'^[\w.-]+@([\w-]+\.)+[\w-]{2,4}$', new_email):
                admin_window = ctk.CTkInputDialog(text="Error: Invalid email format. Please enter a valid email.",
                                                  title="Change email")
                new_email = admin_window.get_input()

            else:
                self.set_email(new_email, user_id)
                self.label_email.configure(text=f"Email: {new_email}")
                break

    def set_email(self, new_email, user_id):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        try:
            cursor.execute("UPDATE credentials SET email = ? WHERE id = ?", (new_email, user_id))
            conn.commit()
        finally:
            cursor.close()
            conn.close()

    def change_password(self, user_id):
        admin_window = ctk.CTkInputDialog(text="Enter new password: ", title="Change password")
        new_password = admin_window.get_input()
        while True:
            if re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&.])[A-Za-z\d@$!%*?&.]{8,}$", new_password):
                hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
                self.set_password(hashed_password, user_id)
                break

            else:
                admin_window = ctk.CTkInputDialog(text="Error: Invalid password ", title="Change password")
                new_password = admin_window.get_input()

    def set_password(self, new_password, user_id):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        try:
            cursor.execute("UPDATE credentials SET password = ? WHERE id = ?", (new_password, user_id))
            conn.commit()
        finally:
            cursor.close()
            conn.close()



