import tkinter as tk
from tkinter import messagebox
import random
import string

def generator_of_password():
    try:
        length = int(length_entry.get())
        if length < 1:
            raise ValueError("Length must be a positive integer.")
    except ValueError as e:
        messagebox.showerror("Invalid Input", str(e))
        return
    
    use_uppercase = uppercase_var.get()
    use_lowercase = lowercase_var.get()
    use_digits = digits_var.get()
    use_special = special_var.get()
    
    if not (use_uppercase or use_lowercase or use_digits or use_special):
        messagebox.showerror("Invalid Selection", "Please select at least one character type.")
        return
    

    characters = ""
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_digits:
        characters += string.digits
    if use_special:
        characters += string.punctuation
    
    password = ''.join(random.choice(characters) for _ in range(length))
    result_label.config(text=f"Generated Password: {password}")

def copy():
    password = result_label.cget("text").split(": ")[1]
    if password:
        root.clipboard_clear()
        root.clipboard_append(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")
    else:
        messagebox.showwarning("Warning", "No password to copy!")

root = tk.Tk()
root.title("Password Generator")
root.geometry("300x250")


length_label = tk.Label(root, text="Password Length:")
length_label.pack()
length_entry = tk.Entry(root)
length_entry.pack()

uppercase_var = tk.BooleanVar()
lowercase_var = tk.BooleanVar()
digits_var = tk.BooleanVar()
special_var = tk.BooleanVar()

uppercase_check = tk.Checkbutton(root, text="Include Uppercase Letters", variable=uppercase_var)
uppercase_check.pack()

lowercase_check = tk.Checkbutton(root, text="Include Lowercase Letters", variable=lowercase_var)
lowercase_check.pack()

digits_check = tk.Checkbutton(root, text="Include Digits", variable=digits_var)
digits_check.pack()

special_check = tk.Checkbutton(root, text="Include Special Characters", variable=special_var)
special_check.pack()

generate_button = tk.Button(root, text="Generate Password", command=generator_of_password)
generate_button.pack()

result_label = tk.Label(root, text="")
result_label.pack()

copy_button = tk.Button(root, text="Copy to Clipboard", command=copy)
copy_button.pack()

root.mainloop()