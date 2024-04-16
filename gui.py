import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from functools import partial
from tkinter import messagebox
import abuseipdb as ab
import os

def get_ips_from_file(filename):
    with open(filename, 'r') as f:
        ips = f.read()
    return ips

def browse_file(file_entry, ips_entry):
    filename = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(tk.END, filename)
    ips_entry.delete('1.0', tk.END)
    ips_entry.insert(tk.END, get_ips_from_file(filename))
    return filename

def run_tool(operation_var, ip_entry, ips_entry, subnet_entry, output_entry, details_var, output_text, counter_label, file_entry):
    operation = operation_var.get()
    ip = ip_entry.get()
    ips = ips_entry.get("1.0", tk.END).strip() # get ip addresses from text widget
    subnet = subnet_entry.get()
    output_file = output_entry.get()
    details = details_var.get()

    counter = int(counter_label.cget("text"))
    counter += 1
    counter_label.config(text=str(counter))

    output_text.config(state=tk.NORMAL)
    output_text.insert(tk.END, f"\n\nRun {counter}:\n")

    if operation == "Check Individual IP":
        if ip:
            output_text.insert(tk.END, ab.check_ip(ip, details, gui=False))
        else:
            messagebox.showerror("Error", "Please provide an IP address.")
    elif operation == "Bulk Check":
        if ips:
            output_text.insert(tk.END, ab.bulkcheck(ips, output_file, details))
        else:
            messagebox.showerror("Error", "Please provide a list of IP addresses.")
    elif operation == "Check Subnet":
        if subnet:
            output_text.insert(tk.END, ab.check_subnet(subnet, output_file))
        else:
            messagebox.showerror("Error", "Please provide a subnet.")
    else:
        messagebox.showerror("Error", "Please select an operation.")

    output_text.config(state=tk.DISABLED)

def clear_output(output_text, counter_label):
    output_text.config(state=tk.NORMAL)
    output_text.delete('1.0', tk.END)
    output_text.config(state=tk.DISABLED)
    counter_label.config(text="0")

def toggle_output(output_label, output_entry):
    if output_label.cget("state") == tk.DISABLED:
        output_label.config(state=tk.NORMAL)
        output_label.grid(row=3, column=0, pady=5, padx=5)
        output_entry.grid(row=3, column=1, pady=5, padx=5)
    else:
        output_label.config(state=tk.DISABLED)
        output_label.grid_forget()
        output_entry.grid_forget()

def create_gui():
    root = tk.Tk()
    root.title("Malicious IP Checker")
    root.configure(background='#f0f0f0')

    operations = ["Check Individual IP", "Bulk Check", "Check Subnet"]
    global operation_var
    operation_var = tk.StringVar()
    operation_label = tk.Label(root, text="Select Operation:", background='#f0f0f0')
    operation_label.grid(row=0, column=0)
    operation_dropdown = ttk.Combobox(root, textvariable=operation_var, values=operations, state="readonly", width=30)
    operation_dropdown.grid(row=0, column=1, pady=10, padx=10)

    ip_label = tk.Label(root, text="IP Address:", background='#f0f0f0')
    ip_entry = tk.Entry(root)
    ips_label = tk.Label(root, text="IP Addresses (one per line):", background='#f0f0f0')
    ips_entry = tk.Text(root, height=4, width=30)
    file_label = tk.Label(root, text="From file (one per line):", background='#f0f0f0')
    file_entry = tk.Entry(root)
    file_button = tk.Button(root, text="Browse", command=partial(browse_file, file_entry, ips_entry))
    subnet_label = tk.Label(root, text="Subnet:", background='#f0f0f0')
    subnet_entry = tk.Entry(root)
    output_label = tk.Label(root, text="Output File:", background='#f0f0f0', state=tk.DISABLED)
    output_entry = tk.Entry(root)
    details_var = tk.BooleanVar()
    details_check = tk.Checkbutton(root, text="Show Details", variable=details_var, background='#f0f0f0')

    def on_operation_select(event):
        operation = operation_var.get()
        if operation == "Check Individual IP":
            ip_label.grid(row=1, column=0, pady=5, padx=5)
            ip_entry.grid(row=1, column=1, pady=5, padx=5)
            ips_label.grid_forget()
            ips_entry.grid_forget()
            file_label.grid_forget()
            file_entry.grid_forget()
            file_button.grid_forget()
            subnet_label.grid_forget()
            subnet_entry.grid_forget()
        elif operation == "Bulk Check":
            ips_label.grid(row=1, column=0, pady=5, padx=5)
            ips_entry.grid(row=1, column=1, pady=5, padx=5)
            file_label.grid(row=2, column=0, pady=5, padx=5)
            file_entry.grid(row=2, column=1, pady=5, padx=5)
            file_button.grid(row=2, column=2, pady=5, padx=5)
            ip_label.grid_forget()
            ip_entry.grid_forget()
            subnet_label.grid_forget()
            subnet_entry.grid_forget()
        elif operation == "Check Subnet":
            subnet_label.grid(row=1, column=0, pady=5, padx=5)
            subnet_entry.grid(row=1, column=1, pady=5, padx=5)
            ip_label.grid_forget()
            ip_entry.grid_forget()
            ips_label.grid_forget()
            ips_entry.grid_forget()
            file_label.grid_forget()
            file_entry.grid_forget()
            file_button.grid_forget()

    operation_var.set("Check Individual IP")    
    ip_label.grid(row=1, column=0, pady=5, padx=5)  
    ip_entry.grid(row=1, column=1, pady=5, padx=5)
    operation_dropdown.bind("<<ComboboxSelected>>", on_operation_select)
    details_check.grid(row=1, column=2, pady=5, padx=5)

    output_text = tk.Text(root, height=18, width=60)
    output_text.grid(row=4, columnspan=3, pady=10, padx=10)
    output_text.configure(bg='#ffffff', state=tk.DISABLED)
    counter_label = tk.Label(root, text="0", background='#f0f0f0')
    counter_label.grid_forget()

    clear_button = tk.Button(root, text="Clear Output", command=partial(clear_output, output_text, counter_label))
    clear_button.grid(row=5, column=0, pady=10, padx=10)

    toggle_button = tk.Button(root, text="Output File", command=partial(toggle_output, output_label, output_entry))
    toggle_button.grid(row=0, column=2, pady=10, padx=10)

    run_button = tk.Button(root, text="Run", command=partial(run_tool, operation_var, ip_entry, ips_entry, subnet_entry, output_entry, details_var, output_text, counter_label, file_entry), bg='#4caf50', fg='#ffffff')
    run_button.grid(row=5, column=2, pady=10, padx=10)
    root.mainloop()

if __name__ == "__main__":
    create_gui()
