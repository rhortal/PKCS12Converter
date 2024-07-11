import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from cryptography.hazmat.primitives.serialization import NoEncryption, BestAvailableEncryption
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates, serialize_key_and_certificates

def convert_pkcs12_to_legacy(infile, outfile, password):
    """
    Convert .p12 to legacy format.
    """
    try:
        with open(infile, 'rb') as p12_file:
            p12_data = p12_file.read()
        
        # Load the p12 file
        private_key, certificate, additional_certificates = load_key_and_certificates(
            p12_data,
            password=password.encode('utf-8') if password else None
        )

        # Serialize back to p12 in legacy format
        new_p12_data = serialize_key_and_certificates(
            name=None,
            key=private_key,
            cert=certificate,
            cas=additional_certificates,
        #    encryption_algorithm=NoEncryption()
            encryption_algorithm=BestAvailableEncryption(password.encode('utf-8')) if password else NoEncryption()
        )
        
        # Write the new p12 file
        with open(outfile, 'wb') as new_p12_file:
            new_p12_file.write(new_p12_data)
        
        return True
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")
        return False

def browse_files():
    file_path = filedialog.askopenfilename(
        title="Select a .p12 Certificate file",
        filetypes=[("PKCS12 files", "*.p12"), ("All files", "*.*")]
    )
    if file_path:
        entry_file.delete(0, tk.END)
        entry_file.insert(0, file_path)

def convert_and_save():
    input_file = entry_file.get()
    if not input_file:
        messagebox.showerror("Error", "Please select a .p12 file first.")
        return

    password = simpledialog.askstring("Password", "Enter the password for the .p12 file (leave blank if none):", show='*')
    output_file = input_file.replace(".p12", ".new.p12")
    
    success = convert_pkcs12_to_legacy(input_file, output_file, password)
    if success:
        messagebox.showinfo("Success", f"Converted file saved as {output_file}")

def quit_app():
    root.destroy()

# Create the main window
root = tk.Tk()
root.title("PKCS12 to Legacy Converter")

# Create and place widgets
frame = tk.Frame(root, padx=10, pady=10)
frame.pack(padx=10, pady=10)

lbl_file = tk.Label(frame, text="Select .p12 File:")
lbl_file.grid(row=0, column=0, pady=5)

entry_file = tk.Entry(frame, width=50)
entry_file.grid(row=0, column=1, pady=5, padx=5)

btn_browse = tk.Button(frame, text="Browse", command=browse_files)
btn_browse.grid(row=0, column=2, pady=5)

btn_convert = tk.Button(frame, text="Convert", command=convert_and_save)
btn_convert.grid(row=1, column=1, pady=10)

btn_quit = tk.Button(frame, text="Quit", command=quit_app)
btn_quit.grid(row=2, column=1, pady=5)

# Run the application
root.mainloop()
