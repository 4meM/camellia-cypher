import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from Encrypt import Camellia128Encrypt, Camellia128Decrypt
from bitarray import bitarray
import base64

class CamelliaGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Camellia-128 - Encriptación")
        self.root.geometry("700x650")
        self.root.resizable(True, True)
        self.root.configure(bg='#f0f0f0')
        
        # Create main frame
        main_frame = tk.Frame(root, bg='#f0f0f0', padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = tk.Label(main_frame, text="🔐 Camellia-128", 
                              font=('Arial', 20, 'bold'), bg='#f0f0f0', fg='#2c3e50')
        title_label.pack(pady=(0, 20))
        
        # Operation selection
        operation_frame = tk.LabelFrame(main_frame, text="Operación", 
                                       font=('Arial', 11, 'bold'), bg='#f0f0f0', 
                                       fg='#2c3e50', padx=15, pady=10)
        operation_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.operation_var = tk.StringVar(value="encrypt")
        
        btn_frame = tk.Frame(operation_frame, bg='#f0f0f0')
        btn_frame.pack()
        
        encrypt_radio = tk.Radiobutton(btn_frame, text="Encriptar", 
                                      variable=self.operation_var, value="encrypt",
                                      command=self.update_labels, font=('Arial', 12),
                                      bg='#f0f0f0', activebackground='#f0f0f0')
        encrypt_radio.pack(side=tk.LEFT, padx=30)
        
        decrypt_radio = tk.Radiobutton(btn_frame, text="Desencriptar", 
                                      variable=self.operation_var, value="decrypt",
                                      command=self.update_labels, font=('Arial', 12),
                                      bg='#f0f0f0', activebackground='#f0f0f0')
        decrypt_radio.pack(side=tk.LEFT, padx=30)
        
        # Key input
        key_frame = tk.LabelFrame(main_frame, text="Clave de Encriptación", 
                                 font=('Arial', 11, 'bold'), bg='#f0f0f0',
                                 fg='#2c3e50', padx=15, pady=10)
        key_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.key_entry = tk.Entry(key_frame, font=('Arial', 12), bg='white')
        self.key_entry.pack(fill=tk.X, ipady=5)
        self.key_entry.insert(0, "ThisIsA16ByteKey")
        
        # Input text
        self.input_label_frame = tk.LabelFrame(main_frame, text="Texto de Entrada", 
                                              font=('Arial', 11, 'bold'), bg='#f0f0f0',
                                              fg='#2c3e50', padx=15, pady=10)
        self.input_label_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.input_text = scrolledtext.ScrolledText(self.input_label_frame, 
                                                     font=('Courier New', 11), 
                                                     wrap=tk.WORD, height=8, bg='white')
        self.input_text.pack(fill=tk.BOTH, expand=True)
        
        # Format selection for decrypt
        self.format_frame = tk.Frame(self.input_label_frame, bg='#f0f0f0')
        self.format_frame.pack(fill=tk.X, pady=(5, 0))
        
        tk.Label(self.format_frame, text="Formato:", font=('Arial', 10),
                bg='#f0f0f0').pack(side=tk.LEFT, padx=(0, 10))
        
        self.format_var = tk.StringVar(value="base64")
        
        format_base64 = tk.Radiobutton(self.format_frame, text="Base64", 
                                      variable=self.format_var, value="base64",
                                      font=('Arial', 10), bg='#f0f0f0', 
                                      activebackground='#f0f0f0')
        format_base64.pack(side=tk.LEFT, padx=10)
        
        format_hex = tk.Radiobutton(self.format_frame, text="Hexadecimal", 
                                   variable=self.format_var, value="hex",
                                   font=('Arial', 10), bg='#f0f0f0',
                                   activebackground='#f0f0f0')
        format_hex.pack(side=tk.LEFT, padx=10)
        
        # Buttons
        button_frame = tk.Frame(main_frame, bg='#f0f0f0')
        button_frame.pack(pady=10)
        
        process_btn = tk.Button(button_frame, text="Procesar", command=self.process, 
                               font=('Arial', 12, 'bold'), bg='#3498db', fg='white',
                               activebackground='#2980b9', activeforeground='white',
                               padx=30, pady=8, cursor='hand2', relief=tk.FLAT)
        process_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = tk.Button(button_frame, text="Limpiar", command=self.clear_all, 
                             font=('Arial', 12), bg='#95a5a6', fg='white',
                             activebackground='#7f8c8d', activeforeground='white',
                             padx=30, pady=8, cursor='hand2', relief=tk.FLAT)
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Output text
        output_frame = tk.LabelFrame(main_frame, text="Resultado", 
                                    font=('Arial', 11, 'bold'), bg='#f0f0f0',
                                    fg='#2c3e50', padx=15, pady=10)
        output_frame.pack(fill=tk.BOTH, expand=True)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, 
                                                      font=('Courier New', 11), 
                                                      wrap=tk.WORD, height=8,
                                                      state='disabled', bg='#ecf0f1')
        self.output_text.pack(fill=tk.BOTH, expand=True)
        
        # Copy button
        copy_btn = tk.Button(output_frame, text="Copiar Resultado", 
                           command=self.copy_output, font=('Arial', 10),
                           bg='#27ae60', fg='white', activebackground='#229954',
                           activeforeground='white', padx=20, pady=5, 
                           cursor='hand2', relief=tk.FLAT)
        copy_btn.pack(pady=(5, 0))
        
        # Initial label update
        self.update_labels()
    
    def update_labels(self):
        """Update labels based on operation selection"""
        if self.operation_var.get() == "encrypt":
            self.input_label_frame.config(text="Texto de Entrada")
            self.format_frame.pack_forget()
        else:
            self.input_label_frame.config(text="Texto Cifrado")
            self.format_frame.pack(fill=tk.X, pady=(5, 0))
    
    def pad_key(self, key_str):
        """Pad or truncate key to 16 bytes"""
        key_bytes = key_str.encode('utf-8')
        if len(key_bytes) > 16:
            return key_bytes[:16]
        else:
            return key_bytes.ljust(16, b'\x00')
    
    def pkcs7_pad(self, data):
        """Apply PKCS7 padding"""
        padding_length = 16 - (len(data) % 16)
        return data + bytes([padding_length]) * padding_length
    
    def pkcs7_unpad(self, data):
        """Remove PKCS7 padding"""
        padding_length = data[-1]
        return data[:-padding_length]
    
    def encrypt_text(self):
        """Encrypt the input text"""
        try:
            # Get inputs
            plaintext = self.input_text.get("1.0", tk.END).strip()
            key_str = self.key_entry.get()
            
            if not plaintext or not key_str:
                messagebox.showerror("Error", "¡Por favor ingrese el texto y la clave!")
                return
            
            # Prepare key
            key_bytes = self.pad_key(key_str)
            key_bits = bitarray()
            key_bits.frombytes(key_bytes)
            
            # Prepare plaintext with padding
            plaintext_bytes = plaintext.encode('utf-8')
            plaintext_bytes = self.pkcs7_pad(plaintext_bytes)
            
            # Encrypt block by block
            ciphertext_bytes = b''
            num_blocks = len(plaintext_bytes) // 16
            
            for i in range(num_blocks):
                block_start = i * 16
                block_end = block_start + 16
                block_bytes = plaintext_bytes[block_start:block_end]
                
                block_bits = bitarray()
                block_bits.frombytes(block_bytes)
                
                cipher_block = Camellia128Encrypt(block_bits, key_bits)
                ciphertext_bytes += cipher_block.tobytes()
            
            # Display results
            output = base64.b64encode(ciphertext_bytes).decode()
            
            self.display_output(output)
            
        except Exception as e:
            messagebox.showerror("Error de Encriptación", f"Ocurrió un error:\n{str(e)}")
    
    def decrypt_text(self):
        """Decrypt the input text"""
        try:
            # Get inputs
            ciphertext_str = self.input_text.get("1.0", tk.END).strip()
            key_str = self.key_entry.get()
            input_format = self.format_var.get()
            
            if not ciphertext_str or not key_str:
                messagebox.showerror("Error", "¡Por favor ingrese el texto cifrado y la clave!")
                return
            
            # Prepare key
            key_bytes = self.pad_key(key_str)
            key_bits = bitarray()
            key_bits.frombytes(key_bytes)
            
            # Parse ciphertext based on format
            if input_format == "base64":
                ciphertext_bytes = base64.b64decode(ciphertext_str)
            else:  # hex
                ciphertext_bytes = bytes.fromhex(ciphertext_str)
            
            # Decrypt block by block
            plaintext_bytes = b''
            num_blocks = len(ciphertext_bytes) // 16
            
            for i in range(num_blocks):
                block_start = i * 16
                block_end = block_start + 16
                block_bytes = ciphertext_bytes[block_start:block_end]
                
                block_bits = bitarray()
                block_bits.frombytes(block_bytes)
                
                plain_block = Camellia128Decrypt(block_bits, key_bits)
                plaintext_bytes += plain_block.tobytes()
            
            # Remove padding
            plaintext_bytes = self.pkcs7_unpad(plaintext_bytes)
            plaintext = plaintext_bytes.decode('utf-8')
            
            # Display results
            output = plaintext
            
            self.display_output(output)
            
        except Exception as e:
            messagebox.showerror("Error de Desencriptación", f"Ocurrió un error:\n{str(e)}")
    
    def process(self):
        """Process encrypt or decrypt based on selection"""
        if self.operation_var.get() == "encrypt":
            self.encrypt_text()
        else:
            self.decrypt_text()
    
    def display_output(self, text):
        """Display text in output area"""
        self.output_text.config(state='normal')
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert("1.0", text)
        self.output_text.config(state='disabled')
    
    def copy_output(self):
        """Copy output to clipboard"""
        output = self.output_text.get("1.0", tk.END).strip()
        if output:
            self.root.clipboard_clear()
            self.root.clipboard_append(output)
            messagebox.showinfo("Éxito", "¡Resultado copiado al portapapeles!")
        else:
            messagebox.showwarning("Advertencia", "¡No hay resultado para copiar!")
    
    def clear_all(self):
        """Clear all input and output fields"""
        self.input_text.delete("1.0", tk.END)
        self.output_text.config(state='normal')
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state='disabled')

def main():
    root = tk.Tk()
    app = CamelliaGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
