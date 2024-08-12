import tkinter as tk
from tkinter import messagebox, filedialog
from sympy import mod_inverse
from tinyec import registry
import hashlib
import secrets
import pickle
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# 获取程序所在的目录
script_dir = os.path.dirname(os.path.abspath(__file__))

# ECC加密和解密函数
def encrypt_ECC(msg, pubKey):
    curve = registry.get_curve('brainpoolP256r1')
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    sharedECCKey = ciphertextPrivKey * pubKey
    hashedSharedECCKey = hashlib.sha256(int.to_bytes(sharedECCKey.x, 32, 'big')).hexdigest()
    ciphertext = ''.join(chr(ord(char) ^ ord(hashedSharedECCKey[i % len(hashedSharedECCKey)])) for i, char in enumerate(msg))
    return (ciphertextPubKey, ciphertext)

def decrypt_ECC(ciphertext, ciphertextPubKey, privKey):
    sharedECCKey = privKey * ciphertextPubKey
    hashedSharedECCKey = hashlib.sha256(int.to_bytes(sharedECCKey.x, 32, 'big')).hexdigest()
    plaintext = ''.join(chr(ord(char) ^ ord(hashedSharedECCKey[i % len(hashedSharedECCKey)])) for i, char in enumerate(ciphertext))
    return plaintext

# RSA加密和解密函数
def encrypt_RSA(msg, pubKey):
    cipher = PKCS1_OAEP.new(pubKey)
    ciphertext = cipher.encrypt(msg.encode('utf-8'))
    return ciphertext

def decrypt_RSA(ciphertext, privKey):
    cipher = PKCS1_OAEP.new(privKey)
    plaintext = cipher.decrypt(ciphertext).decode('utf-8')
    return plaintext

# 生成RSA密钥对
def generate_rsa_keypair():
    key = RSA.generate(2048)
    privKey = key
    pubKey = key.publickey()
    return privKey, pubKey

def save_rsa_keys(privKey, pubKey, filename="rsa_keypair.pkl"):
    file_path = os.path.join(script_dir, filename)
    with open(file_path, 'wb') as f:
        pickle.dump({'privKey': privKey.export_key(), 'pubKey': pubKey.export_key()}, f)
    messagebox.showinfo("保存成功", f"RSA密钥对已保存到文件 {file_path}")

def load_rsa_keys(filename="rsa_keypair.pkl"):
    file_path = os.path.join(script_dir, filename)
    if os.path.exists(file_path):
        with open(file_path, 'rb') as f:
            keys = pickle.load(f)
            privKey = RSA.import_key(keys['privKey'])
            pubKey = RSA.import_key(keys['pubKey'])
            return privKey, pubKey
    else:
        messagebox.showerror("错误", f"文件 {file_path} 不存在。")
        return None, None

# 生成ECC密钥对
def generate_keypair():
    curve = registry.get_curve('brainpoolP256r1')
    privKey = secrets.randbelow(curve.field.n)
    pubKey = privKey * curve.g
    return privKey, pubKey

def save_keys(privKey, pubKey, filename="ecc_keypair.pkl"):
    file_path = os.path.join(script_dir, filename)
    with open(file_path, 'wb') as f:
        pickle.dump({'privKey': privKey, 'pubKey': pubKey}, f)
    messagebox.showinfo("保存成功", f"ECC密钥对已保存到文件 {file_path}")

def load_keys(filename="ecc_keypair.pkl"):
    file_path = os.path.join(script_dir, filename)
    if os.path.exists(file_path):
        with open(file_path, 'rb') as f:
            keys = pickle.load(f)
            return keys.get('privKey'), keys.get('PubKey')
    else:
        messagebox.showerror("错误", f"文件 {file_path} 不存在。")
        return None, None

def upload_key():
    global privKey, pubKey
    file_path = filedialog.askopenfilename(title="选择密钥文件", filetypes=[("Pickle Files", "*.pkl")])
    if file_path:
        with open(file_path, 'rb') as f:
            keys = pickle.load(f)
            if encryption_method.get() == "ECC":
                privKey = keys.get('privKey')
                pubKey = keys.get('pubKey')
            elif encryption_method.get() == "RSA":
                privKey = RSA.import_key(keys.get('privKey'))
                pubKey = RSA.import_key(keys.get('pubKey'))
            if privKey:
                messagebox.showinfo("上传成功", "私钥已成功加载。")
            if pubKey:
                messagebox.showinfo("上传成功", "公钥已成功加载。")

# 检查是否有现有的密钥文件，如果有则加载，否则生成新的密钥对
privKey, pubKey = None, None

def check_and_generate_keys():
    global privKey, pubKey
    if encryption_method.get() == "ECC":
        privKey, pubKey = load_keys()  # 加载ECC密钥
        if not privKey or not pubKey:
            privKey, pubKey = generate_keypair()
            save_keys(privKey, pubKey)
    elif encryption_method.get() == "RSA":
        privKey, pubKey = load_rsa_keys()  # 加载RSA密钥
        if not privKey or not pubKey:
            privKey, pubKey = generate_rsa_keypair()
            save_rsa_keys(privKey, pubKey)

# 仿射加密和解密函数（支持中文）
def affine_encrypt(text, a, b):
    result = ""
    for char in text:
        char_code = ord(char)
        encrypted_char_code = (a * char_code + b) % 65536  # 65536 是 Unicode 的最大值
        result += chr(encrypted_char_code)
    return result

def affine_decrypt(text, a, b):
    result = ""
    try:
        a_inv = mod_inverse(a, 65536)  # 计算a的模逆，模为65536
    except ValueError:
        messagebox.showerror("错误", f"a={a} 与 65536 不互质，无法解密")
        return ""
    
    for char in text:
        char_code = ord(char)
        decrypted_char_code = (a_inv * (char_code - b)) % 65536
        result += chr(decrypted_char_code)
    return result

# 创建Tkinter窗口
window = tk.Tk()
window.title("ECC/RSA/Affine 加密解密工具")

# 加密方法选择
encryption_method = tk.StringVar(value="ECC")
label_method = tk.Label(window, text="选择加密方法:")
label_method.pack(pady=5)
radiobutton_ecc = tk.Radiobutton(window, text="ECC", variable=encryption_method, value="ECC", command=check_and_generate_keys)
radiobutton_ecc.pack(pady=5)
radiobutton_rsa = tk.Radiobutton(window, text="RSA", variable=encryption_method, value="RSA", command=check_and_generate_keys)
radiobutton_rsa.pack(pady=5)
radiobutton_affine = tk.Radiobutton(window, text="Affine", variable=encryption_method, value="Affine")
radiobutton_affine.pack(pady=5)

# 输入消息标签和文本框
label_msg = tk.Label(window, text="输入消息:")
label_msg.pack(pady=5)
entry_msg = tk.Entry(window, width=50)
entry_msg.pack(pady=5)

# 密钥a和b的输入框（仿射加密）
label_a = tk.Label(window, text="输入密钥a:")
label_a.pack(pady=5)
entry_a = tk.Entry(window, width=10)
entry_a.pack(pady=5)

label_b = tk.Label(window, text="输入密钥b:")
label_b.pack(pady=5)
entry_b = tk.Entry(window, width=10)
entry_b.pack(pady=5)

# 加密后消息的标签和文本框
label_enc_msg = tk.Label(window, text="加密后的消息:")
label_enc_msg.pack(pady=5)
entry_enc_msg = tk.Entry(window, width=50, state='readonly')
entry_enc_msg.pack(pady=5)

# 解密后消息的标签和文本框
label_dec_msg = tk.Label(window, text="解密后的消息:")
label_dec_msg.pack(pady=5)
entry_dec_msg = tk.Entry(window, width=50, state='readonly')
entry_dec_msg.pack(pady=5)

# 保存加密结果的全局变量
global_encrypted = None

def encrypt_message():
    global global_encrypted
    msg = entry_msg.get()
    if msg:
        if encryption_method.get() == "ECC":
            ciphertextPubKey, ciphertext = encrypt_ECC(msg, pubKey)
            global_encrypted = (ciphertext, ciphertextPubKey)
        elif encryption_method.get() == "RSA":
            ciphertext = encrypt_RSA(msg, pubKey)
            global_encrypted = (ciphertext, None)
        elif encryption_method.get() == "Affine":
            try:
                a = int(entry_a.get())
                b = int(entry_b.get())
                if a % 2 == 0 or a == 65536 // 2:  # 检查a的合法性（a必须与65536互质）
                    messagebox.showerror("错误", f"a必须与65536互质且不等于{65536//2}")
                else:
                    ciphertext = affine_encrypt(msg, a, b)
                    global_encrypted = (ciphertext, None)
            except ValueError:
                messagebox.showerror("错误", "请输入有效的整数值")
        entry_enc_msg.config(state='normal')
        entry_enc_msg.delete(0, tk.END)
        entry_enc_msg.insert(0, global_encrypted[0])
        entry_enc_msg.config(state='readonly')

def decrypt_message():
    if global_encrypted:
        if encryption_method.get() == "ECC":
            plaintext = decrypt_ECC(global_encrypted[0], global_encrypted[1], privKey)
        elif encryption_method.get() == "RSA":
            plaintext = decrypt_RSA(global_encrypted[0], privKey)
        elif encryption_method.get() == "Affine":
            try:
                a = int(entry_a.get())
                b = int(entry_b.get())
                if a % 2 == 0 or a == 65536 // 2:  # 检查a的合法性（a必须与65536互质）
                    messagebox.showerror("错误", f"a必须与65536互质且不等于{65536//2}")
                else:
                    plaintext = affine_decrypt(global_encrypted[0], a, b)
            except ValueError:
                messagebox.showerror("错误", "请输入有效的整数值")
                return
        entry_dec_msg.config(state='normal')
        entry_dec_msg.delete(0, tk.END)
        entry_dec_msg.insert(0, plaintext)
        entry_dec_msg.config(state='readonly')

# 加密按钮
button_encrypt = tk.Button(window, text="加密", command=encrypt_message)
button_encrypt.pack(pady=10)

# 解密按钮
button_decrypt = tk.Button(window, text="解密", command=decrypt_message)
button_decrypt.pack(pady=10)

# 上传密钥按钮
button_upload = tk.Button(window, text="上传密钥", command=upload_key)
button_upload.pack(pady=10)

# 启动主窗口循环
window.mainloop()
