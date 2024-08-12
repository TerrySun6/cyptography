import tkinter as tk
from tkinter import messagebox
from sympy import mod_inverse

# 定义仿射加密函数
def affine_encrypt(text, a, b):
    result = ""
    for char in text:
        char_code = ord(char)
        encrypted_char_code = (a * char_code + b) % 65536  # 65536 是 Unicode 的最大值
        result += chr(encrypted_char_code)
    return result

# 定义仿射解密函数
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

# 加密按钮的回调函数
def encrypt_text():
    try:
        a = int(entry_a.get())
        b = int(entry_b.get())
        text = entry_text.get()
        if a % 2 == 0 or a == 65536 // 2:  # 检查a的合法性（a必须与65536互质）
            messagebox.showerror("错误", f"a必须与65536互质且不等于{65536//2}")
        else:
            encrypted_text = affine_encrypt(text, a, b)
            entry_result.delete(0, tk.END)  # 清空之前的结果
            entry_result.insert(0, encrypted_text)  # 插入加密结果
    except ValueError:
        messagebox.showerror("错误", "请输入有效的整数值")

# 解密按钮的回调函数
def decrypt_text():
    try:
        a = int(entry_a.get())
        b = int(entry_b.get())
        text = entry_text.get()
        if a % 2 == 0 or a == 65536 // 2:  # 检查a的合法性（a必须与65536互质）
            messagebox.showerror("错误", f"a必须与65536互质且不等于{65536//2}")
        else:
            decrypted_text = affine_decrypt(text, a, b)
            entry_result.delete(0, tk.END)  # 清空之前的结果
            entry_result.insert(0, decrypted_text)  # 插入解密结果
    except ValueError:
        messagebox.showerror("错误", "请输入有效的整数值")

# 创建主窗口
root = tk.Tk()
root.title("仿射加密")

# 创建输入字段和标签
label_text = tk.Label(root, text="输入文本:")
label_text.grid(row=0, column=0, padx=5, pady=5)
entry_text = tk.Entry(root, width=40)
entry_text.grid(row=0, column=1, padx=5, pady=5)

label_a = tk.Label(root, text="输入密钥a:")
label_a.grid(row=1, column=0, padx=5, pady=5)
entry_a = tk.Entry(root, width=10)
entry_a.grid(row=1, column=1, padx=5, pady=5, sticky='w')

label_b = tk.Label(root, text="输入密钥b:")
label_b.grid(row=2, column=0, padx=5, pady=5)
entry_b = tk.Entry(root, width=10)
entry_b.grid(row=2, column=1, padx=5, pady=5, sticky='w')

# 创建加密按钮
button_encrypt = tk.Button(root, text="加密", command=encrypt_text)
button_encrypt.grid(row=3, column=0, pady=10)

# 创建解密按钮
button_decrypt = tk.Button(root, text="解密", command=decrypt_text)
button_decrypt.grid(row=3, column=1, pady=10)

# 显示结果的可复制字段
label_result = tk.Label(root, text="结果:")
label_result.grid(row=4, column=0, padx=5, pady=5)
entry_result = tk.Entry(root, width=40)
entry_result.grid(row=4, column=1, padx=5, pady=5)

# 运行主循环
root.mainloop()
