#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2024/6/11 18:47
# @Author  : ZRH
# @FileName: manager.py.py
# @Software: PyCharm
# @Email    ：3265827943@qq.com

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import sqlite3
import os
import random
import string

# 加密相关参数
salt = b'salt'  # 盐值，用于加密和解密过程
key = PBKDF2(b'password', salt, dkLen=32, count=1000000)  # 使用PBKDF2进行密钥派生
cipher = AES.new(key, AES.MODE_GCM)

# 数据库初始化
conn = sqlite3.connect('passwords.db')
c = conn.cursor()

# 创建密码存储表
c.execute('''CREATE TABLE IF NOT EXISTS passwords
             (website TEXT, username TEXT, password TEXT, encrypted_password BLOB, nonce BLOB)''')
conn.commit()

# 加密和存储密码条目
def store_password(website, username, password):
    nonce = get_random_bytes(16)  # 生成随机nonce
    cipher.update(nonce)
    ciphertext, tag = cipher.encrypt_and_digest(password.encode('utf-8'))
    c.execute('INSERT INTO passwords VALUES (?, ?, ?, ?, ?)', (website, username, password, ciphertext, nonce))
    conn.commit()
    print(f'密码为 {username}@{website} 存储成功.')

# 解密密码条目
def retrieve_password(website, username):
    c.execute('SELECT encrypted_password, nonce FROM passwords WHERE website=? AND username=?', (website, username))
    row = c.fetchone()
    if row:
        encrypted_password, nonce = row
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt(encrypted_password).decode('utf-8')
        print(f'{username}@{website} 的密码是: {plaintext}')
    else:
        print(f'未找到 {username}@{website} 的密码.')

# 生成随机密码
def generate_random_password(length, option):
    if option == 1:
        chars = string.digits
    elif option == 2:
        chars = string.ascii_letters + string.digits
    elif option == 3:
        chars = string.ascii_letters + string.digits + string.punctuation
    else:
        raise ValueError('密码生成选项无效')

    password = ''.join(random.choice(chars) for _ in range(length))  # 生成指定长度的密码
    return password

# 命令行界面
while True:
    print('\n菜单:')
    print('1. 存储密码')
    print('2. 检索密码')
    print('3. 生成随机密码并存储')
    print('4. 退出')
    choice = input('请输入你的选择 (1/2/3/4): ')

    if choice == '1':
        website = input('请输入网站名称: ')
        username = input('请输入用户名: ')
        password = input('请输入密码: ')
        store_password(website, username, password)
    elif choice == '2':
        website = input('请输入网站名称: ')
        username = input('请输入用户名: ')
        retrieve_password(website, username)
    elif choice == '3':
        website = input('请输入网站名称: ')
        username = input('请输入用户名: ')
        length = int(input('请输入密码长度: '))
        print('请选择密码复杂度:')
        print('1. 仅数字')
        print('2. 数字和字母（区分大小写）')
        print('3. 数字、字母和特殊字符')
        option = int(input('请输入你的选择 (1/2/3): '))
        password = generate_random_password(length, option)
        print(f'生成的密码: {password}')
        store_password(website, username, password)
    elif choice == '4':
        break
    else:
        print('无效的选择，请输入 1, 2, 3 或 4.')

# 关闭数据库连接
conn.close()
