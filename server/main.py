# encoding: utf-8
# autor: Adrián Luján Muñoz aka (clhore)

# library
import os
import time
from flask import Flask, request
from threading import Thread

# personal modules
from modules import (
    asymmetric_encryption, symmetric_encryption
)

# variables de entorno
user_account = 'ad5ian'  # os.environ.get('USER')
key_account = '1234'  # os.environ['key']
request_post_key_private = b'QENgNoY_vulHheqHHv2UJd4V85jntqAznXKes6BAs0c='  # os.environ['request_post_key_private']

crypt = asymmetric_encryption.asymmetric()
crypt.generate()  # create asymmetric key
public_key = crypt.public_key_serialization()
print(public_key)

crypt_symmetric = symmetric_encryption.symmetric()
static_key = crypt_symmetric.generate()


def verify_user_account(user_account_encrypt, key_account_encrypt, public_key):
    user_account_decrypt = crypt\
        .decrypt_message(
            eval(
                user_account_encrypt
            )
        ).decode('utf-8')

    key_account_decrypt = crypt\
        .decrypt_message(
            eval(
                key_account_encrypt
            )
        ).decode('utf-8')

    if user_account_decrypt == user_account and key_account_decrypt == key_account:
        global client_public_key, static_key_encrypt

        client_public_key = crypt \
            .import_public_key(public_key)

        static_key_encrypt = crypt \
            .encrypted_message(
            message=f'{static_key}',
            public_key=client_public_key
        )

        return {
            'static_key': f'{static_key_encrypt}',
            'time_zone': 'Europa/Madrid'
        }

    return {
        'status_code': 'error'
    }


# create flask app
app = Flask('')


@app.route('/', methods=['GET'])
def home_get():
    return '<h1>Remote Control</h1>'


@app.route('/', methods=["POST"])
def home():
    if f'{request.form["internal_count"]}' == '1':
        return {
            'public_key': f'{public_key.decode()}',
            'time_zone': 'Europa/Madrid'
        }

    if f'{request.form["internal_count"]}' == '2':
        return verify_user_account(
            request.form["user_account"],
            request.form["key_account"],
            request.form["public_key"]
        )

    if f'{request.form["internal_count"]}' == '3':
        static_key_request = eval(
            crypt.decrypt_message(
                eval(request.form['static_key'])
            )
        )
        request_post_key_private_encrypt = crypt \
            .encrypted_message(
            message=f'{request_post_key_private}',
            public_key=client_public_key
        )

        status_code = static_key_request == static_key
        return {
            'status_code': f'{status_code}',
            'static_key': f'{static_key_encrypt}',
            'request_post_key_private': f'{request_post_key_private_encrypt}',
            'time_zone': 'Europe/Madrid'
        }

    if f'{request.form["internal_count"]}' == '505':
        request_post_key_private_request = eval(
            crypt_symmetric.decrypt(
                eval(request.form['request_post_key_private'])
            )
        )

        if str(request_post_key_private) != str(request_post_key_private_request):
            return {
                'status_code': 'error'
            }

        cmd = request.form['msg']
        print(f'MSG recivido (encryptado): ', cmd)
        cmd = crypt_symmetric.decrypt(
            eval(request.form['msg'])
        ).decode()
        session = crypt_symmetric.decrypt(
            eval(request.form['session'])
        ).decode()
        print(f'MSG recivido (desencryptado): ', cmd)
        cmd_output = os.system(cmd)
        print(f'/dev/shm/output.{session}')
        time.sleep(0.5)

        with open(f'/dev/shm/output.{session}', 'r') as f:
            cmd_output = f.read()
            f.close()

        os.system(f"echo '' > /dev/shm/output.{session}")

        cmd_output_encrypt = crypt_symmetric.encrypt(str(cmd_output))

        return {
            'status_code': 'True',
            'cmd_output': f'{cmd_output_encrypt}'
        }

    return {
        'status_code': 'error'
    }


def run():
    app.run(host='0.0.0.0', port=8080)


Thread(target=run).start()
