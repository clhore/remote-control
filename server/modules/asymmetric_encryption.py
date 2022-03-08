from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class asymmetric():
  def __init__(self, key_size=True):
    self.key_size = 4096 if key_size else key_size
    
  def generate(self):
    self.private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=self.key_size,
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

  def decrypt_message(self, message):
      return self.private_key.decrypt(
          message,
          padding.OAEP(
              mgf=padding.MGF1(algorithm=hashes.SHA512()),
              algorithm=hashes.SHA512(),
              label=None
          )
      )

  @staticmethod
  def encrypted_message(message: str, public_key):
    #public_key = self.public_key if public_key else public_key
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