from cryptography.fernet import Fernet

class symmetric():
  def generate(self):
    self.static_key = Fernet.generate_key()
    return self.static_key

  def encrypt(self, string_data):
    return Fernet(self.static_key).encrypt(string_data.encode())

  def decrypt(self, encrypt_data, static_key=True):
    return Fernet(self.static_key).decrypt(encrypt_data)