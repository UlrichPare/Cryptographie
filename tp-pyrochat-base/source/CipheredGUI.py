import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import dearpygui.dearpygui as dpg
import base64
import logging
import serpent


from basic_gui import BasicGUI

class CipheredGUI(BasicGUI):
    def __init__(self):
        super().__init__()
        self._key = None
        self._salt = b'secure_chat_salt'

    def _create_connection_window(self):
        with dpg.window(label="Connexion", pos=(200, 150), width=400, height=300, show=False, tag="connection_windows"):
            for field in ["host", "port", "name", "password"]:
                with dpg.group(horizontal=True):
                    dpg.add_text(field)
                    if field == "password":
                        dpg.add_input_text(default_value="", tag=f"connection_{field}", password=True)
                    else:
                        dpg.add_input_text(default_value=DEFAULT_VALUES.get(field, ""), tag=f"connection_{field}")
            dpg.add_button(label="Connexion", callback=self.run_chat)

    def run_chat(self, sender, app_data):
        host = dpg.get_value("connection_host")
        port = int(dpg.get_value("connection_port"))
        name = dpg.get_value("connection_name")
        password = dpg.get_value("connection_password")

        if not password:
            self._log.error("Veuillez entrer un mdp")
            return

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,
            salt=self._salt,
            iterations=100000,
        )
        self._key = kdf.derive(password.encode())
        self._log.debug(f"Clé générée : {base64.b64encode(self._key).decode()}")

        super().run_chat(sender, app_data)

    def encrypt(self, message: str) -> tuple:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self._key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        self._log.debug(f"le msg envoyé est chiffré avec IV : {iv.hex()}")
        return iv, encrypted_data

    def decrypt(self, encrypted_tuple: tuple) -> str:
        try:
            iv, encrypted_data = encrypted_tuple
            
            self._log.debug(f"Message bien déchiffré avec IV : {iv.hex()}")

            cipher = Cipher(algorithms.AES(self._key), modes.CTR(iv))
            decryptor = cipher.decryptor()
            
            decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
            
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(decrypted_padded) + unpadder.finalize()
            
            return data.decode()
        except Exception as e:
            self._log.error(f"Erreur de déchiffrement : {str(e)}")
            return "<déchiffrement échoué>"

    def send(self, text):
        if self._key is None:
            self._log.error("Aucune clé de chiffrement disponible.")
            return
        try:
            iv, encrypted_data = self.encrypt(text)
            encrypted_tuple = {
                "iv": base64.b64encode(iv).decode('utf-8'),
                "message": base64.b64encode(encrypted_data).decode('utf-8')
            }
            serialized_data = serpent.dumps(encrypted_tuple)
            self._client.send_message(serpent.tobytes(serialized_data))
        except Exception as e:
            self._log.error(f"Erreur lors de l'envoi du message : {e}")

    def recv(self):
        if self._callback is not None:
            for user, encrypted_data in self._callback.get():
                try:
                    self._log.debug(f"Message reçu de {user}.")
                    self._log.debug(f"données reçues : {type(encrypted_data)}")
                    
                    if isinstance(encrypted_data, dict) and 'data' in encrypted_data:
                        decoded_data = base64.b64decode(encrypted_data['data'])
                        deserialized_data = serpent.loads(decoded_data)
                    else:
                        deserialized_data = serpent.loads(serpent.frombytes(encrypted_data))

                    self._log.debug(f"Données : {deserialized_data}")

                    if isinstance(deserialized_data, dict) and 'iv' in deserialized_data and 'message' in deserialized_data:
                        iv = base64.b64decode(deserialized_data['iv'])
                        encrypted_msg = base64.b64decode(deserialized_data['message'])
                        encrypted_tuple = (iv, encrypted_msg)
                    else:
                        raise ValueError("Format de données incorrect ")

                    message = self.decrypt(encrypted_tuple)
                    self.update_text_screen(f"{user} : {message}")
                except Exception as e:
                    self._log.error(f"Échec du traitement du message de {user} : {e}")
                    self._log.error(f"Données reçues : {encrypted_data}")
            self._callback.clear()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    DEFAULT_VALUES = {
        "host": "127.0.0.1",
        "port": "6666",
        "name": "polytech",
    }

    client = CipheredGUI()
    client.create()
    client.loop()