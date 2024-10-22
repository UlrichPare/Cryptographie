import os
import time
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
import base64
import dearpygui.dearpygui as dpg
import serpent
import logging
from FernetGUI import FernetGUI
import Pyro5

class TimeFernetGUI(FernetGUI):
    def __init__(self):
        super().__init__()
        self.TTL = 30  

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

        key = hashes.Hash(hashes.SHA256())
        key.update(password.encode())
        key_bytes = key.finalize()
        fernet_key = base64.b64encode(key_bytes)
        
        self._fernet = Fernet(fernet_key)
        self._log.debug(f"la clé générée: {fernet_key.decode()}")

        super().run_chat(sender, app_data)

    def encrypt(self, message: str) -> bytes:
        current_time = int(time.time()) - 45  
        encrypted_data = self._fernet.encrypt_at_time(message.encode(), current_time=current_time)
        self._log.debug(f"Message chiffré : {current_time}")
        return encrypted_data

    def decrypt(self, encrypted_data: bytes) -> str:
        try:
            current_time = int(time.time())
            decrypted_data = self._fernet.decrypt_at_time(encrypted_data, ttl=self.TTL, current_time=current_time)
            return decrypted_data.decode()
        except InvalidToken as e:
            self._log.error(f"Erreur de déchiffrement (InvalidToken): {str(e)}")
            return "<déchiffrement échoué: message expiré>"
        except Exception as e:
            self._log.error(f"Erreur de déchiffrement: {str(e)}")
            return "<déchiffrement échoué>"
        
    def send(self, text):
        if self._fernet is None:
            self._log.error("Pas de clé dispo")
            return
        try:
            encrypted_data = self.encrypt(text)
            serialized_data = base64.b64encode(encrypted_data).decode('utf-8')
            self._client.send_message(serialized_data)
        except Exception as e:
            self._log.error(f"Erreur lors de l'envoi du msg : {e}")

    def recv(self):
        if self._callback is not None:
            for user, encrypted_data in self._callback.get():
                try:
                    self._log.debug(f"Message reçu de {user}.")
                    decoded_data = base64.b64decode(encrypted_data)
                    message = self.decrypt(decoded_data)
                    self.update_text_screen(f"{user} : {message}")
                except Exception as e:
                    self._log.error(f"Échec du traitement du msg de {user} : {e}")
                    self._log.error(f"Donnees reçues : {encrypted_data}")
            self._callback.clear()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    DEFAULT_VALUES = {
        "host": "127.0.0.1",
        "port": "6666",
        "name": "polytech",
    }
    client = TimeFernetGUI()
    client.create()
    client.loop()
