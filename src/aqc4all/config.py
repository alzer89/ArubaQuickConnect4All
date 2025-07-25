import os
import configparser

def read_config_variables():
    config_path = "/tmp/aqc/quickconnect/props/config.ini"
    if not os.path.exists(config_path):
        print("[!] config.ini not found!")
        return {}

    print("[*] Reading config.ini...")
    config = configparser.ConfigParser()
    config.read(config_path)

    config_dict = {s: dict(config.items(s)) for s in config.sections()}
    print("[✓] Config variables loaded")
    return config_dict

