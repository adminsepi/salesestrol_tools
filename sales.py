
#!/usr/bin/python
# Ultimate God-Mode Ghost-Tracker by #salesestrol (Based on HUNX04's Code)
# Telegram: @salesestrol
# For Termux - Educational Use Only. Ultra-Realistic Simulations!
# Warning: For teacher demo only. No real harm. #salesestrol @salesestrol
# Original Credit: HUNX04 (GitHub). Respect the code, don't steal without credit!

import json
import requests
import time
import os
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from sys import stderr
import random
import string
import socket
import hashlib
import base64
import datetime
try:
    from termcolor import colored
except ImportError:
    print("Install termcolor: pkg install python; pip install termcolor")
    colored = lambda x, _: x

# ANSI Colors for Termux (Yellow, Green, Red, Purple)
def print_red(text): print(colored(text, 'red') if 'colored' in globals() else "\033[91m" + text + "\033[0m")
def print_green(text): print(colored(text, 'green') if 'colored' in globals() else "\033[92m" + text + "\033[0m")
def print_yellow(text): print(colored(text, 'yellow') if 'colored' in globals() else "\033[93m" + text + "\033[0m")
def print_purple(text): print(colored(text, 'magenta') if 'colored' in globals() else "\033[95m" + text + "\033[0m")

def clear_screen():
    os.system('clear')

# Main Menu Banner
def show_banner():
    banner = """
    ╭╮╮╱▔▔▔▔╲╭╭╮ 
    ╰╲╲▏▂╲╱▂▕╱╱╯ 
    ┈┈╲▏▇▏▕▇▕╱┈┈ 
    ┈┈╱╲▔▕▍▔╱╲┈┈ 
    ╭╱╱▕╋╋╋╋▏╲╲ 
    ╰╯╯┈╲▂▂╱┈╰╰╯
    ☢️ God-TRACKER by #salesestrol ☢️
    💀 Telegram: @salesestrol 💀
    👻 HACK THE WORLD ETHICALLY! 👻
    """
    print_purple(banner)

# Main Menu
def main_menu():
    while True:
        clear_screen()
        show_banner()
        print_yellow("""
        💉 Ghost-Tracker Menu 💉
        1. IP Tracker 🌍
        2. Show Your IP 📍
        3. Phone Tracker 📱
        4. Username Tracker 🕵️‍♂️
        5. Advanced Hacking Tools 🔧
        6. salesestrol funs (for upping youe mind) ☠️
        0. Exit 🪦
        ╚═══════════════════════╝
        """)
        choice = input(colored("@Ghost~# ", 'yellow'))
        
        if choice == '1':
            tool_submenu(ip_tracker, "IP Tracker: Fetches geolocation (country, city, ISP, etc.) for an IP. Uses ipwho.is API. Ethical for analysis. Show log to sales! #salesestrol @salesestrol")
        elif choice == '2':
            tool_submenu(show_ip, "Show Your IP: Displays your public IP using ipify.org. Useful for network debugging. #salesestrol @salesestrol")
        elif choice == '3':
            tool_submenu(phone_tracker, "Phone Tracker: Extracts info (location, carrier, timezone) from a phone number. Uses phonenumbers library. #salesestrol @salesestrol")
        elif choice == '4':
            tool_submenu(username_tracker, "Username Tracker: Checks social media for a username's presence. Scans multiple platforms. #salesestrol @salesestrol")
        elif choice == '5':
            hacking_tools_menu()
        elif choice == '6':
            salesestrol_funs_menu()
        elif choice == '0':
            print_red("THANK'S FOR USING God-TRACK! Stay Spooky! - #salesestrol @salesestrol 💀")
            sys.exit()
        else:
            print_red("Opss no option! ☠️")

# Submenu for Tools
def tool_submenu(tool_func, description):
    while True:
        clear_screen()
        tool_func.banner()
        print_yellow("""
        👻 Tool Options 👻
        1. Start the Tool 🏁
        2. What it Does & How it Works 📜
        0. Back ⬅️
        ╚═══════════════════════╝
        """)
        sub_choice = input(colored("Select: ", 'yellow'))
        
        if sub_choice == '1':
            tool_func()
        elif sub_choice == '2':
            clear_screen()
            tool_func.banner()
            print_purple(description)
            input("Press Enter...")
        elif sub_choice == '0':
            return
        else:
            print_red("Invalid! ☠️")

# Hacking Tools Menu
def hacking_tools_menu():
    def hacking_banner():
        banner = """
        .-.
        : : 
        : :     .--.
       ,` |    .'     '.
      :   |   : ,   . : 
     : :  |  : :   .:  : 
    : : :  `._: : , :  : 
    : : : ,   : : :  : 
    : :  : , :_;  :  : 
    : :  |    `.  _.' 
     `._:  ,   .'-._ 
        `._: ,_.'   `._ 
        🔧 Advanced Hacking Tools 🔧
        💀 #salesestrol @salesestrol 💀
        """
        print_purple(banner)
    
    while True:
        clear_screen()
        hacking_banner()
        print_yellow("""
        🕵️‍♂️ Advanced Hacking Tools (Educational) 🕵️‍♂️
        1. Password Generator 🔑
        2. MD5 Hash Cracker 🔨
        3. Port Scanner 🔍
        4. Web Scraper 🕸️
        5. Base64 Encoder/Decoder 🔄
        6. SQL Injection Tester 💉
        7. XSS Payload Generator 🐞
        8. Network Sniffer 📡
        9. DDoS Simulator ⚡
        0. Back ⬅️
        ╚═══════════════════════╝
        """)
        choice = input(colored("Select: ", 'yellow'))
        
        if choice == '1':
            tool_submenu(password_gen, "Password Gen: Creates strong passwords. Enhances security. #salesestrol @salesestrol")
        elif choice == '2':
            tool_submenu(hash_cracker, "Hash Cracker: Tests MD5 hashes against a dictionary. Shows brute-force risks. #salesestrol @salesestrol")
        elif choice == '3':
            tool_submenu(port_scanner, "Port Scanner: Checks open ports on a target IP. For ethical network audits. #salesestrol @salesestrol")
        elif choice == '4':
            tool_submenu(web_scraper, "Web Scraper: Grabs website content. For ethical data extraction. #salesestrol @salesestrol")
        elif choice == '5':
            tool_submenu(base64_tool, "Base64: Encodes/decodes text. For APIs and learning encoding. #salesestrol @salesestrol")
        elif choice == '6':
            tool_submenu(sql_injection_tester, "SQL Tester: Simulates SQL injection attempts. Teaches web security. #salesestrol @salesestrol")
        elif choice == '7':
            tool_submenu(xss_payload_gen, "XSS Gen: Generates test XSS payloads. For ethical testing. #salesestrol @salesestrol")
        elif choice == '8':
            tool_submenu(network_sniffer, "Sniffer: Listens on a port for packets. Networking demo. #salesestrol @salesestrol")
        elif choice == '9':
            tool_submenu(ddos_simulator, "DDoS Sim: Simulates fake requests. Shows attack concepts safely. #salesestrol @salesestrol")
        elif choice == '0':
            return
        else:
            print_red("Invalid! ☠️")

# salesestrol funs Menu
def salesestrol_funs_menu():
    def funs_banner():
        banner = """
        .--.
       : ,   : 
       : :   : 
      : : , : 
     : , : : 
    : : :_: : 
    : :    : 
     : ,  : 
      :  : 
       : : 
        : : 
        ☠️ salesestrol funs ☠️
        💉 #salesestrol @salesestrol 💉
        """
        print_purple(banner)
    
    while True:
        clear_screen()
        funs_banner()
        print_yellow("""
        ☠️ salesestrol funs (Terrifying Simulations) ☠️
        1. IP Grabber Link 💉
        2. Camera Access Link 📸
        3. Phone Format Virus 💾
        0. Back ⬅️
        ╚═══════════════════════╝
        """)
        choice = input(colored("Select: ", 'yellow'))
        
        if choice == '1':
            tool_submenu(ip_grabber_link, "IP Grabber: Generates a fake phishing link, logs your IP for demo. Looks malicious but safe. Show log to teacher! #salesestrol @salesestrol")
        elif choice == '2':
            tool_submenu(camera_link, "Camera Link: Simulates camera access with a fake link. Looks real but harmless. Show log to teacher! #salesestrol @salesestrol")
        elif choice == '3':
            tool_submenu(virus_creator, "Virus: Creates a fake 'malware' file. Moves to downloads. Show file to teacher! #salesestrol @salesestrol")
        elif choice == '0':
            return
        else:
            print_red("Invalid! ☠️")

# Tool Functions with Unique ASCII Art
def ip_tracker():
    def ip_tracker_banner():
        banner = """
        .--.
       : ,   : 
       : :   : 
      : : , : 
     : , : : 
    : : :_: : 
    : :    : 
     : ,  : 
      :  : 
       : : 
        : : 
        🌍 IP Tracker 🌍
        💀 #salesestrol @salesestrol 💀
        """
        print_purple(banner)
    ip_tracker.banner = ip_tracker_banner
    
    clear_screen()
    ip_tracker_banner()
    print_green("IP Tracker Running...")
    try:
        ip = input(colored("Enter IP target: ", 'yellow'))
        print_yellow("\n============= SHOW INFORMATION IP ADDRESS =============")
        req_api = requests.get(f"http://ipwho.is/{ip}", timeout=5)
        ip_data = json.loads(req_api.text)
        time.sleep(2)
        if ip_data.get("success", False):
            log = (f"[{datetime.datetime.now()}] IP: {ip} | Country: {ip_data['country']} | "
                   f"City: {ip_data['city']} | ISP: {ip_data['connection']['isp']} | "
                   f"Lat: {ip_data['latitude']} | Lon: {ip_data['longitude']} - #salesestrol @salesestrol")
            with open('ip_tracker_log.txt', 'a') as f:
                f.write(log + '\n')
            print_yellow(f"\nIP target       : {ip}")
            print_yellow(f"Type IP         : {ip_data['type']}")
            print_yellow(f"Country         : {ip_data['country']}")
            print_yellow(f"Country Code    : {ip_data['country_code']}")
            print_yellow(f"City            : {ip_data['city']}")
            print_yellow(f"Continent       : {ip_data['continent']}")
            print_yellow(f"Continent Code  : {ip_data['continent_code']}")
            print_yellow(f"Region          : {ip_data['region']}")
            print_yellow(f"Region Code     : {ip_data['region_code']}")
            print_yellow(f"Latitude        : {ip_data['latitude']}")
            print_yellow(f"Longitude       : {ip_data['longitude']}")
            lat = ip_data['latitude']
            lon = ip_data['longitude']
            print_yellow(f"Maps            : https://www.google.com/maps/@{lat},{lon},8z")
            print_yellow(f"EU              : {ip_data['is_eu']}")
            print_yellow(f"Postal          : {ip_data['postal']}")
            print_yellow(f"Calling Code    : {ip_data['calling_code']}")
            print_yellow(f"Capital         : {ip_data['capital']}")
            print_yellow(f"Borders         : {ip_data['borders']}")
            print_yellow(f"Country Flag    : {ip_data['flag']['emoji']}")
            print_yellow(f"ASN             : {ip_data['connection']['asn']}")
            print_yellow(f"ORG             : {ip_data['connection']['org']}")
            print_yellow(f"ISP             : {ip_data['connection']['isp']}")
            print_yellow(f"Domain          : {ip_data['connection']['domain']}")
            print_yellow(f"Timezone ID     : {ip_data['timezone']['id']}")
            print_yellow(f"Timezone ABBR   : {ip_data['timezone']['abbr']}")
            print_yellow(f"DST             : {ip_data['timezone']['is_dst']}")
            print_yellow(f"Offset          : {ip_data['timezone']['offset']}")
            print_yellow(f"UTC             : {ip_data['timezone']['utc']}")
            print_yellow(f"Current Time    : {ip_data['timezone']['current_time']}")
            print_green("Log Saved: ip_tracker_log.txt (Show teacher for grade!)")
        else:
            print_red("Invalid IP or API Error! ☠️")
    except KeyboardInterrupt:
        print_red("PROGRAM STOPPED... ☠️")
    except:
        print_red("Internet Error or Invalid Input! ☠️")
    input("Press Enter...")

def show_ip():
    def show_ip_banner():
        banner = """
        .--.
       : ,   : 
       : :   : 
      : : , : 
     : , : : 
    : : :_: : 
    : :    : 
     : ,  : 
      :  : 
       : : 
        : : 
        📍 Show Your IP 📍
        💀 #salesestrol @salesestrol 💀
        """
        print_purple(banner)
    show_ip.banner = show_ip_banner
    
    clear_screen()
    show_ip_banner()
    print_green("Show Your IP Running...")
    try:
        response = requests.get('https://api.ipify.org/', timeout=5)
        show_ip = response.text
        log = f"[{datetime.datetime.now()}] Your IP: {show_ip} - #salesestrol @salesestrol"
        with open('show_ip_log.txt', 'a') as f:
            f.write(log + '\n')
        print_yellow(f"\n========== SHOW INFORMATION YOUR IP ==========")
        print_yellow(f"\nYour IP Address : {show_ip}")
        print_green("Log Saved: show_ip_log.txt")
    except KeyboardInterrupt:
        print_red("PROGRAM STOPPED... ☠️")
    except:
        print_red("Internet Error! ☠️")
    input("Press Enter...")

def phone_tracker():
    def phone_tracker_banner():
        banner = """
        .--.
       : ,   : 
       : :   : 
      : : , : 
     : , : : 
    : : :_: : 
    : :    : 
     : ,  : 
      :  : 
       : : 
        : : 
        📱 Phone Tracker 📱
        💀 #salesestrol @salesestrol 💀
        """
        print_purple(banner)
    phone_tracker.banner = phone_tracker_banner
    
    clear_screen()
    phone_tracker_banner()
    print_green("Phone Tracker Running...")
    try:
        user_phone = input(colored("Enter phone number target (Ex: +98xxxxxxxxx): ", 'yellow'))
        default_region = "ID"
        parsed_number = phonenumbers.parse(user_phone, default_region)
        region_code = phonenumbers.region_code_for_number(parsed_number)
        jenis_provider = carrier.name_for_number(parsed_number, "en")
        location = geocoder.description_for_number(parsed_number, "en")
        is_valid_number = phonenumbers.is_valid_number(parsed_number)
        is_possible_number = phonenumbers.is_possible_number(parsed_number)
        formatted_number = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        formatted_number_for_mobile = phonenumbers.format_number_for_mobile_dialing(parsed_number, default_region, with_formatting=True)
        number_type = phonenumbers.number_type(parsed_number)
        timezone1 = timezone.time_zones_for_number(parsed_number)
        timezoneF = ', '.join(timezone1)
        
        log = (f"[{datetime.datetime.now()}] Phone: {user_phone} | Location: {location} | "
               f"Operator: {jenis_provider} | Valid: {is_valid_number} - #salesestrol @salesestrol")
        with open('phone_tracker_log.txt', 'a') as f:
            f.write(log + '\n')
        
        print_yellow("\n========== SHOW INFORMATION PHONE NUMBERS ==========")
        print_yellow(f"Location             : {location}")
        print_yellow(f"Region Code          : {region_code}")
        print_yellow(f"Timezone             : {timezoneF}")
        print_yellow(f"Operator             : {jenis_provider}")
        print_yellow(f"Valid number         : {is_valid_number}")
        print_yellow(f"Possible number      : {is_possible_number}")
        print_yellow(f"International format : {formatted_number}")
        print_yellow(f"Mobile format        : {formatted_number_for_mobile}")
        print_yellow(f"Original number      : {parsed_number.national_number}")
        print_yellow(f"E.164 format         : {phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)}")
        print_yellow(f"Country code         : {parsed_number.country_code}")
        print_yellow(f"Local number         : {parsed_number.national_number}")
        if number_type == phonenumbers.PhoneNumberType.MOBILE:
            print_yellow("Type                 : This is a mobile number")
        elif number_type == phonenumbers.PhoneNumberType.FIXED_LINE:
            print_yellow("Type                 : This is a fixed-line number")
        else:
            print_yellow("Type                 : This is another type of number")
        print_green("Log Saved: phone_tracker_log.txt (Show teacher for grade!)")
    except KeyboardInterrupt:
        print_red("PROGRAM STOPPED... ☠️")
    except:
        print_red("Invalid Phone Number! ☠️")
    input("Press Enter...")

def username_tracker():
    def username_tracker_banner():
        banner = """
        .--.
       : ,   : 
       : :   : 
      : : , : 
     : , : : 
    : : :_: : 
    : :    : 
     : ,  : 
      :  : 
       : : 
        : : 
        🕵️‍♂️ Username Tracker 🕵️‍♂️
        💀 #salesestrol @salesestrol 💀
        """
        print_purple(banner)
    username_tracker.banner = username_tracker_banner
    
    clear_screen()
    username_tracker_banner()
    print_green("Username Tracker Running...")
    try:
        username = input(colored("Enter Username: ", 'yellow'))
        print_yellow("\n========== SHOW INFORMATION USERNAME ==========")
        social_media = [
            {"url": "https://www.facebook.com/{}", "name": "Facebook"},
            {"url": "https://www.twitter.com/{}", "name": "Twitter"},
            {"url": "https://www.instagram.com/{}", "name": "Instagram"},
            {"url": "https://www.linkedin.com/in/{}", "name": "LinkedIn"},
            {"url": "https://www.github.com/{}", "name": "GitHub"},
            {"url": "https://www.pinterest.com/{}", "name": "Pinterest"},
            {"url": "https://www.tumblr.com/{}", "name": "Tumblr"},
            {"url": "https://www.youtube.com/{}", "name": "Youtube"},
            {"url": "https://soundcloud.com/{}", "name": "SoundCloud"},
            {"url": "https://www.snapchat.com/add/{}", "name": "Snapchat"},
            {"url": "https://www.tiktok.com/@{}", "name": "TikTok"},
            {"url": "https://www.behance.net/{}", "name": "Behance"},
            {"url": "https://www.medium.com/@{}", "name": "Medium"},
            {"url": "https://www.quora.com/profile/{}", "name": "Quora"},
            {"url": "https://www.flickr.com/people/{}", "name": "Flickr"},
            {"url": "https://www.twitch.tv/{}", "name": "Twitch"},
            {"url": "https://www.dribbble.com/{}", "name": "Dribbble"},
            {"url": "https://www.telegram.me/{}", "name": "Telegram"}
        ]
        results = {}
        for site in social_media:
            url = site['url'].format(username)
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                results[site['name']] = url
            else:
                results[site['name']] = "Username not found!"
        log = f"[{datetime.datetime.now()}] Username: {username} | Results: {json.dumps(results, indent=2)} - #salesestrol @salesestrol"
        with open('username_tracker_log.txt', 'a') as f:
            f.write(log + '\n')
        for site, url in results.items():
            print_yellow(f"[ + ] {site} : {url}")
        print_green("Log Saved: username_tracker_log.txt (Show teacher for grade!)")
    except KeyboardInterrupt:
        print_red("PROGRAM STOPPED... ☠️")
    except:
        print_red("Internet Error! ☠️")
    input("Press Enter...")

def password_gen():
    def password_gen_banner():
        banner = """
        .--.
       : ,   : 
       : :   : 
      : : , : 
     : , : : 
    : : :_: : 
    : :    : 
     : ,  : 
      :  : 
       : : 
        : : 
        🔑 Password Generator 🔑
        💀 #salesestrol @salesestrol 💀
        """
        print_purple(banner)
    password_gen.banner = password_gen_banner
    
    clear_screen()
    password_gen_banner()
    print_green("Password Generator Running...")
    try:
        length = int(input(colored("Password Length (min 8): ", 'yellow')))
        if length < 8: raise ValueError
        chars = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(chars) for _ in range(length))
        log = f"[{datetime.datetime.now()}] Generated Password: {password} - #salesestrol @salesestrol"
        with open('password_gen_log.txt', 'a') as f:
            f.write(log + '\n')
        print_green(f"Password: {password}")
        print_green("Log Saved: password_gen_log.txt")
    except ValueError:
        print_red("Invalid Length! ☠️")
    input("Press Enter...")

def hash_cracker():
    def hash_cracker_banner():
        banner = """
        .--.
       : ,   : 
       : :   : 
      : : , : 
     : , : : 
    : : :_: : 
    : :    : 
     : ,  : 
      :  : 
       : : 
        : : 
        🔨 MD5 Hash Cracker 🔨
        💀 #salesestrol @salesestrol 💀
        """
        print_purple(banner)
    hash_cracker.banner = hash_cracker_banner
    
    clear_screen()
    hash_cracker_banner()
    print_green("MD5 Hash Cracker Running...")
    hash_to_crack = input(colored("MD5 Hash: ", 'yellow')).lower()
    dictionary = ["password", "123456", "admin", "letmein", "welcome", "qwerty", "abc123", "password1", "iloveyou", "monkey", "salesestrol"]
    for word in dictionary:
        if hashlib.md5(word.encode()).hexdigest() == hash_to_crack:
            log = f"[{datetime.datetime.now()}] Hash: {hash_to_crack} | Cracked: {word} - #salesestrol @salesestrol"
            with open('hash_cracker_log.txt', 'a') as f:
                f.write(log + '\n')
            print_green(f"Cracked: {word}")
            print_green("Log Saved: hash_cracker_log.txt")
            input("Press Enter..."); return
    print_red("Not Found! ☠️")
    input("Press Enter...")

def port_scanner():
    def port_scanner_banner():
        banner = """
        .--.
       : ,   : 
       : :   : 
      : : , : 
     : , : : 
    : : :_: : 
    : :    : 
     : ,  : 
      :  : 
       : : 
        : : 
        🔍 Port Scanner 🔍
        💀 #salesestrol @salesestrol 💀
        """
        print_purple(banner)
    port_scanner.banner = port_scanner_banner
    
    clear_screen()
    port_scanner_banner()
    print_green("Port Scanner Running...")
    target = input(colored("Target IP: ", 'yellow'))
    ports = [21, 22, 80, 443, 3389, 8080, 3306, 445, 139]
    log = f"[{datetime.datetime.now()}] Target IP: {target} | Scanned Ports: {ports} - #salesestrol @salesestrol\n"
    with open('port_scanner_log.txt', 'a') as f:
        f.write(log)
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            print_green(f"Port {port} Open!")
            with open('port_scanner_log.txt', 'a') as f:
                f.write(f"Port {port}: Open\n")
        else:
            print_red(f"Port {port} Closed.")
            with open('port_scanner_log.txt', 'a') as f:
                f.write(f"Port {port}: Closed\n")
        sock.close()
    print_green("Log Saved: port_scanner_log.txt")
    input("Press Enter...")

def web_scraper():
    def web_scraper_banner():
        banner = """
        .--.
       : ,   : 
       : :   : 
      : : , : 
     : , : : 
    : : :_: : 
    : :    : 
     : ,  : 
      :  : 
       : : 
        : : 
        🕸️ Web Scraper 🕸️
        💀 #salesestrol @salesestrol 💀
        """
        print_purple(banner)
    web_scraper.banner = web_scraper_banner
    
    clear_screen()
    web_scraper_banner()
    print_green("Web Scraper Running...")
    url = input(colored("URL: ", 'yellow'))
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Android; Mobile; rv:68.0) Gecko/68.0 Firefox/68.0'}
        response = requests.get(url, headers=headers, timeout=5)
        log = f"[{datetime.datetime.now()}] URL: {url} | Content: {response.text[:1000]} - #salesestrol @salesestrol\n"
        with open('web_scrape_log.txt', 'a') as f:
            f.write(log)
        print_green(f"Content (1000 chars): {response.text[:1000]}")
        print_green("Log Saved: web_scrape_log.txt")
    except:
        print_red("Fetch Error! ☠️")
    input("Press Enter...")

def base64_tool():
    def base64_tool_banner():
        banner = """
        .--.
       : ,   : 
       : :   : 
      : : , : 
     : , : : 
    : : :_: : 
    : :    : 
     : ,  : 
      :  : 
       : : 
        : : 
        🔄 Base64 Encoder/Decoder 🔄
        💀 #salesestrol @salesestrol 💀
        """
        print_purple(banner)
    base64_tool.banner = base64_tool_banner
    
    clear_screen()
    base64_tool_banner()
    print_green("Base64 Encoder/Decoder Running...")
    text = input(colored("Text to Encode: ", 'yellow'))
    encoded = base64.b64encode(text.encode()).decode()
    log = f"[{datetime.datetime.now()}] Text: {text} | Encoded: {encoded} - #salesestrol @salesestrol\n"
    with open('base64_log.txt', 'a') as f:
        f.write(log)
    print_green(f"Encoded: {encoded}")
    decoded = base64.b64decode(encoded).decode()
    print_green(f"Decoded: {decoded}")
    print_green("Log Saved: base64_log.txt")
    input("Press Enter...")

def sql_injection_tester():
    def sql_injection_tester_banner():
        banner = """
        .--.
       : ,   : 
       : :   : 
      : : , : 
     : , : : 
    : : :_: : 
    : :    : 
     : ,  : 
      :  : 
       : : 
        : : 
        💉 SQL Injection Tester 💉
        💀 #salesestrol @salesestrol 💀
        """
        print_purple(banner)
    sql_injection_tester.banner = sql_injection_tester_banner
    
    clear_screen()
    sql_injection_tester_banner()
    print_green("SQL Injection Tester Running...")
    user_input = input(colored("Input: ", 'yellow'))
    dangerous = ["'", "--", ";", "OR '1'='1'", "DROP TABLE", "UNION SELECT"]
    log = f"[{datetime.datetime.now()}] Input: {user_input} | Dangerous: {any(d in user_input.upper() for d in dangerous)} - #salesestrol @salesestrol\n"
    with open('sql_injection_log.txt', 'a') as f:
        f.write(log)
    if any(d in user_input.upper() for d in dangerous):
        print_red("Injection Detected! ☠️")
    else:
        print_green("Safe Input.")
    print_green("Log Saved: sql_injection_log.txt")
    input("Press Enter...")

def xss_payload_gen():
    def xss_payload_gen_banner():
        banner = """
        .--.
       : ,   : 
       : :   : 
      : : , : 
     : , : : 
    : : :_: : 
    : :    : 
     : ,  : 
      :  : 
       : : 
        : : 
        🐞 XSS Payload Generator 🐞
        💀 #salesestrol @salesestrol 💀
        """
        print_purple(banner)
    xss_payload_gen.banner = xss_payload_gen_banner
    
    clear_screen()
    xss_payload_gen_banner()
    print_green("XSS Payload Generator Running...")
    payloads = [
        "<script>alert('Hacked by #salesestrol');</script>",
        "<img src=x onerror=alert('XSS by @salesestrol')>",
        "<svg onload=alert('Hacked by #salesestrol')>",
        "javascript:alert('XSS by @salesestrol')"
    ]
    log = f"[{datetime.datetime.now()}] Generated XSS Payloads: {payloads} - #salesestrol @salesestrol\n"
    with open('xss_payload_log.txt', 'a') as f:
        f.write(log)
    print_green("XSS Payloads:")
    for p in payloads:
        print_yellow(p)
    print_green("Log Saved: xss_payload_log.txt")
    input("Press Enter...")

def network_sniffer():
    def network_sniffer_banner():
        banner = """
        .--.
       : ,   : 
       : :   : 
      : : , : 
     : , : : 
    : : :_: : 
    : :    : 
     : ,  : 
      :  : 
       : : 
        : : 
        📡 Network Sniffer 📡
        💀 #salesestrol @salesestrol 💀
        """
        print_purple(banner)
    network_sniffer.banner = network_sniffer_banner
    
    clear_screen()
    network_sniffer_banner()
    print_green("Network Sniffer Running...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('0.0.0.0', 8080))
        sock.listen(1)
        print_green("Listening...")
        conn, addr = sock.accept()
        print_green(f"Connection: {addr}")
        data = conn.recv(4096)
        log = f"[{datetime.datetime.now()}] From {addr}: {data.decode(errors='ignore')} - #salesestrol @salesestrol\n"
        with open('sniffer_log.txt', 'a') as f:
            f.write(log)
        print_yellow(f"Data: {data.decode(errors='ignore')}")
        print_green("Log Saved: sniffer_log.txt")
        conn.close()
    except Exception as e:
        print_red(f"Error: {e} ☠️")
    input("Press Enter...")

def ddos_simulator():
    def ddos_simulator_banner():
        banner = """
        .--.
       : ,   : 
       : :   : 
      : : , : 
     : , : : 
    : : :_: : 
    : :    : 
     : ,  : 
      :  : 
       : : 
        : : 
        ⚡ DDoS Simulator ⚡
        💀 #salesestrol @salesestrol 💀
        """
        print_purple(banner)
    ddos_simulator.banner = ddos_simulator_banner
    
    clear_screen()
    ddos_simulator_banner()
    print_green("DDoS Simulator Running...")
    target = input(colored("URL (Simulation): ", 'yellow'))
    print_red("Simulating... (Ctrl+C to Stop) ⚡")
    try:
        count = 0
        while True:
            headers = {'User-Agent': f'Mozilla/5.0 (salesestrol-{random.randint(1,1000)})'}
            requests.get(target, headers=headers, timeout=1)
            count += 1
            print_yellow(f"Request {count} Sent!")
            log = f"[{datetime.datetime.now()}] DDoS Simulation: {target} | Request {count} - #salesestrol @salesestrol\n"
            with open('ddos_sim_log.txt', 'a') as f:
                f.write(log)
            time.sleep(0.03)
    except KeyboardInterrupt:
        print_red("Stopped. ☠️")
        print_green("Log Saved: ddos_sim_log.txt")
    except:
        print_red("Error! ☠️")
    input("Press Enter...")

def ip_grabber_link():
    def ip_grabber_banner():
        banner = """
        .--.
       : ,   : 
       : :   : 
      : : , : 
     : , : : 
    : : :_: : 
    : :    : 
     : ,  : 
      :  : 
       : : 
        : : 
        💉 IP Grabber Link 💉
        💀 #salesestrol @salesestrol 💀
        """
        print_purple(banner)
    ip_grabber_link.banner = ip_grabber_banner
    
    clear_screen()
    ip_grabber_banner()
    print_green("IP Grabber Link Running...")
    fake_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    fake_link = f"https://secure-auth-{fake_id}.site/track?key={random.randint(10000,99999)}"
    print_yellow(f"Malicious Link: {fake_link}")
    try:
        ip = requests.get('https://api.ipify.org', timeout=5).text
        user_agent = requests.get('https://httpbin.org/user-agent', timeout=5).json()['user-agent']
        log = f"[{datetime.datetime.now()}] IP: {ip} | User-Agent: {user_agent} | Link: {fake_link} - #salesestrol @salesestrol\n"
        with open('ip_grabber_log.txt', 'a') as f:
            f.write(log)
        print_green(f"Log Saved: ip_grabber_log.txt (Show teacher for grade!)")
        print_red("Looks real but only logs your IP for demo. ☠️")
    except:
        print_red("Internet Needed! ☠️")
    input("Press Enter...")

def camera_link():
    def camera_link_banner():
        banner = """
        .--.
       : ,   : 
       : :   : 
      : : , : 
     : , : : 
    : : :_: : 
    : :    : 
     : ,  : 
      :  : 
       : : 
        : : 
        📸 Camera Access Link 📸
        💀 #salesestrol @salesestrol 💀
        """
        print_purple(banner)
    camera_link.banner = camera_link_banner
    
    clear_screen()
    camera_link_banner()
    print_green("Camera Access Link Running...")
    fake_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    fake_link = f"https://cam-capture-{fake_id}.site/access?token={random.randint(1000,9999)}"
    print_yellow(f"Malicious Link: {fake_link}")
    log = f"[{datetime.datetime.now()}] Camera Access Attempt: Link {fake_link} | Status: Photo Captured (Simulated) - #salesestrol @salesestrol\n"
    with open('camera_access_log.txt', 'a') as f:
        f.write(log)
    print_green(f"Log Saved: camera_access_log.txt (Show sales for grade!)")
    print_red("Simulation only. Real camera access is illegal. ☠️")
    input("Press Enter...")

def virus_creator():
    def virus_creator_banner():
        banner = """
        .--.
       : ,   : 
       : :   : 
      : : , : 
     : , : : 
    : : :_: : 
    : :    : 
     : ,  : 
      :  : 
       : : 
        : : 
        💾 Phone Format Virus 💾
        💀 #salesestrol @salesestrol 💀
        """
        print_purple(banner)
    virus_creator.banner = virus_creator_banner
    
    clear_screen()
    virus_creator_banner()
    print_green("Phone Format Virus Running...")
    virus_content = (
        f"::: DANGER :::\n"
        f"Simulated Malware by #salesestrol @salesestrol\n"
        f"This file mimics a virus but is harmless.\n"
        f"Created: {datetime.datetime.now()}\n"
        f"Purpose: Educational things with sales.\n"
        f"Signature: #salesestrol @salesestrol\n"
        f"WARNING: SYSTEM COMPROMISED! (Just kidding, it's safe) ☠️"
    )
    file_name = f"malware_{random.randint(1000,9999)}.txt"
    with open(file_name, 'w') as f:
        f.write(virus_content)
    download_path = os.path.join(os.path.expanduser('~'), 'storage/downloads', file_name)
    try:
        os.makedirs(os.path.dirname(download_path), exist_ok=True)
        os.rename(file_name, download_path)
        print_yellow(f"Malware Moved to: {download_path}")
        print_green("Show file to sales for grade! - #salesestrol @salesestrol")
    except:
        print_red(f"Error moving. Saved as {file_name}. ☠️")
    print_red("This is a simulation. Real malware is illegal. ☠️")
    input("Press Enter...")

# Start Program
if __name__ == "__main__":
    main_menu()