from flask import Flask, request, send_file, current_app
from urllib.parse import unquote
from Crypto.Cipher import AES
import binascii
import requests
import re
import os
import io
import mimetypes

hostphp = "https://peer.byethost12.com" # insert your peer host

def decrypt_slowAES(encrypted_hex, key_hex, iv_hex):
    encrypted_bytes = binascii.unhexlify(encrypted_hex)
    key_bytes = binascii.unhexlify(key_hex)
    iv_bytes = binascii.unhexlify(iv_hex)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    decrypted_bytes = cipher.decrypt(encrypted_bytes)
    decrypted_cookie_hex = binascii.hexlify(decrypted_bytes).decode()
    return decrypted_cookie_hex
            
class Bypasse:
    @staticmethod
    def upload(url, files=None, data=None, headers=None, cookies=None, **kwargs):
        if headers is None:
            headers = { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36" }
        r1 = requests.get(url, headers=headers, **kwargs)
        html_content = r1.text
        a_match = re.search(r'var a=toNumbers\("([a-fA-F0-9]+)"\)', html_content)
        b_match = re.search(r'b=toNumbers\("([a-fA-F0-9]+)"\)', html_content)
        c_match = re.search(r'c=toNumbers\("([a-fA-F0-9]+)"\)', html_content)
        url_match = re.search(r'location\.href="([^"]+)"', html_content)
        aes_key = a_match.group(1) if a_match else None
        aes_iv = b_match.group(1) if b_match else None
        encrypted_data = c_match.group(1) if c_match else None
        redirect_url = url_match.group(1) if url_match else None
        if not all([aes_key, aes_iv, encrypted_data, redirect_url]):
            return requests.post(url, files=files, data=data, headers=headers, cookies=cookies, **kwargs)
        decrypted_value = decrypt_slowAES(encrypted_data, aes_key, aes_iv)
        payload = {"__test": decrypted_value}
        if cookies:
            payload.update(cookies)
        r2 = requests.post(redirect_url, files=files, data=data, headers=headers, cookies=payload, **kwargs)
        return r2

    @staticmethod
    def get_file(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"}, cookies=None, **kwargs):
        r1 = requests.get(url, headers=headers, **kwargs)
        content_type = r1.headers.get('Content-Type', '')
        try:
            html_content = r1.text
            a_match = re.search(r'var a=toNumbers\("([a-fA-F0-9]+)"\)', html_content)
            b_match = re.search(r'b=toNumbers\("([a-fA-F0-9]+)"\)', html_content)
            c_match = re.search(r'c=toNumbers\("([a-fA-F0-9]+)"\)', html_content)
            url_match = re.search(r'location\.href="([^"]+)"', html_content)
            aes_key = a_match.group(1) if a_match else None
            aes_iv = b_match.group(1) if b_match else None
            encrypted_data = c_match.group(1) if c_match else None
            redirect_url = url_match.group(1) if url_match else None
            if not all([aes_key, aes_iv, encrypted_data, redirect_url]):
                return r1
            decrypted_value = decrypt_slowAES(encrypted_data, aes_key, aes_iv)
            payload = {"__test": decrypted_value}
            if cookies:
                payload.update(cookies)
            r2 = requests.get(redirect_url, headers=headers, cookies=payload, **kwargs)
            return r2
        except:
            return r1

app = Flask(__name__)
content_types = {
    ".jpeg": "image/jpeg", ".jpg": "image/jpeg", ".png": "image/png", ".gif": "image/gif", ".webp": "image/webp",
    ".bmp": "image/bmp", ".svg": "image/svg+xml", ".ico": "image/x-icon",
    ".mp4": "video/mp4", ".webm": "video/webm", ".mkv": "video/x-matroska",
    ".mov": "video/quicktime", ".ogv": "video/ogg", ".flv": "video/x-flv",
    ".mp3": "audio/mpeg", ".aac": "audio/aac", ".wav": "audio/wav", ".flac": "audio/flac",
    ".ogg": "audio/ogg", ".opus": "audio/opus", ".m4a": "audio/mp4",
    ".pdf": "application/pdf", ".zip": "application/zip", ".php": "application/x-php",
    ".html": "text/html", ".css": "text/css", ".js": "application/javascript",
    ".json": "application/json", ".xml": "application/xml", ".txt": "text/plain", ".csv": "text/csv",
    ".woff": "font/woff", ".woff2": "font/woff2", ".rar": "application/vnd.rar", ".torrent": "application/x-bittorrent",
}

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,Cache-Control')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

@app.route('/peer/upload', methods=['POST'])
def peerupload():
    file = request.files['file']
    if file is None:
        return "", 200
    try:
        r = Bypasse.upload(hostphp + "/index.php/peer/upload", files={"file": (file.filename, file.stream, file.mimetype)})
        fileid = r.text.split("/")[-1]
        base_url = request.host_url
        if request.headers.get('X-Forwarded-Proto') == 'https' or request.headers.get('X-Forwarded-Scheme') == 'https' or request.headers.get('X-Scheme') == 'https':
            base_url = base_url.replace('http://', 'https://')
        return f"{base_url.rstrip('/')}/peer/{fileid}", 200
    except Exception:
        return "", 200

@app.route('/peer/<path:filename>')
def peerload(filename):
    response = Bypasse.get_file(hostphp + "/index.php/peer/" + filename)
    _, extension = os.path.splitext(filename)
    content_type = content_types.get(extension.lower(), 'application/octet-stream')
    mime_type, _ = mimetypes.guess_type(filename)
    return send_file(io.BytesIO(response.content), mimetype=mime_type)

@app.route('/')
def peerindex():
    return send_file(os.path.join('static', 'peerdata', 'index.html'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False)
