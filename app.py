from flask import Flask, Response, render_template_string, redirect, url_for, flash, request, session
import subprocess
import os
import logging
import requests

# Cấu hình logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = "dashboard_secret"

# Danh sách công cụ kiểm thử
TOOLS = [
    {
        "name": "Dark Proxy Tester",
        "script": "webrawedit.py",
        "desc": "🖥️ Intercept and edit HTTP/HTTPS requests/responses",
        "icon": "📝"
    },
    {
        "name": "Crawler Fuzzing URL",
        "script": "fuzzcrawsniff.py",
        "desc": "🕷️ Crawl websites and fuzz URLs for vulnerabilities",
        "icon": "🌐"
    },
    {
        "name": "CSRF Tester",
        "script": "CSRF.py",
        "desc": "🔍 Test websites for CSRF vulnerabilities",
        "icon": "🛑"
    },
    {
        "name": "Packet Sniffer",
        "script": "sniff.py",
        "desc": "📡 Capture and analyze network packets",
        "icon": "📶"
    },
    {
        "name": "Payload Convert",
        "script": "payload.py",
        "desc": "🔄 Fast and efficient payload converter",
        "icon": "⚙️"
    }
]

def load_file(filename):
    """Đọc nội dung file với xử lý lỗi"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        logger.error(f"Không tìm thấy file: {filename}")
        flash(f"Không tìm thấy file: {filename}", "error")
        return ""
    except Exception as e:
        logger.error(f"Lỗi khi đọc file {filename}: {str(e)}")
        flash(f"Lỗi khi đọc file {filename}: {str(e)}", "error")
        return ""

@app.route('/')
def index():
    html = load_file("index.html")
    if not html:
        return "Lỗi: Không thể tải trang chính", 500
    return render_template_string(html, tools=TOOLS)

@app.route('/style.css')
def style():
    css = load_file("style.css")
    if not css:
        return "Lỗi: Không thể tải CSS", 500
    return Response(css, mimetype='text/css')

@app.route('/favicon.ico')
def favicon():
    return "", 204

@app.route('/validate_key', methods=['POST'])
def validate_key():
    user_key = request.form.get('security_key')
    if not user_key:
        flash("Vui lòng nhập key bảo mật.", "error")
        return redirect(url_for('index'))

    try:
        # Key đã được băm ở phía client, gửi trực tiếp
        response = requests.get(f"https://dungit.id.vn/b/c.php", params={"pas": user_key}, timeout=5)
        response.raise_for_status()
        if response.text.strip() == "true":
            session['key_validated'] = True
            flash("Key bảo mật hợp lệ! Bạn có thể sử dụng các công cụ.", "success")
        else:
            session.pop('key_validated', None)
            flash("Key bảo mật không hợp lệ. Vui lòng mua key tại https://dungit.id.vn.", "error")
    except requests.RequestException as e:
        session.pop('key_validated', None)
        logger.error(f"Lỗi khi kiểm tra key: {str(e)}")
        flash(f"Lỗi khi kiểm tra key: Vui lòng thử lại sau.", "error")

    return redirect(url_for('index'))

@app.route('/run/<script_name>')
def run_script(script_name):
    if not session.get('key_validated'):
        flash("Vui lòng nhập key bảo mật hợp lệ trước khi sử dụng công cụ.", "error")
        return redirect(url_for('index'))

    if not any(tool['script'] == script_name for tool in TOOLS):
        flash(f"Script không hợp lệ: {script_name}", "error")
        logger.warning(f"Yêu cầu chạy script không hợp lệ: {script_name}")
        return redirect(url_for('index'))

    if not os.path.exists(script_name):
        flash(f"Không tìm thấy script: {script_name}", "error")
        logger.error(f"Script không tồn tại: {script_name}")
        return redirect(url_for('index'))

    try:
        subprocess.Popen(["python", script_name], creationflags=subprocess.CREATE_NO_WINDOW)
        flash(f"Đã chạy script: {script_name}", "success")
        logger.info(f"Đã chạy script: {script_name}")
    except Exception as e:
        flash(f"Lỗi khi chạy script {script_name}: {str(e)}", "error")
        logger.error(f"Lỗi khi chạy script {script_name}: {str(e)}")
    return redirect(url_for('index'))

if __name__ == "__main__":
    # Hỏi người dùng cấu hình host và port
    host = input("Nhập host (mặc định: 127.0.0.1): ").strip()
    port_input = input("Nhập port (mặc định: 5000): ").strip()

    host = host if host else "127.0.0.1"
    try:
        port = int(port_input) if port_input else 5000
    except ValueError:
        print("⚠️ Port không hợp lệ, dùng mặc định 5000")
        port = 5000

    print(f"🚀 Khởi chạy Flask tại http://{host}:{port}")
    app.run(debug=True, use_reloader=False, host=host, port=port)