import sys
import time
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QWidget, QPushButton, QTextEdit,
    QLineEdit, QHBoxLayout, QLabel, QListWidget, QMenu, QTabWidget, QMessageBox,
    QTableWidget, QTableWidgetItem, QProgressDialog
)
from PyQt5.QtCore import QThread, pyqtSignal, QUrl, Qt
from PyQt5.QtWebEngineWidgets import QWebEngineView
from scapy.all import sniff, IP, TCP, UDP, DNS
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from urllib.parse import urlparse, urlsplit, urlunsplit, urlencode, parse_qs
import requests
import queue
import threading

class PacketSnifferThread(QThread):
    packetCaptured = pyqtSignal(str)
    statusUpdate = pyqtSignal(str)

    def __init__(self, duration=None):
        super().__init__()
        self.duration = duration  # Duration in seconds (None for unlimited)

    def run(self):
        self.statusUpdate.emit("Bắt đầu sniffing gói tin...")
        def packet_callback(packet):
            if IP in packet:
                info = f"IP: {packet[IP].src} -> {packet[IP].dst}, Len: {len(packet)}"
                if TCP in packet:
                    info += f", TCP: {packet[TCP].sport} -> {packet[TCP].dport}"
                elif UDP in packet:
                    info += f", UDP: {packet[UDP].sport} -> {packet[UDP].dport}"
                elif DNS in packet:
                    info += f", DNS: {packet[DNS].summary()}"
                self.packetCaptured.emit(info)
        sniff(prn=packet_callback, store=0, timeout=self.duration)

class SnifferWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Packet Sniffer GUI')
        self.resize(800, 600)

        # Main layout and widgets
        layout = QVBoxLayout()
        self.startButton = QPushButton('Start Sniffing')
        self.packetLog = QTextEdit()
        self.packetLog.setReadOnly(True)

        layout.addWidget(self.startButton)
        layout.addWidget(self.packetLog)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        # Thread and signals
        self.sniffer = PacketSnifferThread(duration=30)  # sniff for 30 seconds
        self.startButton.clicked.connect(self.startSniffing)
        self.sniffer.packetCaptured.connect(self.logPacket)
        self.sniffer.statusUpdate.connect(self.logStatus)

    def startSniffing(self):
        self.packetLog.clear()
        self.sniffer.start()

    def logPacket(self, info):
        self.packetLog.append(info)

    def logStatus(self, status):
        self.packetLog.append(status)

class CrawlerFuzzerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🕷️ URL Crawler & Fuzzer")
        self.setGeometry(100, 100, 950, 750)

        # Tabs
        self.tabs = QTabWidget()
        self.tab_main = QWidget()
        self.tab_browser = QWidget()
        self.tabs.addTab(self.tab_main, "🛠 Crawler & Fuzzer")
        self.tabs.addTab(self.tab_browser, "🌐 Xem trang web")

        # ==== TAB CHÍNH ====
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Nhập URL để bắt đầu crawl...")

        self.max_depth_input = QLineEdit()
        self.max_depth_input.setPlaceholderText("Giới hạn độ sâu (mặc định: 2)")
        self.max_depth_input.setText("2")

        self.num_threads_input = QLineEdit()
        self.num_threads_input.setPlaceholderText("Số luồng (mặc định: 4)")
        self.num_threads_input.setText("4")

        self.crawl_button = QPushButton("Crawl URL")
        self.crawl_button.clicked.connect(self.start_crawling)

        self.url_list = QListWidget()
        self.url_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.url_list.customContextMenuRequested.connect(self.show_context_menu)
        self.url_list.setEditTriggers(QListWidget.DoubleClicked)

        self.payload_input = QTextEdit()
        self.payload_input.setPlaceholderText("Nhập payload mỗi dòng (hoặc để trống dùng mặc định)")
        default_payloads = [
            "' OR '1'='1-- ",
            "><script>alert(1)</script>",
            "../../../../etc/passwd",
            "../../../../etc/hostname",
            "action=delete",
        ]
        self.payload_input.setPlainText('\n'.join(default_payloads))

        self.fuzz_button = QPushButton("Fuzz URL trong danh sách")
        self.fuzz_button.clicked.connect(self.start_fuzzing)

        self.auto_detect_fuzzable_button = QPushButton("🔎 Thêm URL có tham số GET vào danh sách")
        self.auto_detect_fuzzable_button.clicked.connect(self.detect_fuzzable_urls)

        self.result_table = QTableWidget()
        self.result_table.setColumnCount(7)
        self.result_table.setHorizontalHeaderLabels([
            '📎 Payload', '🔗 URL', '📟 Status', '🧱 Bytes', '📝 Words', '📄 Lines', '⏱ Time'
        ])
        self.result_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.result_table.customContextMenuRequested.connect(self.show_result_context_menu)

        self.urls_to_fuzz_text = QTextEdit()
        self.urls_to_fuzz_text.setPlaceholderText("Nhập các URL cần fuzz, mỗi URL 1 dòng...")

        # Status label
        self.status_label = QLabel("Ready")

        # Layout chính
        layout_main = QVBoxLayout()
        layout_main.addWidget(QLabel("🔎 Nhập URL để Crawler:"))
        layout_main.addWidget(self.url_input)

        url_limit_layout = QHBoxLayout()
        url_limit_layout.addWidget(QLabel("📊 Giới hạn độ sâu:"))
        url_limit_layout.addWidget(self.max_depth_input)
        url_limit_layout.addWidget(QLabel("🔢 Số luồng:"))
        url_limit_layout.addWidget(self.num_threads_input)
        layout_main.addLayout(url_limit_layout)

        layout_main.addWidget(self.crawl_button)
        layout_main.addWidget(QLabel("🌐 Danh sách URL tìm thấy:"))
        layout_main.addWidget(self.url_list)
        layout_main.addWidget(self.auto_detect_fuzzable_button)
        layout_main.addWidget(QLabel("💣 Nhập Payload để Fuzz (mỗi dòng 1 payload):"))
        layout_main.addWidget(self.payload_input)
        layout_main.addWidget(self.fuzz_button)
        layout_main.addWidget(QLabel("📋 Kết quả Fuzz:"))
        layout_main.addWidget(self.result_table)
        layout_main.addWidget(QLabel("🔒 Danh sách URL sẽ Fuzz:"))
        layout_main.addWidget(self.urls_to_fuzz_text)
        layout_main.addWidget(self.status_label)

        self.tab_main.setLayout(layout_main)

        # ==== TAB TRÌNH DUYỆT ====
        self.browser_url_bar = QLineEdit()
        self.browser_url_bar.setReadOnly(True)
        self.browser = QWebEngineView()
        self.browser.urlChanged.connect(self.update_url_bar)

        layout_browser = QVBoxLayout()
        layout_browser.addWidget(self.browser_url_bar)
        layout_browser.addWidget(self.browser)
        self.tab_browser.setLayout(layout_browser)

        # Layout tổng
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tabs)
        self.setLayout(main_layout)

        self.urls_to_fuzz = []

    def update_url_bar(self, qurl: QUrl):
        self.browser_url_bar.setText(qurl.toString())

    def start_crawling(self):
        self.url_list.clear()
        start_url = self.url_input.text().strip()
        if not start_url:
            QMessageBox.warning(self, "Lỗi", "Vui lòng nhập URL.")
            return

        try:
            max_depth = int(self.max_depth_input.text().strip())
            if max_depth < 0:
                raise ValueError
        except ValueError:
            QMessageBox.warning(self, "Lỗi", "Giới hạn độ sâu phải là số nguyên không âm")
            return

        try:
            num_threads = int(self.num_threads_input.text().strip())
            if num_threads <= 0:
                raise ValueError
        except ValueError:
            QMessageBox.warning(self, "Lỗi", "Số luồng phải là số nguyên dương")
            return

        progress = QProgressDialog("Đang crawl các URL...", "Hủy", 0, 0, self)
        progress.setWindowModality(Qt.WindowModal)
        progress.setMinimumDuration(0)
        progress.show()

        cancelled = threading.Event()
        progress.canceled.connect(lambda: cancelled.set())

        self.status_label.setText("Đang crawl...")
        QApplication.processEvents()

        url_queue = queue.Queue()
        visited = set()
        in_queue = set()
        lock = threading.Lock()
        url_queue.put((start_url, 0))
        in_queue.add(start_url)
        found_urls = set()

        def worker():
            options = Options()
            options.add_argument('--headless')
            options.add_argument('--disable-gpu')
            options.add_argument('--no-sandbox')
            driver = webdriver.Chrome(options=options)
            while not cancelled.is_set():
                try:
                    url, depth = url_queue.get(timeout=1)
                except queue.Empty:
                    break
                if cancelled.is_set() or depth > max_depth:
                    url_queue.task_done()
                    continue
                with lock:
                    if url in in_queue:
                        in_queue.remove(url)
                    visited.add(url)
                    found_urls.add(url)
                try:
                    driver.get(url)
                    time.sleep(2)
                    links = [a.get_attribute('href') for a in driver.find_elements("tag name", "a") if a.get_attribute('href')]
                    for link in links:
                        parsed = urlparse(link)
                        if parsed.scheme not in ['http', 'https']:
                            continue
                        with lock:
                            if link not in visited and link not in in_queue and depth + 1 <= max_depth:
                                url_queue.put((link, depth + 1))
                                in_queue.add(link)
                except Exception:
                    pass
                url_queue.task_done()
            driver.quit()

        threads = []
        for _ in range(num_threads):
            thread = threading.Thread(target=worker)
            thread.start()
            threads.append(thread)

        url_queue.join()

        for thread in threads:
            thread.join()

        self.url_list.clear()
        for url in found_urls:
            self.url_list.addItem(url)
        self.status_label.setText(f"Crawl hoàn thành: {len(found_urls)} URL tìm thấy")
        progress.cancel()

    def detect_fuzzable_urls(self):
        fuzzable_urls = []
        for i in range(self.url_list.count()):
            url = self.url_list.item(i).text().strip()
            if urlparse(url).query:
                fuzzable_urls.append(url)
        if fuzzable_urls:
            self.urls_to_fuzz_text.append("\n".join(fuzzable_urls))
            QMessageBox.information(self, "Đã phát hiện",
                                  f"Tìm thấy {len(fuzzable_urls)} URL có thể fuzz và đã thêm vào danh sách.")
        else:
            QMessageBox.information(self, "Không tìm thấy", "Không có URL nào có tham số để fuzz.")

    def start_fuzzing(self):
        fuzz_urls = [u.strip() for u in self.urls_to_fuzz_text.toPlainText().splitlines() if u.strip()]
        if not fuzz_urls:
            QMessageBox.warning(self, "Lỗi", "Vui lòng nhập ít nhất 1 URL để fuzz.")
            return

        payloads = [p.strip() for p in self.payload_input.toPlainText().splitlines() if p.strip()]
        if not payloads:
            payloads = [
            "' OR '1'='1-- ",
            "><script>alert(1)</script>",
            "../../../../etc/passwd",
            "../../../../etc/hostname",
            "action=delete",
            ]

        total = 0
        for url_to_fuzz in fuzz_urls:
            parsed = urlsplit(url_to_fuzz)
            if parsed.query:
                params = parse_qs(parsed.query)
                total += len(params) * len(payloads)
            else:
                total += len(payloads)

        progress = QProgressDialog("Đang fuzzing...", "Hủy", 0, total, self)
        progress.setWindowModality(Qt.WindowModal)
        progress.setMinimumDuration(0)
        progress.show()

        self.result_table.setRowCount(0)
        count = 0
        for url_to_fuzz in fuzz_urls:
            parsed = urlsplit(url_to_fuzz)
            if parsed.query:
                query_dict = parse_qs(parsed.query)
                for param in query_dict:
                    for payload in payloads:
                        if progress.wasCanceled():
                            break
                        new_params = query_dict.copy()
                        new_params[param] = payload
                        fuzzed_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                                              urlencode(new_params, doseq=True), parsed.fragment))
                        try:
                            start_time = time.time()
                            r = requests.get(fuzzed_url, timeout=5)
                            duration = round(time.time() - start_time, 3)
                            content = r.text
                            byte_len = len(content.encode())
                            word_count = len(content.split())
                            line_count = len(content.splitlines())

                            row = self.result_table.rowCount()
                            self.result_table.insertRow(row)
                            self.result_table.setItem(row, 0, QTableWidgetItem(payload))
                            self.result_table.setItem(row, 1, QTableWidgetItem(fuzzed_url))
                            self.result_table.setItem(row, 2, QTableWidgetItem(str(r.status_code)))
                            self.result_table.setItem(row, 3, QTableWidgetItem(str(byte_len)))
                            self.result_table.setItem(row, 4, QTableWidgetItem(str(word_count)))
                            self.result_table.setItem(row, 5, QTableWidgetItem(str(line_count)))
                            self.result_table.setItem(row, 6, QTableWidgetItem(str(duration)))
                        except:
                            pass
                        count += 1
                        progress.setValue(count)
            else:
                for payload in payloads:
                    if progress.wasCanceled():
                        break
                    fuzzed_url = f"{url_to_fuzz}{payload}"
                    try:
                        start_time = time.time()
                        r = requests.get(fuzzed_url, timeout=5)
                        duration = round(time.time() - start_time, 3)
                        content = r.text
                        byte_len = len(content.encode())
                        word_count = len(content.split())
                        line_count = len(content.splitlines())

                        row = self.result_table.rowCount()
                        self.result_table.insertRow(row)
                        self.result_table.setItem(row, 0, QTableWidgetItem(payload))
                        self.result_table.setItem(row, 1, QTableWidgetItem(fuzzed_url))
                        self.result_table.setItem(row, 2, QTableWidgetItem(str(r.status_code)))
                        self.result_table.setItem(row, 3, QTableWidgetItem(str(byte_len)))
                        self.result_table.setItem(row, 4, QTableWidgetItem(str(word_count)))
                        self.result_table.setItem(row, 5, QTableWidgetItem(str(line_count)))
                        self.result_table.setItem(row, 6, QTableWidgetItem(str(duration)))
                    except:
                        pass
                    count += 1
                    progress.setValue(count)

        progress.cancel()
        self.status_label.setText(f"Fuzz hoàn thành: {count}/{total} tác vụ")

    def show_context_menu(self, pos):
        item = self.url_list.itemAt(pos)
        if not item:
            return
        menu = QMenu()
        view_action = menu.addAction("🔍 Xem trang này")
        add_to_fuzz_action = menu.addAction("➕ Thêm vào Fuzz")
        action = menu.exec_(self.url_list.mapToGlobal(pos))
        if action == view_action:
            self.load_webview(item.text())
        elif action == add_to_fuzz_action:
            self.add_to_fuzz(item.text())

    def show_result_context_menu(self, pos):
        idx = self.result_table.indexAt(pos)
        if not idx.isValid() or idx.column() != 1:
            return
        menu = QMenu()
        view_action = menu.addAction("🔍 Xem trang web")
        action = menu.exec_(self.result_table.viewport().mapToGlobal(pos))
        if action == view_action:
            url = self.result_table.item(idx.row(), idx.column()).text()
            self.load_webview(url)

    def load_webview(self, url):
        self.browser.setUrl(QUrl(url))
        self.tabs.setCurrentIndex(1)

    def add_to_fuzz(self, url):
        if url not in self.urls_to_fuzz:
            self.urls_to_fuzz.append(url)
            self.urls_to_fuzz_text.append(url + "\n")
            QMessageBox.information(self, "Thành công", f"URL đã được thêm vào Fuzz: {url}")
        else:
            QMessageBox.warning(self, "Lỗi", "URL này đã có trong danh sách Fuzz.")

def main():
    app = QApplication(sys.argv)
    
    # Initialize and show the Packet Sniffer window
    sniffer_window = SnifferWindow()
    sniffer_window.show()
    
    # Initialize and show the Crawler/Fuzzer window
    crawler_window = CrawlerFuzzerApp()
    crawler_window.show()
    
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
