import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, QPushButton,
    QTextEdit, QLineEdit, QLabel
)
from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import sniff, IP, TCP, UDP, DNS

class PacketSnifferThread(QThread):
    packetCaptured = pyqtSignal(str)
    statusUpdate = pyqtSignal(str)

    def __init__(self, duration=None):
        super().__init__()
        self.duration = duration
        self._running = True

    def stop(self):
        self._running = False

    def run(self):
        self.statusUpdate.emit("🟢 Bắt đầu sniffing gói tin...")

        def packet_callback(packet):
            if not self._running:
                return False  # dừng sniff()
            if IP in packet:
                info = f"IP: {packet[IP].src} -> {packet[IP].dst}, Len: {len(packet)}"
                if TCP in packet:
                    info += f", TCP: {packet[TCP].sport} -> {packet[TCP].dport}"
                elif UDP in packet:
                    info += f", UDP: {packet[UDP].sport} -> {packet[UDP].dport}"
                elif DNS in packet:
                    info += f", DNS: {packet[DNS].summary()}"
                self.packetCaptured.emit(info)

        sniff(prn=packet_callback, store=0, timeout=self.duration, stop_filter=lambda x: not self._running)
        self.statusUpdate.emit("🔴 Đã dừng sniffing.")

class SnifferWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Packet Sniffer GUI')
        self.resize(900, 700)

        self.all_packets = []  # Lưu gói tin để tìm kiếm

        # Layout chính
        main_layout = QVBoxLayout()

        # Nút điều khiển
        control_layout = QHBoxLayout()
        self.startButton = QPushButton('Start Sniffing')
        self.stopButton = QPushButton('Stop Sniffing')
        self.stopButton.setEnabled(False)
        control_layout.addWidget(self.startButton)
        control_layout.addWidget(self.stopButton)

        # Log gói tin
        self.packetLog = QTextEdit()
        self.packetLog.setReadOnly(True)

        # Ô tìm kiếm
        search_layout = QHBoxLayout()
        self.searchInput = QLineEdit()
        self.searchInput.setPlaceholderText("Nhập IP hoặc từ khóa cần tìm...")
        self.searchButton = QPushButton("Search")
        search_layout.addWidget(QLabel("🔍 Tìm kiếm:"))
        search_layout.addWidget(self.searchInput)
        search_layout.addWidget(self.searchButton)

        # Kết quả tìm kiếm
        self.searchResult = QTextEdit()
        self.searchResult.setReadOnly(True)
        self.searchResult.setPlaceholderText("Kết quả tìm kiếm sẽ hiện ở đây...")

        # Ghép layout
        main_layout.addLayout(control_layout)
        main_layout.addLayout(search_layout)
        main_layout.addWidget(QLabel("📥 Log Gói Tin:"))
        main_layout.addWidget(self.packetLog)
        main_layout.addWidget(QLabel("📤 Kết Quả Tìm Kiếm:"))
        main_layout.addWidget(self.searchResult)

        # Thiết lập giao diện
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        # Kết nối tín hiệu & nút
        self.sniffer = None
        self.startButton.clicked.connect(self.startSniffing)
        self.stopButton.clicked.connect(self.stopSniffing)
        self.searchButton.clicked.connect(self.performSearch)

    def startSniffing(self):
       
        self.searchResult.clear()
        self.all_packets.clear()

        self.sniffer = PacketSnifferThread(duration=30)  # sniff trong 30 giây hoặc cho đến khi stop
        self.sniffer.packetCaptured.connect(self.logPacket)
        self.sniffer.statusUpdate.connect(self.logStatus)
        self.sniffer.start()

        self.startButton.setEnabled(False)
        self.stopButton.setEnabled(True)

    def stopSniffing(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer.wait()  # Chờ thread kết thúc
            self.logStatus("⏹ Sniffer đã được dừng.")

        self.startButton.setEnabled(True)
        self.stopButton.setEnabled(False)

    def logPacket(self, info):
        self.all_packets.append(info)
        self.packetLog.append(info)

    def logStatus(self, status):
        self.packetLog.append(f"<i>{status}</i>")

    def performSearch(self):
        keyword = self.searchInput.text().strip()
        self.searchResult.clear()

        if keyword:
            matches = [p for p in self.all_packets if keyword in p]
            if matches:
                self.searchResult.append("\n".join(matches))
            else:
                self.searchResult.setText("❌ Không tìm thấy gói tin phù hợp.")
        else:
            self.searchResult.setText("⚠️ Vui lòng nhập từ khóa để tìm kiếm.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = SnifferWindow()
    window.show()
    sys.exit(app.exec_())
