import sys
import os
import time
import random
from datetime import datetime
import json
import psutil
import numpy as np
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar, 
                             QSlider, QCheckBox, QComboBox, QSystemTrayIcon, QMenu, QAction, QMessageBox,
                             QFileDialog, QLineEdit, QDateEdit, QSpinBox, QGroupBox)
from tensorflow import keras
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal, QDate
from PyQt5.QtGui import QIcon, QColor, QFont, QPainter, QPen, QPixmap
from PyQt5.QtChart import QChart, QChartView, QLineSeries, QValueAxis



# Load local model at startup
LOCAL_MODEL_PATH = "final_model.keras"
try:
    local_model = keras.models.load_model(LOCAL_MODEL_PATH)
    print("Local model loaded successfully!")
except Exception as e:
    local_model = None
    print(f"Failed to load local model: {e}")

# AWS Lambda API endpoint (replace with actual URL)
threat_alert_val =0
# Malware detection thresholds
CPU_THRESHOLD = 70.0  # CPU usage percentage
MEMORY_THRESHOLD = 2_000_000_000  # Memory usage in bytes (2GB)

def predict_with_local_model(data):
    """Runs malware prediction using the local TensorFlow model."""
    if local_model is None:
        print("No local model available. Returning default score.")
        return 50  # Neutral risk score

    try:
        # Extract features & ensure correct shape
        input_vector = np.array([
            data['vector'], data['memory'], data['tx_packets'],
            data['rx_bytes'], data['swap'], data['rx_packets'],
            data['cpu_sys'], data['total_pro'], data['cpu_user'],
            data['max_pid'], data['tx_bytes'], data['malware']
        ], dtype=np.float32)

        # Fix shape: Reshape to (1, 10, 12)
        input_vector = np.tile(input_vector, (10, 1))  # Repeat 10 times
        input_vector = np.expand_dims(input_vector, axis=0)  # Add batch dimension (1, 10, 12)

        # Get prediction
        prediction = local_model.predict(input_vector)

        # Convert probability to risk score (0-100)
        risk_score = int(prediction[0][0] * 100)

        global threat_alert_val
        threat_alert_val = risk_score

        return risk_score
    except Exception as e:
        print(f"⚠️ Error in local model prediction: {e}")
        return 50  # Safe fallback score

def predict_risk_score(process_data):
    try:
        pid = process_data['pid']
        process = psutil.Process(pid)

        with process.oneshot():
            # CPU usage metrics
            cpu_user = process.cpu_times().user if hasattr(process.cpu_times(), 'user') else 0.0
            cpu_sys = process.cpu_times().system if hasattr(process.cpu_times(), 'system') else 0.0
            cpu_percent = process.cpu_percent(interval=0.1)  # Get CPU usage percentage
            
            # Memory usage metrics
            memory = process.memory_info().rss if hasattr(process, 'memory_info') else 0  # In bytes
            memory_mb = memory / 1_000_000  # Convert to MB
            
            # System-wide metrics (network, swap, total processes)
            net_io = psutil.net_io_counters()
            swap = psutil.swap_memory().used
            total_processes = len(psutil.pids())
            max_pid = max(psutil.pids()) if psutil.pids() else 0

            # Per-process network I/O (if accessible)
            try:
                io_counters = process.io_counters()
                tx_bytes = io_counters.bytes_sent
                rx_bytes = io_counters.bytes_recv
                tx_packets = io_counters.write_count
                rx_packets = io_counters.read_count
            except (psutil.AccessDenied, AttributeError):
                tx_bytes, rx_bytes, tx_packets, rx_packets = 0, 0, 0, 0

            # Malware indicator (default to non-malicious)
            is_malware = 0  
            reasons = []

            if cpu_percent > CPU_THRESHOLD:
                reasons.append(f"High CPU: {cpu_percent:.2f}%")
            if memory > MEMORY_THRESHOLD:
                reasons.append(f"High Memory: {memory_mb:.2f}MB")

            # Prepare data for ML model (ensuring correct feature structure)
            process_dict = {
                'vector': pid,  # PID as unique identifier
                'memory': memory,
                'tx_packets': tx_packets,
                'rx_bytes': rx_bytes,
                'swap': swap,
                'rx_packets': rx_packets,
                'cpu_sys': cpu_sys,
                'total_pro': total_processes,
                'cpu_user': cpu_user,
                'max_pid': max_pid,
                'tx_bytes': net_io.bytes_sent,  # Use system-level data
                'malware': is_malware  # Default to non-malware
            }

            # Debug: Print input data
            print("Input data to model:", process_dict)

            # Predict risk score using local ML model
            threat_activity_val = predict_with_local_model(process_dict)
            return threat_activity_val

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return 0  # Process not available
    except Exception as e:
        print(f"Error in predict_risk_score: {e}")
        return 0  # Safe fallback



class ProcessMonitorThread(QThread):
    update_signal = pyqtSignal(list)
    alert_signal = pyqtSignal(dict)
    
    def __init__(self, sensitivity=50):
        super().__init__()
        self.running = True
        self.sensitivity = sensitivity
        self.auto_terminate = False
        
    def run(self):
        while self.running:
            process_list = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
                try:
                    process_info = proc.info
                    risk_score = predict_risk_score(process_info)
                    status = "Normal"
                    
                    # Adjust risk threshold based on sensitivity
                    threshold = 100 - self.sensitivity
                    
                    if risk_score > 80:
                        status = "High Risk"
                        # Send alert for high risk processes
                        if risk_score > threshold:
                            self.alert_signal.emit({
                                'pid': process_info['pid'],
                                'name': process_info['name'],
                                'risk_score': risk_score,
                                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            })
                            
                            # Auto-terminate if enabled
                            if self.auto_terminate and risk_score > 90:
                                try:
                                    p = psutil.Process(process_info['pid'])
                                    p.terminate()
                                    status = "Terminated"
                                except:
                                    pass
                    elif risk_score > 50:
                        status = "Medium Risk"
                    
                    process_list.append({
                        'pid': process_info['pid'],
                        'name': process_info['name'],
                        'cpu_percent': process_info['cpu_percent'],
                        'memory_percent': process_info['memory_percent'],
                        'risk_score': risk_score,
                        'status': status
                    })
                except:
                    continue
            
            # Sort by risk score (highest first)
            process_list.sort(key=lambda x: x['risk_score'], reverse=True)
            
            # Emit signal with the updated process list
            self.update_signal.emit(process_list)
            
            # Sleep to reduce CPU usage
            time.sleep(2)
    
    def set_sensitivity(self, value):
        self.sensitivity = value
        
    def set_auto_terminate(self, enabled):
        self.auto_terminate = enabled
        
    def stop(self):
        self.running = False
        self.wait()

class SystemMetricsThread(QThread):
    update_signal = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.running = True
        
    def run(self):
        while self.running:
            # Get system-wide metrics
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Get network I/O stats
            net_io = psutil.net_io_counters()
            net_sent = net_io.bytes_sent
            net_recv = net_io.bytes_recv
            
            # Generate a synthetic threat activity level (replace with real data)
            threat_activity = threat_alert_val
            
            metrics = {
                'cpu_percent': cpu_percent,
                'memory_percent': memory_percent,
                'net_sent': net_sent,
                'net_recv': net_recv,
                'threat_activity': threat_activity
            }
            
            self.update_signal.emit(metrics)
            time.sleep(1)
    
    def stop(self):
        self.running = False
        self.wait()

class ThreatAlert(QWidget):
    def __init__(self, threat_info, parent=None):
        super().__init__(parent)
        self.threat_info = threat_info
        self.setWindowTitle("Threat Detected")
        self.setWindowFlag(Qt.WindowStaysOnTopHint)
        self.setMinimumWidth(400)
        self.setStyleSheet("background-color: white; border: 1px solid #ddd;")
        self.init_ui()
       
    def init_ui(self):
        layout = QVBoxLayout()
       
        # Header
        header = QLabel("Threat Alert")
        header.setStyleSheet("font-size: 16pt; font-weight: bold; color: red;")
        layout.addWidget(header)
       
        # Threat details
        details_layout = QVBoxLayout()
        details_layout.addWidget(QLabel(f"<b>Process:</b> {self.threat_info['name']} (PID: {self.threat_info['pid']})"))
        details_layout.addWidget(QLabel(f"<b>Risk Score:</b> {self.threat_info['risk_score']}"))
        details_layout.addWidget(QLabel(f"<b>Detected at:</b> {self.threat_info['timestamp']}"))
        details_layout.addWidget(QLabel("<b>Recommendation:</b> Terminate process immediately"))
       
        details_group = QGroupBox("Threat Details")
        details_group.setLayout(details_layout)
        layout.addWidget(details_group)
       
        # Action buttons
        button_layout = QHBoxLayout()
       
        terminate_btn = QPushButton("Terminate")
        terminate_btn.setStyleSheet("background-color: #d9534f; color: white; padding: 8px;")
        terminate_btn.clicked.connect(self.terminate_process)
       
        quarantine_btn = QPushButton("Quarantine")
        quarantine_btn.setStyleSheet("background-color: #f0ad4e; color: white; padding: 8px;")
        quarantine_btn.clicked.connect(self.quarantine_process)
       
        ignore_btn = QPushButton("Ignore")
        ignore_btn.setStyleSheet("background-color: #5bc0de; color: white; padding: 8px;")
        ignore_btn.clicked.connect(self.ignore_process)
       
        whitelist_btn = QPushButton("Whitelist")
        whitelist_btn.setStyleSheet("background-color: #5cb85c; color: white; padding: 8px;")
        whitelist_btn.clicked.connect(self.whitelist_process)
       
        button_layout.addWidget(terminate_btn)
        button_layout.addWidget(quarantine_btn)
        button_layout.addWidget(ignore_btn)
        button_layout.addWidget(whitelist_btn)
       
        layout.addLayout(button_layout)
        self.setLayout(layout)
   
    def terminate_process(self):
        try:
            p = psutil.Process(self.threat_info['pid'])
            p.terminate()
            QMessageBox.information(self, "Success", f"Process {self.threat_info['name']} has been terminated.")
        except:
            QMessageBox.warning(self, "Error", f"Failed to terminate process {self.threat_info['name']}.")
        self.close()
   
    def quarantine_process(self):
        # In a real app, this would involve more complex logic
        QMessageBox.information(self, "Quarantine", f"Process {self.threat_info['name']} has been quarantined.")
        self.close()
   
    def ignore_process(self):
        self.close()
   
    def whitelist_process(self):
        # Add to whitelist (in a real app, this would be saved to a file)
        QMessageBox.information(self, "Whitelist", f"Process {self.threat_info['name']} has been added to whitelist.")
        self.close()


class SecurityMonitor: 
    def __init__(self):
        # Initialize your UI components
        self.last_threat = QLabel("Last Threat: None")
        self.tray_icon = QSystemTrayIcon()
        # Other initialization code...
    
    def process_ml_result(self, result, process_info):
        # Extract the prediction and probabilities
        predicted_class = result["predicted_class"]
        probabilities = result["probabilities"]
        malware_probability = probabilities.get("Class 1", 0)
        
        # Format timestamp
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Log the scan regardless of result
        self.add_log_entry(
            current_time,
            process_info['name'],
            process_info['pid'],
            f"{malware_probability:.2%}",
            "Malware" if predicted_class == 1 else "Safe"
        )
        
        # Only show threat alert if predicted as malware (Class 1)
        if predicted_class == 1:
            # Create threat info
            threat_info = {
                'name': process_info['name'],
                'pid': process_info['pid'],
                'risk_score': f"{malware_probability:.2%}",
                'timestamp': current_time
            }
            
            # Show the threat alert
            self.show_threat_alert(threat_info)
    
    def show_threat_alert(self, threat_info):
        # Update last threat detected
        self.last_threat.setText(f"Last Threat: {threat_info['name']} at {threat_info['timestamp']}")
       
        # Add to logs
        self.add_log_entry(
            threat_info['timestamp'],
            threat_info['name'],
            threat_info['pid'],
            threat_info['risk_score'],
            "Detected"
        )
       
        # Show alert dialog
        self.alert_dialog = ThreatAlert(threat_info)
        self.alert_dialog.show()
       
        # Show tray notification
        self.tray_icon.showMessage(
            "Threat Detected",
            f"High risk process detected: {threat_info['name']} (Score: {threat_info['risk_score']})",
            QSystemTrayIcon.Critical,
            5000
        )
    
    def add_log_entry(self, timestamp, process_name, process_id, risk_score, status):
        # Add entry to your log widget/database
        # Implementation depends on how you're storing logs
        pass

    def scan_process(self, process_info):
        # This would be the method that triggers your ML model
        # and gets the result back
        
        # Example of calling ML model (simulated)
        result = self.run_ml_model(process_info)
        
        # Process the result
        self.process_ml_result(result, process_info)
    
    def run_ml_model(self, process_info):
        # This would be your actual ML model integration
        # For now, just returning a mock result
        return {
            "predicted_class": 0,  # 0 = safe, 1 = malware
            "probabilities": {
                "Class 0": 0.779741644859314,
                "Class 1": 0.22025835514068604
            }
        }

class LogEntry:
    def __init__(self, timestamp, process_name, pid, risk_score, action_taken):
        self.timestamp = timestamp
        self.process_name = process_name
        self.pid = pid
        self.risk_score = risk_score
        self.action_taken = action_taken
    
    def to_dict(self):
        return {
            'timestamp': self.timestamp,
            'process_name': self.process_name,
            'pid': self.pid,
            'risk_score': self.risk_score,
            'action_taken': self.action_taken
        }



class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI Malware Detection")
        self.setMinimumSize(1000, 700)
        
        # Initialize central widget and tab layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(self.central_widget)
        
        # Status bar
        self.status_layout = QHBoxLayout()
        self.protection_status = QLabel("Protection: Active")
        self.protection_status.setStyleSheet("color: green; font-weight: bold;")
        self.last_threat = QLabel("Last Threat: None")
        self.status_layout.addWidget(self.protection_status)
        self.status_layout.addWidget(self.last_threat)
        self.status_layout.addStretch()
        main_layout.addLayout(self.status_layout)
        
        # Tabs
        self.tabs = QTabWidget()
        self.dashboard_tab = QWidget()
        self.logs_tab = QWidget()
        self.settings_tab = QWidget()
        
        self.tabs.addTab(self.dashboard_tab, "Dashboard")
        self.tabs.addTab(self.logs_tab, "Logs & Reports")
        self.tabs.addTab(self.settings_tab, "Settings")
        
        main_layout.addWidget(self.tabs)
        
        # Initialize log storage
        self.logs = []
        
        # Setup each tab
        self.setup_dashboard()
        self.setup_logs()
        self.setup_settings()
        
        # Setup system tray
        self.setup_system_tray()
        
        # Start monitoring threads
        self.start_monitoring()
        
    def setup_dashboard(self):
        layout = QVBoxLayout(self.dashboard_tab)
        
        # Process list section
        process_group = QGroupBox("Process Monitor")
        process_layout = QVBoxLayout()
        
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(6)
        self.process_table.setHorizontalHeaderLabels(["PID", "Name", "CPU%", "RAM%", "Risk", "Status"])
        self.process_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        process_layout.addWidget(self.process_table)
        process_group.setLayout(process_layout)
        layout.addWidget(process_group)
        
        # Charts section
        charts_group = QGroupBox("System Metrics")
        charts_layout = QHBoxLayout()
        
        # CPU chart
        self.cpu_chart = QChart()
        self.cpu_chart.setTitle("CPU Usage")
        self.cpu_series = QLineSeries()
        self.cpu_chart.addSeries(self.cpu_series)
        self.cpu_chart.createDefaultAxes()
        self.cpu_chart.axes(Qt.Horizontal)[0].setRange(0, 60)
        self.cpu_chart.axes(Qt.Vertical)[0].setRange(0, 100)
        self.cpu_chart_view = QChartView(self.cpu_chart)
        
        # RAM chart
        self.ram_chart = QChart()
        self.ram_chart.setTitle("Memory Usage")
        self.ram_series = QLineSeries()
        self.ram_chart.addSeries(self.ram_series)
        self.ram_chart.createDefaultAxes()
        self.ram_chart.axes(Qt.Horizontal)[0].setRange(0, 60)
        self.ram_chart.axes(Qt.Vertical)[0].setRange(0, 100)
        self.ram_chart_view = QChartView(self.ram_chart)
        
        # Threat Activity chart
        self.threat_chart = QChart()
        self.threat_chart.setTitle("Threat Activity")
        self.threat_series = QLineSeries()
        self.threat_chart.addSeries(self.threat_series)
        self.threat_chart.createDefaultAxes()
        self.threat_chart.axes(Qt.Horizontal)[0].setRange(0, 60)
        self.threat_chart.axes(Qt.Vertical)[0].setRange(0, 100)
        self.threat_chart_view = QChartView(self.threat_chart)
        
        # Set chart backgrounds to white for light mode
        self.cpu_chart.setBackgroundBrush(Qt.white)
        self.ram_chart.setBackgroundBrush(Qt.white)
        self.threat_chart.setBackgroundBrush(Qt.white)
        
        # Add charts to layout
        charts_layout.addWidget(self.cpu_chart_view)
        charts_layout.addWidget(self.ram_chart_view)
        charts_layout.addWidget(self.threat_chart_view)
        
        charts_group.setLayout(charts_layout)
        layout.addWidget(charts_group)
        
        # Initialize data for charts
        self.cpu_data = []
        self.ram_data = []
        self.threat_data = []
        self.time_points = list(range(60))
    
    def setup_logs(self):
        layout = QVBoxLayout(self.logs_tab)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        
        filter_layout.addWidget(QLabel("Search:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter by process name...")
        self.search_input.textChanged.connect(self.filter_logs)
        filter_layout.addWidget(self.search_input)
        
        filter_layout.addWidget(QLabel("Risk Level:"))
        self.risk_filter = QComboBox()
        self.risk_filter.addItems(["All", "High Risk", "Medium Risk", "Low Risk"])
        self.risk_filter.currentTextChanged.connect(self.filter_logs)
        filter_layout.addWidget(self.risk_filter)
        
        filter_layout.addWidget(QLabel("From:"))
        self.date_from = QDateEdit()
        self.date_from.setDate(QDate.currentDate().addDays(-7))
        self.date_from.dateChanged.connect(self.filter_logs)
        filter_layout.addWidget(self.date_from)
        
        filter_layout.addWidget(QLabel("To:"))
        self.date_to = QDateEdit()
        self.date_to.setDate(QDate.currentDate())
        self.date_to.dateChanged.connect(self.filter_logs)
        filter_layout.addWidget(self.date_to)
        
        layout.addLayout(filter_layout)
        
        # Log table
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(5)
        self.log_table.setHorizontalHeaderLabels(["Timestamp", "Process Name", "PID", "Risk Score", "Action Taken"])
        self.log_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.log_table)
        
        # Export buttons
        export_layout = QHBoxLayout()
        
        export_csv_btn = QPushButton("Export as CSV")
        export_csv_btn.clicked.connect(lambda: self.export_logs("csv"))
        
        export_json_btn = QPushButton("Export as JSON")
        export_json_btn.clicked.connect(lambda: self.export_logs("json"))
        
        export_pdf_btn = QPushButton("Export as PDF")
        export_pdf_btn.clicked.connect(lambda: self.export_logs("pdf"))
        
        export_layout.addWidget(export_csv_btn)
        export_layout.addWidget(export_json_btn)
        export_layout.addWidget(export_pdf_btn)
        export_layout.addStretch()
        
        layout.addLayout(export_layout)
    
    def setup_settings(self):
        layout = QVBoxLayout(self.settings_tab)
        
        # Detection settings
        detection_group = QGroupBox("Detection Settings")
        detection_layout = QVBoxLayout()
        
        # Sensitivity slider
        sensitivity_layout = QHBoxLayout()
        sensitivity_layout.addWidget(QLabel("Detection Sensitivity:"))
        self.sensitivity_label = QLabel("50%")
        self.sensitivity_slider = QSlider(Qt.Horizontal)
        self.sensitivity_slider.setMinimum(1)
        self.sensitivity_slider.setMaximum(100)
        self.sensitivity_slider.setValue(50)
        self.sensitivity_slider.valueChanged.connect(self.update_sensitivity)
        sensitivity_layout.addWidget(self.sensitivity_slider)
        sensitivity_layout.addWidget(self.sensitivity_label)
        detection_layout.addLayout(sensitivity_layout)
        
        # Auto actions
        self.auto_terminate = QCheckBox("Auto-Terminate High-Risk Processes")
        self.auto_terminate.stateChanged.connect(self.update_auto_terminate)
        detection_layout.addWidget(self.auto_terminate)
        
        detection_group.setLayout(detection_layout)
        layout.addWidget(detection_group)
        
        # Startup settings
        startup_group = QGroupBox("Startup Settings")
        startup_layout = QVBoxLayout()
        
        self.run_on_boot = QCheckBox("Run on System Startup")
        startup_layout.addWidget(self.run_on_boot)
        
        self.minimize_to_tray = QCheckBox("Minimize to System Tray on Startup")
        startup_layout.addWidget(self.minimize_to_tray)
        
        startup_group.setLayout(startup_layout)
        layout.addWidget(startup_group)
        
        # Updates
        update_group = QGroupBox("Updates")
        update_layout = QVBoxLayout()
        
        update_layout.addWidget(QLabel("Model Update Frequency:"))
        self.update_interval = QComboBox()
        self.update_interval.addItems(["Manual", "Daily", "Weekly", "Monthly"])
        update_layout.addWidget(self.update_interval)
        
        check_updates_btn = QPushButton("Check for Updates")
        update_layout.addWidget(check_updates_btn)
        
        update_group.setLayout(update_layout)
        layout.addWidget(update_group)
        
        # Advanced settings
        advanced_group = QGroupBox("Advanced Settings")
        advanced_layout = QVBoxLayout()
        
        self.offline_mode = QCheckBox("Enable Offline Mode")
        advanced_layout.addWidget(self.offline_mode)
        
        clear_logs_btn = QPushButton("Clear All Logs")
        clear_logs_btn.clicked.connect(self.clear_logs)
        advanced_layout.addWidget(clear_logs_btn)
        
        advanced_group.setLayout(advanced_layout)
        layout.addWidget(advanced_group)
        
        # Add stretch to push everything to the top
        layout.addStretch()
    
    def setup_system_tray(self):
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon.fromTheme("security-high"))
        
        # Create tray menu
        tray_menu = QMenu()
        
        show_action = QAction("Show", self)
        show_action.triggered.connect(self.show)
        
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.close_app)
        
        tray_menu.addAction(show_action)
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.tray_activated)
        
        # Show the tray icon
        self.tray_icon.show()
        
    def tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()
            self.activateWindow()
    
    def closeEvent(self, event):
        if self.minimize_to_tray.isChecked():
            event.ignore()
            self.hide()
            self.tray_icon.showMessage("AI Malware Detection", "Application is still running in the background.", QSystemTrayIcon.Information, 2000)
        else:
            self.close_app()
    
    def close_app(self):
        # Stop monitoring threads
        self.process_thread.stop()
        self.metrics_thread.stop()
        QApplication.quit()
    
    def start_monitoring(self):
        # Start process monitoring thread
        self.process_thread = ProcessMonitorThread()
        self.process_thread.update_signal.connect(self.update_process_list)
        self.process_thread.alert_signal.connect(self.show_threat_alert)
        self.process_thread.start()
        
        # Start system metrics thread
        self.metrics_thread = SystemMetricsThread()
        self.metrics_thread.update_signal.connect(self.update_metrics)
        self.metrics_thread.start()
    
    def update_process_list(self, process_list):
        self.process_table.setRowCount(len(process_list))
        
        for row, process in enumerate(process_list):
            # PID
            pid_item = QTableWidgetItem(str(process['pid']))
            self.process_table.setItem(row, 0, pid_item)
            
            # Name
            name_item = QTableWidgetItem(process['name'])
            self.process_table.setItem(row, 1, name_item)
            
            # CPU%
            cpu_item = QTableWidgetItem(f"{process['cpu_percent']:.1f}%")
            self.process_table.setItem(row, 2, cpu_item)
            
            # RAM%
            ram_item = QTableWidgetItem(f"{process['memory_percent']:.1f}%")
            self.process_table.setItem(row, 3, ram_item)
            
            # Risk Score
            risk_item = QTableWidgetItem(str(process['risk_score']))
            
            # Color coding based on risk
            if process['risk_score'] > 80:
                risk_item.setBackground(QColor(255, 200, 200))  # Light red
            elif process['risk_score'] > 50:
                risk_item.setBackground(QColor(255, 235, 156))  # Light yellow
            
            self.process_table.setItem(row, 4, risk_item)
            
            # Status
            status_item = QTableWidgetItem(process['status'])
            if process['status'] == "High Risk":
                status_item.setForeground(QColor(255, 0, 0))  # Red
            elif process['status'] == "Medium Risk":
                status_item.setForeground(QColor(255, 165, 0))  # Orange
            elif process['status'] == "Terminated":
                status_item.setForeground(QColor(128, 0, 128))  # Purple
            
            self.process_table.setItem(row, 5, status_item)
    
    def update_metrics(self, metrics):
        # Update chart data
        self.cpu_data.append(metrics['cpu_percent'])
        self.ram_data.append(metrics['memory_percent'])
        self.threat_data.append(metrics['threat_activity'])
        
        # Keep only the last 60 data points
        if len(self.cpu_data) > 60:
            self.cpu_data.pop(0)
            self.ram_data.pop(0)
            self.threat_data.pop(0)
        
        # Update the series data
        self.cpu_series.clear()
        self.ram_series.clear()
        self.threat_series.clear()
        
        for i, (cpu, ram, threat) in enumerate(zip(self.cpu_data, self.ram_data, self.threat_data)):
            self.cpu_series.append(i, cpu)
            self.ram_series.append(i, ram)
            self.threat_series.append(i, threat)
    
    def show_threat_alert(self, threat_info):
        # Update last threat detected
        self.last_threat.setText(f"Last Threat: {threat_info['name']} at {threat_info['timestamp']}")
        
        # Add to logs
        self.add_log_entry(
            threat_info['timestamp'],
            threat_info['name'],
            threat_info['pid'],
            threat_info['risk_score'],
            "Detected"
        )
        
        # Show alert dialog
        self.alert_dialog = ThreatAlert(threat_info)
        self.alert_dialog.show()
        
        # Show tray notification
        self.tray_icon.showMessage(
            "Threat Detected", 
            f"High risk process detected: {threat_info['name']} (Score: {threat_info['risk_score']})",
            QSystemTrayIcon.Critical,
            5000
        )
    
    def add_log_entry(self, timestamp, process_name, pid, risk_score, action_taken):
        log_entry = LogEntry(timestamp, process_name, pid, risk_score, action_taken)
        self.logs.append(log_entry)
        self.update_log_table()
    
    def update_log_table(self):
        self.log_table.setRowCount(len(self.logs))
        
        for row, log in enumerate(self.logs):
            # Timestamp
            timestamp_item = QTableWidgetItem(log.timestamp)
            self.log_table.setItem(row, 0, timestamp_item)
            
            # Process Name
            name_item = QTableWidgetItem(log.process_name)
            self.log_table.setItem(row, 1, name_item)
            
            # PID
            pid_item = QTableWidgetItem(str(log.pid))
            self.log_table.setItem(row, 2, pid_item)
            
            # Risk Score
            risk_item = QTableWidgetItem(str(log.risk_score))
            
            # Color coding based on risk
            if log.risk_score > 80:
                risk_item.setBackground(QColor(255, 200, 200))  # Light red
            elif log.risk_score > 50:
                risk_item.setBackground(QColor(255, 235, 156))  # Light yellow
            
            self.log_table.setItem(row, 3, risk_item)
            
            # Action Taken
            action_item = QTableWidgetItem(log.action_taken)
            self.log_table.setItem(row, 4, action_item)
    
    def filter_logs(self):
        search_text = self.search_input.text().lower()
        risk_filter = self.risk_filter.currentText()
        date_from = self.date_from.date().toString("yyyy-MM-dd")
        date_to = self.date_to.date().toString("yyyy-MM-dd")
        
        filtered_logs = []
        
        for log in self.logs:
            # Check if log matches search text
            if search_text and search_text not in log.process_name.lower():
                continue
            
            # Check if log matches risk filter
            if risk_filter != "All":
                if risk_filter == "High Risk" and log.risk_score <= 80:
                    continue
                elif risk_filter == "Medium Risk" and (log.risk_score <= 50 or log.risk_score > 80):
                    continue
                elif risk_filter == "Low Risk" and log.risk_score > 50:
                    continue
            
            # Check if log is within date range
            log_date = log.timestamp.split()[0]
            if log_date < date_from or log_date > date_to:
                continue
            
            filtered_logs.append(log)
        
        # Update table with filtered logs
        self.log_table.setRowCount(len(filtered_logs))
        
        for row, log in enumerate(filtered_logs):
            # Timestamp
            timestamp_item = QTableWidgetItem(log.timestamp)
            self.log_table.setItem(row, 0, timestamp_item)
            
            # Process Name
            name_item = QTableWidgetItem(log.process_name)
            self.log_table.setItem(row, 1, name_item)
            
            # PID
            pid_item = QTableWidgetItem(str(log.pid))
            self.log_table.setItem(row, 2, pid_item)
            
            # Risk Score
            risk_item = QTableWidgetItem(str(log.risk_score))
            
            # Color coding based on risk
            if log.risk_score > 80:
                risk_item.setBackground(QColor(255, 200, 200))  # Light red
            elif log.risk_score > 50:
                risk_item.setBackground(QColor(255, 235, 156))  # Light yellow
            
            self.log_table.setItem(row, 3, risk_item)
            
            # Action Taken
            action_item = QTableWidgetItem(log.action_taken)
            self.log_table.setItem(row, 4, action_item)
    
    def export_logs(self, format_type):
        if not self.logs:
            QMessageBox.warning(self, "Export Error", "No logs to export.")
            return
        
        file_dialog = QFileDialog(self)
        file_dialog.setAcceptMode(QFileDialog.AcceptSave)
        
        if format_type == "csv":
            file_dialog.setNameFilter("CSV Files (*.csv)")
            file_dialog.setDefaultSuffix("csv")
            if file_dialog.exec_():
                file_path = file_dialog.selectedFiles()[0]
                try:
                    with open(file_path, 'w') as f:
                        f.write("Timestamp,Process Name,PID,Risk Score,Action Taken\n")
                        for log in self.logs:
                            f.write(f"{log.timestamp},{log.process_name},{log.pid},{log.risk_score},{log.action_taken}\n")
                    QMessageBox.information(self, "Export Successful", f"Logs exported to {file_path}")
                except Exception as e:
                    QMessageBox.critical(self, "Export Error", f"Failed to export logs: {str(e)}")
                
        elif format_type == "json":
            file_dialog.setNameFilter("JSON Files (*.json)")
            file_dialog.setDefaultSuffix("json")
            if file_dialog.exec_():
                file_path = file_dialog.selectedFiles()[0]
                try:
                    with open(file_path, 'w') as f:
                        json.dump([log.to_dict() for log in self.logs], f, indent=4)
                    QMessageBox.information(self, "Export Successful", f"Logs exported to {file_path}")
                except Exception as e:
                    QMessageBox.critical(self, "Export Error", f"Failed to export logs: {str(e)}")
        
        elif format_type == "pdf":
            file_dialog.setNameFilter("PDF Files (*.pdf)")
            file_dialog.setDefaultSuffix("pdf")
            if file_dialog.exec_():
                file_path = file_dialog.selectedFiles()[0]
                try:
                    # In a real app, you would use a PDF library like reportlab
                    # For now, we'll just show a message
                    QMessageBox.information(self, "Export Notice", 
                                          "PDF export would be implemented with a library like reportlab.\n"
                                          f"Your logs would be exported to {file_path}")
                except Exception as e:
                    QMessageBox.critical(self, "Export Error", f"Failed to export logs: {str(e)}")
    
    def update_sensitivity(self, value):
        self.sensitivity_label.setText(f"{value}%")
        self.process_thread.set_sensitivity(value)
    
    def update_auto_terminate(self, state):
        self.process_thread.set_auto_terminate(state == Qt.Checked)
    
    def clear_logs(self):
        reply = QMessageBox.question(self, "Clear Logs", 
                                    "Are you sure you want to clear all logs?",
                                    QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.logs.clear()
            self.update_log_table()
            QMessageBox.information(self, "Logs Cleared", "All logs have been cleared.")

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")  # Use Fusion style for a clean, modern look
    
    # Set application-wide stylesheet for light mode
    app.setStyleSheet("""
        QMainWindow, QWidget {
            background-color: #f8f9fa;
        }
        QTabWidget::pane {
            border: 1px solid #ddd;
            background-color: white;
        }
        QTabBar::tab {
            background-color: #e9ecef;
            border: 1px solid #ddd;
            padding: 8px 16px;
            margin-right: 2px;
        }
        QTabBar::tab:selected {
            background-color: white;
            border-bottom-color: white;
        }
        QGroupBox {
            border: 1px solid #ddd;
            border-radius: 3px;
            margin-top: 20px;
            font-weight: bold;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px;
        }
        QPushButton {
            background-color: #007bff;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
        }
        QPushButton:hover {
            background-color: #0069d9;
        }
        QPushButton:pressed {
            background-color: #0062cc;
        }
        QTableWidget {
            gridline-color: #ddd;
            selection-background-color: #007bff;
            selection-color: white;
        }
        QTableWidget QHeaderView::section {
            background-color: #e9ecef;
            padding: 4px;
            border: 1px solid #ddd;
            font-weight: bold;
        }
        QSlider::groove:horizontal {
            border: 1px solid #ddd;
            height: 8px;
            background: #e9ecef;
            margin: 2px 0;
            border-radius: 4px;
        }
        QSlider::handle:horizontal {
            background: #007bff;
            border: 1px solid #007bff;
            width: 18px;
            margin: -8px 0;
            border-radius: 9px;
        }
        QCheckBox {
            spacing: 8px;
        }
        QCheckBox::indicator {
            width: 18px;
            height: 18px;
        }
        QLineEdit, QComboBox, QDateEdit, QSpinBox {
            border: 1px solid #ddd;
            padding: 6px;
            border-radius: 4px;
            background-color: white;
        }
    """)
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()