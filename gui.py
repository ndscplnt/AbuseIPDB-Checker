import sys
import os
import re
import abuseipdb as ab
import configparser
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QGridLayout, QInputDialog, QMessageBox, QCheckBox, QHBoxLayout, QLabel, QTextEdit, QPushButton, QFileDialog, QDialog, QFormLayout, QComboBox, QLineEdit, QFileDialog
from PyQt6.QtCore import pyqtSlot, Qt, QSize, QDateTime, QTimer
from PyQt6.QtGui import QColor, QPalette, QPixmap, QIcon

class ConfigDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowIcon(QIcon('icon/icon.ico'))
        self.setWindowTitle("Configure GUI Settings")
        self.setGeometry(200, 200, 400, 200)
        layout = QFormLayout(self)
        self.setStyleSheet("""
            QDialog {
                background-color: #2E2E2E;
                color: white;
            }
            QLabel {
                color: white;
                font-weight: bold;
            }
            QLineEdit, QComboBox {
                background-color: #444444;
                color: white;
                border-radius: 5px;
                padding: 5px;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QComboBox {
                padding: 5px;
            }
                           
        """)

        self.save_folder_input = QLineEdit(self)
        self.save_folder_input.setText(parent.save_folder) 
        layout.addRow("Save Folder:", self.save_folder_input)

        select_folder_button = QPushButton("Select Folder", self)
        select_folder_button.clicked.connect(self.on_select_folder)
        layout.addWidget(select_folder_button)

        self.file_type_combo = QComboBox(self)
        self.file_type_combo.addItem("Excel")
        self.file_type_combo.addItem("CSV")
        self.file_type_combo.setCurrentText(parent.file_type)
        layout.addRow("File Type:", self.file_type_combo)

        save_button = QPushButton("Save Settings", self)
        save_button.clicked.connect(self.on_save)
        layout.addWidget(save_button)

    def on_select_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder", self.save_folder_input.text())
        if folder:
            self.save_folder_input.setText(folder)

    def on_save(self):
        parent = self.parent()
        parent.save_folder = self.save_folder_input.text()
        parent.file_type = self.file_type_combo.currentText()
        parent.default_extension = "xlsx" if parent.file_type == "Excel" else "csv"

        parent.save_config() 
        self.accept()  

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.load_config()
        self.setWindowIcon(QIcon('icon/icon.ico'))
        self.counter = 1 

    def initUI(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        palette = self.palette()
        palette.setColor(QPalette.ColorRole.Window, QColor(46, 46, 46))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))        
        self.setPalette(palette)
        
        self.setWindowTitle('AbuseIPDB Checker')
        self.setGeometry(300, 300, 500, 400)
         
        logo_label = QLabel(self)
        logo_pixmap = QPixmap('icon/abuseipdb.png') 
        logo_label.setPixmap(logo_pixmap.scaled(400, 200, aspectRatioMode=Qt.AspectRatioMode.KeepAspectRatio)) 
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)  
        layout.addWidget(logo_label)
        
        top_layout = QHBoxLayout()
        top_layout.setAlignment(Qt.AlignmentFlag.AlignRight)  
        self.config_button = QPushButton()
        self.config_button.setIcon(QIcon('icon/settings.png'))  
        self.config_button.setIconSize(QSize(30, 40))  
        self.config_button.setStyleSheet("background-color: transparent; border: none;")
        self.config_button.clicked.connect(self.on_configure)
        top_layout.addWidget(self.config_button)

        layout.addLayout(top_layout)  
        
        input_group_layout = QVBoxLayout()
        self.input_area = QTextEdit()
        self.input_area.setPlaceholderText("Enter IP, subnet or IPs (one per line) here")
        self.input_area.setStyleSheet("background-color: #2c3e50; color: white; font-size: 14px; border-radius: 8px; padding: 10px;")
        input_group_layout.addWidget(self.input_area)
        layout.addLayout(input_group_layout)

        load_file_button = QPushButton("Load from File")
        load_file_button.setStyleSheet("background-color: #5D6D7E; color: white; border-radius: 8px; padding: 10px; font-size: 14px;")
        load_file_button.clicked.connect(self.on_load_file)
        layout.addWidget(load_file_button)
        
        hlayout = QGridLayout()
        self.status_label = QLabel("Status: Ready")
        self.status_label.setStyleSheet("color: #95a5a6; font-size: 14px; padding: 5;")
        hlayout.addWidget(self.status_label, 0, 0,Qt.AlignmentFlag.AlignLeft)

        self.export_checkbox = QCheckBox("Export to file")
        self.export_checkbox.setStyleSheet("color: #95a5a6; font-size: 14px; padding: 5px;")
        hlayout.addWidget(self.export_checkbox, 0, 1, Qt.AlignmentFlag.AlignRight)

        layout.addLayout(hlayout)  

        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setStyleSheet("background-color: #34495e; color: white; font-size: 14px; border-radius: 8px; padding: 10px;")
        self.output_text.setFixedHeight(200)
        layout.addWidget(self.output_text)
        
        clear_button = QPushButton("Clear Output")
        clear_button.setStyleSheet("background-color: #E74C3C; color: white; border-radius: 8px; padding: 10px; font-size: 14px;")
        clear_button.clicked.connect(self.on_clear_output)
        layout.addWidget(clear_button)
        
        run_button = QPushButton("Run")
        run_button.setStyleSheet("background-color: #1ABC9C; color: white; border-radius: 8px; padding: 10px; font-size: 14px;")
        run_button.clicked.connect(self.on_run)
        layout.addWidget(run_button)

    @pyqtSlot()
    def on_clear_output(self):
        self.output_text.clear()
        self.status_label.setText("Status: Cleared")
        QTimer.singleShot(1000, lambda: self.status_label.setText("Status: Ready"))  

    @pyqtSlot()
    def on_load_file(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Open IP List File", "", "Text Files (*.txt);;All Files (*)", options=options)
        if file_name:
            try:
                with open(file_name, 'r') as file:
                    file_content = file.read()
                    self.input_area.setText(file_content.strip())
            except Exception as e:
                self.output_text.append(f"Error reading file: {e}")
    @pyqtSlot()
    def on_run(self):
        if not self.input_area.toPlainText().strip():
            self.status_label.setText("No input provided")
            return
        self.status_label.setText("Status: Loading...")  
        QApplication.processEvents()  
        input_text = self.input_area.toPlainText().strip()  
        ip_list = []
        for line in input_text.splitlines():  
            ips = line.strip().split()  
            ip_list.extend(ips)  
        results = [f"Run: #{self.counter}\n"]
        self.counter += 1
        date = QDateTime.currentDateTime().toString('yyyy-MM-dd-hh-mm-ss')
        try:
            if len(ip_list) > 1:
                if self.export_checkbox.isChecked():
                    output_file = self.save_folder + f'/abuseipdb_output-{date}.' + self.default_extension
                else:
                    output_file = None
                result = ab.bulkcheck(ip_list, None, output_file, gui=True)
                results.append(f"Bulk Check Results:\n{result}")
                self.status_label.setText("File saved in the specified folder")  
            else:
                for ip in ip_list:
                    if self.is_valid_ip(ip):
                        result = ab.check_ip(ip, details=True, gui=True)
                        results.append(f"Result for IP {ip}:\n{result}\n")
                    elif self.is_subnet(ip):
                        if self.export_checkbox.isChecked():
                            output_file = self.save_folder + f'/abuseipdb_output-{date}.' + self.default_extension
                        else:
                            output_file = None
                        result = ab.check_subnet(ip,output_file)
                        results.append(f"Result for Subnet {ip}:\n{result}\n")
                    else:
                        results.append(f"Invalid format: {ip}. Please provide a valid IP or subnet.\n")

        except Exception as e:
            results.append(f"Error: {e}")
        
        self.output_text.append("\n".join(results))
        self.status_label.setText("Status: Ready")  

    def is_valid_ip(self, ip):
        ip_regex = r"^(\d{1,3}\.){3}\d{1,3}$"
        return bool(re.match(ip_regex, ip)) and all(0 <= int(part) <= 255 for part in ip.split('.'))

    def is_subnet(self, ip):
        subnet_regex = r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$"
        return bool(re.match(subnet_regex, ip))
    
    def on_configure(self):
        dialog = ConfigDialog(self)
        dialog.exec()

    def load_config(self):
        config = configparser.ConfigParser()
        config.read('config.ini')
        if 'api_key' not in config['DEFAULT'] or config['DEFAULT']['api_key'] == '':
            input_dialog = QInputDialog(self)
            input_dialog.setWindowTitle("Insert Key")
            input_dialog.setLabelText("API KEY not found. Please enter the API KEY:")
            input_dialog.setWindowIcon(QIcon("icon/icon.ico")) 
            input_dialog.setStyleSheet("""
                QInputDialog {
                    background-color: #2E2E2E;
                    color: white;
                }
                QLabel {
                    color: white;
                    font-size: 14px;
                }
                QLineEdit { color: black; }
                QPushButton {
                    background-color: #4CAF50;
                    color: white;
                    border-radius: 2px;
                    padding: 5px 10px;
                }
                QPushButton:hover {
                    background-color: #45a049;
                }
            """)
            ok = input_dialog.exec()
            key = input_dialog.textValue()
        
            if ok and key:  
                config['DEFAULT']['api_key'] = key
                with open('config.ini', 'w') as configfile:
                    config.write(configfile)

                success_msg = QMessageBox(self)
                success_msg.setWindowTitle("Success")
                success_msg.setText("KEY has been added to the configuration.")
                success_msg.setIcon(QMessageBox.Icon.Information)
                success_msg.setWindowIcon(QIcon("icon/icon.ico"))  
                success_msg.exec()
            else:
                error_msg = QMessageBox(self)
                error_msg.setWindowTitle("Error")
                error_msg.setText("KEY is required. Application cannot proceed.")
                error_msg.setIcon(QMessageBox.Icon.Critical)
                error_msg.setWindowIcon(QIcon("icon/icon.ico"))
                error_msg.exec()
                quit()
        self.save_folder = config.get('GUI', 'save_folder', fallback=os.getcwd())  
        self.file_type = config.get('GUI', 'file_type', fallback='Excel')  
        self.default_extension = config.get('GUI', 'default_extension', fallback='xlsx')  
    
    def save_config(self):
        config = configparser.ConfigParser()
        config.read('config.ini')

        if 'GUI' not in config:
            config.add_section('GUI')

        config.set('GUI', 'save_folder', self.save_folder)
        config.set('GUI', 'file_type', self.file_type)
        config.set('GUI', 'default_extension', self.default_extension)

        with open('config.ini', 'w') as configfile:
            config.write(configfile)

def create_gui():
    app = QApplication(sys.argv)
    mainWin = MainWindow()
    mainWin.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    create_gui()