import sys
import json
import requests
import datetime
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, QComboBox,
                             QLineEdit, QPushButton, QMessageBox)
from PyQt5.QtCore import Qt

class CurrencyConverter(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Currency Converter")
        self.setGeometry(200, 200, 350, 200)

        self.parent_window = parent
        self.layout = QVBoxLayout()

        self.from_currency_label = QLabel("From Currency:")
        self.from_currency_combo = QComboBox()
        self.to_currency_label = QLabel("To Currency:")
        self.to_currency_combo = QComboBox()
        self.amount_label = QLabel("Amount:")
        self.amount_input = QLineEdit()
        self.result_label = QLabel("Result:")
        self.result_display = QLineEdit()
        self.result_display.setReadOnly(True)

        self.currencies = ["USD", "EUR", "CZK", "GBP", "JPY"]
        self.from_currency_combo.addItems(self.currencies)
        self.to_currency_combo.addItems(self.currencies)
        self.from_currency_combo.setCurrentText("CZK")
        self.to_currency_combo.setCurrentText("USD")

        controls_layout = QHBoxLayout()
        controls_layout.addWidget(self.amount_label)
        controls_layout.addWidget(self.amount_input)

        button_layout = QHBoxLayout()
        self.convert_button = QPushButton("Convert")
        self.convert_button.clicked.connect(self.convert_currency)
        button_layout.addWidget(self.convert_button)

        self.paste_button = QPushButton("Paste to Price")
        self.paste_button.clicked.connect(self.paste_to_price)
        self.paste_button.setEnabled(False)
        button_layout.addWidget(self.paste_button)

        self.layout.addWidget(self.from_currency_label)
        self.layout.addWidget(self.from_currency_combo)
        self.layout.addWidget(self.to_currency_label)
        self.layout.addWidget(self.to_currency_combo)
        self.layout.addLayout(controls_layout)
        self.layout.addLayout(button_layout)
        self.layout.addWidget(self.result_label)
        self.layout.addWidget(self.result_display)

        self.setLayout(self.layout)
        self.converted_amount = None
        self.target_currency = None

    def convert_currency(self):
        from_currency = self.from_currency_combo.currentText()
        self.target_currency = self.to_currency_combo.currentText()
        amount_str = self.amount_input.text()

        try:
            amount = float(amount_str)
            if amount < 0:
                QMessageBox.warning(self, "Invalid Input", "Amount must be a positive number.")
                return
        except ValueError:
            QMessageBox.warning(self, "Invalid Input", "Please enter a valid number for the amount.")
            return

        api_url = f"https://api.exchangerate-api.com/v4/latest/{from_currency}"

        try:
            response = requests.get(api_url)
            response.raise_for_status()
            data = response.json()
            rate = data['rates'].get(self.target_currency)
            if rate is not None:
                self.converted_amount = amount * rate
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                result_text = f"{self.converted_amount:.2f} {self.target_currency} (as of {timestamp})"
                self.result_display.setText(result_text)
                self.paste_button.setEnabled(True)
            else:
                QMessageBox.critical(self, "Conversion Error", f"Could not find exchange rate for {self.target_currency}.")
                self.paste_button.setEnabled(False)
                self.converted_amount = None
        except requests.exceptions.RequestException as e:
            QMessageBox.critical(self, "Network Error", f"Could not fetch exchange rates. Please check your internet connection.\n{e}")
            self.paste_button.setEnabled(False)
            self.converted_amount = None
        except (json.JSONDecodeError, KeyError):
            QMessageBox.critical(self, "API Error", "Failed to parse exchange rate data.")
            self.paste_button.setEnabled(False)
            self.converted_amount = None

    def paste_to_price(self):
        if self.parent_window and hasattr(self.parent_window, 'field_inputs') and 'PRICE' in self.parent_window.field_inputs and self.converted_amount is not None and self.target_currency is not None:
            self.parent_window.field_inputs['PRICE'].setText(f"{self.converted_amount:.2f} {self.target_currency}")
            QMessageBox.information(self, "Success", f"Result pasted to the 'PRICE' field with currency '{self.target_currency}'.")
        elif not ('PRICE' in self.parent_window.field_inputs):
            QMessageBox.warning(self, "Warning", "The 'PRICE' field was not found in the main window.")
        else:
            QMessageBox.warning(self, "Warning", "No conversion result or target currency available to paste.")