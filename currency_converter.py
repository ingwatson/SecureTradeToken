import sys
import json
import requests
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, QComboBox,
                             QLineEdit, QPushButton, QMessageBox)
from PyQt5.QtCore import Qt

class CurrencyConverter(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Currency Converter")
        self.setGeometry(200, 200, 300, 150)

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

        # Předpokládáme, že máš seznam dostupných měn. Pro jednoduchost je zde statický seznam.
        # V reálné aplikaci by se tento seznam mohl načítat z API nebo konfiguračního souboru.
        self.currencies = ["USD", "EUR", "CZK", "GBP", "JPY"]
        self.from_currency_combo.addItems(self.currencies)
        self.to_currency_combo.addItems(self.currencies)
        self.from_currency_combo.setCurrentText("CZK")
        self.to_currency_combo.setCurrentText("EUR")

        controls_layout = QHBoxLayout()
        controls_layout.addWidget(self.amount_label)
        controls_layout.addWidget(self.amount_input)

        button_layout = QHBoxLayout()
        self.convert_button = QPushButton("Convert")
        self.convert_button.clicked.connect(self.convert_currency)
        button_layout.addWidget(self.convert_button)

        self.layout.addWidget(self.from_currency_label)
        self.layout.addWidget(self.from_currency_combo)
        self.layout.addWidget(self.to_currency_label)
        self.layout.addWidget(self.to_currency_combo)
        self.layout.addLayout(controls_layout)
        self.layout.addLayout(button_layout)
        self.layout.addWidget(self.result_label)
        self.layout.addWidget(self.result_display)

        self.setLayout(self.layout)

    def convert_currency(self):
        from_currency = self.from_currency_combo.currentText()
        to_currency = self.to_currency_combo.currentText()
        amount_str = self.amount_input.text()

        try:
            amount = float(amount_str)
            if amount < 0:
                QMessageBox.warning(self, "Invalid Input", "Amount must be a positive number.")
                return
        except ValueError:
            QMessageBox.warning(self, "Invalid Input", "Please enter a valid number for the amount.")
            return

        # Zde budeme volat API pro získání směnného kurzu.
        # Pro tento příklad použijeme veřejné API exchangerate-api.com.
        api_url = f"https://api.exchangerate-api.com/v4/latest/{from_currency}"

        try:
            response = requests.get(api_url)
            response.raise_for_status()  # Raise an exception for HTTP errors
            data = response.json()
            rate = data['rates'].get(to_currency)
            if rate is not None:
                result = amount * rate
                self.result_display.setText(f"{result:.2f} {to_currency}")
            else:
                QMessageBox.critical(self, "Conversion Error", f"Could not find exchange rate for {to_currency}.")
        except requests.exceptions.RequestException as e:
            QMessageBox.critical(self, "Network Error", f"Could not fetch exchange rates. Please check your internet connection.\n{e}")
        except (json.JSONDecodeError, KeyError):
            QMessageBox.critical(self, "API Error", "Failed to parse exchange rate data.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    converter = CurrencyConverter()
    converter.show()
    sys.exit(app.exec_())