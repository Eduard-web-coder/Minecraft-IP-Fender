# Minecraft-IP-Fender
Это пример программы для поиска локальных серверов в маинкрафт 

Библеотеки:

from PyQt5.QtWidgets import (QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QCheckBox, QListWidget, QVBoxLayout, QWidget, QMessageBox)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import QTimer
import sys
import socket
import threading
import os
from mcstatus import JavaServer

