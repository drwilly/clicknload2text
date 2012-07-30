#!/usr/bin/env python3
import unittest

import threading
import http.server

import urllib.parse
import urllib.request

import re

import ClickNLoad2text

class CNLHandlerTest(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		ip, port = "127.0.0.1", 0 # port 0 -> random unused port
		cls.httpd = http.server.HTTPServer((ip, port), ClickNLoad2text.CNLHandler)
		server_thread = threading.Thread(target=cls.httpd.serve_forever)
		# Exit the server thread when the main thread terminates
		server_thread.daemon = True
		server_thread.start()

	#
	# GET
	#
	def test_alive(self):
		output = self.client("")
		self.assertEqual(output, "JDownloader")

	def test_jdcheck(self):
		output = self.client("jdcheck.js")
		pattern = re.compile(r"jdownloader\s*=\s*true", re.IGNORECASE)
		self.assertIsNotNone(pattern.search(output))

	@unittest.skip("")
	def test_crossdomain(self):
		pass

	#
	# POST
	#
	def test_add(self):
		params = {
			"passwords" : "myPassword",
			"source"    : "http://jdownloader.org/spielwiese",
			"urls"      : "http://www.rapidshare.com/files/407970280/RapidShareManager2WindowsSetup.exe",
		}

		actual = self.client("flash/add", params)

		expected = ClickNLoad2text.format_package(
			"http://jdownloader.org/spielwiese",
			["http://www.rapidshare.com/files/407970280/RapidShareManager2WindowsSetup.exe"],
			"myPassword"
		)

		self.assertEqual(actual, expected)

	@unittest.skip("Click'N'Load 1")
	def test_addcrypted(self):
		pass

	def test_addcrypted2(self):
		params = {
			"passwords" : "myPassword",
			"source"    : "http://jdownloader.org/spielwiese",
			"jk"        : "function f() { return '31323334353637383930393837363534'; }",
			"crypted"   : "DRurBGEf2ntP7Z0WDkMP8e1ZeK7PswJGeBHCg4zEYXZSE3Qqxsbi5EF1KosgkKQ9SL8qOOUAI+eDPFypAtQS9A==",
		}

		actual = self.client("flash/addcrypted2", params)

		expected = ClickNLoad2text.format_package(
			"http://jdownloader.org/spielwiese",
			["http://rapidshare.com/files/285626259/jDownloader.dmg"],
			"myPassword"
		)

		self.assertEqual(actual, expected)

	@unittest.skip("")
	def test_flashgot(self):
		pass

	def client(self, path, params=None):
		ENCODING = 'utf-8'
		url = "http://{}:{}/{}".format(
			self.httpd.server_address[0],
			self.httpd.server_address[1],
			path
		)
		if params is not None:
			headers = {
				"Content-Type": "application/x-www-form-urlencoded;charset={}".format(ENCODING),
			}
			request = urllib.request.Request(url, urllib.parse.urlencode(params).encode(ENCODING), headers)
		else:
			request = urllib.request.Request(url)

		with urllib.request.urlopen(request) as f:
			return f.read().decode(ENCODING)

	@classmethod
	def tearDownClass(cls):
		cls.httpd.shutdown()

if __name__ == "__main__":
	unittest.main()
