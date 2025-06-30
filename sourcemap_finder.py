# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener
from java.net import URL
from java.io import PrintWriter
import re

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Auto Source Map Finder")

        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.registerHttpListener(self)
        self.stdout.println("[+] Source Map Finder Loaded")

    def processHttpMessage(self, toolFlag, messageIsRequest, message):
        if messageIsRequest:
            return

        response_info = self._helpers.analyzeResponse(message.getResponse())
        headers = response_info.getHeaders()
        body = message.getResponse()[response_info.getBodyOffset():]
        body_str = self._helpers.bytesToString(body)

        request_info = self._helpers.analyzeRequest(message)
        url = request_info.getUrl().toString()

        if url.endswith(".js"):
            map_url = url + ".map"
            self.stdout.println("[+] Trying: " + map_url)

            try:
                map_bytes = self._callbacks.makeHttpRequest(
                    message.getHttpService(),
                    self._helpers.buildHttpRequest(URL(map_url))
                )

                map_response = self._helpers.analyzeResponse(map_bytes.getResponse())
                status_code = map_response.getStatusCode()

                if status_code == 200:
                    self.stdout.println("[!] Found source map: " + map_url)
                else:
                    self.stdout.println("[-] No .map found (status {}): {}".format(status_code, map_url))

            except Exception as e:
                self.stderr.println("Error requesting .map for {}: {}".format(url, e))
