# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, ITab, IScannerCheck, IScanIssue
from java.io import PrintWriter
from java.net import URL
from javax.swing import (
    JPanel, JTable, JScrollPane, JSplitPane,
    BorderFactory, JButton, BoxLayout
)
from javax.swing.table import DefaultTableModel


class BurpExtender(IBurpExtender, IHttpListener, ITab, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Source Map Finder")

        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        self.enabled = False  # Start/Stop toggle
        self.checkedJS = set()  # Avoid re-checking same .js files

        # Models
        self.foundModel = DefaultTableModel(["JS File", "SourceMap URL"], 0)
        self.failedModel = DefaultTableModel(["JS File", "Attempted Map URL"], 0)
        foundTable = JTable(self.foundModel)
        failedTable = JTable(self.failedModel)

        scroll1 = JScrollPane(foundTable)
        scroll2 = JScrollPane(failedTable)
        scroll1.setBorder(BorderFactory.createTitledBorder("Found Maps"))
        scroll2.setBorder(BorderFactory.createTitledBorder("Failed Lookups"))

        # Split view
        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        splitPane.setTopComponent(scroll1)
        splitPane.setBottomComponent(scroll2)
        splitPane.setResizeWeight(0.5)

        # Start/Stop button
        self.toggleButton = JButton("Start", actionPerformed=self.toggleExtension)

        # Main UI Panel
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.add(self.toggleButton)
        panel.add(splitPane)
        self.uiPanel = panel

        # Register
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)

        self.stdout.println("[+] Source Map Finder loaded (inactive)")

    def toggleExtension(self, event):
        self.enabled = not self.enabled
        self.toggleButton.setText("Stop" if self.enabled else "Start")
        status = "enabled" if self.enabled else "disabled"
        self.stdout.println("[*] Extension {}".format(status))

    def getTabCaption(self):
        return "Map Finds"

    def getUiComponent(self):
        return self.uiPanel

    def processHttpMessage(self, toolFlag, messageIsRequest, message):
        if not self.enabled or messageIsRequest:
            return

        try:
            analyzed = self._helpers.analyzeRequest(message)
            url = analyzed.getUrl()
            urlStr = url.toString()

            if not urlStr.endswith(".js"):
                return
            if urlStr in self.checkedJS:
                return

            self.checkedJS.add(urlStr)
            map_url = urlStr + ".map"
            self.stdout.println("[*] Checking: " + map_url)

            map_request = self._helpers.buildHttpRequest(URL(map_url))
            map_response = self._callbacks.makeHttpRequest(message.getHttpService(), map_request)
            map_info = self._helpers.analyzeResponse(map_response.getResponse())
            status_code = map_info.getStatusCode()

            if status_code == 200:
                self.stdout.println("[+] Source map found: " + map_url)
                self.foundModel.addRow([urlStr, map_url])

                self._callbacks.addScanIssue(SourceMapIssue(
                    map_response.getHttpService(),
                    self._helpers.analyzeRequest(map_response).getUrl(),
                    [map_response],
                    "Source Map Exposed",
                    "A source map file is accessible at: <b>{}</b>".format(map_url),
                    "Information"
                ))
            else:
                self.stdout.println("[-] Map not found ({}): {}".format(status_code, map_url))
                self.failedModel.addRow([urlStr, map_url])
        except Exception as e:
            self.stderr.println("[ERROR] Exception during map check: {}".format(e))

    def doPassiveScan(self, baseRequestResponse):
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return -1 if existingIssue.getIssueName() == newIssue.getIssueName() else 0


class SourceMapIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0  # Custom issue

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return (
            "JavaScript source maps allow mapping minified code back to the original source. "
            "If exposed in production, they may reveal internal code structure, comments, "
            "file names, and sensitive logic."
        )

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return (
            "Ensure source maps are not deployed in production environments, "
            "or restrict access via web server configuration."
        )

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
