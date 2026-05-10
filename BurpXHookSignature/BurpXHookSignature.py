import json
import datetime
from java.io import PrintWriter
from burp import IBurpExtender, IBurpExtenderCallbacks, ISessionHandlingAction
import hashlib
import base64


class BurpExtender(IBurpExtender, ISessionHandlingAction):
        NAME = "Bearer Authorization Token"  ###this seems bonkers

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()

        callbacks.setExtensionName("X-Hook-Signature Generator")

        self.callbacks.registerSessionHandlingAction(self)
        self.stdout = PrintWriter(callbacks.getStdout(), True)

        self.stdout.println("X-Hook-Signature Generator\n")
        self.stdout.println('starting at time : {:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()))
        self.stdout.println("-----------------------------------------------------------------\n\n")

        return

    def getActionName(self):
        return self.NAME

    def createHash(self, request_body):
        key = ''  # Your Key goes here
        s_body = self.helpers.bytesToString(request_body).encode('ascii','ignore')
        self.stdout.println('Body:%s\nKey:%s' % (s_body, key))
        _b64HashedValue = base64.b64encode(hashlib.sha512(key + s_body).digest())
        self.stdout.println('Calculated value:%s' % _b64HashedValue)
        self.stdout.println("---------------------------------\n")
        return _b64HashedValue


    def performAction(self, currentRequest, macroItems):
        request_info = self.helpers.analyzeRequest(currentRequest)
        request_body = currentRequest.getRequest()[request_info.getBodyOffset():]

        request_headers = request_info.getHeaders()

        #Remove supplied headers to avoid duplication

        hookHeader = [header for header in request_headers if header.find("X-Hook-Signature") != -1]
        if hookHeader:
            for header in request_headers:
                if header.find("X-Hook-Signature") != -1:
                    index = request_headers.indexOf(header)

            headerLine = 'X-Hook-Signature: %s' % self.createHash(request_body)

            request_headers.set(index, headerLine)

        else:
            request_headers.add('X-Hook-Signature: %s' % self.createHash(request_body))
        message = self.helpers.buildHttpMessage(request_headers, request_body)

        # Update Request with New Header
        currentRequest.setRequest(message)
        return