# Burp extension to add CSP headers to responses
__author__ = 'jay.kelath'

# setup Imports
from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo

# Class BurpExtender (Required) contaning all functions used to interact with Burp Suite API
class BurpExtender(IBurpExtender, IHttpListener):

    # define registerExtenderCallbacks: From IBurpExtender Interface
    def registerExtenderCallbacks(self, callbacks):

        # keep a reference to our callbacks object (Burp Extensibility Feature)
        self._callbacks = callbacks
        # obtain an extension helpers object (Burp Extensibility Feature)
        # http://portswigger.net/burp/extender/api/burp/IExtensionHelpers.html
        self._helpers = callbacks.getHelpers()
        # set our extension name that will display in Extender Tab
        self._callbacks.setExtensionName("Add a CSP header")
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)

    # define processHttpMessage: From IHttpListener Interface
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # determine if request or response:
        if not messageIsRequest:#only handle responses
            response = messageInfo.getResponse() #get Response from IHttpRequestResponse instance
            responseStr = self._callbacks.getHelpers().bytesToString(response)
            responseParsed = self._helpers.analyzeResponse(response)
            body = responseStr[responseParsed.getBodyOffset():]
            headers = responseParsed.getHeaders()
            headers.add('MYHEADER: CSP') #add csp header here
            httpResponse = self._callbacks.getHelpers().buildHttpMessage(headers, body)
            messageInfo.setResponse(httpResponse)
            return
