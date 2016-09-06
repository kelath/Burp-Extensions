from burp import IBurpExtender
from burp import IHttpListener
from burp import IScannerListener
from java.net import URL
from java.io import File
import datetime
import time

class BurpExtender(IBurpExtender, IHttpListener, IScannerListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
	self._callbacks.setExtensionName("Proxy History Tester")
	httpReqResp = callbacks.getProxyHistory()
	print "There are %d items in the list" % httpReqResp.__len__()

	for item in httpReqResp:
            #print item.getRequest().tostring()
            print item.getHttpService().getHost()
            print item.getHttpService().getPort()
            self._callbacks.doActiveScan(item.getHttpService().getHost(),item.getHttpService().getPort(),0,item.getRequest())
