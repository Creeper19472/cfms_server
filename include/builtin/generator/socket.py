# -*- coding: UTF-8 -*-
import time

"""
前代遗留物。
生成标准响应包供传输用。
这里 Code 等等 keyword 都是大写，因为太麻烦就不改了。
客户端同理。
"""


class GeneratePackage(object):
    def __init__(self, required_client_version, server_info=None):
        self.rcv = required_client_version
        # self.sinfo = server_info
        
    def FileNotFound(self, Msg="Ooops! File Not Found."):
        Package = {
            "Code": 404,
            "Message": Msg,
            "required_client_version": self.rcv,
            # "server_info": self.sinfo,
            "server_time": time.asctime()
            }
        return Package

    def Forbidden(self, Msg="Forbidden!"):
        Package = {
            "Code": 403,
            "Message": Msg,
            "required_client_version": self.rcv,
            # "server_info": self.sinfo,
            "server_time": time.asctime()
            }
        return Package

    def BadRequest(self, Msg="Bad Request"):
        Package = {
            "Code": 400,
            "Title": "Bad_Request",
            "Message": Msg,
            "required_client_version": self.rcv,
            # "server_info": self.sinfo,
            "server_time": time.asctime()
            }
        return Package

    def Message(self, Title, Msg, Code=200):
        Package = {
            "Code": Code,
            "Title": Title,
            "Message": Msg,
            "required_client_version": self.rcv,
            # "server_info": self.sinfo,
            "server_time": time.asctime()
            }
        return Package
