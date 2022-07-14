#!/usr/bin/python3

import sqlite3
import hashlib, json

"""
UserObject 类
用来处理用户登录（记录登录）等事务。
来自于上个大版本，因此许多变量名仍沿用上个大版本的编码习惯。
"""

class UserObject(object):
    def __init__(self, username, **kwargs):
        self.username = str(username) # 确保数据类型无误
        self.root_dir = kwargs['root_dir']
        self.log = kwargs['log']
        dbconn = sqlite3.connect(self.root_dir + "/content/database.db")
        dbcursor = dbconn.cursor()
        users = dbcursor.execute(
            "select username, password, level, role from {0}auth".format(kwargs['database_prefix'])
        )
        self.user_exists = False
        self.online = False
        self.password = None
        self.userrole = None
        for row in users:
            if row[0] == self.username:
                self.password = json.loads(row[1]) # with salt
                self.userlevel = row[2]
                self.userrole = row[3]
                self.log.logger.debug(
                    _("Found user {0}, password: {1}, userlevel: {2}, userrole: {3}").format(row[0], row[1], row[2], row[3])
                )
                self.user_exists = True
                break
        dbconn.close()

    def login(self, reqpass):
        if self.user_exists != True:
            self.online = False
            return
        hs = hashlib.md5(self.password[1].encode())
        hs.update(reqpass.encode()) # PS: 千万注意 update务必指定要加密的字符串的字符编码
        req_return = hs.hexdigest()
        self.log.logger.debug("运算后所得带salt的摘要：%s" % req_return)
        if req_return == self.password[0]:
            self.online = True
        else:
            self.online = False

    def logout(self):
        self.online = False
        return
