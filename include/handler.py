#!/usr/bin/python3

import gettext, sys, json
import sqlite3
import builtin.crypt
import threading
import builtin.generator.socket as gpkg # 历史遗留下来的别名
import builtin.logfunc as logfunc
from  classes.user import UserObject

class ConnHandlerObject(object):
    def __init__(self, *args, **kwargs):
        self.name = "".join(args) # 子线程的名称，由主线程创建时赋参
        # 这里为什么不用方括号呢？因为赋的参数就一个（如果用方括号读出的结果就不对了
        # 用 join 的原因是不知道为什么会输出元组 所以用这种方法临时补救
        self.conn = kwargs['conn'] # 这里得到由主线程赋予的连接对象，是能够通信的核心
        self.addr = kwargs['addr']
        self.rsa_ekey, self.rsa_fkey = kwargs['rsa_keys']
        self.root_dir = kwargs["root_dir"]
        self.config = kwargs["config"] # 引入主线程已经配置好的config对象，不必重复传参
        ### 从 config 读取设置
        self.locale = self.config.get("general", "locale")
        self.db_prefix = self.config.get("general", "database_prefix")
        self.servername = self.config.get("general","servername") # 服务器名称，由客户端请求显示
        self.gpkg = gpkg.GeneratePackage(8)
        self.run() # 不知道为什么如果不加这个后面的都没法运行

    def run(self):
        es = gettext.translation("connHandler", localedir=self.root_dir + "/content/locale", languages=[self.locale], fallback=True)
        es.install()

        self.REQUIRED_CLIENT_VERSION = 0 # 内部定义，决定何种版本的客户端能与此建立链接

        self.log = logfunc.log(logname="main.connHandler.{0}".format(self.name), filepath=''.join((self.root_dir, '/content/logs/main.log')))

        """ 还没什么用
        db_conn = sqlite3.connect("".join((self.root_dir, "/content/database.db")))
        db_cursor = db_conn.cursor()
        db_conn.close()
        """

        ### 标准连接程序 - 服务器和客户端能正常交流的必要协议。
        recv = self.conn.recv(1024)
        self.log.logger.debug('client request data: %s' % recv.decode())
        if ('HTTP/1.1' or "HTTP/2.0") in recv.decode(): # 检查是不是 HTTP 请求，如果是就显示不支持信息
            response_start_line = "HTTP/1.1 200 OK\r\n"
            response_headers = "Server: CFMS Server\r\n"
            response_body = _("<p>This server does not support http(s).</p>")
            response = response_start_line + response_headers + "\r\n" + response_body
            self.conn.send(bytes(response, encoding='utf-8'))
            self.log.logger.info(_('Disconnecting from %s: HTTP requests. Closing %s.') \
                                 % (self.addr, self.name))
            self.conn.close()
            sys.exit()
        elif 'CFMS-PROT/1.0 200' not in recv.decode():
            self.log.logger.info(_('Disconnecting from %s: Unknown request. Closing %s.') \
                                 % (self.addr, self.name))
            self.conn.close()
            sys.exit()
        self.conn.send(self.rsa_fkey)  # Send RSA Public Key
        self.bf_key = builtin.crypt.RSA.decrypt(self.conn.recv(8192), self.rsa_ekey) # 密钥是由客户端生成的
        self.log.logger.debug(
            _("Encryption enabled successfully. Blowfish key: %s.") % self.bf_key
        )
        self.__send__(self.gpkg.Message("Success", "OK")) # 这一行来自于上个大版本，估计用于回复和防出错。
        ### 进入收消息迟滞循环。收到消息后另开新线程进行处理，以保证并行效率。
        count = 0 # 设定循环次数
        while True:
            count = count + 1
            try:
                recv = self.__recv__()
            except (ConnectionResetError, json.decoder.JSONDecodeError):
                self.log.logger.info(
                    _("Connection Reset %s. Closing %s.") % (self.addr, self.name)
                )
                sys.exit()
            except SystemExit:
                self.log.logger.info(
                    _("Disconnected from %s. Closing %s.") % (self.addr, self.name)
                )
                sys.exit()
            except:
                self.log.logger.fatal(
                    _("In %s, one (or more) exceptions were caught:") % self.name,
                    exc_info=True,
                )
                self.log.logger.fatal(
                    _("Due to the above exception, this thread cannot continue to run.")
                )
                sys.exit()
            threadName = "%s.processRecvObject.%s" % (self.name, count)
            Thread = threading.Thread(
                target=processRecvObject, args=str(threadName), kwargs={'recv': recv, 'gpkg': self.gpkg, \
                    'root_dir': self.root_dir, 'bf_key': self.bf_key, 'conn': self.conn, 'db_prefix': self.db_prefix, \
                        'addr': self.addr}
            )
            Thread.start()
            

        
    ### 这里定义的是使用 BLOWFISH 加密后的通信函数。
    def __send__(self, msg):
        self.log.logger.debug(_("Send: %s") % msg)
        bytes_msg = builtin.crypt.BLOWFISH.encrypt(msg, self.bf_key)
        self.conn.send(bytes_msg)

    def __recv__(self, limit=8192):
        cipher_bytes_text = self.conn.recv(limit)
        text = builtin.crypt.BLOWFISH.decrypt(cipher_bytes_text, self.bf_key)
        self.log.logger.debug(_("Get: %s.") % text)
        return text

"""
processRecvObject 类
用于处理收到的信息，独立作为一个线程运行。
"""
class processRecvObject(ConnHandlerObject):
    def __init__(self, *args, **kwargs):
        self.name = "".join(args)
        ### 收到的信息解析部分
        self.recv = kwargs['recv']
        self.msgtype = self.recv['Type'].split('/')
        self.data = self.recv['Data']
        ### 对象与必要变量
        self.gpkg = kwargs['gpkg']
        self.conn = kwargs['conn']
        self.addr = str(kwargs['addr']) # 这里的addr只是用来记日志，所以就直接str化了
        self.db_prefix = kwargs['db_prefix']
        self.root_dir = kwargs["root_dir"]
        self.bf_key = kwargs["bf_key"]
        self.log = logfunc.log(logname="main.connHandler.{0}".format(self.name), filepath=''.join((self.root_dir, '/content/logs/main.log')))
        self.run()
    
    def __commandHandler__(self):
        if self.data['cmd'] == 'disconnect': # 这里会直接断开连接，因此客户端发完请求之后直接退出
            self.conn.close()
            sys.exit()
        elif self.data['cmd'] == 'login':
            self.log.logger.debug('检测到命令: login')

            # 定义从客户端来的用户名密码
            username = self.data['username']
            password = self.data['password']
            
            if not 'user' in dir():
                user = UserObject(username, database_prefix=self.db_prefix, root_dir=self.root_dir, log=self.log) # 定义 user 对象（UserObject类）
            if user.online:
                self.log.logger.info(
                    _("%s: User %s is already logged in.") % (self.addr, username)
                )
                self.__send__(
                    self.gpkg.Message("Already logged in", "Please logout first.")
                )
                sys.exit()
            user.login(password)
            if user.online == False:
                if user.user_exists != True:
                    self.log.logger.warn(
                        _("%s: Username is incorrect. Login failed.") % self.addr
                    )
                    self.__send__(
                        self.gpkg.Message(
                            "Login FAILED", "Incorrect username or password.", 400
                        )
                    )
                else:
                    self.log.logger.warn(
                        _("%s: User %s's password is incorrect. Login failed.") % (self.addr, username)
                    )
                    self.__send__(
                        self.gpkg.Message(
                            "Login FAILED", "Incorrect username or password.", 400
                        )
                    )
            else:
                self.log.logger.info(
                    _("%s: User %s's password is match. Can login.")
                    % (self.addr, username)
                )
                self.__send__(self.gpkg.Message("SUCCESS", "Login Success!"))
        elif self.data['cmd'] == 'dir':
            pass
        else: # 如果请求命令与上述所有 if 全不匹配，就返回400
            self.log.logger.debug("bad command. unable to find the command in the definition.")
            self.__send__(self.gpkg.BadRequest())
            sys.exit()
            


    def run(self):
        if len(self.msgtype) < 2:
            self.__send__(self.gpkg.BadRequest())
            print('a')
            sys.exit()
        if self.msgtype[0:2] != ['client', 'request']:
            self.__send__(self.gpkg.BadRequest())
            print('b')
            print(self.msgtype[0:2])
            sys.exit()
        if len(self.msgtype) == 3:
            if self.msgtype[2] == 'command':
                try:
                    self.__commandHandler__()
                except: # 以后再补全异常处理
                    raise
            else:
                print('c')
                self.__send__(self.gpkg.BadRequest())
                sys.exit()
        else: # 目前规定 client/request 后必须有子类别（且只能有一个），因此发现组内长度小于3就返回错误
            self.__send__(self.gpkg.BadRequest())
            sys.exit()
        self.log.logger.handlers.clear() # 销毁 Handlers，修复重复log的问题
        sys.exit()
