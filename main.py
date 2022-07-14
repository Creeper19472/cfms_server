#!/usr/bin/python3

"""
苦力怕团队: CFMS Server 主程序
本 .py 文件加载子目录下的各个模块并启动监听。
"""

VERSION = "0.0.1.4945[r]"

import sys, os, json, socket, sqlite3, gettext, time, random
import threading
import configparser

# 预声明 _() 函数，防止出现未定义提醒
_ = lambda s: s
# 好吧不能这么做

### 定义环境变量
# 当前目录路径。对logger等函数至关重要。
# 这一步必须首先完成。
current_dir = os.path.dirname(os.path.abspath(__file__))

### 引入自定义库
# 把存放自建包的目录加入Py的扫描范围中
sys.path.append(''.join((current_dir, '/include')))
import builtin.crypt
from builtin.iprocotol import *
from handler import ConnHandlerObject

# 引入自建日志函数并定义当前环境下的logger
import builtin.logfunc as logfunc
log = logfunc.log(logname="main", filepath=''.join((current_dir, '/content/logs/main.log')))
# 使用示例：log.logger.debug()
# 接下来开始在必要步骤进行记录

"""
请注意：实现上，本版本不再尝试实现彩色显示，因为需要付出的成本太高而收获太小。
因同样的原因一些得不偿失的功能也会被抛弃。
"""

if __name__ == "__main__":
    ### 如果被作为主程序运行，就开始面向前台的准备过程
    starttime = time.time()
    log.logger.info("Starting Classified File Management System - Server...")
    log.logger.info("Version {0}".format(VERSION))
    log.logger.info("Running On: Python %s" % sys.version)
    if sys.version_info[0] < 3: # 基于Py3开发，因此低于此版本就无法运行
        log.logger.fatal("您正在运行的 Python 版本低于本系统的最低要求。")
        log.logger.fatal("由于此原因，程序无法继续。")
        sys.exit()
    ### 导入 config.ini
    config = configparser.ConfigParser()
    config.read("config.ini", encoding="utf-8")

    # 加载语言配置
    language = config.get("general", "locale")
    es = gettext.translation("main", localedir="./content/locale", languages=["zh_CN"], fallback=True)
    es.install()

    ### 检测是否存在 database.db，如果没有就进行初始化
    # （检测是否空文件还没有实现）
    if not os.path.exists(''.join((current_dir, '/content/database.db'))):
        log.logger.info(_("Initializing database..."))
        log.logger.debug(_("Connecting to the database..."))
        # 初始化连接（即使数据库不存在也可以这么做）
        db_conn = sqlite3.connect("./content/database.db")
        log.logger.debug(_("Connected."))
        db_cursor = db_conn.cursor() # 建立光标，进行操作
        log.logger.debug(_("Preparing data for the next operation..."))

        initial_auth_data = ['master'] # 整体是一个列表，之后逐个添加要素
        initial_auth_data.append(bytes(json.dumps(['a48b644cb419a2a4870f5475a6e2dd93', '00aa']), encoding='utf-8'))
        # 原 SHA256 : 8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92
        initial_auth_data.append(5)
        initial_auth_data.append(bytes(json.dumps(['admin']), encoding='utf-8'))

        initial_role_data = ['admin', -1]
        initial_role_data.append(bytes(json.dumps(['manage_server']), encoding='utf-8'))
        """
        与上个大版本不同的是，本版本只将账户和索引信息存储在数据库中，而使文档以实体形式存在：
        因为文档的格式是多样的，一味往数据库里塞也不利于管理。
        """
        try:
            #                 insert into {0}role values('admin', -1, b('manage_server'));
            database_prefix = config.get("general", "database_prefix")
            execlist = """ 
                create table {0}auth(username, password, level, role);
                create table {0}role(rolename, level, permission);
                create table {0}index(id, name, path, level, owner)
                """.format(database_prefix)
            db_conn.executescript(execlist)
            db_conn.execute("insert into {0}auth values (?,?,?,?)".format(database_prefix), initial_auth_data)
            db_conn.execute("insert into {0}role values (?,?,?)".format(database_prefix), initial_role_data)
            """
            有关 index 表：
            存储调取各种文档所需的信息。
            CFMS 支持一个id下不同安全等级有不同对应文档 (可以完全不同), 
            因而id是总领这一系列版本的关键字段。
            name 决定当前等级（level 的等级）下文档的名称。
            path 是对应路径（实际存放它的地方）。
            owner 是所有者，规定谁可编辑（更新）文档。
            （除了所有者外，还有一些有特殊 role 和 permission 的用户可以编辑）
            """
            """
            级别说明：
            -1级表示无论文档级数多高全部可见;
            master账户本身赋了5级权限, 然而-1级比5级更高, 因此遵从那个更高的标准;
            其他账户规则与此一致。
            """
        except:
            raise
        log.logger.debug(_("Total changes: %s.") % db_conn.total_changes)
        db_conn.commit()
        log.logger.debug(_("Committed. Closing the connection with the database."))
        db_conn.close() # 提交并关闭，以免不必要的麻烦
    if not os.path.exists(''.join((current_dir, '/content/cert/e.pem'))) or \
        (not os.path.exists(''.join((current_dir, '/content/cert/f.pem')))):
        log.logger.info(_("Initializing RSA Keys..."))
        os.chdir("./content/cert/")
        builtin.crypt.RSA.createNewKey(2048)
        os.chdir("../../")
        # 这里还是使用之前的代码，所以没有 .join() 之类的函数
    ### 开始加载配置
    # 加载 ipv46 设置，之后以此判断是否使用ipv46协议
    has_ipv4 = config.getboolean("general", "has_ipv4")
    has_ipv6 = config.getboolean("general", "has_ipv6")
    if has_ipv4 is False and has_ipv6 is False:
        log.logger.fatal(_("The IPv4 and IPv6 protocols in the configuration are not enabled, and it's meaningless to continue running."))
        sys.exit()
    # 加载 IPv4 / 6 地址
    if has_ipv4:
        ipv4_addr = config.get("general", "ipv4_addr").split(":")
        ipv4_addr[1] = int(ipv4_addr[1])
        ipv4_addr = tuple(ipv4_addr)
        log.logger.debug(_("IPv4 address read: {0}").format(ipv4_addr))
    if has_ipv6:
        ipv6_addr = config.get("general", "ipv6_addr").split(":")
        ipv6_addr[1] = int(ipv6_addr[1])
        ipv6_addr = tuple(ipv6_addr)
        log.logger.debug(_("IPv6 address read: {0}").format(ipv6_addr))

    # 创建 socket 实例
    server = socket.socket()

    try:
        if has_ipv4 is True:
            ipvstatus = IPvStatus(ipv4_addr[0])
            if ipvstatus.ipv4():
                server.bind(ipv4_addr)
                server.listen(0)
            else:
                has_ipv4 = False
        if has_ipv6 is True:
            ipvstatus = IPvStatus(ipv6_addr[0])
            if ipvstatus.ipv6():
                server.bind(ipv6_addr)
                server.listen(0)
            else:
                has_ipv6 = False
    except:
        raise
    if has_ipv4 is False and has_ipv6 is False:
        log.logger.fatal(_("An exception occurred. Failed to listen on the specified configuration."))
        sys.exit()
    if has_ipv4:
        log.logger.info(_("IPv4 Address: {0}").format(ipv4_addr))
    else:
        log.logger.info(_("IPv4 is not supported."))
    if has_ipv6:
        log.logger.info(_("IPv6 Address: {0}").format(ipv6_addr))
    else:
        log.logger.info(_("IPv6 is not supported."))

    log.logger.debug(_("Loading RSA resources..."))
    with open("./content/cert/e.pem", "rb") as x:
        ekey = x.read()
    with open("./content/cert/f.pem", "rb") as x:
        fkey = x.read()
    endtime = time.time()
    log.logger.info(_("Done( %s s)!") % (endtime - starttime))
    while True:
        conn, addr = server.accept()  # 等待链接,多个链接的时候就会出现问题,其实返回了两个值
        log.logger.info(_("New connection: %s") % str(addr))
        threadName = "Thread-%s" % random.randint(1, 10000)
        Thread = threading.Thread(
            target=ConnHandlerObject, args=threadName, kwargs={'root_dir':current_dir, \
                'rsa_keys': (ekey, fkey),'config': config, 'conn': conn, 'addr': addr}
        )
        Thread.start()
        log.logger.debug(_("A new thread %s has started.") % threadName)

        


