#!/usr/bin/python
# -*- coding: utf-8

from utils.syslog import setlog
from utils.getdatetime import getdatetime
from utils.qr import create_validate_code
from utils.report import *
from lxml import etree
from concurrent.futures import ThreadPoolExecutor
from tornado.web import UIModule
from math import ceil
import tornado.autoreload
import tornado.ioloop
import tornado.web
import tornado.gen
import datetime
import logging
import hashlib
import torndb
import urllib
import redis
import time
import json
import sys
import re
import os
import StringIO

reload(sys)
sys.setdefaultencoding("utf8")



try:
    try:
        version = sys.argv[1]
    except:
        version = 0
    if version == 'local':
        if os.path.exists('config/config.ini'):
            configfile = 'config/config.ini'
        else:
            configfile = '../config/config.ini'
    else:
        if os.path.exists('config/config_server.ini'):
            configfile = 'config/config_server.ini'
            print conf
        else:
            configfile = '../config/config_server.ini'
    fp = file(configfile)
    config_data = fp.read()
    fp.close()

    config_json = json.loads(config_data)['config']

    redis_host = config_json['redis_host']
    redis_port = config_json['redis_port']
    mysql_host = config_json['mysql_host']
    mysql_db = config_json['mysql_db']
    mysql_user = config_json['mysql_user']
    mysql_pass = config_json['mysql_pass']
    # 写数据库
    mysql_write_host = config_json['mysql_write_host']
    mysql_write_user = config_json['mysql_write_user']
    mysql_write_pass = config_json['mysql_write_pass']

    pre_system = config_json['pre_system']
    port = config_json['http_port']
    DEBUG = config_json['DEBUG']
except Exception, ex:
    print ex
    sys.exit(-1)

ISOTIMEFORMAT = '%Y-%m-%d %X'

# 链接redis
pool = redis.ConnectionPool(host=redis_host, port=redis_port)
redis_cache = redis.Redis(connection_pool=pool)

# 链接mysql
mysql_cursor = torndb.Connection(mysql_host, mysql_db, user=mysql_user,
                                 password=mysql_pass, charset="utf8mb4")

mysql_write_cursor = torndb.Connection(mysql_write_host, mysql_db, user=mysql_write_user,
                                 password=mysql_write_pass, charset="utf8mb4")


class BaseHandler(tornado.web.RequestHandler):
    '''
        重写get_current_user
    '''

    def get_current_user(self):
        if re.findall(r'sqlmap', self.request.headers['User-Agent']):
            self.write('Attack')
        else:
            return self.get_secure_cookie(pre_system + 'username')

    def data_received(self, chunk):
        """Implement this method to handle streamed request data.

        Requires the `.stream_request_body` decorator.
        """
        pass

    def write_error(self, status_code, **kwargs):
        # super(BaseHandler, self).write_error(status_code, **kwargs)
        self.write(str(status_code))


class LogoutHandler(BaseHandler):

    @tornado.web.authenticated
    def get(self):
        self.clear_cookie(pre_system + 'username')
        self.clear_cookie(pre_system + 'groupid')
        self.clear_cookie(pre_system + 'userid')
        self.redirect('/login')


class LoginHandler(BaseHandler):
    # 登录接口
    def get(self):
        is_login = self.get_secure_cookie(pre_system + 'userid')
        if is_login:
            self.redirect('/home')
        else:
            self.render('login.html')

    def post(self):
        user_name = self.get_argument("username", "")
        password = self.get_argument("password", "")
        qrcode = self.get_argument('qrcode', '')
        if self.request.headers.get('X-Real-IP', ''):
            remote_ip = self.request.headers['X-Real-IP']
        else:
            remote_ip = self.request.remote_ip
        if user_name and password:
            qrcode_save = self.get_secure_cookie(pre_system + 'qrcode')
            if not qrcode or not qrcode_save or qrcode.lower() != qrcode_save.lower():
                # 验证码错误
                self.write('4')
                return
            sql = "select `userid`,`username`,`expiretime`,`groupid` from system_user where username=%s and password=%s"
            password = hashlib.md5(password).hexdigest()
            result = mysql_cursor.query(sql, user_name, password)

            if not result:
                # 用户名或密码错误
                self.write("2")
                return
            logintime = time.strftime(
                ISOTIMEFORMAT, time.localtime(time.time()))

            # 判断用户是否过期
            expiretime = str(result[0]['expiretime'])
            expiretime = time.mktime(time.strptime(
                expiretime, '%Y-%m-%d %H:%M:%S'))
            nowtime = time.mktime(time.strptime(
                logintime, '%Y-%m-%d %H:%M:%S'))

            if expiretime < nowtime:
                self.write("5")
                return
            userid = result[0]["userid"]
            # 0：管理员 1：普通
            user_group = result[0]["groupid"]

            try:
                # 更新用户状态
                update_sql = "update system_user set lastlogintime = %s, lastloginip = %s where userid = %s"
                mysql_write_cursor.execute(
                    update_sql, logintime, remote_ip, userid)
            except Exception, e:
                # 数据库操作异常
                logging.info(e)
                print e
                self.write("0")
                return

            # 设置cookie
            self.set_secure_cookie(
                pre_system + "username", user_name, expires=time.time() + 1800, httponly=True)
            self.set_secure_cookie(pre_system + 'userid', str(
                userid), expires=time.time() + 1800, httponly=True)
            self.set_secure_cookie(pre_system + 'groupid', str(
                user_group), expires=time.time() + 1800, httponly=True)

            # 记录登录日志
            setlog(userid, user_name, remote_ip, '登录系统', 0, mysql_cursor)
            del userid
            # 普通登录成功
            self.write("1")
        else:
            # 缺少用户名或密码
            self.write("3")


class MainHandler(BaseHandler):
    # 后台首页
    @tornado.web.authenticated
    def get(self):
        groupid = self.get_secure_cookie(pre_system + 'groupid')
        username = self.get_secure_cookie(pre_system + 'username')
        if groupid == '1':
            # 普通帐号
            self.redirect('/home')
        else:
            # 管理员后台
            # 获取用户列表
            total = mysql_cursor.query(
                'select count(*) as "count" from system_user where `username`!="root"')[0]['count']
            pagesize = float(self.get_argument('pagenum', 20))
            maxpage = int(ceil(int(total) / pagesize))
            page_cur = int(self.get_argument('page', 0))
            method = self.get_argument('method', 'top')

            if method == 'top':
                page = 0
            elif method == 'prev':
                if page_cur > 1:
                    page = page_cur - 1
                else:
                    page = 0
            elif method == 'next':
                if page_cur < maxpage - 1:
                    page = page_cur + 1
                else:
                    if maxpage != 0:
                        page = maxpage - 1
                    else:
                        page = 0
            elif method == 'bottom':
                if maxpage != 0:
                    page = maxpage - 1
                else:
                    page = 0
            else:
                page = page_cur - 1

            startindex = page * pagesize
            stopindex = pagesize

            startpagenum = (page_cur - 6 < 1) and 1 or (page_cur - 6)
            endpagenum = (startpagenum + 9 >
                          maxpage) and maxpage or startpagenum + 9
            sql = 'select userid, username, createtime, expiretime,comment, lastloginip, lastlogintime from system_user where `username`!="root" order by userid desc limit %s, %s'
            userlist = mysql_cursor.query(sql, startindex, stopindex)
            self.render(r'admin/usermanage.html',
                        userlist=userlist,
                        page=page,
                        total=total,
                        pagenum=maxpage,
                        startpagenum=startpagenum,
                        endpagenum=endpagenum
                        )


class HomeHandler(BaseHandler):

    @tornado.web.authenticated
    def get(self):
        groupid = self.get_secure_cookie(pre_system + 'groupid')
        username = self.get_secure_cookie(pre_system + 'username')
        userid = self.get_secure_cookie(pre_system + 'userid')
        if groupid == '0':
            # 管理员后台
            # 获取用户列表
            total = mysql_cursor.query(
                'select count(*) as "count" from system_user where `username`!="root"')[0]['count']
            pagesize = float(self.get_argument('pagenum', 20))
            maxpage = int(ceil(int(total) / pagesize))
            page_cur = int(self.get_argument('page', 0))
            method = self.get_argument('method', 'top')

            if method == 'top':
                page = 0
            elif method == 'prev':
                if page_cur > 1:
                    page = page_cur - 1
                else:
                    page = 0
            elif method == 'next':
                if page_cur < maxpage - 1:
                    page = page_cur + 1
                else:
                    if maxpage != 0:
                        page = maxpage - 1
                    else:
                        page = 0
            elif method == 'bottom':
                if maxpage != 0:
                    page = maxpage - 1
                else:
                    page = 0
            else:
                page = page_cur - 1

            startindex = page * pagesize
            stopindex = pagesize

            startpagenum = (page_cur - 6 < 1) and 1 or (page_cur - 6)
            endpagenum = (startpagenum + 9 >
                          maxpage) and maxpage or startpagenum + 9
            sql = 'select userid, username, createtime, expiretime,comment, lastloginip, lastlogintime from system_user where `username`!="root" order by userid desc limit %s, %s'
            userlist = mysql_cursor.query(sql, startindex, stopindex)
            self.render(r'admin/home.html',
                        userlist=userlist,
                        page=page,
                        total=total,
                        pagenum=maxpage,
                        startpagenum=startpagenum,
                        endpagenum=endpagenum
                        )
        else:
            # 首页统计数据
            sql = 'select count(*) as total_wxqun from system_grouplist where `userid`=%s'
            total_wxqun = mysql_cursor.query(sql, userid)[0]['total_wxqun']

            #sql = 'select count(*) as total_wxmsg from system_content where `userid`=%s'
            sql = 'select msg_total as total_wxmsg from system_total where userid=%s'
            total_wxmsg = mysql_cursor.query(sql, userid)
            if total_wxmsg:
               total_wxmsg = total_wxmsg[0]['total_wxmsg']
            else:
               total_wxmsg = 0

            sql = 'select count(*) as total_wxnum from system_wechatlist where `userid`=%s'
            total_wxnum = mysql_cursor.query(sql, userid)[0]['total_wxnum']

            #sql = 'select count(*) as total_wxwarning from system_warning where `userid`=%s'
            sql = 'select warn_total as total_wxwarning from system_total where userid=%s'
            total_wxwarning = mysql_cursor.query(sql, userid)
            if total_wxwarning:
                total_wxwarning = total_wxwarning[0]['total_wxwarning']
            else:
                total_wxwarning = 0

            sql = 'select count(gid) as total from system_grouplist where userid=%s and newmsg>=20 group by gid'
            today = datetime.date.today()
            start_time = str(today) + ' 00:00:00'
            stop_time = str(today) + ' 23:59:59'
            ret = mysql_cursor.query(sql, userid)
            total_active = len(ret)
            self.render('home.html', username=username,
                        total_wxqun=total_wxqun,
                        total_wxnum=total_wxnum,
                        total_wxmsg=total_wxmsg,
                        total_wxwarning=total_wxwarning,
                        total_active=total_active,
                        )

    @tornado.web.authenticated
    def post(self):
        pass


class QRCodeHandler(BaseHandler):
    '''
    验证码获取接口
    '''

    def get(self):
        code_img, strs = create_validate_code()
        self.set_secure_cookie(pre_system + 'qrcode', strs)
        buf = StringIO.StringIO()
        code_img.save(buf, 'JPEG', quality=70)

        buf_str = buf.getvalue()
        self.set_header('Content-Type', 'image/jpeg')
        self.write(buf_str)


class SysLogHandler(BaseHandler):
    # 系统日志接口

    @tornado.web.authenticated
    def get(self):
        groupid = self.get_secure_cookie(pre_system + 'groupid')
        typeid = self.get_argument('typeid', 0)
        username = self.get_argument('username', '')
        ip = self.get_argument('ip', '')
        if groupid != '0':
            self.redirect('/home')
            return
        if username:
            total = mysql_cursor.query(
                'select count(*) as "count" from system_syslog where `typeid`=%s and `username`=%s', typeid, username)[0]['count']
        elif ip:
            total = mysql_cursor.query(
                'select count(*) as "count" from system_syslog where `typeid`=%s and `ip`=%s', typeid, ip)[0]['count']
        else:
            total = mysql_cursor.query(
                'select count(*) as "count" from system_syslog where `typeid`=%s', typeid)[0]['count']
        pagesize = float(self.get_argument('pagenum', 15))
        maxpage = int(ceil(int(total) / pagesize))
        page_cur = int(self.get_argument('page', 0))
        method = self.get_argument('method', 'top')

        if method == 'top':
            page = 0
        elif method == 'prev':
            if page_cur > 1:
                page = page_cur - 1
            else:
                page = 0
        elif method == 'next':
            if page_cur < maxpage - 1:
                page = page_cur + 1
            else:
                if maxpage != 0:
                    page = maxpage - 1
                else:
                    page = 0
        elif method == 'bottom':
            if maxpage != 0:
                page = maxpage - 1
            else:
                page = 0
        else:
            page = page_cur - 1

        startindex = page * pagesize
        stopindex = pagesize

        startpagenum = (page_cur - 6 < 1) and 1 or (page_cur - 6)
        endpagenum = (startpagenum + 9 >
                      maxpage) and maxpage or startpagenum + 9
        if username:
            sql = 'select `id`,`username`,`ip`,`optime`, `msg`, `typeid` from system_syslog where `typeid`=%s and `username`=%s order by `id` desc limit %s, %s'
            loginfo = mysql_cursor.query(
                sql, typeid, username, startindex, stopindex)
        elif ip:
            sql = 'select `id`,`username`,`ip`,`optime`, `msg`, `typeid` from system_syslog where `typeid`=%s and `ip`=%s order by `id` desc limit %s, %s'
            loginfo = mysql_cursor.query(
                sql, typeid, ip, startindex, stopindex)
        else:
            sql = 'select `id`,`username`,`ip`,`optime`, `msg`, `typeid` from system_syslog where `typeid`=%s order by `id` desc limit %s, %s'
            loginfo = mysql_cursor.query(sql, typeid, startindex, stopindex)
        self.render('admin/userlog.html',
                    loginfo=loginfo,
                    username=username,
                    ip=ip,
                    typeid=typeid,
                    page=page,
                    total=total,
                    pagenum=maxpage,
                    startpagenum=startpagenum,
                    endpagenum=endpagenum
                    )


class UserInfoHandler(BaseHandler):

    @tornado.web.authenticated
    def get(self):
        pass

    @tornado.web.authenticated
    def post(self):
        userid = self.get_secure_cookie(pre_system + 'userid')
        sql = 'select username, createtime, expiretime, lastlogintime, lastloginip from system_user where `userid`=%s'
        userinfo = mysql_cursor.query(sql, userid)
        userinfo = userinfo[0]
        userinfo['expiretime'] = str(userinfo['expiretime'])
        userinfo['createtime'] = str(userinfo['createtime'])
        userinfo['lastlogintime'] = str(userinfo['lastlogintime'])
        self.write(json.dumps({'userinfo': userinfo}))


class AccountListHandler(BaseHandler):
    # 微信号列表

    @tornado.web.authenticated
    def get(self):
        username = self.get_secure_cookie(pre_system + 'username')
        userid = self.get_secure_cookie(pre_system + 'userid')

        total = mysql_cursor.query(
            'select count(*) as "count" from system_wechatlist where `userid`=%s', userid)[0]['count']
        pagesize = float(self.get_argument('pagenum', 15))
        maxpage = int(ceil(int(total) / pagesize))
        page_cur = int(self.get_argument('page', 0))
        method = self.get_argument('method', 'top')

        if method == 'top':
            page = 0
        elif method == 'prev':
            if page_cur > 1:
                page = page_cur - 1
            else:
                page = 0
        elif method == 'next':
            if page_cur < maxpage - 1:
                page = page_cur + 1
            else:
                if maxpage != 0:
                    page = maxpage - 1
                else:
                    page = 0
        elif method == 'bottom':
            if maxpage != 0:
                page = maxpage - 1
            else:
                page = 0
        else:
            page = page_cur - 1

        startindex = page * pagesize
        stopindex = pagesize

        startpagenum = (page_cur - 6 < 1) and 1 or (page_cur - 6)
        endpagenum = (startpagenum + 9 >
                      maxpage) and maxpage or startpagenum + 9
        sql = 'select * from system_wechatlist where `userid`=%s order by id desc limit %s, %s'
        accountlist = mysql_cursor.query(sql, userid, startindex, stopindex)
        self.render('accountlist.html',
                    accountlist=accountlist,
                    username=username,
                    page=page,
                    total=total,
                    pagenum=maxpage,
                    startpagenum=startpagenum,
                    endpagenum=endpagenum
                    )


class GroupListHandler(BaseHandler):
    # 微信群列表

    @tornado.web.authenticated
    def get(self):
        username = self.get_secure_cookie(pre_system + 'username')
        userid = self.get_secure_cookie(pre_system + 'userid')
        wechatid = self.get_argument('id', '')
        keyword = self.get_argument('keyword', '')
        # 不是对tag进行搜索 正常的群列表或群搜索
        notsearch = 1
        sort = self.get_argument('sort', '')
        order = self.get_argument('order', 'desc')

        if order not in ['asc', 'desc']:
            # 防止乱输入
            order = 'asc'

        if sort:
            # 防止乱输入排序规则
            if sort not in ['totaluser', 'newmem', 'newmsg']:
                sort = ''

        # 判断是否是在进行搜索操作
        if keyword:
            tmpkeyword = '%' + keyword + '%'
            total = mysql_cursor.query(
                'select count(*) as "count" from system_grouplist where `userid`=%s and `nickname` like %s', userid, tmpkeyword)[0]['count']
            pagesize = float(self.get_argument('pagenum', 20))
            maxpage = int(ceil(int(total) / pagesize))
            page_cur = int(self.get_argument('page', 0))
            method = self.get_argument('method', 'top')

            if method == 'top':
                page = 0
            elif method == 'prev':
                if page_cur > 1:
                    page = page_cur - 1
                else:
                    page = 0
            elif method == 'next':
                if page_cur < maxpage - 1:
                    page = page_cur + 1
                else:
                    if maxpage != 0:
                        page = maxpage - 1
                    else:
                        page = 0
            elif method == 'bottom':
                if maxpage != 0:
                    page = maxpage - 1
                else:
                    page = 0
            else:
                page = page_cur - 1

            startindex = page * pagesize
            stopindex = pagesize

            startpagenum = (page_cur - 6 < 1) and 1 or (page_cur - 6)
            endpagenum = (startpagenum + 9 >
                          maxpage) and maxpage or startpagenum + 9

            sql = 'select `id`,`gid`,`nickname`,`createtime`,`tag`, `displayName`, `totaluser`, `newmem`, `newmsg`, `wechatid` from system_grouplist where `userid`=%s and `nickname` like %s limit %s, %s'

            grouplist = mysql_cursor.query(sql, userid, tmpkeyword, startindex, stopindex)
            for group in grouplist:
                if group['totaluser'] < 0:
                    group['totaluser'] = 0
                if group['totaluser'] < group['newmem'] :
                    group['totaluser'] = group['newmem']
            # 获取标签列表
            sql = 'select tagid, tagname from system_tags where `userid`=%s order by tagid desc limit %s, %s'
            tagslist = mysql_cursor.query(sql, userid, startindex, stopindex)
            self.render('grouplist.html', username=username,
                        sort=sort,
                        order=order,
                        notsearch=notsearch,
                        wid=wechatid,
                        keyword=keyword,
                        grouplist=grouplist,
                        tagslist=tagslist,
                        page=page,
                        total=total,
                        pagenum=maxpage,
                        startpagenum=startpagenum,
                        endpagenum=endpagenum
                        )
            return

        if wechatid:
            # 单个微信号的所有群
            total = mysql_cursor.query(
                'select count(*) as "count" from system_grouplist where `wid`=%s and `userid`=%s', wechatid, userid)[0]['count']
            pagesize = float(self.get_argument('pagenum', 20))
            maxpage = int(ceil(int(total) / pagesize))
            page_cur = int(self.get_argument('page', 0))
            method = self.get_argument('method', 'top')

            if method == 'top':
                page = 0
            elif method == 'prev':
                if page_cur > 1:
                    page = page_cur - 1
                else:
                    page = 0
            elif method == 'next':
                if page_cur < maxpage - 1:
                    page = page_cur + 1
                else:
                    if maxpage != 0:
                        page = maxpage - 1
                    else:
                        page = 0
            elif method == 'bottom':
                if maxpage != 0:
                    page = maxpage - 1
                else:
                    page = 0
            else:
                page = page_cur - 1

            startindex = page * pagesize
            stopindex = pagesize

            startpagenum = (page_cur - 6 < 1) and 1 or (page_cur - 6)
            endpagenum = (startpagenum + 9 >
                          maxpage) and maxpage or startpagenum + 9
            sql = 'select `id`,`gid`,`nickname`,`createtime`,`tag`, `displayName`, \
            `totaluser`, `newmem`, `newmsg` , `wechatid` from system_grouplist where `wid`=%s \
            and `userid`=%s limit %s, %s'
            grouplist = mysql_cursor.query(
                sql, wechatid, userid, startindex, stopindex)
        else:
            # 所有群
            total = mysql_cursor.query(
                'select count(*) as "count" from system_grouplist where `userid`=%s', userid)[0]['count']
            pagesize = float(self.get_argument('pagenum', 20))
            maxpage = int(ceil(int(total) / pagesize))
            page_cur = int(self.get_argument('page', 0))
            method = self.get_argument('method', 'top')

            if method == 'top':
                page = 0
            elif method == 'prev':
                if page_cur > 1:
                    page = page_cur - 1
                else:
                    page = 0
            elif method == 'next':
                if page_cur < maxpage - 1:
                    page = page_cur + 1
                else:
                    if maxpage != 0:
                        page = maxpage - 1
                    else:
                        page = 0
            elif method == 'bottom':
                if maxpage != 0:
                    page = maxpage - 1
                else:
                    page = 0
            else:
                page = page_cur - 1

            startindex = page * pagesize
            stopindex = pagesize

            startpagenum = (page_cur - 6 < 1) and 1 or (page_cur - 6)
            endpagenum = (startpagenum + 9 >
                          maxpage) and maxpage or startpagenum + 9
            if sort:
                if sort == 'newmsg':
                    if order == 'asc':
                        sql = 'select `id`,`gid`,`nickname`,`createtime`,`tag`, `displayName`, `totaluser`, `newmem`, `newmsg`, `wechatid` from system_grouplist where `userid`=%s order by newmsg asc limit %s, %s'
                        grouplist = mysql_cursor.query(sql, userid, startindex, stopindex)
                    else:
                        sql = 'select `id`,`gid`,`nickname`,`createtime`,`tag`, `displayName`, `totaluser`, `newmem`, `newmsg`, `wechatid` from system_grouplist where `userid`=%s order by newmsg desc limit %s, %s'
                        grouplist = mysql_cursor.query(sql, userid, startindex, stopindex)

                if sort == 'newmem':
                    if order == 'asc':
                        sql = 'select `id`,`gid`,`nickname`,`createtime`,`tag`, `displayName`, `totaluser`, `newmem`, `newmsg`, `wechatid` from system_grouplist where `userid`=%s order by newmem asc limit %s, %s'
                        grouplist = mysql_cursor.query(sql, userid, startindex, stopindex)
                    else:
                        sql = 'select `id`,`gid`,`nickname`,`createtime`,`tag`, `displayName`, `totaluser`, `newmem`, `newmsg`, `wechatid` from system_grouplist where `userid`=%s order by newmem desc limit %s, %s'
                        grouplist = mysql_cursor.query(sql, userid, startindex, stopindex)

                if sort == 'totaluser':
                    if order == 'asc':
                        sql = 'select `id`,`gid`,`nickname`,`createtime`,`tag`, `displayName`, `totaluser`, `newmem`, `newmsg`, `wechatid` from system_grouplist where `userid`=%s order by totaluser asc limit %s, %s'
                        grouplist = mysql_cursor.query(sql, userid, startindex, stopindex)
                    else:
                        sql = 'select `id`,`gid`,`nickname`,`createtime`,`tag`, `displayName`, `totaluser`, `newmem`, `newmsg`, `wechatid` from system_grouplist where `userid`=%s order by totaluser desc limit %s, %s'
                        grouplist = mysql_cursor.query(sql, userid, startindex, stopindex)
            else:
                sql = 'select `id`,`gid`,`nickname`,`createtime`,`tag`, `displayName`, `totaluser`, `newmem`, `newmsg`, `wechatid` from system_grouplist where `userid`=%s limit %s, %s'
                grouplist = mysql_cursor.query(sql, userid, startindex, stopindex)

        for group in grouplist:
            if group['totaluser'] < 0:
                group['totaluser'] = 0
            if group['totaluser'] < group['newmem'] :
                group['totaluser'] = group['newmem']
        # 获取标签列表
        sql = 'select tagid, tagname from system_tags where `userid`=%s order by tagid desc'
        tagslist = mysql_cursor.query(sql, userid)
        self.render('grouplist.html', username=username,
                    sort=sort,
                    order=order,
                    notsearch=notsearch,
                    wid=wechatid,
                    keyword=keyword,
                    grouplist=grouplist,
                    tagslist=tagslist,
                    page=page,
                    total=total,
                    pagenum=maxpage,
                    startpagenum=startpagenum,
                    endpagenum=endpagenum
                    )

    # 异步获取 微信群人数 新增人数 新增消息数量
    @tornado.web.authenticated
    def post(self):
        gid = self.get_argument('gid', '')
        userid = self.get_secure_cookie(pre_system + 'userid')
        if not gid:
            self.write('0')
            return
        sql = 'select count(*) as totaluser from system_group_members where `gid`=%s and `userid`=%s'
        totaluser = mysql_cursor.query(sql, gid, userid)[0]['totaluser']
        if not int(totaluser):
            # 如果总人数为0  则其它两个值也为0
            incr_user = 0
            incr_msg = 0
        else:
            today = time.strftime('%Y-%m-%d') + ' 00:00:00'
            sql = 'select count(*) as incr_user from system_group_members where `gid`=%s and `userid`=%s and `createtime` >=  %s'
            incr_user = mysql_cursor.query(sql, gid, userid, today)[
                0]['incr_user']
            sql = 'select count(*) as incr_msg from system_content where `gid`=%s and `userid`=%s and `createtime` >= %s'
            incr_msg = mysql_cursor.query(sql, gid, userid, today)[
                0]['incr_msg']
        self.write(json.dumps({'totaluser': totaluser,
                               'incr_user': incr_user, 'incr_msg': incr_msg}))


class GroupListMethodHandler(BaseHandler):
    '''群列表搜索功能
    1. 根据标签来搜索
    2. 根据群名称来搜索
    3. 获取今日新增成员
    '''
    def get(self, method):
        userid = self.get_secure_cookie(pre_system + 'userid')
        username = self.get_secure_cookie(pre_system + 'username')
        gid = self.get_argument('gid', '')
        tag = self.get_argument('tag', '')
        wechatid = self.get_argument('id', '')

        sort = self.get_argument('sort', '')
        order = self.get_argument('order', 'desc')

        if order not in ['asc', 'desc']:
            # 防止乱输入
            order = 'desc'

        if sort:
            # 防止乱输入排序规则
            if sort not in ['totaluser', 'newmem', 'newmsg']:
                sort = ''

        if not userid:
            # 登录失效
            self.write('2')
            return

        if method == 'tag':
            notsearch = 0
            if not tag:
                self.write('0')
                return

            if wechatid:
                total = mysql_cursor.query(
                    'select count(*) as "count" from system_grouplist where `wid`=%s and `tag`=%s', wechatid, tag)[0]['count']
                pagesize = float(self.get_argument('pagenum', 20))
                maxpage = int(ceil(int(total) / pagesize))
                page_cur = int(self.get_argument('page', 0))
                method = self.get_argument('method', 'top')

                if method == 'top':
                    page = 0
                elif method == 'prev':
                    if page_cur > 1:
                        page = page_cur - 1
                    else:
                        page = 0
                elif method == 'next':
                    if page_cur < maxpage - 1:
                        page = page_cur + 1
                    else:
                        if maxpage != 0:
                            page = maxpage - 1
                        else:
                            page = 0
                elif method == 'bottom':
                    if maxpage != 0:
                        page = maxpage - 1
                    else:
                        page = 0
                else:
                    page = page_cur - 1

                startindex = page * pagesize
                stopindex = pagesize

                startpagenum = (page_cur - 6 < 1) and 1 or (page_cur - 6)
                endpagenum = (startpagenum + 9 >
                              maxpage) and maxpage or startpagenum + 9
                sql = 'select `id`,`gid`,`nickname`,`createtime`,`tag`, `displayName`, `totaluser`, `newmem`, `newmsg`, `wechatid` from system_grouplist where `wid`=%s and `tag`=%s limit %s, %s'
                grouplist = mysql_cursor.query(
                    sql, wechatid, tag, startindex, stopindex)
            else:
                total = mysql_cursor.query(
                    'select count(*) as "count" from system_grouplist where `tag`=%s', tag)[0]['count']
                pagesize = float(self.get_argument('pagenum', 20))
                maxpage = int(ceil(int(total) / pagesize))
                page_cur = int(self.get_argument('page', 0))
                method = self.get_argument('method', 'top')

                if method == 'top':
                    page = 0
                elif method == 'prev':
                    if page_cur > 1:
                        page = page_cur - 1
                    else:
                        page = 0
                elif method == 'next':
                    if page_cur < maxpage - 1:
                        page = page_cur + 1
                    else:
                        if maxpage != 0:
                            page = maxpage - 1
                        else:
                            page = 0
                elif method == 'bottom':
                    if maxpage != 0:
                        page = maxpage - 1
                    else:
                        page = 0
                else:
                    page = page_cur - 1

                startindex = page * pagesize
                stopindex = pagesize

                startpagenum = (page_cur - 6 < 1) and 1 or (page_cur - 6)
                endpagenum = (startpagenum + 9 >
                              maxpage) and maxpage or startpagenum + 9
                sql = 'select `id`,`gid`,`nickname`,`createtime`,`tag`, `displayName`, `totaluser`, `newmem`, `newmsg`, `wechatid`  from system_grouplist where `tag`=%s limit %s, %s'
                grouplist = mysql_cursor.query(sql, tag, startindex, stopindex)
            # 获取标签列表
            sql = 'select tagid, tagname from system_tags where `userid`=%s order by tagid desc limit 20'
            tagslist = mysql_cursor.query(sql, userid)
            self.render('grouplist.html', username=username,
                        sort=sort,
                        order=order,
                        notsearch=notsearch,
                        wid=wechatid,
                        searchtag=tag,
                        grouplist=grouplist,
                        tagslist=tagslist,
                        page=page,
                        total=total,
                        pagenum=maxpage,
                        startpagenum=startpagenum,
                        endpagenum=endpagenum
                        )

    def post(self, method):
        userid = self.get_secure_cookie(pre_system + 'userid')
        username = self.get_secure_cookie(pre_system + 'username')
        gid = self.get_argument('gid', '')
        tag = self.get_argument('tag', '')
        wechatid = self.get_argument('id', '')
        if not userid:
            # 登录失效
            self.write('2')
            return

        if method == 'newmem':
            if not gid:
                self.write('0')
                return
            today = time.strftime('%Y-%m-%d') + '%'
            total = mysql_cursor.query(
                'select count(*) as "count" from system_group_members where `gid`=%s and `userid`=%s and `createtime` like %s', gid, userid, today)[0]['count']
            pagesize = float(self.get_argument('pagenum', 20))
            maxpage = int(ceil(int(total) / pagesize))
            page_cur = int(self.get_argument('page', 0))

            startindex = page_cur * pagesize
            stopindex = pagesize

            sql = 'select gid, alias, username, nickname, createtime from system_group_members where `gid`=%s and `userid`=%s and `createtime` like %s limit %s, %s'
            data = mysql_cursor.query(sql, gid, userid, today, startindex, stopindex)
            for line in data:
                line['createtime'] = str(line['createtime'])
            self.write(json.dumps({'data': data, 'total': maxpage, 'page': page_cur}))
            return


class GroupMemberListHandler(BaseHandler):
    # 获取群成员列表接口

    @tornado.web.authenticated
    def get(self):
        pass

    @tornado.web.authenticated
    def post(self):
        # 提交参数gid
        gid = self.get_argument('gid', '')
        userid = self.get_secure_cookie(pre_system + 'userid')

        if not userid:
            # 登录过期
            self.write('2')
            return

        if not gid:
            self.write('0')
            return
        total = mysql_cursor.query(
            'select count(*) as "count" from system_group_members where `gid`=%s and `userid`=%s', gid, userid)[0]['count']
        pagesize = float(self.get_argument('pagenum', 20))
        maxpage = int(ceil(int(total) / pagesize))
        page_cur = int(self.get_argument('page', 0))

        startindex = page_cur * pagesize
        stopindex = pagesize

        sql = 'select gid, alias, username, nickname, createtime from system_group_members where `gid`=%s and `userid`=%s limit %s, %s'
        data = mysql_cursor.query(sql, gid, userid, startindex, stopindex)
        for line in data:
            line['createtime'] = str(line['createtime'])
        self.write(json.dumps({'data': data, 'total': maxpage, 'page': page_cur}))


class GroupMSGHandler(BaseHandler):
    # 群消息列表

    @tornado.web.authenticated
    def get(self):
        username = self.get_secure_cookie(pre_system + 'username')
        userid = self.get_secure_cookie(pre_system + 'userid')
        gid = self.get_argument('gid', '')
        wechatid = self.get_argument('wechatid', '')

        # 群消息数量设置为0
        redis_cache.delete(pre_system + 'groupinfonum:' + str(userid))

        if gid:
            if wechatid:
                # 单个用户在群里的发言
                total = mysql_cursor.query(
                    'select count(*) as "count" from system_content where `userid`=%s and `gid`=%s and `sender_wechatid`=%s', userid, gid, wechatid)[0]['count']
            else:
                # 查看单独的群信息
                total = mysql_cursor.query(
                    'select count(*) as "count" from system_content where `userid`=%s and `gid`=%s', userid, gid)[0]['count']
        else:
            total = mysql_cursor.query(
                'select count(*) as "count" from system_content where `userid`=%s', userid)[0]['count']
        pagesize = float(self.get_argument('pagenum', 15))
        maxpage = int(ceil(int(total) / pagesize))
        page_cur = int(self.get_argument('page', 0))
        method = self.get_argument('method', 'top')

        if method == 'top':
            page = 0
        elif method == 'prev':
            if page_cur > 1:
                page = page_cur - 1
            else:
                page = 0
        elif method == 'next':
            if page_cur < maxpage - 1:
                page = page_cur + 1
            else:
                if maxpage != 0:
                    page = maxpage - 1
                else:
                    page = 0
        elif method == 'bottom':
            if maxpage != 0:
                page = maxpage - 1
            else:
                page = 0
        else:
            page = page_cur - 1

        startindex = page * pagesize
        stopindex = pagesize

        startpagenum = (page_cur - 6 < 1) and 1 or (page_cur - 6)
        endpagenum = (startpagenum + 9 >
                      maxpage) and maxpage or startpagenum + 9
        if gid:
            # 判断是否是查看该群的某个用户的所有信息
            if wechatid:
                # 查看单独的群中的单独用户发言信息
                sql = 'select * from system_content where `userid`=%s and `gid`=%s and `sender_wechatid`=%s order by id desc limit %s, %s'
                msglist = mysql_cursor.query(
                    sql, userid, gid, wechatid, startindex, stopindex)
            else:
                # 查看单独的群信息
                sql = 'select * from system_content where `userid`=%s and `gid`=%s order by id desc limit %s, %s'
                msglist = mysql_cursor.query(
                    sql, userid, gid, startindex, stopindex)
        else:
            sql = 'select * from system_content where `userid`=%s order by id desc limit %s, %s'
            msglist = mysql_cursor.query(sql, userid, startindex, stopindex)
        self.render('groupmsg.html',
                    msglist=msglist,
                    gid=gid,
                    wechatid=wechatid,
                    username=username,
                    page=page,
                    total=total,
                    pagenum=maxpage,
                    startpagenum=startpagenum,
                    endpagenum=endpagenum
                    )


    @tornado.web.authenticated
    def post(self):
        # 获取群列表
        userid = self.get_secure_cookie(pre_system + 'userid')
        total = mysql_cursor.query(
            'select count(*) as "count" from system_grouplist where `userid`=%s', userid)[0]['count']
        pagesize = float(self.get_argument('pagenum', 27))
        maxpage = int(ceil(int(total) / pagesize))
        page_cur = int(self.get_argument('page', 0))
        method = self.get_argument('method', 'next')

        if method == 'next':
            if page_cur < maxpage - 1:
                page = page_cur + 1
            else:
                if maxpage != 0:
                    page = maxpage - 1
                else:
                    page = 0
        else:
            page = page_cur - 1

        startindex = page * pagesize
        stopindex = pagesize

        startpagenum = (page_cur - 6 < 1) and 1 or (page_cur - 6)
        endpagenum = (startpagenum + 9 >
                      maxpage) and maxpage or startpagenum + 9
        sql = 'select `gid`, `displayName` from system_grouplist where `userid`=%s limit %s, %s'
        grouplist = mysql_cursor.query(sql, userid, startindex, stopindex)
        self.write(json.dumps({'grouplist': grouplist, 'total': maxpage, 'page': page_cur}))


class WarningListHandler(BaseHandler):
    # 预警推送

    @tornado.web.authenticated
    def get(self):
        username = self.get_secure_cookie(pre_system + 'username')
        userid = self.get_secure_cookie(pre_system + 'userid')

        # 将预警推送数量设置为0
        redis_cache.delete(pre_system + 'warningnum:' + str(userid))

        # 一次性取10条记录
        warninglist = []
        for _ in xrange(10):
            ret = redis_cache.lpop(pre_system + 'warninglist:' + str(userid))
            if ret:
                warninglist.append(ret)
            else:
                break
        tmpwarninglist = []
        for line in warninglist:
            tmpwarninglist.append(json.loads(line))

        self.render('warninglist.html', username=username,
                    warninglist=tmpwarninglist,
                    )

    @tornado.web.authenticated
    def post(self):
        # 重点微信号 获取 预警的群列表
        # 单个微信号 所有预警的群列表
        # 1 微信号为空
        # 0 登录失效

        wechatid = self.get_argument('wechatid', '')
        userid = self.get_secure_cookie(pre_system + 'userid')

        if not wechatid:
            self.write('1')
            return

        if not userid:
            # 则登录已经失效
            self.write('0')
            return


        total = mysql_cursor.query(
            'select count(*) as "count" from (select gid from system_warning where `userid`=%s and `sender_wechatid`=%s and gname is not null group by gid) as t', userid, wechatid)[0]['count']
        pagesize = float(self.get_argument('pagenum', 10))
        maxpage = int(ceil(int(total) / pagesize))
        page_cur = int(self.get_argument('page', 0))
        addkey = self.get_argument('addkey','')
        if not addkey:
            # 则登录已经失效
            self.write('0')
            return
        startindex = page_cur * pagesize
        stopindex = pagesize

        # sql = 'select userid, gid, gname, sender_wechatid from system_warning where `userid`=%s and `sender_wechatid`=%s group by gid limit %s, %s'
        sql = '''
            SELECT
                w.userid, w.gid, w.gname as gname, w.sender_wechatid
            FROM
                system_warning as w, system_grouplist as g
            WHERE
                w.gid=g.gid and w.userid=g.userid and w.userid=%s and w.sender_wechatid=%s
            group by gid limit %s, %s
        '''
        data = mysql_cursor.query(sql, userid, wechatid, startindex, stopindex)
        for d in data:
            userid = str(d['userid'])
            sender_wechatid = str(d['sender_wechatid'])
            gid = str(d['gid'])
            addkey = str(addkey)
            sql = 'select * from system_warning where userid = %s and sender_wechatid = %s and gid = %s  and keywords = %s'
            res =  mysql_cursor.query(sql, userid,sender_wechatid,gid,addkey)
            if res:
                d['status'] = 1
            else:
                d['status'] = 0
        # 没有群名称的 重新进行获取
        # for line in data:
        #     sql = 'select displayName,gid from system_grouplist where `gid`=%s and `userid`=%s'
        #     ret = mysql_cursor.query(sql, line['gid'], userid)
        #     if ret:
        #         line['gname'] = ret[0]['displayName']

        self.write(json.dumps({'data': data, 'total': maxpage, 'page': page_cur}))
        return


class WarnListHandler(BaseHandler):
    # 预警推送

    @tornado.web.authenticated
    def get(self):
        username = self.get_secure_cookie(pre_system + 'username')
        userid = self.get_secure_cookie(pre_system + 'userid')
        searchtime = self.get_argument('t', '')
        kwid = self.get_argument('kwid', '')
        t = searchtime
        if not searchtime:
            # 2017-03-27 - 2017-03-27
            _t = time.strftime('%Y-%m-%d', time.localtime())
            searchtime = '%s - %s' % (_t, _t)
        if searchtime:
            searchtime = urllib.unquote(searchtime)
            start_time = searchtime.split(' ')[0] + ' 00:00:00'
            stop_time = searchtime.split(' ')[2] + ' 23:59:59'
            if kwid:
                # total = mysql_cursor.query(
                #     'select count(*) as "count" from system_warning where `userid`=%s and `kwid`=%s and `createtime`>=%s and `createtime`<=%s', userid, kwid, start_time, stop_time)[0]['count']
                sql = '''
                    SELECT
                        count(*) as count
                    FROM
                        system_content as c, system_warning as w,
                        system_grouplist as g
                    WHERE
                        c.id=w.conid and g.userid=c.userid and c.userid=w.userid and c.userid=%s and g.gid=c.gid
                        and w.kwid=%s and w.createtime>=%s and w.createtime<=%s
                '''
                total = mysql_cursor.query(sql, userid, kwid, start_time, stop_time)[0]['count']
            else:
                # total = mysql_cursor.query(
                #     'select count(*) as "count" from system_warning where `userid`=%s and `createtime`>=%s and `createtime`<=%s', userid, start_time, stop_time)[0]['count']
                sql = '''
                    SELECT
                        count(*) as count
                    FROM
                        system_content as c, system_warning as w,
                        system_grouplist as g
                    WHERE
                        c.id=w.conid and g.userid=c.userid and c.userid=w.userid and c.userid=%s and g.gid=c.gid
                        and w.createtime>=%s and w.createtime<=%s
                '''
                total = mysql_cursor.query(sql, userid, start_time, stop_time)[0]['count']
        else:
            if kwid:
                # total = mysql_cursor.query(
                #     'select count(*) as "count" from system_warning where `userid`=%s and `kwid`=%s', userid, kwid)[0]['count']
                sql = '''
                    SELECT
                        count(*) as count
                    FROM
                        system_content as c, system_warning as w,
                        system_grouplist as g
                    WHERE
                        c.id=w.conid and g.userid=c.userid and c.userid=w.userid and c.userid=%s and g.gid=c.gid and w.kwid=%s

                '''
                total = mysql_cursor.query(sql, userid, kwid)[0]['count']
            else:
                sql = 'select count(*) as "count" from system_warning where `userid`=%s'
                # sql = '''
                #     SELECT
                #         count(*) as count
                #     FROM
                #         system_content as c, system_warning as w,
                #         system_grouplist as g
                #     WHERE
                #         c.id=w.conid and c.userid=%s and g.gid=c.gid
                # '''
                # total = mysql_cursor.query(
                #     'select count(*) as "count" from system_warning where `userid`=%s', userid)[0]['count']
                total = mysql_cursor.query(sql, userid)[0]['count']
        pagesize = float(self.get_argument('pagenum', 20))
        maxpage = int(ceil(int(total) / pagesize))
        page_cur = int(self.get_argument('page', 0))
        method = self.get_argument('method', 'top')

        if method == 'top':
            page = 0
        elif method == 'prev':
            if page_cur > 1:
                page = page_cur - 1
            else:
                page = 0
        elif method == 'next':
            if page_cur < maxpage - 1:
                page = page_cur + 1
            else:
                if maxpage != 0:
                    page = maxpage - 1
                else:
                    page = 0
        elif method == 'bottom':
            if maxpage != 0:
                page = maxpage - 1
            else:
                page = 0
        else:
            page = page_cur - 1

        startindex = page * pagesize
        stopindex = pagesize
        startpagenum = (page - 6 < 1) and 1 or (page - 6)
        endpagenum = (startpagenum + 9 >
                      maxpage) and maxpage or startpagenum + 9

        if searchtime:
            if kwid:
                # sql = 'select c.content, c.gid, c.gname, c.sender_wechatid, c.username, w.createtime, w.keywords from system_content as c, system_warning as w where c.id=w.conid and c.userid=%s and w.kwid=%s and w.createtime>=%s and w.createtime<=%s order by w.id desc limit %s, %s'
                sql = '''
                    SELECT
                        c.content, c.gid, c.sender_wechatid,
                        c.username, w.createtime, w.keywords,
                        g.nickname as gname
                    FROM
                        system_content as c, system_warning as w,
                        system_grouplist as g
                    WHERE
                        c.id=w.conid and g.userid=c.userid and c.userid=w.userid and c.userid=%s and g.gid=c.gid
                        and w.kwid=%s and w.createtime>=%s and w.createtime<=%s
                    order by w.id desc limit %s, %s

                '''
                warnlist = mysql_cursor.query(sql, userid, kwid, start_time, stop_time, startindex, stopindex)
            else:
                # sql = 'select c.content, c.gid, c.gname, c.sender_wechatid, \
                # c.username, w.createtime, w.keywords from system_content as c, \
                # system_warning as w where c.id=w.conid and c.userid=%s and \
                # w.createtime>=%s and w.createtime<=%s order by w.id desc limit %s, %s'
                # sql = '''
                #     SELECT
                #         c.content, c.gid, c.sender_wechatid,
                #         c.username, w.createtime, w.keywords,
                #         g.nickname as gname
                #     FROM
                #         system_content as c, system_warning as w,
                #         system_grouplist as g
                #     WHERE
                #         c.id=w.conid and c.userid=%s and g.gid=c.gid
                #         and w.createtime>=%s and w.createtime<=%s
                #     order by w.id desc limit %s, %s
                # '''
                sql = '''
                    SELECT
                        c.content, c.gid, c.sender_wechatid,
                        c.username, w.createtime, w.keywords,
                        g.nickname as gname
                    FROM
                        system_content as c, system_warning as w,
                        system_grouplist as g
                    WHERE
                        c.id=w.conid and g.userid=c.userid and c.userid=w.userid and w.userid=%s and g.gid=c.gid
                        and w.createtime>=%s and w.createtime<=%s
                    order by w.id desc limit %s, %s
                '''
                warnlist = mysql_cursor.query(sql, userid, start_time, stop_time, startindex, stopindex)
        else:
            if kwid:
                # sql = 'select c.content, c.gid, c.gname, c.sender_wechatid, c.username,\
                #  w.createtime, w.keywords from system_content as c, system_warning as \
                #  w where c.id=w.conid and c.userid=%s and w.kwid=%s order by w.id desc limit %s, %s'
                sql = '''
                    SELECT
                        c.content, c.gid, c.sender_wechatid,
                        c.username, w.createtime, w.keywords,
                        g.nickname as gname
                    FROM
                        system_content as c, system_warning as w,
                        system_grouplist as g
                    WHERE
                        c.id=w.conid and g.userid=c.userid and c.userid=w.userid and c.userid=%s and g.gid=c.gid and w.kwid=%s
                    order by w.id desc limit %s, %s

                '''
                warnlist = mysql_cursor.query(sql, userid, kwid, startindex, stopindex)
            else:
                # sql = 'select c.content, c.gid, c.gname, c.sender_wechatid, \
                # c.username, w.createtime, w.keywords from system_content as c, \
                # system_warning as w where c.id=w.conid and c.userid=%s order by \
                # w.id desc limit %s, %s'
                sql = '''
                    SELECT
                        c.content, c.gid, c.sender_wechatid,
                        c.username, w.createtime, w.keywords,
                        g.nickname as gname
                    FROM
                        system_content as c, system_warning as w,
                        system_grouplist as g
                    WHERE
                        c.id=w.conid and g.userid=c.userid and c.userid=w.userid and c.userid=%s and g.gid=c.gid
                    order by w.id desc limit %s, %s

                '''
                warnlist = mysql_cursor.query(sql, userid, startindex, stopindex)
        # 获取专题名
        sql = 'select kwid, subname from system_keywords where `userid`=%s'
        kwlist = mysql_cursor.query(sql, userid)
        self.render('warnlist.html', username=username,
                        t=t,
                        kwid=kwid,
                        kwlist=kwlist,
                        warnlist=warnlist,
                        page=page,
                        total=total,
                        pagenum=maxpage,
                        startpagenum=startpagenum,
                        endpagenum=endpagenum
                    )


class WarningListMethodHandler(BaseHandler):
    # ajax获取预警信息

    @tornado.web.authenticated
    def post(self, method):
        if method == 'get':
            userid = self.get_secure_cookie(pre_system + 'userid')

            if not userid:
                # 则登录已经失效
                self.write('2')
                return

            # 一次性取10条记录
            warninglist = []
            for _ in xrange(10):
                ret = redis_cache.lpop(
                    pre_system + 'warninglist:' + str(userid))
                if ret:
                    warninglist.append(ret)
                else:
                    break
            tmpwarninglist = []

            for line in warninglist:
                tmpline = json.loads(line)
                tmpwarninglist.append(tmpline)

            self.write(json.dumps({'warninglist': tmpwarninglist}))
            return


class QrCodeListHandler(BaseHandler):
    # 二维码预警

    @tornado.web.authenticated
    def get(self):
        username = self.get_secure_cookie(pre_system + 'username')
        self.render('qrcodelist.html', username=username)


class WechatHandler(BaseHandler):
    # 微信 添加 删除 修改接口

    @tornado.web.authenticated
    def post(self, method):
        userid = self.get_secure_cookie(pre_system + 'userid')
        username = self.get_secure_cookie(pre_system + 'username')
        ip = self.request.remote_ip
        addtime = getdatetime()
        wechatid = self.get_argument('wechatid', '')
        comment = self.get_argument('comment', '')
        wid = self.get_argument('id', '')
        if method == 'add':
            if not wechatid:
                # 参数为空
                self.write('0')
                return
            # 判断 微信id是否已经添加过
            sql = 'select id from system_wechatlist where `wechatid`=%s'
            ret = mysql_cursor.query(sql, wechatid)
            if ret:
                self.write('2')
                return
            try:
                comment = comment[:200]
                sql = 'insert into system_wechatlist (`wechatid`, `comment`, `addtime`, \
                      `userid`) values (%s, %s, %s, %s)'
                mysql_write_cursor.execute(sql, wechatid, comment, addtime, userid)
                setlog(userid, username, ip, '%s 添加微信号 %s' %
                       (username, wechatid), 1, mysql_cursor)
                self.write('1')
            except Exception, ex:
                print ex
                self.write('0')

        if method == 'del':
            if not wid:
                # 参数为空
                self.write('0')
                return
            try:
                sql = 'delete from system_wechatlist where `id`=%s and `userid`=%s'
                mysql_write_cursor.execute(sql, wid, userid)
                setlog(userid, username, ip, '%s 删除了微信号 %s' %
                       (username, wechatid), 1, mysql_cursor)
                self.write('1')
            except Exception, ex:
                print ex
                self.write('0')

        if method == 'edit':
            comment = comment[:200]
            sql = 'update system_wechatlist set `wechatid`=%s, `comment`=%s where `id`=%s'
            mysql_write_cursor.execute(sql, wechatid, comment, wid)
            self.write('1')


class KeywordsHandler(BaseHandler):
    # 关键字预警设置接口

    @tornado.web.authenticated
    def get(self):
        userid = self.get_secure_cookie(pre_system + 'userid')
        username = self.get_secure_cookie(pre_system + 'username')
        total = mysql_cursor.query(
            'select count(*) as "count" from system_keywords where `userid`=%s', userid)[0]['count']
        pagesize = float(self.get_argument('pagenum', 15))
        maxpage = int(ceil(int(total) / pagesize))
        page_cur = int(self.get_argument('page', 0))
        method = self.get_argument('method', 'top')

        if method == 'top':
            page = 0
        elif method == 'prev':
            if page_cur > 1:
                page = page_cur - 1
            else:
                page = 0
        elif method == 'next':
            if page_cur < maxpage - 1:
                page = page_cur + 1
            else:
                if maxpage != 0:
                    page = maxpage - 1
                else:
                    page = 0
        elif method == 'bottom':
            if maxpage != 0:
                page = maxpage - 1
            else:
                page = 0
        else:
            page = page_cur - 1

        startindex = page * pagesize
        stopindex = pagesize

        startpagenum = (page_cur - 6 < 1) and 1 or (page_cur - 6)
        endpagenum = (startpagenum + 9 >
                      maxpage) and maxpage or startpagenum + 9

        sql = 'select * from system_keywords where `userid`=%s order by kwid desc limit %s, %s'
        keywordslist = mysql_cursor.query(sql, userid, startindex, stopindex)
        self.render('keywords.html', username=username,
                    keywordslist=keywordslist,
                    page=page,
                    total=total,
                    pagenum=maxpage,
                    startpagenum=startpagenum,
                    endpagenum=endpagenum
                    )


class KeyWordsMethodHandler(BaseHandler):
    # 关键字预警 添加 删除  修改

    @tornado.web.authenticated
    def get(self, method):
        pass

    @tornado.web.authenticated
    def post(self, method):
        userid = self.get_secure_cookie(pre_system + 'userid')
        username = self.get_secure_cookie(pre_system + 'username')
        subname = self.get_argument('subname', '')
        keywords = self.get_argument('keywords', '')
        kwid = self.get_argument('kwid', '')
        remote_ip = self.request.remote_ip

        if method == 'add':
            # 添加专题
            if not (subname and keywords):
                # 内容不能为空
                self.write('0')
                return

            # 判断专题是否已经添加过
            sql = 'select kwid from system_keywords where `userid`=%s and `subname`=%s'
            ret = mysql_cursor.query(sql, userid, subname)
            if ret:
                self.write('2')
                return

            sql = 'insert into system_keywords (`subname`, `keywords`, `userid`, `addtime`) values (%s, %s, %s, %s)'
            addtime = getdatetime()
            keywords = keywords.replace('，', ',')
            mysql_write_cursor.execute(sql, subname, keywords, userid, addtime)

            # 记录操作日志
            setlog(userid, username, remote_ip, '%s 添加了一个专题预警: %s' %
                   (username, subname), 1, mysql_cursor)
            self.write('1')
            return

        if method == 'del':
            # 删除专题
            if not kwid:
                self.write('0')
                return

            sql = 'delete from system_keywords where `kwid`=%s and `userid`=%s'
            mysql_write_cursor.execute(sql, kwid, userid)

            # 记录日志
            setlog(userid, username, remote_ip, '%s 删除了一个专题' %
                   username, 1, mysql_cursor)
            self.write('1')
            return

        if method == 'edit':
            # 编辑专题
            if not (subname and keywords and kwid):
                # 内容不能为空
                self.write('0')
                return

            # # 判断专题是否已经添加过
            # sql = 'select kwid from system_keywords where `userid`=%s and `subname`=%s'
            # ret = mysql_cursor.query(sql, userid, subname)
            # if ret:
            #     self.write('2')
            #     return

            sql = 'update system_keywords set `subname`=%s, `keywords`=%s where `kwid`=%s and `userid`=%s'
            mysql_write_cursor.execute(sql, subname, keywords, kwid, userid)

            # 记录日志
            setlog(userid, username, remote_ip, '%s 修改了一个专题' %
                   username, 1, mysql_cursor)
            self.write('1')
            return


class TagsHandler(BaseHandler):
    # 标签管理接口

    @tornado.web.authenticated
    def get(self):
        userid = self.get_secure_cookie(pre_system + 'userid')
        username = self.get_secure_cookie(pre_system + 'username')
        total = mysql_cursor.query(
            'select count(*) as "count" from system_tags where `userid`=%s', userid)[0]['count']
        pagesize = float(self.get_argument('pagenum', 15))
        maxpage = int(ceil(int(total) / pagesize))
        page_cur = int(self.get_argument('page', 0))
        method = self.get_argument('method', 'top')

        if method == 'top':
            page = 0
        elif method == 'prev':
            if page_cur > 1:
                page = page_cur - 1
            else:
                page = 0
        elif method == 'next':
            if page_cur < maxpage - 1:
                page = page_cur + 1
            else:
                if maxpage != 0:
                    page = maxpage - 1
                else:
                    page = 0
        elif method == 'bottom':
            if maxpage != 0:
                page = maxpage - 1
            else:
                page = 0
        else:
            page = page_cur - 1

        startindex = page * pagesize
        stopindex = pagesize

        startpagenum = (page_cur - 6 < 1) and 1 or (page_cur - 6)
        endpagenum = (startpagenum + 9 >
                      maxpage) and maxpage or startpagenum + 9

        sql = 'select * from system_tags where `userid`=%s order by tagid desc limit %s, %s'
        tagslist = mysql_cursor.query(sql, userid, startindex, stopindex)
        self.render('tags.html', username=username,
                    tagslist=tagslist,
                    page=page,
                    total=total,
                    pagenum=maxpage,
                    startpagenum=startpagenum,
                    endpagenum=endpagenum
                    )


class TagsMethodHandler(BaseHandler):
    # 标签 添加  删除  修改  设置群标签

    @tornado.web.authenticated
    def get(self, method):
        pass

    @tornado.web.authenticated
    def post(self, method):
        userid = self.get_secure_cookie(pre_system + 'userid')
        username = self.get_secure_cookie(pre_system + 'username')
        tagname = self.get_argument('tagname', '')
        tagid = self.get_argument('tagid', '')
        gids = self.get_arguments('gids', True)
        remote_ip = self.request.remote_ip

        if method == 'add':
            # 判断标签是否已经添加过
            sql = 'select tagid from system_tags where `userid`=%s and `tagname`=%s'
            ret = mysql_cursor.query(sql, userid, tagname)
            if ret:
                self.write('2')
                return

            addtime = getdatetime()
            sql = 'insert into system_tags (`userid`, `tagname`, `addtime`) values (%s, %s, %s)'
            mysql_write_cursor.execute(sql, userid, tagname, addtime)

            # 记录操作日志
            setlog(userid, username, remote_ip, '%s 添加了一个标签: %s' %
                   (username, tagname), 1, mysql_cursor)
            self.write('1')
            return

        if method == 'del':
            # 删除标签
            if not tagid:
                self.write('0')
                return

            sql = 'delete from system_tags where `tagid`=%s and `userid`=%s'
            mysql_write_cursor.execute(sql, tagid, userid)

            # 将已经是这个tag的记录设置为空
            sql = 'update system_grouplist set `tag`="" where `userid`=%s and `tagid`=%s'
            mysql_write_cursor.execute(sql, userid, tagid)

            # 记录日志
            setlog(userid, username, remote_ip, '%s 删除了一个标签' %
                   username, 1, mysql_cursor)
            self.write('1')
            return

        if method == 'edit':
            # 编辑标签
            if not (tagname and tagid):
                # 内容不能为空
                self.write('0')
                return

            # # 判断标签是否已经添加过
            # sql = 'select tagid from system_tags where `userid`=%s and `tagname`=%s'
            # ret = mysql_cursor.query(sql, userid, tagname)
            # if ret:
            #     self.write('2')
            #     return

            sql = 'update system_tags set `tagname`=%s where `tagid`=%s and `userid`=%s'
            mysql_write_cursor.execute(sql, tagname, tagid, userid)

            # 修改群tagid
            sql = 'update system_grouplist set `tag`=%s where `tagid`=%s and `userid`=%s'
            mysql_write_cursor.execute(sql, tagname, tagid, userid)

            # 记录日志
            setlog(userid, username, remote_ip, '%s 修改了一个标签' %
                   username, 1, mysql_cursor)
            self.write('1')
            return

        if method == 'set':
            # 设置群标签
            if len(gids) > 1:
                try:
                    sql_in = '(%s)'
                    in_p = ', '.join(map(lambda x: '%s', gids))
                    sql_in = sql_in % in_p
                    sql = 'update system_grouplist set `tag`=%s, `tagid`=%s where `userid`=%s and `gid` in ' + sql_in
                    mysql_write_cursor.execute(sql, tagname, tagid, userid, *gids)
                except Exception, ex:
                    print ex
                    self.write('0')
                    return
            else:
                try:
                    sql = 'update system_grouplist set `tag`=%s, `tagid`=%s where `gid`=%s and `userid`=%s'
                    mysql_write_cursor.execute(sql, tagname, tagid, gids[0], userid)
                except Exception, ex:
                    print ex
                    self.write('0')
                    return
            self.write('1')


class AnalysisHandler(BaseHandler):
    '''统计分析接口
    '''

    @tornado.web.authenticated
    def get(self):
        username = self.get_secure_cookie(pre_system + 'username')
        userid = self.get_secure_cookie(pre_system + 'userid')
        sql = 'select kwid, subname from system_keywords where `userid`=%s'
        keywordslist = mysql_cursor.query(sql, userid)
        self.render('analysis.html', username=username,
                    keywordslist=keywordslist,
                    )


class AnalysisMethodHandler(BaseHandler):
    '''统计分析模块
    1. 倾向性走势图
    '''
    def post(self, method):
        userid = self.get_secure_cookie(pre_system + 'userid')
        if not userid:
            self.write('2')
            return

        if method == 'filter':
            # 只查看单个关键字数据
            # 倾向性走势图
            kwid = self.get_argument('kwid', '')
            createtime = self.get_argument('createtime', '')
            if not (kwid and createtime):
                # 缺少参数
                return 0
            createtime = urllib.unquote(createtime)
            start_time = createtime.split(' ')[0] + ' 00:00:00'
            stop_time = createtime.split(' ')[2] + ' 23:59:59'

            date_list = []
            begin_date = datetime.datetime.strptime(createtime.split(' ')[0], "%Y-%m-%d")
            end_date = datetime.datetime.strptime(createtime.split(' ')[2], "%Y-%m-%d")
            while begin_date <= end_date:
                date_str = begin_date.strftime("%Y-%m-%d")
                date_list.append(date_str)
                begin_date += datetime.timedelta(days=1)

            sql = 'select count(*) as count,createtime,kwid from system_warning where userid=%s and kwid=%s and createtime>=%s and createtime<=%s group by date(createtime)'
            warning_data = mysql_cursor.query(sql, userid, kwid, start_time, stop_time)

            result = []
            data_w = []
            total_w = 0
            for line in date_list:
                num = 0
                for tmpline in warning_data:
                    if line in str(tmpline['createtime']):
                        total_w += int(tmpline['count'])
                        num = int(tmpline['count'])
                        break
                data_w.append(num)
            # 数据组合
            warning = {}
            warning['data'] = data_w
            warning['name'] = '预警信息总数'
            warning['total'] = total_w
            result.append(warning)

            # 群消息量饼状图
            sql = 'select count(gid) as count, gname, kwid from system_warning where userid=%s and kwid=%s and createtime>=%s and createtime<=%s group by gid order by count desc limit 20'
            ret = mysql_cursor.query(sql, userid, kwid, start_time, stop_time)

            groupinfonum = []
            total = 0
            for line in ret:
                total += int(line['count'])
                groupinfonum.append({'gname': line['gname'], 'count': line['count']})
            groupinfonum.append({'total': total})

            self.write(json.dumps({'msg': result, 'groupinfonum': groupinfonum}))
            return

        if method == 'keyword':
            # 倾向性走势图
            today = datetime.date.today()
            sixday = datetime.timedelta(days=6)
            week = today - sixday

            start_time = str(week) + ' 00:00:00'
            stop_time = str(today) + ' 23:59:59'
            date_list = []
            begin_date = datetime.datetime.strptime(str(week), "%Y-%m-%d")
            end_date = datetime.datetime.strptime(str(today), "%Y-%m-%d")
            while begin_date <= end_date:
                date_str = begin_date.strftime("%Y-%m-%d")
                date_list.append(date_str)
                begin_date += datetime.timedelta(days=1)
            sql = 'select count(*) as count,createtime from system_content where userid=%s \
            and createtime>=%s and createtime<=%s group by date(createtime)'
            # 群消息总数
            content_data = mysql_cursor.query(sql, userid, start_time, stop_time)
            # sql = 'select count(1) as count,createtime, subname from system_warning as warn, \
            #     system_keywords as kw where warn.kwid=kw.kwid and warn.userid=%s and createtime>=%s and createtime<=%s group by date(createtime)'
            # keyword_data = mysql_cursor.query(sql, userid, start_time, stop_time)
            # 保存每个月的值

            sql = 'select count(*) as count,createtime from system_warning where \
            userid=%s and createtime>=%s and createtime<=%s group by date(createtime)'
            # 预警消息总数
            warning_data = mysql_cursor.query(sql, userid, start_time, stop_time)

            data_d = []
            total_d = 0
            data_w = []
            total_w = 0
            for line in date_list:
                num = 0
                for tmpline in content_data:
                    if line in str(tmpline['createtime']):
                        total_d += int(tmpline['count'])
                        num = int(tmpline['count'])
                        break
                data_d.append(num)

                num = 0
                for tmpline in warning_data:
                    if line in str(tmpline['createtime']):
                        total_w += int(tmpline['count'])
                        num = int(tmpline['count'])
                        break
                data_w.append(num)
            # 数据组合
            result = []
            content = {}
            content['data'] = data_d
            content['name'] = '群信息总数'
            content['total'] = total_d

            warning = {}
            warning['data'] = data_w
            warning['name'] = '预警信息总数'
            warning['total'] = total_w
            result.append(content)
            result.append(warning)

            # 群消息量饼状图
            sql = 'select * from (select count(gid) as count, gid,gname from system_content where `userid`=%s \
                    and createtime>=%s and createtime<=%s group by gid, gname) as t order by t.count desc limit 20'
            ret = mysql_cursor.query(sql, userid, start_time, stop_time)
            groupinfonum = []
            total = 0
            for line in ret:
                total += int(line['count'])
                groupinfonum.append({'gname': line['gname'], 'count': line['count']})
            groupinfonum.append({'total': total})

            # 今日发言量前十
            sql = 'select * from (select count(*) as count, gid,gname from system_content where `userid`=%s \
                and createtime>=%s and createtime<=%s group by gid, gname) as t order by count desc limit 10'
            start_today = str(today) + ' 00:00:00'
            stop_today = str(today) + ' 23:59:59'
            top10_msg = mysql_cursor.query(sql, userid, start_today, stop_today)

            # 今日预警消息量前十
            sql = 'select * from (select count(*) as count, gid, gname from system_warning where `userid`=%s \
                and createtime>=%s and createtime<=%s group by gid, gname) as t order by count desc limit 10'
            top10_warning = mysql_cursor.query(sql, userid, start_today, stop_today)

            # 人数排名前十
            # sql = 'select count(m.gid) as count, m.gid, displayName from system_group_members as m where m.userid=%s group by gid order by count desc limit 10'
            # sql = '''
            #     SELECT
            #         count(m.gid) as count, max(m.gid) as gid, max(g.displayName) as displayName
            #     FROM
            #         system_group_members as m, system_grouplist as g
            #     WHERE
            #         m.userid=%s and m.gid=g.gid and g.userid=%s
            #     group by m.gid order by count desc limit 10
            #
            # '''
            # top10_member = mysql_cursor.query(sql, userid, userid)
            sql = '''
            SELECT
               t.count, g.nickName as displayName,t.gid
            from
                system_grouplist as g ,
                (select * from (select
                    count(*) as count , gid
                from system_group_members
                where userid=%s
                group by gid) as t_in order by count desc limit 10) as t

            where
                g.userid=%s and g.gid=t.gid;
            '''
            top10_member = mysql_cursor.query(sql, userid, userid)
            # # 修改群名称
            # gidlist = [i['gid'] for i in top10_member_incr]
            # in_p = ','.join(map(lambda x:'%s', gidlist))
            # sql = 'select displayName from system_grouplist as g where gid in (%s)' % in_p
            # dispalynamelist = mysql_cursor.query(sql, *gidlist)

            # 今日新增人数排名前十
            # sql = 'select count(m.gid) as count, m.gid, displayName from system_group_members\
            #  as m where m.userid=%s and m.createtime>=%s and m.createtime<=%s group by \
            #  gid order by count desc limit 10'
            sql = '''
                SELECT
                    count(m.gid) as count, max(m.gid) as gid, max(g.nickName) as displayName
                FROM
                    system_group_members as m, system_grouplist as g
                WHERE
                    m.userid=%s and m.gid=g.gid and g.userid=%s
                    and m.createtime>=%s and m.createtime<=%s
                group by m.gid order by count desc limit 10
            '''
            top10_member_incr = mysql_cursor.query(sql, userid, userid, start_today, stop_today)


            self.write(json.dumps({'msg': result,
                                    'groupinfonum': groupinfonum,
                                    'top10_msg': top10_msg,
                                    'top10_warning': top10_warning,
                                    'top10_member': top10_member,
                                    'top10_member_incr': top10_member_incr
                                    })
                                )

        if method == 'msg': #走势图
            # 倾向性走势图
            today = datetime.date.today()
            sixday = datetime.timedelta(days=6)
            week = today - sixday

            start_time = str(week) + ' 00:00:00'
            stop_time = str(today) + ' 23:59:59'
            date_list = []
            begin_date = datetime.datetime.strptime(str(week), "%Y-%m-%d")
            end_date = datetime.datetime.strptime(str(today), "%Y-%m-%d")
            while begin_date <= end_date:
                date_str = begin_date.strftime("%Y-%m-%d")
                date_list.append(date_str)
                begin_date += datetime.timedelta(days=1)
            # 群消息总数
            # sql = 'select count(*) as count,createtime from system_content where userid=%s \
            # and createtime>=%s and createtime<=%s group by date(createtime)'
            # content_data = mysql_cursor.query(sql, userid, start_time, stop_time)
            #sql = """
            #    SELECT
            #    	sum(qunmsg) as qunmsg, sum(warnmsg) as warnmsg,
            #        date(a.createtime) as createtime
            #    from
            #    	system_analysis as a, system_grouplist as g
            #    where
            #    	g.gid=a.gid and g.userid=%s
            #        and a.createtime>=%s
            #        and a.createtime<=%s
            #    group by
            #    	a.createtime
            #"""
            sql = '''
                SELECT
                sum(msg_total) as qunmsg ,sum(warn_total) as warnmsg , date(updatetime) as createtime
                from
                system_everyday_total
                where
                userid = %s
                and updatetime >=%s and updatetime <=%s
                group by updatetime
            '''
            content_data = mysql_cursor.query(sql, userid, start_time, stop_time)
            for content in content_data:
                content['createtime'] = str(content['createtime'])
                content['qunmsg'] = str(content['qunmsg'])
                content['warnmsg'] = str(content['warnmsg'])



            # 群消息量饼状图
            #sql = """
            #    SELECT
            #        a.qunmsg, g.nickname, g.displayName
            #    FROM
            #        system_analysis as a, system_grouplist as g
            #    WHERE
            #        g.gid=a.gid and g.userid=%s
            #        and a.createtime>=%s
            #        and a.createtime<=%s
            #    ORDER BY a.qunmsg desc limit 20
            #"""

            sql = '''
                SELECT
                    n.qunmsg, g.nickname,g.displayName
                FROM
                    (select sum(a.qunmsg)as qunmsg,a.gid
                    from system_analysis as a
                    where a.createtime>=%s and a.createtime<=%s
                    group by a.gid) as n,system_grouplist as g
                WHERE
                    g.gid=n.gid and g.userid=%s
                ORDER BY n.qunmsg desc limit 20
            '''
            groupinfo = mysql_cursor.query(sql, start_time, stop_time, userid)
            groupinfonum = [{'gname':str(group['nickname']), 'count':str(group['qunmsg'])} for group in groupinfo]
            total = sum([group['qunmsg'] for group in groupinfo])
            groupinfonum.append({'total': str(total)})

            # sql = 'select * from (select count(gid) as count, gid,gname from \
            # system_content where `userid`=%s and createtime>=%s and \
            # createtime<=%s group by gid, gname) as t order by t.count desc limit 20'
            # ret = mysql_cursor.query(sql, userid, start_time, stop_time)
            # groupinfonum = []
            # total = 0
            # for line in ret:
            #     total += int(line['count'])
            #     groupinfonum.append({'gname': line['gname'], 'count': line['count']})
            # groupinfonum.append({'total': total})
            self.write(json.dumps({'msg': content_data,
                                    'groupinfonum': groupinfonum,
                                    })
                                )

        if method == 'top':
            # 倾向性走势图
            today = datetime.date.today()
            sixday = datetime.timedelta(days=6)
            week = today - sixday

            start_time = str(week) + ' 00:00:00'
            stop_time = str(today) + ' 23:59:59'
            date_list = []
            begin_date = datetime.datetime.strptime(str(week), "%Y-%m-%d")
            end_date = datetime.datetime.strptime(str(today), "%Y-%m-%d")
            while begin_date <= end_date:
                date_str = begin_date.strftime("%Y-%m-%d")
                date_list.append(date_str)
                begin_date += datetime.timedelta(days=1)
            # 今日发言量前十
            sql = """
                SELECT newmsg as count, nickname as gname From system_grouplist
                where userid=%s order by newmsg desc limit 10
            """
            start_today = str(today) + ' 00:00:00'
            stop_today = str(today) + ' 23:59:59'
            top10_msg = mysql_cursor.query(sql, userid)

            # 今日预警消息量前十
            sql = 'select * from (select count(*) as count, gid, gname from system_warning where `userid`=%s \
                and createtime>=%s and createtime<=%s group by gid, gname) as t order by count desc limit 10'
            top10_warning = mysql_cursor.query(sql, userid, start_today, stop_today)

            # 人数排名前十
            # sql = '''
            # SELECT
            #    t.count, g.displayName,t.gid
            # from
            #     system_grouplist as g ,
            #     (select * from (select
            #         count(*) as count , gid
            #     from system_group_members
            #     where userid=%s
            #     group by gid) as t_in order by count desc limit 10) as t
            #
            # where
            #     g.userid=%s and g.gid=t.gid;
            # '''
            sql = 'select nickName as displayName, gid, totaluser as count from \
            system_grouplist where userid=%s order by totaluser desc limit 10'
            top10_member = mysql_cursor.query(sql, userid)

            # 今日新增人数排名前十
            sql = '''
                SELECT
                    count(m.gid) as count, max(m.gid) as gid, max(g.nickName) as displayName
                FROM
                    system_group_members as m, system_grouplist as g
                WHERE
                    m.userid=%s and m.gid=g.gid and g.userid=%s
                    and m.createtime>=%s and m.createtime<=%s
                group by m.gid order by count desc limit 10
            '''
            top10_member_incr = mysql_cursor.query(sql, userid, userid, start_today, stop_today)
            self.write(json.dumps({
                                    'top10_msg': top10_msg,
                                    'top10_warning': top10_warning,
                                    'top10_member': top10_member,
                                    'top10_member_incr': top10_member_incr
                                    })
                                )

class PullInfoHandler(BaseHandler):
    '''右下角拉取推送信息接口
    '''
    @tornado.web.authenticated
    def get(self):
        pass

    def post(self):
        userid = self.get_secure_cookie(pre_system + 'userid')
        if not userid:
            # 则登录已经失效
            self.write('2')
            return

        # 一次性取3条记录
        warninglist = []
        for _ in xrange(3):
            ret = redis_cache.rpop(pre_system + 'warninglist:' + str(userid))
            if ret:
                warninglist.append(ret)
            else:
                break
        tmpwarninglist = []

        for line in warninglist:
            tmpline = json.loads(line)
            if tmpline['content'].startswith('<?xml version="1.0"?>'):
                # 如果掉是xml的内容  否则右下角窗口无法显示
                continue
            tmpwarninglist.append(tmpline)

        # 将数据写回队列  右下角只是提示功能  并不真正取数据
        for line in tmpwarninglist:
            redis_cache.rpush(pre_system + 'warninglist:' + userid, json.dumps({'username': line['username'],
            'gname': line['gname'], 'createtime': line['createtime'], 'content': line['content'],
            'keyword': line['keyword'], 'conid': line['conid'], 'sender_wechatid': line['sender_wechatid'], 'gid': line['gid']}))

        self.write(json.dumps({'data': tmpwarninglist}))


class LeftPanelHandler(BaseHandler):
    '''# 左边消息数量 接口
       # 如果值是2 则登录已经失效
    '''
    def post(self, method):
        userid = self.get_secure_cookie(pre_system + 'userid')
        if not userid:
            self.write('2')
            return

        if method == 'num':
            groupinfonum = redis_cache.get(
                pre_system + 'groupinfonum:' + str(userid))
            warningnum = redis_cache.get(
                pre_system + 'warningnum:' + str(userid))
            if not warningnum:
                warningnum = 0

            if not groupinfonum:
                groupinfonum = 0
            self.write(json.dumps(
                {'groupinfonum': groupinfonum, 'warningnum': warningnum}))
            return


class UserManageHandler(BaseHandler):
    # 管理员后台用户管理模块

    @tornado.web.authenticated
    def get(self, method):
        print method

    @tornado.web.authenticated
    def post(self, method):
        userid = self.get_secure_cookie(pre_system + 'userid')
        username = self.get_secure_cookie(pre_system + 'username')
        groupid = self.get_secure_cookie(pre_system + 'groupid')
        ip = self.request.remote_ip
        if method == 'chgpass':
            # 普通用户修改密码
            password1 = self.get_argument('password1', '')
            password2 = self.get_argument('password2', '')
            if password1 != password2:
                # 两次密码不相同
                self.write('2')
            elif len(password1) < 6:
                # 密码长度不能小于6
                self.write('3')
            else:
                password = hashlib.md5(password1).hexdigest()
                sql = 'update system_user set `password`=%s where `userid`=%s'
                mysql_write_cursor.execute(sql, password, userid)
                setlog(userid, username, ip, '修改了密码', 1, mysql_cursor)
                self.write('1')
            return

        # 管理员后台需要权限限制
        if groupid != '0':
            self.write('0')
            return

        if method == 'del':
            # 删除用户
            userid = self.get_argument('userid', '')
            sql = 'delete from system_user where `userid`=%s'
            mysql_write_cursor.execute(sql, userid)
            setlog(userid, username, ip, '删除了userid为%s的帐号' %
                   userid, 1, mysql_cursor)
            self.write('1')
            return
        elif method == 'edit':
            # 编辑
            uid = self.get_argument('userid', '')
            expiretime = self.get_argument('expiretime', '')
            comment = self.get_argument('comment', '')
            sql = 'update system_user set `expiretime`=%s, `comment`=%s where `userid`=%s'
            mysql_write_cursor.execute(sql, expiretime, comment, uid)
            self.write('1')
            return
        elif method == 'add':
            # 添加用户
            opname = self.get_secure_cookie(pre_system + 'username')
            username = self.get_argument('username', '')
            expiretime = self.get_argument('expiretime', '')
            comment = self.get_argument('comment', '')
            if username and expiretime and comment:
                # 判断用户是否已经存在
                sql = 'select username from system_user where `username`=%s'
                ret = mysql_cursor.query(sql, username)
                if ret:
                    self.write('2')
                    return
                sql = 'insert into system_user (`groupid`, `username`, `password`, \
                `createtime`, `expiretime`, `comment`, `lastloginip`) \
                values (%s, %s, %s, %s, %s, %s, %s)'
                password = hashlib.md5('123456').hexdigest()
                createtime = getdatetime()
                mysql_write_cursor.execute(
                    sql, 1, username, password, createtime, expiretime, comment, '')
                setlog(userid, opname, ip, '添加了一个帐号, %s' %
                       username, 1, mysql_cursor)
                self.write('1')
            else:
                self.write('0')
            return
        elif method == 'resetpass':
            # 重置密码
            uid = self.get_argument('userid', '')
            password = hashlib.md5('123456').hexdigest()
            sql = 'update system_user set `password`=%s where `userid`=%s'
            mysql_write_cursor.execute(sql, password, uid)
            self.write('1')


class SearchHandler(BaseHandler):
    '''信息检索 模块
    '''
    @tornado.web.authenticated
    def get(self):
        username = self.get_secure_cookie(pre_system + 'username')
        userid = self.get_secure_cookie(pre_system + 'userid')
        searchtype = self.get_argument('searchtype', '')
        keyword = self.get_argument('keyword', '')
        gids = self.get_argument('gids', '')
        createtime = self.get_argument('createtime', '')

        if searchtype == '2':
            # 暂不支持内容搜索
            self.write('2')
            return

        if not searchtype:
            sql = 'select `id`,`gid`,`nickname`,`createtime`,`tag`, `displayName` from system_grouplist where `userid`=%s'
            grouplist = mysql_cursor.query(sql, userid)
            msglist = ''
            gids = ''
            self.render('search.html', username=username,
                        grouplist=grouplist,
                        msglist=msglist,
                        gids=gids,
                        )
            return

        if searchtype and keyword and gids and createtime:
            createtime = urllib.unquote(createtime)
            start_time = createtime.split(' ')[0] + ' 00:00:00'
            stop_time = createtime.split(' ')[2] + ' 23:59:59'
            # 判断是不是全选
            if gids == 'all':
                # 所有群查询
                total = mysql_cursor.query('select count(*) as "count" from (select * from system_content where \
                `userid`=%s and `createtime` >=%s and `createtime`<=%s) as tmp where `sender_wechatid`=%s', userid, start_time, stop_time, keyword)[0]['count']
                pagesize = float(self.get_argument('pagenum', 15))
                maxpage = int(ceil(int(total) / pagesize))
                page_cur = int(self.get_argument('page', 0))
                method = self.get_argument('method', 'top')

                if method == 'top':
                    page = 0
                elif method == 'prev':
                    if page_cur > 1:
                        page = page_cur - 1
                    else:
                        page = 0
                elif method == 'next':
                    if page_cur < maxpage - 1:
                        page = page_cur + 1
                    else:
                        if maxpage != 0:
                            page = maxpage - 1
                        else:
                            page = 0
                elif method == 'bottom':
                    if maxpage != 0:
                        page = maxpage - 1
                    else:
                        page = 0
                else:
                    page = page_cur - 1

                startindex = page * pagesize
                stopindex = pagesize

                startpagenum = (page_cur - 6 < 1) and 1 or (page_cur - 6)
                endpagenum = (startpagenum + 9 >
                              maxpage) and maxpage or startpagenum + 9

                sql = 'select * from (select * from system_content where `userid`=%s and `createtime` >=%s and `createtime`<=%s) as tmp where `sender_wechatid`=%s order by id desc limit %s, %s'
                msglist = mysql_cursor.query(sql, userid, start_time, stop_time, keyword, startindex, stopindex)
                sql = 'select `id`,`gid`,`nickname`,`createtime`,`tag`, `displayName` from system_grouplist where `userid`=%s'
                grouplist = mysql_cursor.query(sql, userid)
                self.render('search.html', username=username,
                            grouplist=grouplist,
                            msglist=msglist,
                            gids=gids,
                            keyword=keyword,
                            searchtype=searchtype,
                            createtime=createtime,
                            page=page,
                            total=total,
                            pagenum=maxpage,
                            startpagenum=startpagenum,
                            endpagenum=endpagenum
                            )
                return

            # 多群查询时要用到原始gids
            tmpgids = gids
            gids = gids.split(',')
            if len(gids) == 1:
                # 单个群查询
                total = mysql_cursor.query('select count(*) as "count" from (select * from system_content where \
                `userid`=%s and `createtime` >=%s and `gid`=%s and `createtime`<=%s) as tmp where `sender_wechatid`=%s', userid, start_time, stop_time, gids[0], keyword)[0]['count']
                pagesize = float(self.get_argument('pagenum', 15))
                maxpage = int(ceil(int(total) / pagesize))
                page_cur = int(self.get_argument('page', 0))
                method = self.get_argument('method', 'top')

                if method == 'top':
                    page = 0
                elif method == 'prev':
                    if page_cur > 1:
                        page = page_cur - 1
                    else:
                        page = 0
                elif method == 'next':
                    if page_cur < maxpage - 1:
                        page = page_cur + 1
                    else:
                        if maxpage != 0:
                            page = maxpage - 1
                        else:
                            page = 0
                elif method == 'bottom':
                    if maxpage != 0:
                        page = maxpage - 1
                    else:
                        page = 0
                else:
                    page = page_cur - 1

                startindex = page * pagesize
                stopindex = pagesize

                startpagenum = (page_cur - 6 < 1) and 1 or (page_cur - 6)
                endpagenum = (startpagenum + 9 >
                              maxpage) and maxpage or startpagenum + 9

                sql = 'select * from (select * from system_content where `userid`=%s and `gid`=%s and `createtime` >=%s \
                    and `createtime`<=%s) as tmp where `sender_wechatid`=%s limit %s, %s'
                msglist = mysql_cursor.query(sql, userid, gids[0], start_time, stop_time, keyword, startindex, stopindex)
                sql = 'select `id`,`gid`,`nickname`,`createtime`,`tag`, `displayName` from system_grouplist where `userid`=%s'
                grouplist = mysql_cursor.query(sql, userid)
                self.render('search.html', username=username,
                            grouplist=grouplist,
                            msglist=msglist,
                            gids=gids[0],
                            keyword=keyword,
                            searchtype=searchtype,
                            createtime=createtime,
                            page=page,
                            total=total,
                            pagenum=maxpage,
                            startpagenum=startpagenum,
                            endpagenum=endpagenum
                            )
                return
            else:
                # 多个群查询
                args = []
                args.append(userid)
                for line in gids:
                    args.append(line)
                args.append(start_time)
                args.append(stop_time)
                args.append(keyword)
                in_p = ', '.join(map(lambda x: '%s', gids))

                sql = 'select count(*) as "count" from (select * from system_content where `userid`=%s and `gid` in (' + in_p + ') and `createtime` >=%s and `createtime`<=%s) as tmp where `sender_wechatid`=%s'
                total = mysql_cursor.query(sql, *args)[0]['count']
                pagesize = float(self.get_argument('pagenum', 15))
                maxpage = int(ceil(int(total) / pagesize))
                page_cur = int(self.get_argument('page', 0))
                method = self.get_argument('method', 'top')

                if method == 'top':
                    page = 0
                elif method == 'prev':
                    if page_cur > 1:
                        page = page_cur - 1
                    else:
                        page = 0
                elif method == 'next':
                    if page_cur < maxpage - 1:
                        page = page_cur + 1
                    else:
                        if maxpage != 0:
                            page = maxpage - 1
                        else:
                            page = 0
                elif method == 'bottom':
                    if maxpage != 0:
                        page = maxpage - 1
                    else:
                        page = 0
                else:
                    page = page_cur - 1

                startindex = page * pagesize
                stopindex = pagesize

                startpagenum = (page_cur - 6 < 1) and 1 or (page_cur - 6)
                endpagenum = (startpagenum + 9 >
                              maxpage) and maxpage or startpagenum + 9

                args.append(startindex)
                args.append(stopindex)
                sql = 'select * from (select * from system_content where `userid`=%s and `gid` in (' + in_p + ') \
                    and `createtime` >=%s and `createtime`<=%s) as tmp where `sender_wechatid`=%s limit %s, %s'
                msglist = mysql_cursor.query(sql, *args)
                sql = 'select `id`,`gid`,`nickname`,`createtime`,`tag`, `displayName` from system_grouplist where `userid`=%s'
                grouplist = mysql_cursor.query(sql, userid)
                self.render('search.html', username=username,
                            grouplist=grouplist,
                            msglist=msglist,
                            gids=tmpgids,
                            keyword=keyword,
                            searchtype=searchtype,
                            createtime=createtime,
                            page=page,
                            total=total,
                            pagenum=maxpage,
                            startpagenum=startpagenum,
                            endpagenum=endpagenum
                            )
                return


class nopageHandler(BaseHandler):
    '''没有被收集到的错误默认为404'''

    def get(self, *args, **kwargs):
        self.render('404.html')


class KeyWechatList(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        username = self.get_secure_cookie(pre_system + 'username')
        userid = self.get_secure_cookie(pre_system + 'userid')
        wechatid = self.get_argument('wechatid', '')
        if wechatid:
            total = mysql_cursor.query(
                'select count(*) as "count" from system_keywechat_list where `userid`=%s and `wechatid`=%s', userid, wechatid)[0]['count']
        else:
            total = mysql_cursor.query(
                'select count(*) as "count" from system_keywechat_list where `userid`=%s', userid)[0]['count']
        pagesize = float(self.get_argument('pagenum', 15))
        maxpage = int(ceil(int(total) / pagesize))
        page_cur = int(self.get_argument('page', 0))
        method = self.get_argument('method', 'top')

        if method == 'top':
            page = 0
        elif method == 'prev':
            if page_cur > 1:
                page = page_cur - 1
            else:
                page = 0
        elif method == 'next':
            if page_cur < maxpage - 1:
                page = page_cur + 1
            else:
                if maxpage != 0:
                    page = maxpage - 1
                else:
                    page = 0
        elif method == 'bottom':
            if maxpage != 0:
                page = maxpage - 1
            else:
                page = 0
        else:
            page = page_cur - 1

        startindex = page * pagesize
        stopindex = pagesize

        startpagenum = (page_cur - 6 < 1) and 1 or (page_cur - 6)
        endpagenum = (startpagenum + 9 >
                      maxpage) and maxpage or startpagenum + 9
        if wechatid:
            sql = 'select id, wechatid, nickname, addkey, addtime from system_keywechat_list where `userid`=%s and `wechatid`=%s order by id desc limit %s, %s'
            userlist = mysql_cursor.query(sql, userid, wechatid, startindex, stopindex)
        else:
            sql = 'select id, wechatid, nickname, addkey, addtime from system_keywechat_list where `userid`=%s order by id desc limit %s, %s'
            userlist = mysql_cursor.query(sql, userid, startindex, stopindex)
        self.render('keywechat.html', username=username,
                    wechatid=wechatid,
                    userlist=userlist,
                    page=page,
                    total=total,
                    pagenum=maxpage,
                    startpagenum=startpagenum,
                    endpagenum=endpagenum
                    )

    @tornado.web.authenticated
    def post(self, method):
        username = self.get_secure_cookie(pre_system + 'username')
        userid = self.get_secure_cookie(pre_system + 'userid')
        if not userid:
            # 4 登录超时
            self.write('4')
            return

        if method == 'add':
            # 3 参数为空
            # 2 已经添加过
            # 1 添加成功
            # 0 添加失败
            wechatid = self.get_argument('wechatid', '')
            nickname = self.get_argument('nickname', '')
            addkey = self.get_argument('addkey','')
            if not addkey:
                self.write('3')
                return
            if not (wechatid and nickname):
                # 已经添加过
                self.write('3')
                return
            sql = 'select id from system_keywechat_list where `userid`=%s and `wechatid`=%s'
            ret = mysql_cursor.query(sql, userid, wechatid)
            if ret:
                self.write('2')
                return
            sql = 'insert into system_keywechat_list (`wechatid`, `nickname`, `addtime`, `userid`, `addkey`) values (%s, %s, %s, %s, %s)'
            try:
                mysql_write_cursor.execute(sql, wechatid, nickname, getdatetime(), userid, addkey)
                self.write('1')
            except Exception, ex:
                print ex
                self.write('0')

        if method == 'del':
            # 删除成功
            wid = self.get_argument('id', '')
            sql = 'delete from system_keywechat_list where `userid`=%s and `id`=%s'
            try:
                mysql_write_cursor.execute(sql, userid, wid)
                self.write('1')
            except Exception, ex:
                print ex
                self.write('0')


class GroupMSGFrameHandler(BaseHandler):
    # 群消息Frame窗体列表

    @tornado.web.authenticated
    def get(self):
        username = self.get_secure_cookie(pre_system + 'username')
        userid = self.get_secure_cookie(pre_system + 'userid')
        gid = self.get_argument('gid', '')
        wechatid = self.get_argument('wechatid', '')
        # 按时间段搜索
        searchtime = self.get_argument('t', '')

        t = searchtime
        if searchtime:
            searchtime = urllib.unquote(searchtime)
            start_time = searchtime.split(' ')[0] + ' 00:00:00'
            stop_time = searchtime.split(' ')[2] + ' 23:59:59'
        else:
            # 默认之查看当天数据
            start_time = time.strftime('%Y-%m-%d 00:00:00', time.localtime())
            stop_time = time.strftime('%Y-%m-%d 23:59:59', time.localtime())

        # 群消息数量设置为0
        redis_cache.delete(pre_system + 'groupinfonum:' + str(userid))

        if gid:
            if wechatid:
                # 单个用户在群里的发言
                total = mysql_cursor.query(
                    'select count(*) as "count" from system_content where `userid`=%s and `gid`=%s and `sender_wechatid`=%s', userid, gid, wechatid)[0]['count']
            else:
                # 查看单独的群信息
                total = mysql_cursor.query(
                    'select count(*) as "count" from system_content where `userid`=%s and `gid`=%s and `createtime`>=%s and `createtime`<=%s', userid, gid, start_time, stop_time)[0]['count']
        else:
            total = mysql_cursor.query(
                'select count(*) as "count" from system_content where `userid`=%s', userid)[0]['count']

        pagesize = float(self.get_argument('pagenum', 15))
        maxpage = int(ceil(int(total) / pagesize))
        page_cur = int(self.get_argument('page', 0))
        method = self.get_argument('method', 'top')

        if method == 'top':
            page = 0
        elif method == 'prev':
            if page_cur > 1:
                page = page_cur - 1
            else:
                page = 0
        elif method == 'next':
            if page_cur < maxpage - 1:
                page = page_cur + 1
            else:
                if maxpage != 0:
                    page = maxpage - 1
                else:
                    page = 0
        elif method == 'bottom':
            if maxpage != 0:
                page = maxpage - 1
            else:
                page = 0
        else:
            page = page_cur - 1

        startindex = page * pagesize
        stopindex = pagesize

        startpagenum = (page_cur - 6 < 1) and 1 or (page_cur - 6)
        endpagenum = (startpagenum + 9 >
                      maxpage) and maxpage or startpagenum + 9
        if gid:
            # 判断是否是查看该群的某个用户的所有信息
            if wechatid:
                # 查看单独的群中的单独用户发言信息
                sql = 'select id,userid,content,sender_wechatid,username,gid,createtime,gname from system_content where `userid`=%s and `gid`=%s and `sender_wechatid`=%s order by id desc limit %s, %s'
                msglist = mysql_cursor.query(
                    sql, userid, gid, wechatid, startindex, stopindex)
            else:
                # 查看单独的群信息
                sql = 'select id,userid,content,sender_wechatid,username,gid,createtime,gname from system_content where `userid`=%s and `gid`=%s and \
                    `createtime`>=%s and `createtime`<=%s order by id desc limit %s, %s'
                msglist = mysql_cursor.query(
                    sql, userid, gid, start_time, stop_time, startindex, stopindex)
        else:
            sql = 'select id,userid,content,sender_wechatid,username,gid,createtime,gname from system_content where `userid`=%s order by id desc limit %s, %s'
            msglist = mysql_cursor.query(sql, userid, startindex, stopindex)

        if msglist:
            dispgname = msglist[0]['gname']
        else:
            dispgname = ''
        self.render('msgframe.html',
                    t=t,
                    dispgname=dispgname,
                    msglist=msglist,
                    gid=gid,
                    wechatid=wechatid,
                    username=username,
                    page=page,
                    total=total,
                    pagenum=maxpage,
                    startpagenum=startpagenum,
                    endpagenum=endpagenum
                    )


    @tornado.web.authenticated
    def post(self):
        # 获取群列表
        userid = self.get_secure_cookie(pre_system + 'userid')
        total = mysql_cursor.query(
            'select count(*) as "count" from system_grouplist where `userid`=%s', userid)[0]['count']
        pagesize = float(self.get_argument('pagenum', 27))
        maxpage = int(ceil(int(total) / pagesize))
        page_cur = int(self.get_argument('page', 0))
        method = self.get_argument('method', 'next')

        if method == 'next':
            if page_cur < maxpage - 1:
                page = page_cur + 1
            else:
                if maxpage != 0:
                    page = maxpage - 1
                else:
                    page = 0
        else:
            page = page_cur - 1

        startindex = page * pagesize
        stopindex = pagesize

        startpagenum = (page_cur - 6 < 1) and 1 or (page_cur - 6)
        endpagenum = (startpagenum + 9 >
                      maxpage) and maxpage or startpagenum + 9
        sql = 'select `gid`, `displayName` from system_grouplist where `userid`=%s limit %s, %s'
        grouplist = mysql_cursor.query(sql, userid, startindex, stopindex)
        self.write(json.dumps({'grouplist': grouplist, 'total': maxpage, 'page': page_cur}))


class Executor(ThreadPoolExecutor):
  _instance = None

  def __new__(cls, *args, **kwargs):
    if not getattr(cls, '_instance', None):
      cls._instance = ThreadPoolExecutor(max_workers=10)
    return cls._instance


class ReportHandler(BaseHandler):
    # 导出报表
    # def get(self):
    #     pass

    @tornado.web.asynchronous
    @tornado.gen.coroutine
    @tornado.web.authenticated
    def post(self):
        userid = self.get_secure_cookie(pre_system + 'userid')
        gid = self.get_argument('gid', '')
        wechatid = self.get_argument('wechatid', '')
        # 按时间段搜索
        searchtime = self.get_argument('t', '')
        t = searchtime
        if searchtime:
            searchtime = urllib.unquote(searchtime)
            start_time = searchtime.split(' ')[0] + ' 00:00:00'
            stop_time = searchtime.split(' ')[2] + ' 23:59:59'
        else:
            # 默认之查看当天数据
            start_time = time.strftime('%Y-%m-%d 00:00:00', time.localtime())
            stop_time = time.strftime('%Y-%m-%d 23:59:59', time.localtime())

        if gid:
            # 判断是否是查看该群的某个用户的所有信息
            if wechatid:
                # 查看单独的群中的单独用户发言信息
                sql = 'select id,userid,content,sender_wechatid,username,gid,createtime\
                ,gname from system_content where `userid`=%s and `gid`=%s and \
                `sender_wechatid`=%s and \
                    `createtime`>=%s and `createtime`<=%s order by id desc'
                msglist = mysql_cursor.query(
                    sql, userid, gid, wechatid, start_time, stop_time)
            else:
                # 查看单独的群信息
                sql = 'select id,userid,content,sender_wechatid,username,gid,\
                createtime,gname from system_content where `userid`=%s and `gid`=%s and \
                    `createtime`>=%s and `createtime`<=%s order by id desc'
                msglist = mysql_cursor.query(
                    sql, userid, gid, start_time, stop_time)
        else:
            sql = 'select id,userid,content,sender_wechatid,username,gid,\
            createtime,gname from system_content where `userid`=%s and \
                `createtime`>=%s and `createtime`<=%s order by id desc'
            msglist = mysql_cursor.query(sql, userid, start_time, stop_time)
        if not msglist:
            self.write(json.dumps({'status':0,'error':'没有数据'}))
            return
        # 开始导出
        future = Executor().submit(exreport, msglist, userid)
        try:
            ret = yield tornado.gen.with_timeout(datetime.timedelta(seconds=60), future)
            ret = ret.result()
        except tornado.gen.TimeoutError:
            ret = {'status':0, 'error':'超时,请选择更小的任务'}
        self.write(json.dumps(ret))

class DownloadHandler(BaseHandler):
    #下载报表
    def get(self, filename):
        self.set_header ('Content-Type', 'application/octet-stream')
        self.set_header ('Content-Disposition', 'attachment; filename=' + filename)
        buf_size = 4096
        with open(os.path.join('static/excel/' + filename), 'rb') as f:
            while True:
              data = f.read(buf_size)
              if not data:
                break
              self.write(data)
        self.finish()



class ChatMsg_Module(UIModule):
    '''
    聊天消息模块
    '''
    def render(self, content):
        if content.startswith('<msg>'):
            try:
                root = etree.HTML(content)
                title = root.xpath('.//title/text()')[0]
                appname = root.xpath('.//appname/text()')[0]
                url = root.xpath('.//url/text()')[0]
                result = '从 <strong>%s</strong> 分享消息:<br> %s<br><a href="%s" target="ablank">%s</a>' % (appname, title
                , url, url)
            except Exception,e:
                print e
                result = content
            return result
        else:
            return content

uiModule = {
            'chatmsg_module': ChatMsg_Module,
        }


def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
        (r"/log", SysLogHandler),
        (r"/login", LoginHandler),
        (r"/logout", LogoutHandler),
        (r"/qrcode", QRCodeHandler),
        (r"/home", HomeHandler),
        (r"/search", SearchHandler),
        (r"/leftpanel/(num)", LeftPanelHandler),
        (r"/pull", PullInfoHandler),
        (r"/analysis", AnalysisHandler),
        (r"/analysis/(keyword|filter|msg|top)", AnalysisMethodHandler),
        (r"/keywords", KeywordsHandler),
        (r"/keywords/(add|del|edit)", KeyWordsMethodHandler),
        (r"/tags", TagsHandler),
        (r"/tags/(add|del|edit|set)", TagsMethodHandler),
        (r"/wechat/(add|edit|del)", WechatHandler),
        (r"/userinfo", UserInfoHandler),
        (r"/accountlist", AccountListHandler),
        (r"/grouplist", GroupListHandler),
        (r"/grouplist/(tag|newmem)", GroupListMethodHandler),
        (r"/groupmsg", GroupMSGHandler),
        (r"/groupmemberlist", GroupMemberListHandler),
        (r"/usermanage/(edit|del|add|resetpass|chgpass)", UserManageHandler),
        (r"/warninglist", WarningListHandler),
        (r"/warnlist", WarnListHandler),
        (r"/warninglist/(get)", WarningListMethodHandler),
        (r"/qrcodelist", QrCodeListHandler),
        (r"/msgframe", GroupMSGFrameHandler),
        (r"/keywechat", KeyWechatList),
        (r"/keywechat/(add|del)", KeyWechatList),
        (r"/report", ReportHandler),
        (r"/download/([0-9\_]+\.xlsx)", DownloadHandler),
        (r'.*', nopageHandler),
    ],
        ui_modules=uiModule,
        cookie_secret="46546gd465gd46@@5gd456gd4gd56s$$",
        login_url='/login',
        static_path="static",
        xsrf_cookies=True,
        template_path='templates',
        debug=True,
        xheaders=True
    )


if __name__ == "__main__":
    app = make_app()
    app.listen(port)
    loop = tornado.ioloop.IOLoop.instance()
    tornado.autoreload.start(loop)
    loop.start()
