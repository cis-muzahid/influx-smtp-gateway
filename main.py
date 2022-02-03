#!/usr/bin/env python3
"""
Serve cloud init files
"""

import configparser
import os
import json
import smtplib
import socket
import sys
from email.header import Header
from email.mime.text import MIMEText

import uuid as uuid_module
from ipaddress import AddressValueError, IPv4Address, IPv6Address

import cherrypy

PATH = os.path.dirname(os.path.abspath(__file__))
CONFIG = configparser.ConfigParser()
CONFIG.read(os.path.join(PATH, "config.ini"))

TO_MAIL = CONFIG["app"].get("to_mail")
FROM_MAIL = CONFIG["app"].get("from_mail")
FROM_MAIL_PASSWORD = CONFIG["app"].get("from_mail_password")
print("TO_MAIL: ", TO_MAIL)
print("FROM_MAIL: ", FROM_MAIL)
print("FROM_MAIL_PASSWORD: ", FROM_MAIL_PASSWORD)


class CloudInitRequest:
    """
    Request data for persistence across methods
    """
    def __init__(self, request, uuid=None):
        self.remoteip = None
        self.hostinfo = ('localhost', )
        self.request = request
        self.meta_data = None
        self.meta_data_loaded = False
        self.user_data = None

        try:
            self.uuid = str(uuid_module.UUID('{' + uuid + '}'))
        # ValueError is wrong UUID syntax
        # TypeError is None
        except (ValueError, TypeError):
            self.uuid = None

        self._init_ip()

    def _can_ip_be_proxy(self):
        """
        Assuming the connection is through a proxy, is this proxy permitted?
        Can't proxy from a publicly reachable IP.
        """
        self.remoteip = self.request.remote.ip
        try:
            ipobj = IPv4Address(self.remoteip)
        except AddressValueError:
            try:
                ipobj = IPv6Address(self.remoteip)
            except AddressValueError:
                return False
        return not ipobj.is_global

    def _init_ip(self):
        """
        Get remote IP
        """
        if self._can_ip_be_proxy():
            try:
                self.remoteip = self.request.headers.get(
                    'X-Real-Ip',
                    self.request.remote.ip
                )
            except KeyError:
                pass

        try:
            self.hostinfo = socket.gethostbyaddr(self.remoteip)
            forward_lookup = socket.gethostbyname(self.hostinfo[0])
            if forward_lookup != self.remoteip:
                self.hostinfo = ('localhost', )
        except socket.herror:
            self.hostinfo = ('localhost', )
        except socket.gaierror:
            self.hostinfo = (self.remoteip, )


class CloudInitApp:
    """
    Serve cloud init files
    """

    @staticmethod
    def _content_type(data):
        if not data:
            return "text/cloud-config"
        if data.startswith("#include"):
            return "text/x-include-url"
        if data.startswith("## template: jinja"):
            return "text/jinja2"
        return "text/cloud-config"

    def _send_mail(self):
        try:
            # pylint: disable=deprecated-lambda
            cl = cherrypy.request.headers['Content-Length']
            rawbody = cherrypy.request.body.read(int(cl))
            req_body = json.loads(rawbody)
            subject = req_body['subject']
            body = req_body['body']
            client = smtplib.SMTP('smtp.gmail.com')
            msg = MIMEText(body, 'plain', 'utf-8')
            msg['Subject'] = Header(subject, 'utf-8')
            msg['From'] = FROM_MAIL
            msg['To'] = TO_MAIL

            client.ehlo()
            client.starttls()
            client.ehlo()
            client.login(msg["From"], FROM_MAIL_PASSWORD)
            client.sendmail(msg['From'], msg['To'], msg.as_string())
            client.quit()
            return "mail sent successfully"
        except Exception as e:
            return "some error: {}".format(e)

    @cherrypy.expose
    def send_mail(self):
        """
        v1 api endpoint user-data
        """
        return self._send_mail()


ROOT = CloudInitApp()

if __name__ == "__main__":
    cherrypy.server.socket_host = \
        CONFIG["server"].get("server_host", "127.0.0.1")
    cherrypy.server.socket_port = \
        CONFIG["server"].getint("server_port", 8081)
    ENGINE = cherrypy.engine

    CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
    CONFIG = {
        '/include': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': os.path.join(CURRENT_DIR,
                                                'data',
                                                'include'),
            'tools.staticdir.content_types': {
                'yml': 'text/yaml'
                }
            }
        }
    cherrypy.tree.mount(ROOT, config=CONFIG)

    if hasattr(ENGINE, "signal_handler"):
        ENGINE.signal_handler.subscribe()
    if hasattr(ENGINE, "console_control_handler"):
        ENGINE.console_control_handler.subscribe()
    try:
        ENGINE.start()
    except Exception:  # pylint: disable=broad-except
        sys.exit(1)
    else:
        ENGINE.block()
