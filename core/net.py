import ftplib
import paramiko
import requests

import mysql.connector

ip_cache = None


def mysql_login(host, username, password, port):
    try:
        mysql.connector.connect(
            host=host,
            user=username,
            password=password,
            port=port
        )
        return True
    except Exception as e:
        return True


mysql_login("localhost", "a", "b", 3306)


def ftp_login(host, username, password, port):
    try:
        server = ftplib.FTP()
        server.connect(host, port)
        server.login(username, password)
        return True
    except ftplib.all_errors as e:
        err_string = str(e).split(None, 1)[0]
        return "530" in err_string  # auth failed


def ssh_login(host, username, password, port):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port, username, password)
        ssh.close()
        return True
    except paramiko.ssh_exception.AuthenticationException:
        return True
    except Exception:
        return False


def get_external_ip():
    global ip_cache
    if ip_cache is None:
        ip_cache = requests.get('https://api.ipify.org').text
    return ip_cache.strip()


def silent_kill_http_server(url):
    try:
        requests.request(method="SILENT_TERMINATE", url=url)
    except:
        pass
