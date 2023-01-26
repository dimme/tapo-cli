#!/usr/bin/python3

import os
import click
import requests
import urllib3
import hashlib
import hmac
import base64
import uuid
import time
import json

# Secrets extracted from the .apk
access_key = '4d11b6b9d5ea4d19a829adbb9714b057'
secret = '6ed7d97f3e73467f8a5bab90b577ba4c'

# Every request needs a uuid nonce and time
nonce = str(uuid.uuid1())
now = str(int(time.time()))

# Yeah Tapo is using expired certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Weird MD5 implementation for the Content-Md5 header
def content_md5(content):
    return base64.b64encode(hashlib.md5(content.encode('UTF-8')).digest()).decode('UTF-8')

# Signature algorithm for the X-Authorization header
def signature(content, endpoint):
    payload = (content_md5(content) + '\n' + now + '\n' + nonce + '\n' + endpoint).encode('UTF-8')
    return hmac.new(secret.encode('UTF-8'), payload, hashlib.sha1).digest().hex()

# X-Authorization header contents
def x_authorization(content, endpoint):
    return 'Timestamp=' + now + ', Nonce=' + nonce + ', AccessKey=' + access_key + ', Signature=' + signature(content, endpoint)

# Gets authorization token from ~/.tapo-cli/.token
def get_token():
    try:
        token = open(os.path.expanduser('~') + '/.tapo-cli/.token', 'r')
        
        if token.readline().strip() != 'TPTOKEN':
            click.echo('Malformed credentials file.')
            exit(0)

        token = token.readline().strip()

        return token
    except:
        click.echo('Please login first.')
        exit(0)

# Print and die when we get an error from Tapo
def error(obj):
    print('Something went wrong:')
    print(obj)
    exit(obj['error_code'])

# Post with my own settings (e.g. with Burp Proxy for debugging)
def post(url, data, headers):
    return json.loads(requests.post(url, data = data, headers = headers, verify = False, proxies = { "https" : "https://10.0.0.127:8080" }).text)

@click.group()
def tapo():
    """Command-line based application for batch-downloading your video files from the Tapo TP-Link Cloud."""
    pass

# Login
@click.command()
@click.option('--username', default="email@example.com", prompt="Username", help='Your Tapo TP-Link username.')
@click.option('--password', default="H0p3ful1yN0tY0urP@$$w0rd", prompt="Password", help='Your Tapo TP-Link password.')
def login(username, password):
    click.echo('Access token saved in ~/.tapo-cli/.token')

# Devices
@click.command()
def devices():
    token = get_token()
    endpoint = '/api/v2/common/getDeviceListByPage'
    url = 'https://n-euw1-wap-gw.tplinkcloud.com' + endpoint + '?token=' + token
    content = '{"deviceTypeList":["SMART.TAPOPLUG","SMART.TAPOBULB","SMART.IPCAMERA","SMART.TAPOROBOVAC","SMART.TAPOHUB","SMART.TAPOSENSOR","SMART.TAPOSWITCH"],"index":0,"limit":20}'
    headers = {
        'Content-Md5' : content_md5(content),
        'X-Authorization' : x_authorization(content, endpoint),
        'Content-Type': 'application/json; charset=UTF-8',
        'User-Agent': 'okhttp/3.12.13'
    }

    devices = post(url, content, headers)

    if (devices['error_code'] != 0):
        error(devices)
    else:
        print('Found ' + str(devices['result']['totalNum']) + ' devices:')
        for device in devices['result']['deviceList']:
            print(json.dumps(device, indent = 4))
        return devices

# List
@click.command()
@click.option('--days', default=30, prompt="Last X days", help='Last X days which you want to list videos for.')
def list(days):
    token = get_token()
    click.echo('Listed ' + str(days))

# Download
@click.command()
@click.option('--days', default=30, prompt="Last X days", help='Last X days which you want to download videos for.')
@click.option('--path', default="~/", prompt="Path", help='Path where you want your videos to be downloaded. It will create directories based on dates and overwrite any existing files using the same name.')
def download(days, path):
    token = get_token()
    click.echo('Downloaded to ' + path)

tapo.add_command(login)
tapo.add_command(devices)
tapo.add_command(list)
tapo.add_command(download)

if __name__ == '__main__':
    tapo()