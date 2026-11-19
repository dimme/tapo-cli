#!/usr/bin/env python3

# DO NOT RUN ANY OF THIS CODE UNLESS YOU UNDERSTAND WHAT IT DOES
# I TAKE NO RESPONSIBILITY FOR ANYTHING, USE ON YOUR OWN RISK

# There are no sanity checks or checks for errors in this script. If it fails, if fails. Usually it doesn't fail. Just run it again or fix the error and submit a pull request. Be thankful you didn't have to reverse engineer Tapo's HMAC-SHA1 signature nightmare.

# Copyright Dimme 2023

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
import re
import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Secrets extracted from the .apk
access_key = '4d11b6b9d5ea4d19a829adbb9714b057'
secret = '6ed7d97f3e73467f8a5bab90b577ba4c'

# Every request needs a uuid nonce and time, any value seems to work but let's not raise any suspicions.
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

# The global entry point for logging in. Your account is pinned to a regional
# server and this one only points us at it, see login().
login_url = 'https://n-wap-gw.tplinkcloud.com'

# Tapo Care is regional too. If we cannot tell which region an account belongs
# to we assume EU West, which is what this script used to hardcode for everyone.
default_region = 'euw1'

# Every URL Tapo hands us at login carries the region, e.g.
# https://n-use1-wap-gw.tplinkcloud.com or https://use1-account-api.i.tplinkcloud.com
def region(config):
    for key, pattern in (('appServerUrl', r'^https?://n-([a-z0-9]+)-wap[-.]'),
                         ('appServerUrlV2', r'^https?://n-([a-z0-9]+)-wap[-.]'),
                         ('accountApiUrl', r'^https?://([a-z0-9]+)-account-api[-.]')):
        match = re.match(pattern, config.get(key) or '')
        if match:
            return match.group(1)
    return default_region

# Where this account's Tapo Care videos live
def tapo_care_url(config):
    return 'https://' + region(config) + '-app-tapo-care.i.tplinknbu.com'

def config_path():
    return os.path.join(os.path.expanduser('~'), '.tapo-cli', '.config')

# Gets authorization token from ~/.tapo-cli/.config
# No idea if this works on Windows, what are you, some kind of psychopath?
def get_config():
    try:
        with open(config_path(), 'r') as file:
            config = json.loads(file.read())
        token = config['token']
    except (IOError, OSError, ValueError, KeyError):
        print('Please login first.')
        exit(1)

    # Configs written by older versions have no tapoCareUrl, so work it out from
    # the other URLs they did save rather than making them login again.
    return (token, config.get('email', ''), config.get('appServerUrl') or login_url,
            config.get('tapoCareUrl') or tapo_care_url(config))

# The app gateway calls it error_code, the account endpoints call it errorCode
# and send it as a string. Returns 0 when Tapo is happy.
def error_code(obj):
    if not isinstance(obj, dict):
        return 0
    for key in ('error_code', 'errorCode'):
        if key in obj:
            try:
                return int(obj[key])
            except (TypeError, ValueError):
                return 1
    return 0

# Tapo's way of saying "login again"
def token_expired(obj):
    if not isinstance(obj, dict):
        return False
    if error_code(obj) == -20651:
        return True
    return 'token' in (str(obj.get('msg', '')) + ' ' + str(obj.get('errorMsg', ''))).lower()

# Print and die when we get an error from Tapo
def error(obj):
    print('Something went wrong:')
    print(json.dumps(obj, indent = 4) if isinstance(obj, (dict, list)) else obj)
    if token_expired(obj):
        print('\nYour access token is no longer valid. Run "tapo-cli.py login" to get a new one.')
    exit(1)

# Headers that the Android app is using with GET endpoints in general.
def headers_get(token):
    return {
        'Authorization' : 'ut|' + token,
        'X-App-Name' : 'TP-Link_Tapo_Android'
    }

# Headers that the Android app is using with POST endpoints in general.
def headers_post(content, endpoint):
    return {
        'Content-Md5' : content_md5(content),
        'X-Authorization' : x_authorization(content, endpoint),
        'Content-Type': 'application/json; charset=UTF-8',
        'User-Agent': 'Tapo CameraClient Android' if '/api/v2/common/passthrough' in endpoint else 'okhttp/3.12.13'
    }

# GET with my own settings (e.g. with Burp Proxy for debugging)
def get(url, params, headers):
    return json.loads(requests.get(url, params = params, headers = headers, verify = False).text)

# POST with my own settings (e.g. with Burp Proxy for debugging)
def post(url, data, headers):
    return json.loads(requests.post(url, data = data, headers = headers, verify = False).text)

# Downloads a file from the Intenetz and decrypts it
def download(url, key_b64, file_path, file_name):
    if not os.path.exists(file_path): os.makedirs(file_path)

    res = requests.get(url)
    content = res.content

    if key_b64:
        key = base64.b64decode(key_b64)
        iv = content[:16]
        enc_data = content[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        dec_content = unpad(cipher.decrypt(enc_data), AES.block_size)
    else:
        dec_content = content

    with open(os.path.join(file_path, file_name), 'wb') as file:
        file.write(dec_content)

def probe_endpoint_get(params, endpoint):
    token, null, null, app_server_url_get = get_config()
    url = app_server_url_get + endpoint
    res = get(url, params, headers_get(token))
    if error_code(res) != 0:
        error(res)
    return res

def probe_endpoint_post(content, endpoint):
    token, null, app_server_url_post, null = get_config()
    url = app_server_url_post + endpoint + '?token=' + token
    res = post(url, content, headers_post(content, endpoint))
    if error_code(res) != 0:
        error(res)
    return res['result']

# Anything that identifies you or lets someone act as you, stripped before we
# print a response so that debug output is safe to paste into a bug report.
secret_keys = ('token', 'refreshToken', 'cloudPassword', 'password', 'accountId',
               'email', 'mfaEmail', 'cloudUserName', 'nickname', 'MFAProcessId')

def redact(obj):
    if isinstance(obj, dict):
        return dict((key, '<redacted>' if key in secret_keys else redact(value)) for key, value in obj.items())
    if isinstance(obj, list):
        return [redact(value) for value in obj]
    return obj

debug_enabled = False

def debug(label, obj):
    if debug_enabled:
        print('\n[debug] ' + label)
        print(json.dumps(redact(obj), indent = 4))

# How the verification code reaches you. The login response lists the types the
# account supports in supportedMFATypes: 1 is a push notification to a Tapo app
# already bound to the account, 2 is email. A fresh terminalUUID like the one
# this script generates is bound to nothing, so push has nowhere to arrive.
mfa_push, mfa_email = 1, 2

mfa_type_names = {mfa_push: 'push notification to the Tapo app', mfa_email: 'email'}

# The push endpoint's name is known from the app. The email one is not, so these
# are tried in order by the probe-mfa command until Tapo accepts one.
mfa_endpoints = {
    mfa_push: ['/api/v2/account/getPushVC4TerminalMFA'],
    mfa_email: ['/api/v2/account/getEmailVC4TerminalMFA',
                '/api/v2/account/sendEmailVC4TerminalMFA',
                '/api/v2/account/getEmailVC4TerminalBind',
                '/api/v2/account/getVC4TerminalMFA',
                '/api/v2/account/getEmailVerifyCode'],
}

# POSTs to one of the unauthenticated account endpoints and returns its result
def account_post(base_url, endpoint, content):
    debug('POST ' + base_url + endpoint, content)
    content = json.dumps(content)
    res = post(base_url + endpoint, content, headers_post(content, endpoint))
    debug('response from ' + endpoint, res)
    if error_code(res) != 0:
        error(res)
    result = res.get('result')
    return result if isinstance(result, dict) else {}

# Midnight-to-midnight window covering the last X days. Local time, because that
# is the clock Tapo filters on and reports eventLocalTime in.
def time_range(days):
    today = datetime.datetime.now().replace(hour = 0, minute = 0, second = 0, microsecond = 0)
    start_time = (today - datetime.timedelta(days = days)).strftime('%Y-%m-%d %H:%M:%S')
    end_time = (today + datetime.timedelta(days = 1)).strftime('%Y-%m-%d %H:%M:%S')
    return start_time, end_time

# An empty listing is usually a region or a subscription problem, so say so
# instead of quietly printing zeroes.
def no_videos_hint(app_server_url_get):
    print('\nNo videos were found. Worth checking:')
    print(' - Only Tapo Care cloud recordings can be listed here, not clips stored on the camera SD card.')
    print(' - Try a larger --days value.')
    print(' - We looked on ' + app_server_url_get + '. If your account belongs to another')
    print('   region, delete ' + config_path() + ' and login again.')

@click.group()
def tapo():
    """Command-line application for batch-downloading your videos from the Tapo TP-Link Cloud."""
    pass

@click.command()
@click.option('--username', default="email@example.com", prompt="Username", help='Your Tapo TP-Link username.')
@click.option('--password', prompt="Password", hide_input=True, help='Your Tapo TP-Link password. Prefer the prompt over this option, which leaks into shell history.')
@click.option('--mfa-type', default=None, type=int, help='How to receive the MFA code: 1 for a Tapo app push notification, 2 for email.')
@click.option('--debug', 'show_debug', is_flag=True, default=False, help='Print the requests and responses, with your credentials redacted.')
def login(username, password, mfa_type, show_debug):
    """Authenticates a user towards the TP-Link Tapo Cloud."""
    global debug_enabled
    debug_enabled = show_debug
    terminal_uuid = str(uuid.uuid1()).replace('-','').upper()

    base_url = login_url
    endpoint = '/api/v2/account/login'
    content = {"appType":"TP-Link_Tapo_Android","appVersion":"2.12.705","cloudPassword":password,"cloudUserName":username,"platform":"Android 12","refreshTokenNeeded":False,"terminalMeta":"1","terminalName":"Tapo CLI","terminalUUID":terminal_uuid}
    result = account_post(base_url, endpoint, content)

    # Accounts outside the region of the global entry point get bounced with
    # -20212 "Incorrect service entry address", which names the server to use.
    if error_code(result) == -20212 and result.get('appServerUrl'):
        base_url = result['appServerUrl']
        print('Your account belongs to ' + base_url + ', logging in there instead.')
        result = account_post(base_url, endpoint, content)

    # Login but with extra steps
    if 'MFAProcessId' in result:
        mfa_process_id = result['MFAProcessId']
        supported = result.get('supportedMFATypes') or [mfa_push]
        if mfa_type is None:
            mfa_type = supported[0]
        if mfa_type not in supported:
            print('Your account does not support MFA type ' + str(mfa_type) + '. It supports: '
                  + ', '.join(str(one) + ' (' + mfa_type_names.get(one, 'unknown') + ')' for one in supported))
            exit(1)

        print('Requesting an MFA code by ' + mfa_type_names.get(mfa_type, 'type ' + str(mfa_type)) + '.')
        content = {"appType":"TP-Link_Tapo_Android","cloudPassword":password,"cloudUserName":username,"terminalUUID":terminal_uuid}
        sent = account_post(base_url, mfa_endpoints[mfa_type][0], content)

        # This request is what actually sends the code. Its verdict used to be
        # thrown away, which left you staring at a prompt for a code that was
        # never going to arrive.
        if error_code(sent) != 0:
            print('\nTapo would not send the code:')
            print(json.dumps(redact(sent), indent = 4))
            if len(supported) > 1:
                print('\nYour account also supports: ' + ', '.join(
                    str(one) + ' (' + mfa_type_names.get(one, 'unknown') + ')' for one in supported if one != mfa_type))
                print('Try again with --mfa-type ' + str([one for one in supported if one != mfa_type][0]) + '.')
            exit(1)

        if mfa_type == mfa_push:
            print('Check your Tapo app. The push only arrives if this terminal is already')
            print('bound to your account, so if nothing shows up try --mfa-type 2 for email.')
        else:
            print('Check your email (including the spam folder) for the code.')

        mfa_code = str(input('MFA Code (no spaces or dashes): '))

        content = {"appType":"TP-Link_Tapo_Android","cloudUserName":username,"code":mfa_code,"MFAProcessId":mfa_process_id,"MFAType":mfa_type,"terminalBindEnabled":True}
        result = account_post(base_url, '/api/v2/account/checkMFACodeAndLogin', content)

    # Go by errorCode only. errorMsg is localised, so comparing it against the
    # English "Success" used to throw away logins that had in fact succeeded.
    if error_code(result) != 0 or 'token' not in result:
        error(result)

    # Remember which region this account lives in, so that the other commands
    # ask the right servers instead of assuming EU West.
    result['appServerUrl'] = result.get('appServerUrl') or base_url
    result['tapoCareUrl'] = tapo_care_url(result)

    file_path = os.path.dirname(config_path())
    if not os.path.exists(file_path): os.makedirs(file_path)
    with open(config_path(), 'w+') as file:
        file.write(json.dumps(result, indent = 4))
    print('Access token saved in ' + config_path())

@click.command()
@click.option('--username', default="email@example.com", prompt="Username", help='Your Tapo TP-Link username.')
@click.option('--password', prompt="Password", hide_input=True, help='Your Tapo TP-Link password.')
@click.option('--mfa-type', default=2, type=int, help='Which delivery channel to probe. 2 is email.')
def probe_mfa(username, password, mfa_type):
    """Finds which endpoint sends an MFA code, for when the push never arrives."""
    global debug_enabled
    debug_enabled = True
    terminal_uuid = str(uuid.uuid1()).replace('-','').upper()

    base_url = login_url
    endpoint = '/api/v2/account/login'
    content = {"appType":"TP-Link_Tapo_Android","appVersion":"2.12.705","cloudPassword":password,"cloudUserName":username,"platform":"Android 12","refreshTokenNeeded":False,"terminalMeta":"1","terminalName":"Tapo CLI","terminalUUID":terminal_uuid}
    result = account_post(base_url, endpoint, content)

    if error_code(result) == -20212 and result.get('appServerUrl'):
        base_url = result['appServerUrl']
        result = account_post(base_url, endpoint, content)

    if 'MFAProcessId' not in result:
        print('\nThis account did not ask for MFA, so there is nothing to probe.')
        return

    print('\nAccount supports MFA types: ' + ', '.join(
        str(one) + ' (' + mfa_type_names.get(one, 'unknown') + ')' for one in result.get('supportedMFATypes', [])))

    # Stop at the first endpoint Tapo accepts. Each attempt is a real request
    # against your account, so we do not keep hammering after one works.
    content = {"appType":"TP-Link_Tapo_Android","cloudPassword":password,"cloudUserName":username,"terminalUUID":terminal_uuid}
    for candidate in mfa_endpoints.get(mfa_type, []):
        print('\nTrying ' + candidate)
        res = post(base_url + candidate, json.dumps(content), headers_post(json.dumps(content), candidate))
        print(json.dumps(redact(res), indent = 4))
        # Both layers have to be happy: the envelope can say error_code 0 while
        # the result inside carries the real refusal.
        if error_code(res) == 0 and error_code(res.get('result')) == 0:
            print('\n==> ' + candidate + ' was accepted. Check whether a code actually arrived.')
            print('    If it did, login with: ./tapo-cli.py login --mfa-type ' + str(mfa_type))
            return

    print('\nNone of the candidate endpoints were accepted. Paste this output into the issue.')

@click.command()
def account_info():
    """Lists information about your account."""
    null, email, null, null = get_config()
    endpoint = '/api/v2/account/getAccountInfo'

    # Vulnerabilities found here, it will return:
    # - 'Account not found' if the account is not found
    # - 'Token incorrect' if the account exists but you are not logged in as that user
    # Which makes it possible to enumerate users with Tapo accounts

    content = '{"cloudUserName":"' + email + '"}'
    res = probe_endpoint_post(content, endpoint)
    print(json.dumps(res, indent = 4))

@click.command()
def devices():
    """Lists your first 20 Tapo devices."""
    get_config() # Checks if logged in
    endpoint = '/api/v2/common/getDeviceListByPage'
    content = '{"deviceTypeList":["SMART.TAPOPLUG","SMART.TAPOBULB","SMART.IPCAMERA","SMART.TAPOROBOVAC","SMART.TAPOHUB","SMART.TAPOSENSOR","SMART.TAPOSWITCH"],"index":0,"limit":20}'
    res = probe_endpoint_post(content, endpoint)
    print(json.dumps(res, indent = 4))

@click.command()
def devices_limit():
    """Lists the device limits for your account by device type."""
    get_config() # Checks if logged in
    endpoint = '/api/v2/common/batchGetDeviceUserNumberLimit'
    content = '{"deviceTypeList":["SMART.TAPOPLUG","SMART.TAPOBULB","SMART.IPCAMERA","SMART.TAPOROBOVAC","SMART.TAPOHUB","SMART.TAPOSENSOR","SMART.TAPOSWITCH"]}'
    res = probe_endpoint_post(content, endpoint)
    print(json.dumps(res, indent = 4))

@click.command()
def devices_info():
    """Lists A LOT of parameters for your devices."""
    get_config() # Checks if logged in
    endpoint = '/api/v2/common/getDeviceListByPage'
    content = '{"deviceTypeList":["SMART.TAPOPLUG","SMART.TAPOBULB","SMART.IPCAMERA","SMART.TAPOROBOVAC","SMART.TAPOHUB","SMART.TAPOSENSOR","SMART.TAPOSWITCH"],"index":0,"limit":20}'
    devs = probe_endpoint_post(content, endpoint)

    endpoint = '/api/v2/common/passthrough'
    for dev in devs['deviceList']:
        print('\nGetting ' + dev['alias'] + ':')
        content = '{"deviceId":"' + dev['deviceId'] + '","requestData":{"method":"multipleRequest","params":{"requests":[{"method":"getDeviceInfo","params":{"device_info":{"name":["basic_info"]}}},{"method":"getLastAlarmInfo","params":{"system":{"name":["last_alarm_info"]}}},{"method":"getAppComponentList","params":{"app_component":{"name":["app_component_list"]}}},{"method":"getVideoCapability","params":{"video_capability":{"name":["main","minor"]}}},{"method":"checkFirmwareVersionByCloud","params":{"cloud_config":{"check_fw_version":"null"}}},{"method":"getCloudConfig","params":{"cloud_config":{"name":["upgrade_info"]}}},{"method":"getP2PSharePassword","params":{"user_management":{"get_p2p_sharepwd":{}}}}]}}}'
        try:
            res = probe_endpoint_post(content, endpoint)
            print(json.dumps(res, indent = 4))
        except:
            continue

@click.command()
def service_urls():
    """Lists URLs for various Tapo services."""
    get_config() # Checks if logged in 
    endpoint = '/api/v2/common/getAppServiceUrl'
    content = '{"serviceIds":["nbu.iot-app-server.app","nbu.iot-cloud-gateway.app","nbu.iot-security.appdevice","cipc.api"]}'
    res = probe_endpoint_post(content, endpoint)
    print(json.dumps(res, indent = 4))

@click.command()
def notifications():
    """Lists notifications from your phone app."""
    get_config() # Checks if logged in
    endpoint = '/api/v2/common/getAppNotificationByPage'

    # Vulnerabilities found here:
    # - deviceToken should not be allowed to be empty
    # - terminalUUID is not required if replaced by a single "'"
    # Thankfully the API doesn't return any screenshots for other users

    content = '{"appType":"TP-Link_Tapo_Android","contentVersion":2,"deviceToken":"","direction":"asc","index":0,"indexTime":' + now + ',"limit":50,"locale":"en_US","mobileType":"ANDROID","msgTypes":["UNKNOWN_NOTIFICATION_MSG","tapoShareLaunch","tapoNewFirmware","Motion","Audio","BabyCry","tapoFfsNewDeviceFound","smartTapoDeviceActivity","PersonDetected","PersonEnhanced","tapoCameraSDNeedInitialization","tapoCameraSDInsufficientStorage","tapoCameraAreaIntrusionDetection","tapoCameraLinecrossingDetection","tapoCameraCameraTampering","tapoGlassBreakingDetected","tapoSmokeAlarmDetected","tapoMeowDetected","tapoBarkDetected","TAPO_CARE_TRIAL_EXPIRING_IN_3_DAYS","TAPO_CARE_TRIAL_EXPIRED","TAPO_CARE_SUBSCRIPTION_EXPIRING_IN_3_DAYS","TAPO_CARE_SUBSCRIPTION_EXPIRED","TAPO_CARE_SUBSCRIPTION_PAYMENT_FAILED","tapoHubTriggered","tapoContactSensorTriggered","tapoMotionSensorTriggered","tapoSmartButtonTriggered","tapoSmartSwitchTriggered","tapoDeviceLowBattery","tapoSensorFrequentlyTriggered","brandPromotion","marketPromotion","announcement","userResearch","tapoDeviceOverheat","tapoDeviceOverheatRelieve","videosummaryGenerated","videosummaryCanCreateFromClips","tapoCareWeeklyReport","tapoCareWeeklyReportNewFeature","BatteryEmpty","BatteryFullyCharged","PowerSavingModeEnabled","CameraLowBattery","PetDetected","VehicleDetected","deliverPackageDetected","pickUpPackageDetected","antiTheft","ringEvent","missRingEvent","tapoSensorWaterLeakDetected","tapoSensorWaterLeakSolved","tapoSensorTempTooWarm","tapoSensorTempTooCool","tapoSensorTooHumid","tapoSensorTooDry","lensMaskChargingEnabled","tapoDevicePowerProtection","tpSimpleSetup","other","robotBatteryExceptionEvent","robotCleanRelativeEvent","robotLocateFailEvent","robotIssueDetected"],"terminalUUID":"\'"}'
    res = probe_endpoint_post(content, endpoint)
    print(json.dumps(res, indent = 4))

@click.command()
def subscriptions():
    """Lists your email subscriptions."""
    null, email, null, null = get_config() # Checks if logged in
    endpoint = '/api/v2/account/getTopicSubscription'
    content = '{"email":"' + email + '","productLine":"NBU"}'
    res = probe_endpoint_post(content, endpoint)
    print(json.dumps(res, indent = 4))

@click.command()
def mfa_status():
    """Lists your MFA status."""
    get_config() # Checks if logged in
    endpoint = '/api/v2/account/getMFAFeatureStatus'
    content = '{}'
    res = probe_endpoint_post(content, endpoint)
    print(json.dumps(res, indent = 4))

@click.command()
@click.option('--days', default=1, prompt="Last X days", help='Last X days which you want to list videos for.')
def list_videos(days):
    """Lists videos for the last X days."""
    get_config() # Checks if logged in
    endpoint = '/api/v2/common/getDeviceListByPage'
    content = '{"deviceTypeList":["SMART.IPCAMERA"],"index":0,"limit":20}'
    devs = probe_endpoint_post(content, endpoint)
    
    start_time, end_time = time_range(days)

    endpoint = '/v2/videos/list'
    total = 0
    for dev in devs['deviceList']:
        params = 'deviceId=' + dev['deviceId'] + '&page=0&pageSize=3000&order=desc&startTime=' + start_time + '&endTime=' + end_time
        videos = probe_endpoint_get(params, endpoint)
        total += videos.get('total', 0)
        print('\nFound ' + str(videos.get('total', 0)) + ' videos for ' + dev['alias'] + ':')
        for video in videos.get('index', []):
            print(video['eventLocalTime'], end = ", ")
            #print(video['video'][0]['uri']) # This will print URLs to the videos if you want to download them using another tool, but don't forget to get the AES key from video['video'][0]['decryptionInfo']['key']
        if videos.get('total', 0) > 0: print('')

    if total == 0:
        null, null, null, app_server_url_get = get_config()
        no_videos_hint(app_server_url_get)

@click.command()
@click.option('--days', default=1, prompt="Last X days", help='Last X days which you want to download videos for.')
@click.option('--path', default="~/", prompt="Path", help='Path where you want your videos to be downloaded. It will create directories based on dates.')
@click.option('--overwrite', default=0, prompt="Overwrite", help='Overwrite any files using the same name in the same location.')
def download_videos(days, path, overwrite):
    """Downloads videos for the last X days to path."""
    get_config() # Checks if logged in
    
    path = os.path.join(os.path.expanduser(path), '')
    
    endpoint = '/api/v2/common/getDeviceListByPage'
    content = '{"deviceTypeList":["SMART.IPCAMERA"],"index":0,"limit":20}'
    devs = probe_endpoint_post(content, endpoint)
    
    start_time, end_time = time_range(days)

    result = []
    endpoint = '/v2/videos/list'
    for dev in devs['deviceList']:
        params = 'deviceId=' + dev['deviceId'] + '&page=0&pageSize=3000&order=desc&startTime=' + start_time + '&endTime=' + end_time
        videos = probe_endpoint_get(params, endpoint)
        print('\nFound ' + str(videos.get('total', 0)) + ' videos for ' + dev['alias'] + ':')
        for video in videos.get('index', []):
            clip = video['video'][0]
            url = clip['uri']
            method = clip.get('encryptionMethod', 'NONE')
            if method == 'AES-128-CBC':
                key_b64 = clip['decryptionInfo']['key']
            elif method == 'NONE':
                key_b64 = False
            else:
                print(f"Unsupported encryption method: {method}. Quitting...")
                print("Create an issue here: https://github.com/dimme/tapo-cli/issues")
                exit(1)

            file_path = path + dev['alias'] + '/' + datetime.datetime.strptime(video['eventLocalTime'], '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d') + '/'
            file_name = video['eventLocalTime'].replace(':','-') + '.mp4'
            if os.path.exists(file_path + file_name) and overwrite == 0:
                print('Already exists ' + file_path + file_name)
                result.append({'file': file_path + file_name, 'device': dev['alias'], 'new_video': False, 'video': video})
            else:
                print('Downloading to ' + file_path + file_name)
                download(url, key_b64, file_path, file_name)
                result.append({'file': file_path + file_name, 'device': dev['alias'], 'new_video': True, 'video': video})

    if not result:
        null, null, null, app_server_url_get = get_config()
        no_videos_hint(app_server_url_get)

    return result

tapo.add_command(login, 'login')
tapo.add_command(probe_mfa, 'probe-mfa')
tapo.add_command(account_info, 'list-account-info')
tapo.add_command(devices_limit, 'list-devices-limit')
tapo.add_command(devices_info, 'list-devices-info')
tapo.add_command(devices, 'list-devices')
tapo.add_command(service_urls, 'list-service-urls')
tapo.add_command(notifications, 'list-notifications')
tapo.add_command(subscriptions, 'list-subscriptions')
tapo.add_command(mfa_status, 'list-mfa-status')
tapo.add_command(list_videos, 'list-videos')
tapo.add_command(download_videos, 'download-videos')

if __name__ == '__main__':
    tapo()
