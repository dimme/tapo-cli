#!/usr/bin/python3

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

# Gets authorization token from ~/.tapo-cli/.config
# No idea if this works on Windows, what are you, some kind of psychopath?
def get_config():
    try:
        file = open(os.path.expanduser('~') + '/.tapo-cli/.config', 'r')
        config = json.loads(file.read())

        token = config['token']
        email = config['email']
        app_server_url_post = config['appServerUrl']

        return token, email, app_server_url_post, 'https://euw1-app-tapo-care.i.tplinknbu.com'
    except:
        print('Please login first.')
        exit(1)

# Print and die when we get an error from Tapo
def error(obj):
    print('Something went wrong:')
    print(obj)
    if 'error_code' in obj:
        exit(obj['error_code'])
    else:
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
    return res

def probe_endpoint_post(content, endpoint):
    token, null, app_server_url_post, null = get_config()
    url = app_server_url_post + endpoint + '?token=' + token
    res = post(url, content, headers_post(content, endpoint))
    if (res['error_code'] != 0):
        error(res)
    else:
        return res['result']

@click.group()
def tapo():
    """Command-line application for batch-downloading your videos from the Tapo TP-Link Cloud."""
    pass

@click.command()
@click.option('--username', default="email@example.com", prompt="Username", help='Your Tapo TP-Link username.')
@click.option('--password', default="H0p3ful1yN0tY0urP@$$w0rd", prompt="Password", help='Your Tapo TP-Link password.')
def login(username, password):
    """Authenticates a user towards the TP-Link Tapo Cloud."""
    terminal_uuid = str(uuid.uuid1()).replace('-','').upper()

    url = 'https://n-wap-gw.tplinkcloud.com/api/v2/account/login'
    content = {"appType":"TP-Link_Tapo_Android","appVersion":"2.12.705","cloudPassword":password,"cloudUserName":username,"platform":"Android 12","refreshTokenNeeded":False,"terminalMeta":"1","terminalName":"Tapo CLI","terminalUUID":terminal_uuid}
    content = json.dumps(content)
    res = post(url, content, headers_post(content, '/api/v2/account/login'))
    if (res['error_code'] != 0):
        error(res)
    
    config = json.dumps(res['result'], indent = 4)

    # Login but with extra steps
    if 'MFAProcessId' in config:
        mfa_process_id = res['result']['MFAProcessId']
        url = 'https://n-wap-gw.tplinkcloud.com/api/v2/account/getPushVC4TerminalMFA'
        content = {"appType":"TP-Link_Tapo_Android","cloudPassword":password,"cloudUserName":username,"terminalUUID":terminal_uuid}
        content = json.dumps(content)
        res = post(url, content, headers_post(content, '/api/v2/account/getPushVC4TerminalMFA'))
        if (res['error_code'] != 0):
            error(res) 

        print('Check your Tapo App for the MFA code!')
        mfa_code = str(input('MFA Code (no spaces or dashes): '))
    
        url = 'https://n-wap-gw.tplinkcloud.com/api/v2/account/checkMFACodeAndLogin'
        content = {"appType":"TP-Link_Tapo_Android","cloudUserName":username,"code":mfa_code,"MFAProcessId":mfa_process_id,"MFAType":1,"terminalBindEnabled":True}
        content = json.dumps(content)
        res = post(url, content, headers_post(content, '/api/v2/account/checkMFACodeAndLogin'))
        if (res['error_code'] != 0):
            error(res)
        config = json.dumps(res['result'], indent = 4)

    if 'errorMsg' in config and res.get('result', {})['errorMsg'] != "Success":
        error(config)

    file_path = os.path.expanduser('~') + '/.tapo-cli/'
    file_name = '.config'
    if not os.path.exists(file_path): os.makedirs(file_path)
    with open(file_path + file_name, 'w+') as file:
        file.write(config)
    print('Access token saved in ' + file_path + file_name)

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
    
    end_unixtime = time.time() + 86400
    start_unixtime = end_unixtime - (days + 1) * 86400
    end_time = datetime.datetime.utcfromtimestamp(end_unixtime).strftime('%Y-%m-%d 00:00:00')
    start_time = datetime.datetime.utcfromtimestamp(start_unixtime).strftime('%Y-%m-%d 00:00:00')

    endpoint = '/v2/videos/list'
    for dev in devs['deviceList']:
        params = 'deviceId=' + dev['deviceId'] + '&page=0&pageSize=3000&order=desc&startTime=' + start_time + '&endTime=' + end_time
        videos = probe_endpoint_get(params, endpoint)
        print('\nFound ' + str(videos['total']) + ' videos for ' + dev['alias'] + ':')
        if 'index' in videos:
            for video in videos['index']:
                print(video['eventLocalTime'], end = ", ")
                #print(video['video'][0]['uri']) # This will print URLs to the videos if you want to download them using another tool, but don't forget to get the AES key from video['video'][0]['decryptionInfo']['key']
        if videos['total'] > 0: print('')

@click.command()
@click.option('--days', default=1, prompt="Last X days", help='Last X days which you want to download videos for.')
@click.option('--path', default="~/", prompt="Path", help='Path where you want your videos to be downloaded. It will create directories based on dates.')
@click.option('--overwrite', default=0, prompt="Overwrite", help='Overwrite any files using the same name in the same location.')
def download_videos(days, path, overwrite):
    """Downloads videos for the last X days to path."""
    get_config() # Checks if logged in
    
    path = path if path[-1] == '/' else path + '/'
    path = os.path.expanduser(path)
    
    endpoint = '/api/v2/common/getDeviceListByPage'
    content = '{"deviceTypeList":["SMART.IPCAMERA"],"index":0,"limit":20}'
    devs = probe_endpoint_post(content, endpoint)
    
    end_unixtime = time.time() + 86400
    start_unixtime = end_unixtime - (days + 1) * 86400
    end_time = datetime.datetime.utcfromtimestamp(end_unixtime).strftime('%Y-%m-%d 00:00:00')
    start_time = datetime.datetime.utcfromtimestamp(start_unixtime).strftime('%Y-%m-%d 00:00:00')

    result = []
    endpoint = '/v2/videos/list'
    for dev in devs['deviceList']:
        params = 'deviceId=' + dev['deviceId'] + '&page=0&pageSize=3000&order=desc&startTime=' + start_time + '&endTime=' + end_time
        videos = probe_endpoint_get(params, endpoint)
        print('\nFound ' + str(videos['total']) + ' videos for ' + dev['alias'] + ':')
        if 'index' in videos:
            for video in videos['index']:
                url = video['video'][0]['uri']
                key_b64 = False

                # Check if the video is encrypted and get the key
                if 'encryptionMethod' in video['video'][0]:
                    method = video['video'][0]['encryptionMethod']
                    if method != "AES-128-CBC":
                        print(f"Unsupported encryption method: {method}. Quitting...")
                        print("Create an issue here: https://github.com/dimme/tapo-cli/issues")
                        exit(1)

                    key_b64 = video['video'][0]['decryptionInfo']['key']
                
                file_path = path + dev['alias'] + '/' + datetime.datetime.strptime(video['eventLocalTime'], '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d') + '/'
                file_name = video['eventLocalTime'].replace(':','-') + '.mp4'
                if os.path.exists(file_path + file_name) and overwrite == 0:
                    print('Already exists ' + file_path + file_name)    
                    result.append({'file': file_path + file_name, 'device': dev['alias'], 'new_video': False, 'video': video})
                else:
                    print('Downloading to ' + file_path + file_name)
                    download(url, key_b64, file_path, file_name)
                    result.append({'file': file_path + file_name, 'device': dev['alias'], 'new_video': True, 'video': video})
    return result

tapo.add_command(login, 'login')
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
