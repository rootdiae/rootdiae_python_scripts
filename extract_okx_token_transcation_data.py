import os
import json
import logging
import requests
import pandas as pd
import re
from datetime import datetime, timedelta

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('data_fetcher.log'),
        logging.StreamHandler()
    ]
)

# 设置代理
os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:40880'

# cURL配置（用户需要从浏览器复制并替换这里的内容)
# OKX的筛选器时间为北京时间
# 筛选好所需的条件之后右键检查---Network---filter-list?t=---右键copy-copy as cURL
CURL_COMMAND = """
curl 'https://web3.okx.com/priapi/v1/dx/market/v2/trading-history/filter-list?t=1754709575' \
  -H 'accept: application/json' \
  -H 'accept-language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7' \
  -H 'app-type: web' \
  -H 'content-type: application/json' \
  -b '_ym_uid=173910051124871163; _ym_d=1739100511; intercom-id-ny9cf50h=0c5a0583-2ac8-4994-afb0-f1e3c6e3fd2c; intercom-device-id-ny9cf50h=1d3b37a-eae7-40d2-9391-9f96eef05371; OptanonAlertBoxClosed=2025-02-28T07:52:47.314Z; OptanonConsent=isGpcEnabled=0&datestamp=Sun+Mar+02+2025+14%3A55%3A58+GMT%2B0800+(%E4%B8%AD%E5%9B%BD%E6%A0%87%E5%87%86%E6%97%B6%E9%97%B4)&version=202405.1.0&browserGpcFlag=0&isIABGlobal=false&hosts=&landingPath=NotLandingPage&groups=C0004%3A1%2CC0002%3A1%2CC0003%3A1%2CC0001%3A1&AwaitingReconsent=false&geolocation=US%3BWA; devId=7ea7f394-82a4-41fd-8100-147966bdd450; ok_site_info===QfzojI5RXa05WZiwiIMFkQPx0Rfh1SPJiOiUGZvNmIsIySIJiOi42bpdWZyJye; locale=zh_CN; ok_prefer_udColor=0; ok_prefer_udTimeZone=0; fingerprint_id=7ea7f394-82a4-41fd-8100-147966bdd450; first_ref=https%3A%2F%2Fx.com%2Fpumpdotfun%2Fstatus%2F1942947308103991363; ok_global={%22g_t%22:2}; _gcl_au=1.1.401470299.1753154507; _gid=GA1.2.1210750573.1753154507; connected=1; mse=0; ok-exp-time=1753328476729; tmx_session_id=lp3igc7zkso_1753328480184; fp_s=0; ok_prefer_currency=0%7C1%7Cfalse%7CUSD%7C2%7C%24%7C1%7C1%7C%E7%BE%8E%E5%85%83; f8553adb1e94368c52b9617f669a0227=ce2701dc-0439-4da5-80c4-7d5dc0eb5c52; okg.currentMedia=xl; traceId=213013348410007; _ga=GA1.1.20292356.1742025424; _ga_G0EKWWQGTZ=GS2.1.s17539$o69$g1$t1753340377$j50$l0$h0; __cf_bm=laGWKcWiv2cISPYI69YXIPrVNNTkRN0PKJWP9WBJBro-1753340553-1.0.1.1-ZGXFslE4CpglCr6CO8NI5eVhX2maGVhKPjRIXQhv0602rcFW2_9hyuOrIwI7lJfJ6MmnCEXglQciWbVZoZu6SxA6RHZ1pFF807DtvhFn77I; _monitor_extras={"deviceId":"3xl3toaTB_8b3aVB3xPbNP","eventId":1809,"sequenceNumber":1809}; ok-ses-id=z2VjgcPBPjMSMbeTUZAX7+ITuAzX2F3H8PfrRYffOXscYVuCoT7eXIk02Qrsw+nxnk+Bt+dc3PBJi1/47Uz/0R/Y1Dly5aqAwc1FbuJyIIkX5ak4eWkusxJNE640ySGZ' \
  -H 'devid: 7ea7f394-82a4-41fd-8100-147966bdd450' \
  -H 'ok-timestamp: 175340709581' \
  -H 'ok-verify-sign: rld/+g2hKsP5rKlwYW6Gy9Nte+/4KCS1MmXYTolMEQ=' \
  -H 'ok-verify-token: aaa4b7c5-5973-4cfd-a393-22ebcba7dc2c' \
  -H 'origin: https://web3.okx.com' \
  -H 'priority: u=1, i' \
  -H 'referer: https://web3.okx.com/zh-hans/token/bsc/0x75a5863a19af60ec0098d62ed8c34cc594fb470f' \
  -H 'sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "Linux"' \
  -H 'sec-fetch-dest: empty' \
  -H 'sec-fetch-mode: cors' \
  -H 'sec-fetch-site: same-origin' \
  -H 'user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36' \
  -H 'x-cdn: https://web3.okx.com' \
  -H 'x-fptoken: eyJraWQiOiIxNjgzMzgiCJhbGciOiJFUzI1NiJ9.eyJpYXQiOjE3NTMzMjg0ODAsImVmcCI6I0lwNnU2V0ljeWc2QTRvaUpLTE1CYUxIQkM1WjlmemttTk5IZndvSFpw3a1IxQ1VDY09mWWEwZERHSE8iLCJkaWQiOiI3ZWE3ZjM5NC04MmE0LTQxZmQtODEwMC0xNDc5NjZiZGQ0NTAiLCJjcGsiOiJNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVKTmNEUDRSM3NXeWlwVmg2NWhCT0YrTnlFVmNQM3hSWHhsemN5MzlzeElzSjY1SVo1T2tIRDdCbGVLSkw5bEptbWFKL0Z2RmNuVmZyT0hHR2F3TmIxZz09In0.hWoGyoMpdx6pyV1dOynhXklnBOXy-rtvUFgMQrsCCP715xFaLTafa7lp6YxHQszzc5u7VKSOrdNnbMs1EnXv-w' \
  -H 'x-fptoken-signature: {P1363}i9ImgQQ18zxG338tw1WE6KY0GBcyJ6uiSYUCF4vkjgT2JNei6Ui7sM1ADvFtSg6BfOCqdBk0vXexVFufsw==' \
  -H 'x-id-group: 2131133377681004-c-626' \
  -H 'x-locale: zh_CN' \
  -H 'x-request-timestamp: 1753340709575' \
  -H 'x-simulated-trading: undefined' \
  -H 'x-site-info: ==QfzojI5RXawiIMFkQPx0Rfh1SPOiUGZvNmIsIySIJiOi42bpdWZyJye' \
  -H 'x-utc: 8' \
  -H 'x-zkdex-env: 0' \
  --data-raw '{"desc":false,"orderBy":"timestamp","limit":100,"tradingHistoryFilter":{"chainId":"56","tokenContractAddress":"0x75a589af600098d62ed8c34cc594fb470f","type":"1","currentUserWalletAddress":"0x6e05ff068926b161169ab62ec899f266b338a3d8","userAddressList":[],"volumeMin":"500","volumeMax":"","priceMin":"","priceMax":"","startTime":1751806200000,"endTime":1751810400000}}'
"""

def extract_payload(curl_cmd):
    """从curl命令中提取并解析payload，处理特殊字符"""
    # 查找--data-raw或-d参数
    data_pattern = re.compile(r'--data-raw\s+(\$?\'[^\']+\'|\$?"[^"]+"|\$?{[^}]+})| -d\s+(\$?\'[^\']+\'|\$?"[^"]+"|\$?{[^}]+})')
    match = data_pattern.search(curl_cmd)
    
    if match:
        # 提取匹配的分组
        payload_str = match.group(1) or match.group(2)
        
        # 去除前后引号和$符号
        if payload_str.startswith(("'", '"', "$'", '$"')):
            payload_str = payload_str.replace("$", "")  # 移除可能的$前缀
            payload_str = payload_str[1:-1]
        
        # 处理Unicode转义字符，如\u0021
        try:
            payload_str = payload_str.encode('utf-8').decode('unicode_escape')
        except UnicodeDecodeError:
            pass
        
        try:
            return json.loads(payload_str)
        except json.JSONDecodeError as e:
            logging.error(f"解析payload失败: {str(e)}")
            logging.error(f"提取的payload字符串: {payload_str}")
    
    # 如果自动提取失败，提示手动输入
    logging.warning("无法从cURL命令中提取payload，请手动输入")
    while True:
        try:
            payload_str = input("请输入初始payload: ")
            return json.loads(payload_str)
        except json.JSONDecodeError as e:
            logging.error(f"JSON格式错误: {str(e)}，请重新输入")

def extract_curl_parameters(curl_command):
    """从cURL命令中提取请求参数"""
    try:
        # 提取URL
        url_match = re.search(r"curl '(https?://[^']+)", curl_command)
        if not url_match:
            raise ValueError("无法从cURL命令中提取URL")
        url = url_match.group(1)
        
        # 提取headers
        headers = {}
        header_matches = re.finditer(r"-H '([^:]+): ([^']+)'", curl_command)
        for match in header_matches:
            headers[match.group(1)] = match.group(2)
        
        # 提取payload
        payload = extract_payload(curl_command)
        
        return url, headers, payload
    
    except Exception as e:
        logging.error(f"解析cURL命令失败: {e}")
        raise

def fetch_data(url, headers, payload):
    """获取数据"""
    try:
        logging.info(f"正在请求数据，payload: {payload}")
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logging.error(f"请求数据失败: {e}")
        raise

def process_data(raw_data):
    """处理原始数据"""
    processed_data = []
    
    if not raw_data.get("data") or not raw_data["data"].get("list"):
        logging.warning("返回数据中没有交易列表")
        return processed_data
    
    for item in raw_data["data"]["list"]:
        try:
            # 转换交易时间到北京时间
            timestamp = item["timestamp"] / 1000  # 转换为秒
            beijing_time = datetime.fromtimestamp(timestamp) + timedelta(hours=8)
            trade_time = beijing_time.strftime("%Y-%m-%d %H:%M:%S")
            
            # 交易类型
            trade_type = "买入" if item.get("isBuy") == "1" else "卖出"
            
            # 总价值
            volume = round(float(item.get("volume", 0)), 2)
            
            # 代币价格
            price = round(float(item.get("price", 0)), 6)
            
            # 代币数量
            token0_amount = 0
            token1_amount = 0
            if item.get("changedTokenInfo") and len(item["changedTokenInfo"]) >= 2:
                token0_amount = round(float(item["changedTokenInfo"][0].get("amount", 0)), 2)
                token1_amount = round(float(item["changedTokenInfo"][1].get("amount", 0)), 2)
            
            # 交易哈希
            tx_hash = ""
            if item.get("txHashUrl"):
                tx_hash = item["txHashUrl"].split("/tx/")[-1]
            tx_url = f"https://bscscan.com/tx/{tx_hash}" if tx_hash else ""
            
            # 用户地址
            user_address = item.get("userAddress", "")
            
            processed_data.append({
                "交易时间": trade_time,
                "类型": trade_type,
                "总价值(USD)": volume,
                "代币价格": price,
                "代币0数量": token0_amount,
                "代币1数量": token1_amount,
                "用户地址": user_address,
                "交易哈希": tx_url
            })
            
        except Exception as e:
            logging.error(f"处理数据项失败: {e}, 原始数据: {item}")
            continue
    
    return processed_data

def save_to_csv(data, filename):
    """保存数据到CSV文件"""
    try:
        df = pd.DataFrame(data)
        df.to_csv(filename, index=False, encoding='utf-8-sig')
        logging.info(f"数据已保存到 {filename}")
    except Exception as e:
        logging.error(f"保存CSV文件失败: {e}")
        raise

def main():
    try:
        # 从cURL命令中提取参数
        url, headers, payload = extract_curl_parameters(CURL_COMMAND)
        
        all_processed_data = []
        page = 1
        has_more = True
        
        while has_more:
            logging.info(f"正在获取第 {page} 页数据...")
            
            # 获取数据
            raw_data = fetch_data(url, headers, payload)
        
            
            # 处理数据
            processed_data = process_data(raw_data)
            all_processed_data.extend(processed_data)
            
            # 检查是否有更多数据
            has_more = raw_data.get("data", {}).get("hasMore") == "1"
            
            if has_more and raw_data.get("data", {}).get("list"):
                # 更新payload中的dataId为最后一条数据的id
                last_item = raw_data["data"]["list"][-1]
                if "id" in last_item:
                    payload["dataId"] = last_item["id"]
                page += 1
            else:
                has_more = False
        
        # 保存处理后的数据到CSV
        csv_filename = "processed_data.csv"
        save_to_csv(all_processed_data, csv_filename)
        
        logging.info(f"数据处理完成，共获取 {len(all_processed_data)} 条记录")
    
    except Exception as e:
        logging.error(f"主程序运行出错: {e}")

if __name__ == "__main__":
    main()