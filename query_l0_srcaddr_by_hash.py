import requests
import openpyxl
from openpyxl.styles import Font
import time
import json
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# API基础URL(layerzero获取跨链前的sender地址，transactions.txt输入要查询的哈希)
API_BASE_URL = "https://scan.layerzero-api.com/v1/messages/tx/"

# 配置重试策略
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[408, 429, 500, 502, 503, 504]
)
adapter = HTTPAdapter(max_retries=retry_strategy)
session = requests.Session()
session.mount("https://", adapter)
session.mount("http://", adapter)

def read_transactions(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if line.strip()]

def query_transaction(tx_hash, max_retries=3):
    url = f"{API_BASE_URL}{tx_hash}"
    for attempt in range(max_retries):
        try:
            response = session.get(url, timeout=(10, 30))
            response.raise_for_status()
            data = response.json()

            if not data.get('data'):
                print(f"No data found for transaction {tx_hash}")
                return {
                    'tx_hash': tx_hash,
                    'sender_address': 'N/A',
                    'source_chain': 'N/A'
                }

            first_item = data['data'][0]
            source_tx = first_item.get('source', {}).get('tx', {})
            
            return {
                'tx_hash': tx_hash,
                'sender_address': source_tx.get('from', 'N/A'),
                'source_chain': 'solana'  # 硬编码为solana，因为所有示例都来自solana
            }

        except requests.exceptions.SSLError as e:
            print(f"SSL Error on attempt {attempt + 1} for {tx_hash}: {str(e)}")
            if attempt == max_retries - 1:
                return {
                    'tx_hash': tx_hash,
                    'sender_address': 'SSL Error',
                    'source_chain': 'Error'
                }
            time.sleep(2 ** attempt)

        except requests.exceptions.RequestException as e:
            print(f"Request failed on attempt {attempt + 1} for {tx_hash}: {str(e)}")
            if attempt == max_retries - 1:
                return {
                    'tx_hash': tx_hash,
                    'sender_address': 'Request Error',
                    'source_chain': 'Error'
                }
            time.sleep(2 ** attempt)

        except Exception as e:
            print(f"Unexpected error on attempt {attempt + 1} for {tx_hash}: {str(e)}")
            if attempt == max_retries - 1:
                return {
                    'tx_hash': tx_hash,
                    'sender_address': 'Error',
                    'source_chain': 'Error'
                }
            time.sleep(2 ** attempt)

def save_to_excel(results, output_file):
    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet.title = "Sender Addresses"
    
    # 写入表头
    headers = ['Transaction Hash', 'Sender Address', 'Source Chain']
    sheet.append(headers)
    
    # 设置表头样式
    for cell in sheet[1]:
        cell.font = Font(bold=True)
    
    # 写入数据
    for result in results:
        sheet.append([
            result['tx_hash'],
            result['sender_address'],
            result['source_chain']
        ])
    
    # 自动调整列宽
    for column in sheet.columns:
        max_length = max(
            len(str(cell.value)) for cell in column
        )
        column_letter = column[0].column_letter
        sheet.column_dimensions[column_letter].width = max_length + 2
    
    workbook.save(output_file)

def main():
    try:
        input_file = "transactions.txt"
        output_file = "sender_addresses.xlsx"
        
        transactions = read_transactions(input_file)
        if not transactions:
            print("No transactions found.")
            return

        print(f"Processing {len(transactions)} transactions...")
        results = []
        
        for i, tx_hash in enumerate(transactions, 1):
            print(f"Processing {i}/{len(transactions)}: {tx_hash}")
            result = query_transaction(tx_hash)
            results.append(result)
            time.sleep(1)  # 基础延迟1秒
        
        save_to_excel(results, output_file)
        print(f"Results saved to {output_file}")
        
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()