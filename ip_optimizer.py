import os
import requests
import random
import numpy as np
import time
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from tqdm import tqdm
import urllib3
import ipaddress

####################################################
# 可配置参数（程序开头）
####################################################
CONFIG = {
    "MODE": "TCP",  # 测试模式：PING/TCP
    "PING_TARGET": "https://www.apple.com/library/test/success.html",  # Ping测试目标
    "PING_COUNT": 3,  # Ping次数
    "PING_TIMEOUT": 5,  # Ping超时(秒)
    "PORT": 443,  # TCP测试端口
    "RTT_RANGE": "10~2000",  # 延迟范围(ms)
    "LOSS_MAX": 30.0,  # 最大丢包率(%)
    "THREADS": 50,  # 并发线程数
    "IP_POOL_SIZE": 50000,  # IPv4池总大小
    "IPV6_POOL_SIZE": 20000,  # IPv6池总大小
    "TEST_IP_COUNT": 1000,  # IPv4实际测试IP数量
    "TEST_IPV6_COUNT": 1000,  # IPv6实际测试IP数量
    "TOP_IPS_LIMIT": 15,  # 精选IP数量
    "CLOUDFLARE_IPS_URL": "https://www.cloudflare.com/ips-v4",
    "CLOUDFLARE_IPS_V6_URL": "https://www.cloudflare.com/ips-v6",
    "CUSTOM_IPS_FILE": "custom_ips.txt",  # 自定义IPv4池文件路径
    "CUSTOM_IPS_V6_FILE": "custom_ips_v6.txt",  # 自定义IPv6池文件路径
    "TCP_RETRY": 2,  # TCP重试次数
    "SPEED_TIMEOUT": 5,  # 测速超时时间
    "SPEED_URL": "https://speed.cloudflare.com/__down?bytes=10000000"  # 测速URL
}

####################################################
# 核心功能函数
####################################################

def init_env():
    for key, value in CONFIG.items():
        os.environ[key] = str(value)
    cf_url = os.getenv('CLOUDFLARE_IPS_URL')
    if cf_url and not cf_url.startswith(('http://', 'https://')):
        os.environ['CLOUDFLARE_IPS_URL'] = f"https://{cf_url}"
    urllib3.disable_warnings()

def fetch_ip_ranges(ipv6=False):
    custom_file = os.getenv('CUSTOM_IPS_V6_FILE') if ipv6 else os.getenv('CUSTOM_IPS_FILE')
    if custom_file and os.path.exists(custom_file):
        print(f"🔧 使用自定义{'IPv6' if ipv6 else 'IPv4'} IP池文件: {custom_file}")
        try:
            with open(custom_file, 'r') as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        except Exception as e:
            print(f"🚨 读取自定义IP池失败: {e}")
    url = os.getenv('CLOUDFLARE_IPS_V6_URL') if ipv6 else os.getenv('CLOUDFLARE_IPS_URL')
    try:
        res = requests.get(url, timeout=10, verify=False)
        return res.text.splitlines()
    except Exception as e:
        print(f"🚨 获取Cloudflare {'IPv6' if ipv6 else 'IPv4'} IP段失败: {e}")
    return []

# 生成随机IP（基于位运算实现）
def generate_random_ip(subnet):
    """根据CIDR生成子网内的随机合法IP（排除网络地址和广播地址）"""
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        if network.version == 6:
            first_ip = int(network.network_address) + 1
            last_ip = int(network.broadcast_address) - 1
            if last_ip < first_ip:
                return str(network.network_address)
            random_ip_int = random.randint(first_ip, last_ip)
            return str(ipaddress.IPv6Address(random_ip_int))
        elif network.version == 4:
            first_ip = int(network.network_address) + 1
            last_ip = int(network.broadcast_address) - 1
            if last_ip < first_ip:
                return str(network.network_address)
            random_ip_int = random.randint(first_ip, last_ip)
            return str(ipaddress.IPv4Address(random_ip_int))
        else:
            print(f"不支持的IP版本: {network.version}")
            return None
    except Exception as e:
        print(f"生成随机IP错误: {e}，使用简单方法生成")
        try:
            if ':' in subnet:  # IPv6 fallback
                base_ip = subnet.split('/')[0]
                parts = base_ip.split(':')
                while len(parts) < 8:
                    parts.append('%x' % random.randint(0, 0xFFFF))
                ip = ':'.join(parts[:8])
                return str(ipaddress.IPv6Address(ip))
            else:  # IPv4 fallback
                base_ip = subnet.split('/')[0]
                parts = base_ip.split('.')
                while len(parts) < 4:
                    parts.append(str(random.randint(0, 255)))
                parts = [str(min(255, max(0, int(p)))) for p in parts[:3]] + [str(random.randint(1, 254))]
                ip = '.'.join(parts)
                return str(ipaddress.IPv4Address(ip))
        except Exception as e2:
            print(f"最终IP生成失败: {e2}")
            return None

def custom_ping(ip):
    target = urlparse(os.getenv('PING_TARGET')).netloc or os.getenv('PING_TARGET')
    count = int(os.getenv('PING_COUNT'))
    timeout = int(os.getenv('PING_TIMEOUT'))
    try:
        if os.name == 'nt':
            cmd = f"ping -n {count} -w {timeout*1000} {target}"
        else:
            cmd = f"ping -c {count} -W {timeout} -I {ip} {target}"
        result = subprocess.run(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout + 2
        )
        output = result.stdout.lower()
        if "100% packet loss" in output or "unreachable" in output:
            return float('inf'), 100.0
        loss_line = next((l for l in result.stdout.split('\n') if "packet loss" in l.lower()), "")
        timing_lines = [l for l in result.stdout.split('\n') if "time=" in l.lower()]
        loss_percent = 100.0
        if loss_line:
            loss_parts = loss_line.split('%')
            if loss_parts:
                try:
                    loss_percent = float(loss_parts[0].split()[-1])
                except:
                    pass
        delays = []
        for line in timing_lines:
            if "time=" in line:
                time_str = line.split("time=")[1].split()[0]
                try:
                    delays.append(float(time_str))
                except:
                    continue
        avg_delay = np.mean(delays) if delays else float('inf')
        return avg_delay, loss_percent
    except subprocess.TimeoutExpired:
        return float('inf'), 100.0
    except Exception as e:
        print(f"Ping测试异常: {e}")
        return float('inf'), 100.0

def tcp_ping(ip, port, timeout=2):
    retry = int(os.getenv('TCP_RETRY', 3))
    success_count = 0
    total_rtt = 0
    for _ in range(retry):
        start = time.time()
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                rtt = (time.time() - start) * 1000  # 毫秒
                total_rtt += rtt
                success_count += 1
        except:
            pass
        time.sleep(0.1)
    loss_rate = 100 - (success_count / retry * 100)
    avg_rtt = total_rtt / success_count if success_count > 0 else float('inf')
    return avg_rtt, loss_rate

def speed_test(ip):
    url = os.getenv('SPEED_URL')
    timeout = float(os.getenv('SPEED_TIMEOUT', 10))
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        start_time = time.time()
        response = requests.get(
            url, headers={'Host': host}, timeout=timeout, verify=False, stream=True
        )
        total_bytes = 0
        for chunk in response.iter_content(chunk_size=8192):
            total_bytes += len(chunk)
            if time.time() - start_time > timeout:
                break
        duration = time.time() - start_time
        speed_mbps = (total_bytes * 8 / duration) / 1e6 if duration > 0 else 0
        return speed_mbps
    except Exception as e:
        print(f"测速异常: {e}")
        return 0.0

def ping_test(ip):
    if os.getenv('MODE') == "PING":
        rtt, loss = custom_ping(ip)
    else:
        rtt, loss = tcp_ping(ip, int(os.getenv('PORT')))
    return (ip, rtt, loss)

def full_test(ip_data):
    ip = ip_data[0]
    speed = speed_test(ip)
    return (*ip_data, speed)

####################################################
# 主逻辑
####################################################
if __name__ == "__main__":
    init_env()
    for family in ["IPv4", "IPv6"]:
        print(f"\n{'='*30} {family} 测试 {'='*30}")
        is_v6 = (family == "IPv6")
        subnets = fetch_ip_ranges(ipv6=is_v6)
        if not subnets:
            print(f"❌ 无法获取{family} IP段，程序终止")
            continue
        pool_size = int(os.getenv('IPV6_POOL_SIZE')) if is_v6 else int(os.getenv('IP_POOL_SIZE'))
        test_count = int(os.getenv('TEST_IPV6_COUNT')) if is_v6 else int(os.getenv('TEST_IP_COUNT'))
        top_limit = int(os.getenv('TOP_IPS_LIMIT'))
        full_ip_pool = set()
        print(f"🔧 正在生成 {pool_size} 个随机{family} IP...")
        with tqdm(total=pool_size, desc=f"生成{family}池", unit="IP") as pbar:
            while len(full_ip_pool) < pool_size:
                subnet = random.choice(subnets)
                ip = generate_random_ip(subnet)
                if ip and ip not in full_ip_pool:
                    full_ip_pool.add(ip)
                    pbar.update(1)
        print(f"✅ 成功生成 {len(full_ip_pool)} 个随机{family} IP")
        if test_count > len(full_ip_pool):
            test_count = len(full_ip_pool)
        test_ip_pool = random.sample(list(full_ip_pool), test_count)
        print(f"🔧 随机选取 {len(test_ip_pool)} 个{family} IP进行测试")

        # 1. Ping/TCP测试
        ping_results = []
        with ThreadPoolExecutor(max_workers=int(os.getenv('THREADS'))) as executor:
            future_to_ip = {executor.submit(ping_test, ip): ip for ip in test_ip_pool}
            with tqdm(
                total=len(test_ip_pool),
                desc=f"🚀 {family}延迟丢包测试",
                unit="IP",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
            ) as pbar:
                for future in as_completed(future_to_ip):
                    try:
                        ping_results.append(future.result())
                    except Exception as e:
                        print(f"\n🔧 {family} Ping测试异常: {e}")
                    finally:
                        pbar.update(1)
        rtt_min, rtt_max = map(int, os.getenv('RTT_RANGE').split('~'))
        loss_max = float(os.getenv('LOSS_MAX'))
        passed_ips = [
            ip_data for ip_data in ping_results
            if rtt_min <= ip_data[1] <= rtt_max and ip_data[2] <= loss_max
        ]
        print(f"\n✅ {family} Ping测试完成: 总数 {len(ping_results)}, 通过 {len(passed_ips)}")

        # 2. 测速
        if not passed_ips:
            print(f"❌ 没有通过{family} Ping测试的IP，程序终止")
            continue
        full_results = []
        with ThreadPoolExecutor(max_workers=int(os.getenv('THREADS'))) as executor:
            future_to_ip = {executor.submit(full_test, ip_data): ip_data for ip_data in passed_ips}
            with tqdm(
                total=len(passed_ips),
                desc=f"📊 {family}下载测速",
                unit="IP",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
            ) as pbar:
                for future in as_completed(future_to_ip):
                    try:
                        full_results.append(future.result())
                    except Exception as e:
                        print(f"\n🔧 {family} 测速异常: {e}")
                    finally:
                        pbar.update(1)

        # 3. 精选排序
        sorted_ips = sorted(
            full_results,
            key=lambda x: (-x[3], x[1])
        )[:top_limit]

        # 4. 保存结果
        os.makedirs('results', exist_ok=True)
        suffix = 'v6' if is_v6 else 'v4'
        with open(f'results/all_ips_{suffix}.txt', 'w') as f:
            f.write("\n".join([ip[0] for ip in ping_results]))
        with open(f'results/passed_ips_{suffix}.txt', 'w') as f:
            f.write("\n".join([ip[0] for ip in passed_ips]))
        with open(f'results/full_results_{suffix}.csv', 'w') as f:
            f.write("IP,延迟(ms),丢包率(%),速度(Mbps)\n")
            for ip_data in full_results:
                f.write(f"{ip_data[0]},{ip_data[1]:.2f},{ip_data[2]:.2f},{ip_data[3]:.2f}\n")
        with open(f'results/top_ips_{suffix}.txt', 'w') as f:
            f.write("\n".join([ip[0] for ip in sorted_ips]))
        with open(f'results/top_ips_details_{suffix}.csv', 'w') as f:
            f.write("IP,延迟(ms),丢包率(%),速度(Mbps)\n")
            for ip_data in sorted_ips:
                f.write(f"{ip_data[0]},{ip_data[1]:.2f},{ip_data[2]:.2f},{ip_data[3]:.2f}\n")

        # 5. 统计输出
        print("\n" + "="*60)
        print(f"{'🔥 ' + family + ' 测试结果统计':^60}")
        print("="*60)
        print(f"IP池大小: {pool_size}")
        print(f"实际测试IP数: {len(ping_results)}")
        print(f"通过Ping测试IP数: {len(passed_ips)}")
        print(f"测速IP数: {len(full_results)}")
        print(f"精选TOP IP: {len(sorted_ips)}")
        if sorted_ips:
            print("\n🏆【最佳IP TOP5】")
            for i, ip_data in enumerate(sorted_ips[:5]):
                print(f"{i+1}. {ip_data[0]} | 延迟:{ip_data[1]:.2f}ms | 丢包:{ip_data[2]:.2f}% | 速度:{ip_data[3]:.2f}Mbps")
        print("="*60)
        print(f"✅ 结果已保存至 results/ 目录，文件后缀_{suffix}")

    # 检查IPv6合法性
    if is_v6:
        with open('results/all_ips_v6.txt') as f:
            for line in f:
                try:
                    ipaddress.IPv6Address(line.strip())
                except Exception as e:
                    print('非法IPv6:', line.strip())
