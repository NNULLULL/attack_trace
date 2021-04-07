#!/usr/bin/python
#encoding:utf-8
import re 
import requests
import sys
import os
import json
import nmap

headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X)'
}
global site

#调用微步api进行相关查询
def weibu(session, ip):

    url1 = "https://api.threatbook.cn/v3/scene/ip_reputation" #IP信誉
    url2 = "https://api.threatbook.cn/v3/ip/query"  #IP分析
    url3 = "https://api.threatbook.cn/v3/domain/query" #域名分析
    if os.path.getsize("./weibuapi_key.txt") == 0:
        exit("weibuapi_key is None!!!")
    else:
        with open("weibuapi_key.txt", "r") as f:
            key = f.read()
    data = {
        'apikey': key,
        'resource': ip,
        'lang': 'zh',
    }
    r = session.post(url1, data).json()
    if r['response_code'] == 0: 
        r = r['data']
        for name in r:  
            info = r[name]
            severity = info['severity']     # 危害程度  
            judgmentsarr = info['judgments']   # 类型数组
            ibasic = info['basic']
            blocation = ibasic['location']
            carrier = ibasic['carrier']       # 运营商
            country = blocation['country']    # 国家
            province = blocation['province']  # 省
            city = blocation['city']          # 城市
            locationname = '%s %s %s %s' % (country, province, city, carrier)
            locationname = re.sub(r' +', '/', locationname)
            judgments = '/'
            for j in judgmentsarr:
                judgments = '%s%s/' % (judgments, j)
            return severity, locationname, judgments
    else: 
        print("key is wrong!!")


# 调用dnsgrep进行ip反查域名
def ip_domain(ip):
    total = []
    token = ""  # 需要向dnsgrep进行申请即可获得token
    url = "https://www.dnsgrep.cn/api/query?q={0}&token={1}".format(ip,token)
    req = requests.get(url,headers=headers).json()   
    if req['status'] == 200:  # 数据正常
        r = req['data']
        r = r['data']
        for name in r:
            domain = name["domain"]
            time = name["time"]
            if domain != "" and time != "":
                total.append(domain + "/" + time)
                site = domain
                print("================================================================")
                print(site + "/" + time)
                whois(site)
        return total,site
# 调用nmap进行端口扫描
def nmap_scan(ip):
    nm = nmap.PortScanner()
    nm.scan(ip,arguments='-Pn --open -T4 1-65535')
    print('----------------------------------------------------')
    r = nm.command_line()
    print(r)
    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
            lport = nm[host][proto].keys()
            for port in lport:
                print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

def whois(site):
    try:
        url = "http://whois.4.cn/api/main"
        data = {'domain': site}
        req = requests.post(url,data=data,headers=headers,verify=False)
        json_data = json.loads(req.text)
        if json_data['data']['owner_name'] != "":
            print("[+]域名所有者:"+json_data['data']['owner_name'])
            print("[+]域名所有者邮箱:"+json_data['data']['owner_email'])
            print("[+]域名所有者注册:"+json_data['data']['registrars'])
    except:
        pass

#对url.txt中对url进行比遍历
def urls(filename):
    session = requests.Session()
    print("================================================================")
    with open(filename, 'r') as f:
        while True:
            line = f.readline()
            if not line:
                break
            if line == " ":
                continue  
            if len(sys.argv) == 3:
                nmap_scan(line)  
            try:
                severity, locationname, judgments = weibu(session, line)
                print('[+]%s,%s,%s,%s' % (
                    line, severity, locationname, judgments))
            except:
                print('weibuapi_key is wrong!!!')
            try:
                total ,site = ip_domain(line)
            except:
                pass
        session.close()


if __name__ == '__main__':
    urls(sys.argv[1])
