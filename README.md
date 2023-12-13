# tcp_stateless-communication
通过scapy实现使用tcp syn包进行网络通信的简易cmd，可避免建立tcp连接而被检测，也可在特定情况下bypass firewall

TODO:
  后续将实现密钥交换、源ip伪造等

使用：
  Sender: 
usage: python Sender.py [-h] -s SRC -d DST -sp SRC_PORT -dp DST_PORT [-P PASSWD]

options:
  -h, --help            show this help message and exit
  -s SRC, --src SRC     src ip
  -d DST, --dst DST     dst ip
  -sp SRC_PORT, --src_port SRC_PORT
                        src port
  -dp DST_PORT, --dst_port DST_PORT
                        dst port
  -P PASSWD, --Passwd PASSWD
                        Passwd

  Receiver: 
    Usage:python Receiver.py port passwd
