# pcap_to_txt
通过DNS pcap文件生成描述DNS协议网络传输报文的文本文件

---
使用方法：
    python generate_metadata_from_pcap.py your-pcap-file-path metadata-save-dir

例如：
    python generate_metadata_from_pcap.py demo.pcap .

将在当前文件夹下生成demo.pcap.txt

**注：使用前需要安装wireshark，因为底层本质上是使用tshark命令进行解析。**
