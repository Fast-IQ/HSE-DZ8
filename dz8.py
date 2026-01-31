import sys
from scapy.all import *
import random


host = "google-gruyere.appspot.com"
instance_id = "606349775900031768833848789123437690829"
dport = 80


path = sys.argv[2] if len(sys.argv) > 2 else ''
getStr = f'GET /{instance_id}/{path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n'


max_val = int(sys.argv[3]) if len(sys.argv) > 3 else 10

def parse_http_response(data):

    if b'\r\n\r\n' not in data:
        return b'', data
    
    headers, body = data.split(b'\r\n\r\n', 1)
    

    if b'Transfer-Encoding: chunked' in headers.lower():
        decoded_body = b''
        while body:
          
            if body.startswith(b'\r\n'):
                body = body[2:]
                continue
          
            chunk_size_line, body = body.split(b'\r\n', 1)
            try:
                chunk_size = int(chunk_size_line.split(b';')[0], 16)
            except:
                break
            if chunk_size == 0:
                break
         
            decoded_body += body[:chunk_size]
            body = body[chunk_size + 2:]  
        return headers, decoded_body
    
    return headers, body

for counter in range(max_val):
    sport = random.randint(1025, 65535)
    
    syn = IP(dst=host)/TCP(sport=sport, dport=dport, flags='S', seq=1000)
    syn_ack = sr1(syn, timeout=5)
    if syn_ack is None:
        print(f"[{counter}] Нет SYN-ACK от {host}")
        continue
    
    server_ip = syn_ack[IP].src
    client_seq = syn_ack[TCP].ack 
    server_seq = syn_ack[TCP].seq + 1  
    

    ack = IP(dst=server_ip)/TCP(sport=sport, dport=dport, seq=client_seq, ack=server_seq, flags='A')
    send(ack, verbose=False)
    
    http_req = IP(dst=server_ip)/TCP(sport=sport, dport=dport, seq=client_seq, ack=server_seq, flags='PA')/getStr
    send(http_req, verbose=False)
    client_seq += len(getStr) 
    
    responses = sniff(
        filter=f"tcp and src host {server_ip} and src port {dport} and dst port {sport}",
        timeout=10,
        store=True
    )
    
    packets_data = {}
    for pkt in responses:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            seq = pkt[TCP].seq
            data = pkt[Raw].load
            packets_data[seq] = data
            

            ack_pkt = IP(dst=server_ip)/TCP(
                sport=sport,
                dport=dport,
                seq=client_seq,
                ack=seq + len(data),
                flags='A'
            )
            send(ack_pkt, verbose=False)
            server_seq = seq + len(data) 
    

    full_body = b''
    for seq in sorted(packets_data.keys()):
        full_body += packets_data[seq]
    
    if full_body:
        headers, body = parse_http_response(full_body)
        
        print(f"\n=== Запрос #{counter+1} ===")
        print("Заголовки ответа:")
        print(headers.decode('utf-8', errors='ignore'))
        
        print("\n Тело ответа:")
        try:
            print(body.decode('utf-8', errors='replace'))
        except:
            print(body)
    else:
        print(f"[{counter}] Нет данных в ответе. Поймано пакетов: {len(responses)}")
        for pkt in responses:
            print(f"  {pkt.summary()} | flags: {pkt[TCP].flags} | has Raw: {pkt.haslayer(Raw)}")
    

    fin = IP(dst=server_ip)/TCP(sport=sport, dport=dport, seq=client_seq, ack=server_seq, flags='FA')
    send(fin, verbose=False)

    time.sleep(1)

print(f"\n Завершено {counter+1} запросов")