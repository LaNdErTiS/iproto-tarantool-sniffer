# 🐘 iproto-tarantool-sniffer  
**A command-line tool for sniffing and decoding Tarantool Iproto packets**  

---

## 🚀 Features  
- **Live packet capture** or **PCAP file analysis**  
- Decodes **Tarantool Iproto protocol** (including `SELECT`, `ERROR`, `AUTH`, etc.)  
- Parses **greeting messages** (128-byte header)  
- Structured JSON output with optional **hex dumps**  
- Supports filtering by interface, port, and packet content  
- Works with **TCP/3301** (default Tarantool port)  

---

## 📦 Installation  
```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install git+https://github.com/LaNdErTiS/iproto-tarantool-sniffer.git or python3 -m pip install '.[dev]' or python3 -m pip install .
```

**Requirements**:  
- Python 3.13+  
- [Scapy](https://scapy.net/)  
- [msgpack](https://github.com/msgpack/msgpack-python)  
- [Rich](https://github.com/Textualize/rich)  

---

## 🛠 Usage  
```bash
iproto-sniffer --help  
Usage: iproto-sniffer [OPTIONS]

  A command-line network packet sniffer that captures and processes TCP
  packets.

  This tool captures TCP packets based on a specified filter, processes their
  payloads, and outputs the results in a structured format, either to the
  console or a file. It can read packets from a live network interface or a
  .pcap file.

Options:
  --interface TEXT  Network interface to sniff on.
  --filter TEXT     Traffic filter for sniffing (e.g., 'tcp port 3301').
  --from_pcap TEXT  Path to a .pcap file to read from.
  --hex             Include payload hex in output.
  --output TEXT     Path to the output file.
  --empty_packet    Show packets with empty payload.
  --show_headers    Show detailed IP/TCP headers.
  --help            Show this message and exit.
```

### 🔍 Example Commands  
1. **Live sniffing**:  
   ```bash
   iproto-sniffer --interface eth0 --filter "tcp port 3301" --hex
   ```

2. **Analyze PCAP**:  
   ```bash
   iproto-sniffer --from_pcap=traffic.pcap --output=result.txt
   ```

3. **Show raw hex**:  
   ```bash
   iproto-sniffer --hex --show_headers
   ```

---

## 📘 Output Format  
Decoded packets are structured as nested dictionaries.
Empty example:
```text
Packet from 127.0.0.1:3301 to 127.0.0.1:51694
IP ID: 11089 | TCP Seq: 865758586 | Ack: 951312929 | Window: 6379
Timestamp: 2025-09-07 20:20:12

Packet with empty payload

================================================================================
```

Greeting example:  
```json
{
    "Greeting message": {
        "Tarantool Version": {
            "Hex": "54 61 72 61 6e 74 6f 6f 6c 20 33 2e 31 2e 30 20 28 42 69 6e 61 72 79 29",
            "Decoded": "Tarantool 3.1.0 (Binary)"
        },
        "Instance UUID": {
            "Hex": "33 63 64 61 31 35 66 38 2d 66 30 39 32 2d 34 37 31 33 2d 61 39 37 33 2d 63 35 37 33 35 63 61 64 38 65 36 36",
            "Decoded": "3cda15f8-f092-4713-a973-c5735cad8e66"
        },
        "Salt": {
            "Hex": "2b 44 6d 48 72 43 5a 37 50 45 43 53 4b 70 71 49 38 68 32 6d 44 77 34 75 47 47 64 71 33 43 72 55 44 64 57 5a 6c 7a 59 55 6a 6c 51 3d",
            "Decoded": "+DmHrCZ7PECSKpqI8h2mDw4uGGdq3CrUDdWZlzYUjlQ="
        }
    }
}
```

Command example:  
```json
[{
    "Iproto0": {
        "Size": {
            "Hex": "20",
            "Decoded": 32
        },
        "Header": {
            "Hex": "83 00 08 01 00 05 00",
            "Decoded": {
                "IPROTO_REQUEST_TYPE": "IPROTO_EVAL",
                "IPROTO_SYNC": 0,
                "IPROTO_SCHEMA_VERSION": 0
            }
        },
        "Body": {
            "Hex": "82 27 b4 72 65 74 75 72 6e 20 62 6f 78 2e 69 6e 66 6f 28 29 2e 72 6f 21 90",
            "Decoded": {
                "IPROTO_EXPR": "return box.info().ro",
                "IPROTO_TUPLE": []
            }
        }
    }
},
{
    "Iproto0": {
        "Size": {
            "Hex": "ce 00 00 00 23",
            "Decoded": 35
        },
        "Header": {
            "Hex": "83 00 ce 00 00 00 00 01 cf 00 00 00 00 00 00 00 00 05 cf 00 00 00 00 00 00 00 53",
            "Decoded": {
                "IPROTO_REQUEST_TYPE": "IPROTO_OK",
                "IPROTO_SYNC": 0,
                "IPROTO_SCHEMA_VERSION": 83
            }
        },
        "Body": {
            "Hex": "81 30 dd 00 00 00 01 c2",
            "Decoded": {
                "IPROTO_DATA": [
                    false
                ]
            }
        }
    }
}]
```

---

## 🧠 How It Works  
1. **Packet Capture**: Uses Scapy to sniff TCP traffic.  
2. **Payload Parsing**:  
   - **Iproto Packets**: Split into `Size`, `Header`, `Body` using MessagePack.  
   - **Greeting Messages**: Parses 128-byte text header with version/UUID/salt.  
3. **Decoding**: Maps numeric keys to human-readable names via `HEADER_MAP` and `BODY_MAP`.  

---

## 🛡️ License  
MIT License © [Ivan Gavalidi](mailto:malisek00@mail.ru)  
See [LICENSE](LICENSE) for details.

---

## 📢 Contribute  
- Report bugs: [GitHub Issues](https://github.com/LaNdErTiS/iproto-tarantool-sniffer/issues)  
- Submit PRs for new features (e.g., support for newer Iproto versions)  
- Improve documentation or add tests  

---

## 🌐 Links  
- [Homepage](https://github.com/LaNdErTiS/iproto-tarantool-sniffer)  
- [Tarantool Iproto Docs](https://www.tarantool.io/en/doc/latest/reference/internals/)  

---
