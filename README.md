# FfufDast
Make ffuf to DAST scanner

# HTTP Request Tools

Welcome to the **HTTP Request Tools** repository! This collection of Python scripts is designed to help you extract and manipulate HTTP requests easily. 

## 📂 Tools Included

### 1. `hartorawreq.py`
**Extract Raw HTTP Requests from a HAR File**

This script allows you to extract raw HTTP requests from a HAR (HTTP Archive) file and save each request in separate files.

#### ⚙️ How to Use:
```bash
python3 hartorawreq.py -h
```

📋 Usage:
usage: hartorawreq.py [-h] -f FILE [-o OUTPUT] [-s SCOPE]





Extract raw requests from a HAR file

# `ffufMod.py` - Modify RAW HTTP Requests for FFUF Fuzzing

## Overview

`ffufMod.py` is a powerful Python script designed to modify raw HTTP requests, making them compatible with FFUF (Fuzz Faster U Fool). This tool allows you to mark request parameters for advanced fuzzing techniques, facilitating a more efficient and effective testing process.

### ⚙️ How to Use

To get started with `ffufMod.py`, you can view the help message by running the following command:

```bash
python3 ffufMod.py -h
```

📋 Usage
Here’s how to use the script:
usage: ffufMod.py [-h] -p PATH -o OUTPUT

Mark raw request parameters with §


## Run FFUF over every reques file 
```
for i in $(ls); do ffuf -request $i -w ~/pentest/wordlist/PayloadsAllTheThings/Directory\ Traversal/Intruder/dotdotpwn.txt -mr "root:x" -mode sniper -replay-proxy http://127.0.0.1:8080;done
```

