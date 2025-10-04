---
title: Shaken, not stirred - Mobile Hacking Lab
date: 2025-4-1 00:00:00 +/-TTTT
categories: [Mobile Hacking Lab]
tags: [mobile hacking lab, writeup, mobile penetration testing, android]     # TAG names should always be lowercase
---



<br />

### Introduction

A spy has infiltrated a private intelligence company in Paris and was able to steal sensitive documents. Luckily, he is not a tech geek and could easily be tracked down by law enforcement 24 hours after infiltration. His mobile phone could be seized. However, it was damaged on purpose by the suspect and only a small fragment of user artifacts could be retrieved. The key for decrypting the flag could not be extracted. Are you able to find a way to decrypt it?

<br />

### Objective

- Extract and analyze mobile device artifacts
- Perform cryptographic operations to decrypt the final flag

<br />

In the Audio directory, there is a file named `awful noise.wav` that contains Morse code. I used an [online decoder](https://morsecode.world/international/decoder/audio-decoder-adaptive.html) to translate the Morse code and obtained the text: `PBKDF2 WITH SHA256`.

<br />

![](/assets/img/mhl/Shaken/1.png)

<br />

In the `SecureFolder`, there is a file named `flag_mhc.enc` containing a single packet, which appears to be encrypted.

![](/assets/img/mhl/Shaken/3.png)



<br />

In the `db` directory, there is a file named `samsung_notes.db`. Some of the notes reference `PBKDF2 WITH SHA256`:  a key derivation iteration count of 10,000 and a 32-bit key.

```
# sqlite3 .\samsung_notes.db
Enter ".help" for usage hints.
sqlite> .tables
notes
sqlite> select * from notes;
1|Reminder|I have to meet Elian tomorrow
2|Travel|Flight to Paris 11:45 for 226 Euro
3|Luggage|Key on separate bag
4|Random Note|The quick brown fox jumps over the lazy dog.
5|Math|Pi is approximately 3.14159
6|Key Derivation|10000 Iterations
7|Idea|Building the future requires better questions.
8|Draft|Not all who wander are lost, some just like maps.
9|Reminder|key 32 bit
```

<br />

From: Browser\data\com.sec.android.app.sbrowser\databases

```
# sqlite3 .\BrowserHistory.db
SQLite version 3.44.4 2025-02-19 00:18:53 (UTF-16 console I/O)
Enter ".help" for usage hints.
sqlite> .tables
history
sqlite> select * from history;
1|https://www.google.com/search?q=What+is+the+best+country+without+extradition|Google Search: What is the best country without extradition|1753930518358|0
2|https://www.google.com/search?q=Is+aes+encryption+secure|Google Search: Is aes encryption secure|1754015178358|0
3|https://www.google.com/search?q=Can+aes+be+broken|Google Search: Can aes be broken|1753988898358|0
4|https://www.google.com/search?q=What+are+best+aes+modes|Google Search: What are best aes modes|1753968018358|0
5|https://www.google.com/search?q=What+should+i+do+to+hide+data+in+an+android+phone|Google Search: What should i do to hide data in an android phone|1753969218358|0
6|https://www.google.com/search?q=Can+someone+find+data+within+an+encrypted+container+or+file|Google Search: Can someone find data within an encrypted container or file|1754003778358|0
7|https://www.google.com/search?q=Is+it+possible+to+detect+the+encryption+type|Google Search: Is it possible to detect the encryption type|1753960278358|0
8|https://www.google.com/search?q=Where+do+i+need+to+store+sensitive+files|Google Search: Where do i need to store sensitive files|1753945578358|0
9|https://www.google.com/search?q=What+is+the+best+sensitive+file+storage+method|Google Search: What is the best sensitive file storage method|1753877478358|0
10|https://www.google.com/search?q=Can+cloud+storage+providers+be+trusted|Google Search: Can cloud storage providers be trusted|1753874478358|0
11|https://www.google.com/search?q=Does+VPN+help+communicate+securely|Google Search: Does VPN help communicate securely|1753975218358|0
12|https://www.google.com/search?q=Top+10+best+VPNs+for+2025|Google Search: Top 10 best VPNs for 2025|1754022918358|0
```

<br />

Using the `zsteg` tool, we extracted the text `VDNybTFuNGxBY2Mzc3MhIQ==`, which decodes to `T3rm1n4lAcc3ss!!`.

```
└─# zsteg -a School.png | head
imagedata           .. text: "\r\r(*.@DJ"
b1,r,lsb,xy         .. text: "GxBY2Mzc3MhIQ=="
b1,rgb,lsb,xy       .. text: "VDNybTFuNGxBY2Mzc3MhIQ=="
                                                                                                                                                                                 
┌──(root㉿kali)-[~kali/Desktop/ios/mhl/Images]
└─# echo "VDNybTFuNGxBY2Mzc3MhIQ==" | base64 -d 
T3rm1n4lAcc3ss!!                                                                                                                 
```

<br />

By using `exiftool` to examine the image metadata, we found a comment containing `"For3ns1cQ"`.

```
└─# exiftool beautiful_thing.png
User Comment                    : For3ns1cQ
```

<br />

In the `images` directory there were several images containing QR codes; each QR code revealed a fragment of the password. When combined, the fragments form the password **red34DuckMango!#2022++**.

<br />

```
passphr1.png >> red
2.png >> 34Duck
3.png >> Mango
4.png >> !#2022
5.png >> ++
```

<br />

![](/assets/img/mhl/Shaken/2.png)

<br />

Python script that reads an AES-CBC encrypted file, derives the AES key from a password using PBKDF2-HMAC-SHA256, decrypts the file, and removes padding to recover the original plaintext.

```python
from pathlib import Path
from hashlib import pbkdf2_hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import base64

# ---------------------------
# Load encrypted file and parameters
# ---------------------------
ct = Path("flag_mhc.enc").read_bytes()
iv = base64.b64decode("VDNybTFuNGxBY2Mzc3MhIQ==")
password = b"red34DuckMango!#2022++"
salt = b"For3ns1cQ"

# ---------------------------
# Derive AES key using PBKDF2-HMAC-SHA256
# ---------------------------
key = pbkdf2_hmac("sha256", password, salt, 10000, dklen=32)

# ---------------------------
# Decrypt using AES-CBC
# ---------------------------
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
decryptor = cipher.decryptor()
decrypted_padded = decryptor.update(ct) + decryptor.finalize()

# ---------------------------
# Remove PKCS7 padding
# ---------------------------
unpadder = padding.PKCS7(128).unpadder()
plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()

# ---------------------------
# Output result
# ---------------------------
print(plaintext.decode())
```

<br />

```
└─# python3 solve.py
MHC{mobile_4n6_1s_N0T_TH4t_H4Rd_h30d8fn48nfwuhf32f892fh23urh328}
```

<br />

**Flag:** MHC{mobile_4n6_1s_N0T_TH4t_H4Rd_h30d8fn48nfwuhf32f892fh23urh328}