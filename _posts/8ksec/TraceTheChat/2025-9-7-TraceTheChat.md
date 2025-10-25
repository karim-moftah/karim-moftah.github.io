---
title: TraceTheChat - 8kSec
date: 2025-9-7 00:00:00 +/-TTTT
categories: [8kSec]
tags: [8kSec, writeup, mobile penetration testing, ios]     # TAG names should always be lowercase
---

<br />

**Description:**

**TraceTheChat** is a seemingly innocent messaging app. Type a message, hit send, and it gets routed to a mysterious contact. But beneath the surface, the message travels through an obfuscated class that hides the details from plain sight.

<br />

**Objective:**

- Use Frida to dynamically trace and intercept the actual message being sent at runtime.
- Identify the class or method responsible for dispatching messages, hook into it with Frida, and extract the message contents and recipient live as they’re sent.

<br />

**Restrictions:**

You must extract the message only through instrumentation.

<br />

**Explore the application**

When you launch the app, it shows a screen where you can start chatting with **Bot_9001** and send messages.

<br />

![](/assets/img/8ksec/TraceTheChat/1.jpg)

<br />

With Frida, we can enumerate the app’s classes.

```javascript
for (var className in ObjC.classes) {
    if (ObjC.classes.hasOwnProperty(className)) {
        if (className.toLowerCase().indexOf("tracethechat") !== -1) {
            console.log(className);
        }
    }
}
```

output

```
Spawned `com.8ksec.TraceTheChat.W46SY5ZJ6Z`. Resuming main thread!      
[iOS Device::com.8ksec.TraceTheChat.W46SY5ZJ6Z ]->  _TtC12TraceTheChatP33_BF948D250337C3375DCE4307755C166C19ResourceBundleClass
_TtGC7SwiftUIP10$1a30af3d014AnyViewStorageV12TraceTheChat11ContentView_
TraceTheChat.ObfMessage
TraceTheChat.MessageRouter
TraceTheChat.InternalMsgHandler
```

<br />

**Reverse Engineering With Ghidra**

The `MessageRouter.dispatch()` function invokes the `ObfMessage.contacts()` function.

![](/assets/img/8ksec/TraceTheChat/1.png)

<br />

The `ObfMessage.contacts()` function, located at offset `0x9ac4`, takes four parameters.

![](/assets/img/8ksec/TraceTheChat/3.png)



<br />

This Frida script attaches to the function at `TraceTheChat.debug.dylib` + `0x9ac4`. When that function returns, the script reads the returned pointer (`retval`) and inspects two fields inside the returned structure at offsets `0x8` and `0x18`. For each field it attempts a safe byte read and collects the consecutive printable ASCII characters starting at that address. If it finds text it logs the absolute address and the string; if the string contains `"Bot"` it tags the line as `Bot`, otherwise it tags it as `Message`. If no readable text is found at an offset it reports `<no text>`. 



```javascript
var hookOffset = ptr('0x9ac4');
var t_module = 'TraceTheChat.debug.dylib';

var base = Module.getBaseAddress(t_module);
if (base === null) throw new Error('Module not found: ' + t_module);
var target = base.add(hookOffset);

console.log('[+] Module base: ' + base);
console.log('[+] Hooking target: ' + target);

// simple printable test
function isPrintable(b) { return b >= 0x20 && b <= 0x7e; }

// read a UTF-8 string at addr safely, fallback to inline printable bytes if not a C-string
function readTextAt(addr, maxCStrLen = 1024, maxScan = 256) {
    try {
        if (addr.isNull()) return null;
    } catch (e) { return null; }


    // try reading bytes and return consecutive printable chars starting at addr
    try {
        var ba = Memory.readByteArray(addr, maxScan);
        if (!ba) return null;
        var u8 = new Uint8Array(ba);
        var out = '';
        for (var i = 0; i < u8.length; i++) {
            if (isPrintable(u8[i])) out += String.fromCharCode(u8[i]);
            else break;
        }
        return out.length ? out : null;
    } catch (e) {
        return null;
    }
}

Interceptor.attach(target, {
    onEnter: function (args) {

    },

    onLeave: function (retval) {
        try {
            var basePtr = retval;
            if (basePtr.isNull()) {
                console.log('[!] retval is NULL');
                return;
            }

            var offsets = [0x8, 0x18];
            offsets.forEach(function(off) {
                try {
                    var addr = basePtr.add(off);
                    var txt = readTextAt(addr, 4096, 1024);
                    if (txt) {
                    	if(txt.indexOf("Bot") !== -1){
                    		console.log('[+] offset=0x' + off.toString(16) + ' Bot -> "' + txt + '"');
                    	}
                    	else{
                        	console.log('[+] offset=0x' + off.toString(16) + ' Message -> "' + txt + '"');
                	    }
                    } else {
                        console.log('[+] offset=0x' + off.toString(16) + ' -> <no text>');
                    }
                } catch (e) {
                    console.log('[!] offset=0x' + off.toString(16) + ' error:', e);
                }
            });
        } catch (e) {
            console.log('[!] onLeave exception:', e);
        }
    }
});
```

output

```
Spawning `com.8ksec.TraceTheChat.W46SY5ZJ6Z`...                         
[+] Module base: 0x102da4000
[+] Hooking target: 0x102dadac4
Spawned `com.8ksec.TraceTheChat.W46SY5ZJ6Z`. Resuming main thread!      
[iOS Device::com.8ksec.TraceTheChat.W46SY5ZJ6Z ]-> [+] offset=0x8 Message -> "Hi"
[+] offset=0x18 Bot -> "Bot_9001"
[iOS Device::com.8ksec.TraceTheChat.W46SY5ZJ6Z ]->
[iOS Device::com.8ksec.TraceTheChat.W46SY5ZJ6Z ]-> [+] offset=0x8 Message -> "Frida"
[+] offset=0x18 Bot -> "Bot_9001"
[iOS Device::com.8ksec.TraceTheChat.W46SY5ZJ6Z ]->
```





![](/assets/img/8ksec/TraceTheChat/2.jpg)
