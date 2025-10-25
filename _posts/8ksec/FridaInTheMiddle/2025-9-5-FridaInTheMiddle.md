---
title: FridaInTheMiddle - 8kSec
date: 2025-9-5 00:00:00 +/-TTTT
categories: [8kSec]
tags: [8kSec, writeup, mobile penetration testing, ios]     # TAG names should always be lowercase
---

<br />

**Description:**

Welcome to **FridaInTheMiddle**, a Swift-based iOS application that’s extremely sensitive to uninvited interference. It comes equipped with active runtime tamper detection that watches for signs of **Frida,** whether through suspicious ports, injected dylibs, or unauthorized hooks.

<br />

**Objective:**

Keep the app running while Frida is attached, and intercept the argument passed to **dummyFunction(flag:)** to extract the flag.

<br />

**Restrictions**:

 Using Static reverse engineering is not allowed—you must rely on dynamic analysis to retrieve the flag during execution.

<br />



**Explore the application**

When you launch the app on a jailbroken device with the Frida server running, the app detects Frida, displays an alert, and then closes after 3 seconds.

![](/assets/img/8ksec/FridaInTheMiddle/1.jpg)



<br />

Frida’s default server listens on TCP port **27042** (and its companion port **27043** for the device-to-host reverse connection in some setups). That default is a convention used by the official Frida server binary but can be changed by passing a different port when launching the server. Detecting a Frida server from an application typically amounts to probing for a TCP service bound to that port and checking whether it behaves like Frida.



<br />

A Frida script that hooks the `connect()` function and verifies whether it’s invoked with port `27042`.

```javascript
function ntohs(n) {
    return ((n & 0xff) << 8) | ((n >> 8) & 0xff);
}

// Hook connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
var connectSym = Module.findExportByName(null, "connect");
if (connectSym) {
    Interceptor.attach(connectSym, {
        onEnter: function(args) {
            try {
                this.sockfd = args[0].toInt32();
                this.addrPtr = args[1];
                if (this.addrPtr.isNull()) {
                    console.log("[connect] fd=" + this.sockfd + " addr=NULL");
                    return;
                }

                var port_be = Memory.readU16(this.addrPtr.add(2));
                var port = ntohs(port_be);

                console.log("[connect] " + port);


            } catch (e) {
                console.log("[connect] onEnter error:", e);
            }
        }
    });
} else {
    console.log("[!] connect symbol not found");
}
```

A `connect()` call to port `27042` was found.

```
[iOS Device::com.8ksec.FridaInTheMiddle.W46SY5ZJ6Z ]-> [connect] 27042
```

<br />



To bypass this check, we can alter the return value of `connect()` so it is non-zero, or change the port argument from `27042` to a different port.

<br />

A Frida script that hooks `connect()` and forces its return value to `-1` when the port argument is `27042`.

```javascript
var frida_port_check = false;
function ntohs(n) {
    return ((n & 0xff) << 8) | ((n >> 8) & 0xff);
}


// Hook connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
var connectSym = Module.findExportByName(null, "connect");
if (connectSym) {
    Interceptor.attach(connectSym, {
        onEnter: function(args) {
            try {
                this.sockfd = args[0].toInt32();
                this.addrPtr = args[1];
                if (this.addrPtr.isNull()) {
                    console.log("[connect] fd=" + this.sockfd + " addr=NULL");
                    return;
                }

                var port_be = Memory.readU16(this.addrPtr.add(2));
                var port = ntohs(port_be);

                // Check for Frida default port
                var isFridaPort = (port === 27042);
      
                console.log("[connect] " + port);
                if (isFridaPort) {
                    frida_port_check = true
                    console.log("Checking if frida-server port 27042 is open")
                }

            } catch (e) {
                console.log("[connect] onEnter error:", e);
            }
        },
        onLeave: function(retval) {
            try {
                if (frida_port_check) {
                    retval.replace(ptr(-1));
                    console.log("[connect] forced return = -1");
                }
            } catch (e) { console.log("[connect] force-return error:", e); }

        }
    });
} else {
    console.log("[!] connect symbol not found");
}
```

output

```
Spawned `com.8ksec.FridaInTheMiddle.W46SY5ZJ6Z`. Resuming main thread!  
[iOS Device::com.8ksec.FridaInTheMiddle.W46SY5ZJ6Z ]-> [connect] 27042
Checking if frida-server port 27042 is open
[connect] forced return = -1
```

<br />

Spawn the application with the provided Frida script. The app will open without detecting Frida.

<br />

![](/assets/img/8ksec/FridaInTheMiddle/2.jpg)

<br />

An alternative Frida script that intercepts `connect()` and replaces the port argument `27042` with `5555`.

```javascript
var frida_port_check = false;
function ntohs(n) {
    return ((n & 0xff) << 8) | ((n >> 8) & 0xff);
}
function htons(n) {
    return ((n & 0xff) << 8) | ((n >> 8) & 0xff);
}

// Hook connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
var connectSym = Module.findExportByName(null, "connect");
if (connectSym) {
    Interceptor.attach(connectSym, {
        onEnter: function(args) {
            try {
                this.sockfd = args[0].toInt32();
                this.addrPtr = args[1];
                if (this.addrPtr.isNull()) {
                    console.log("[connect] fd=" + this.sockfd + " addr=NULL");
                    return;
                }

                // Read port (network byte order at offset 2)
                var port_be = Memory.readU16(this.addrPtr.add(2));
                var port = ntohs(port_be);

                console.log("[connect] original port:", port);

                // If Frida default port found, replace with 5555 (write in network byte order)
                if (port === 27042) {
                    var newPort = 5555;
                    var newPort_be = htons(newPort);
                    try {
                        Memory.writeU16(this.addrPtr.add(2), newPort_be);
                        frida_port_check = true;
                        console.log("[connect] replaced port 27042 ->", newPort);
                    } catch (werr) {
                        console.log("[connect] failed to write new port:", werr);
                    }
                }

            } catch (e) {
                console.log("[connect] onEnter error:", e);
            }
        }
    });
} else {
    console.log("[!] connect symbol not found");
}
```

output

```
Spawned `com.8ksec.FridaInTheMiddle.W46SY5ZJ6Z`. Resuming main thread!  
[iOS Device::com.8ksec.FridaInTheMiddle.W46SY5ZJ6Z ]-> [connect] original port: 27042
[connect] replaced port 27042 -> 5555
```

<br />

After bypassing Frida detection, hook the function `dummyFunction(flag)` and read the value of its `flag` parameter.

<br />

This Frida script will search for a function named `dummyFunction()` and print its mangled name and address.

```javascript
var TOKEN = "FridaInTheMiddle";

console.log("[*] Searching symbols for token:", TOKEN);

var modules = Process.enumerateModulesSync();
for (var mi = 0; mi < modules.length; mi++) {
    var mod = modules[mi];
    try {
        var syms = Module.enumerateSymbolsSync(mod.name);
        for (var i = 0; i < syms.length; i++) {
            var s = syms[i];
            if ((s.name && s.name.indexOf(TOKEN) !== -1) && s.name.indexOf("dummyFunction") !== -1){
                console.log("[match] module:", mod.name, " symbol:", s.name, " @", s.address);
            }
        }
    } catch (e) {
        console.log("[!] couldn't enumerate symbols for", mod.name, ":", e);
    }
}

console.log("[*] done.");
```

**module: FridaInTheMiddle.debug.dylib**
 This is the dynamic library (dylib) that defines the symbol. 

**symbol: $s16FridaInTheMiddle11ContentViewV13dummyFunction4flagySS_tF**
 This is a **Swift-mangled symbol name**. Swift uses a compact mangling scheme that encodes the module, type, function name, parameter labels and types, and the return type.

```
Spawning `com.8ksec.FridaInTheMiddle.W46SY5ZJ6Z`...                     
[*] Searching symbols for token: FridaInTheMiddle
[match] module: FridaInTheMiddle.debug.dylib  symbol: $s16FridaInTheMiddle11ContentViewV13dummyFunction4flagySS_tF  @ 0x104f55d24
```

<br />

The `FridaInTheMiddle.debug.dylib` library is included in the IPA and is opened via `dlopen` at application startup.

```
└─# unzip FridaInTheMiddle.zip            
Archive:  FridaInTheMiddle.zip
   creating: Payload/
   creating: Payload/FridaInTheMiddle.app/
   creating: Payload/FridaInTheMiddle.app/_CodeSignature/
  inflating: Payload/FridaInTheMiddle.app/_CodeSignature/CodeResources  
  inflating: Payload/FridaInTheMiddle.app/AppIcon60x60@2x.png  
   creating: Payload/FridaInTheMiddle.app/META-INF/
  inflating: Payload/FridaInTheMiddle.app/__preview.dylib  
  inflating: Payload/FridaInTheMiddle.app/Assets.car  
  inflating: Payload/FridaInTheMiddle.app/AppIcon76x76@2x~ipad.png  
  inflating: Payload/FridaInTheMiddle.app/FridaInTheMiddle  
  inflating: Payload/FridaInTheMiddle.app/embedded.mobileprovision  
  inflating: Payload/FridaInTheMiddle.app/FridaInTheMiddle.debug.dylib  
  inflating: Payload/FridaInTheMiddle.app/Info.plist  
 extracting: Payload/FridaInTheMiddle.app/PkgInfo 
```

<br />



A Frida script that bypasses Frida detection, hooks `dummyFunction()`, and reads the `flag` parameter

Note: the Frida GitHub issue [here](https://github.com/frida/frida/issues/1089) includes code showing how to read a Swift `String` with Frida 

```javascript
var frida_port_check = false;
function ntohs(n) {
    return ((n & 0xff) << 8) | ((n >> 8) & 0xff);
}
function htons(n) {
    return ((n & 0xff) << 8) | ((n >> 8) & 0xff);
}

// Hook connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
var connectSym = Module.findExportByName(null, "connect");
if (connectSym) {
    Interceptor.attach(connectSym, {
        onEnter: function(args) {
            try {
                this.sockfd = args[0].toInt32();
                this.addrPtr = args[1];
                if (this.addrPtr.isNull()) {
                    console.log("[connect] fd=" + this.sockfd + " addr=NULL");
                    return;
                }

                // Read port (network byte order at offset 2)
                var port_be = Memory.readU16(this.addrPtr.add(2));
                var port = ntohs(port_be);

                console.log("[connect] original port:", port);

                // If Frida default port found, replace with 5555 (write in network byte order)
                if (port === 27042) {
                    var newPort = 5555;
                    var newPort_be = htons(newPort);
                    try {
                        Memory.writeU16(this.addrPtr.add(2), newPort_be);
                        frida_port_check = true;
                        console.log("[connect] replaced port 27042 ->", newPort);
                    } catch (werr) {
                        console.log("[connect] failed to write new port:", werr);
                    }
                }

            } catch (e) {
                console.log("[connect] onEnter error:", e);
            }
        }
    });
} else {
    console.log("[!] connect symbol not found");
}
                                                                                                                                                                                   

 

var myMethod = Module.findExportByName(null, "$s16FridaInTheMiddle11ContentViewV13dummyFunction4flagySS_tF");
if (myMethod) {
    Interceptor.attach(myMethod, {
        onEnter: function (args) {
            var flag = print_swift_string(args[1]);
            console.log('Flag: ', flag);
        }
    });
} else {
    console.log("Hooking Swift method failed!");
}


function print_swift_string(x1){

    // remove the hight bit of x1 to get the string pointer
    var addr = BigInt(x1) ^ BigInt(0x8 * 16 ** 15); 
    
    // shift 32 bytes, then we can get the true string pointer
    var offset = 32;
    addr = addr + BigInt(offset);
    // convert the addr to NativePointer, then read string value.
    var ptrOfString = ptr(addr.toString())

    return ptrOfString.readCString();
}
```

<br />

output

```
Spawned `com.8ksec.FridaInTheMiddle.W46SY5ZJ6Z`. Resuming main thread!  
[iOS Device::com.8ksec.FridaInTheMiddle.W46SY5ZJ6Z ]-> [connect] original port: 27042
[connect] replaced port 27042 -> 5555
[iOS Device::com.8ksec.FridaInTheMiddle.W46SY5ZJ6Z ]-> Flag:  CTF{you_evaded_frida_detection}
```

<br />

**Flag:**  CTF{you_evaded_frida_detection}

<br /><br />

Another Frida script to hook the function by its address.

```javascript
var frida_port_check = false;
function ntohs(n) {
    return ((n & 0xff) << 8) | ((n >> 8) & 0xff);
}
function htons(n) {
    return ((n & 0xff) << 8) | ((n >> 8) & 0xff);
}

// Hook connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
var connectSym = Module.findExportByName(null, "connect");
if (connectSym) {
    Interceptor.attach(connectSym, {
        onEnter: function(args) {
            try {
                this.sockfd = args[0].toInt32();
                this.addrPtr = args[1];
                if (this.addrPtr.isNull()) {
                    console.log("[connect] fd=" + this.sockfd + " addr=NULL");
                    return;
                }

                // Read port (network byte order at offset 2)
                var port_be = Memory.readU16(this.addrPtr.add(2));
                var port = ntohs(port_be);

                console.log("[connect] original port:", port);

                // If Frida default port found, replace with 5555 (write in network byte order)
                if (port === 27042) {
                    var newPort = 5555;
                    var newPort_be = htons(newPort);
                    try {
                        Memory.writeU16(this.addrPtr.add(2), newPort_be);
                        frida_port_check = true;
                        console.log("[connect] replaced port 27042 ->", newPort);
                    } catch (werr) {
                        console.log("[connect] failed to write new port:", werr);
                    }
                }

            } catch (e) {
                console.log("[connect] onEnter error:", e);
            }
        }
    });
} else {
    console.log("[!] connect symbol not found");
}
                                                                                                                                                                                   

  
var addr = ptr(0x5d24);
var t_module = 'FridaInTheMiddle.debug.dylib';
var nw = Module.getBaseAddress(t_module);
var toAtt = nw.add(addr);

Interceptor.attach(toAtt, {
    onEnter: function (args) {
        var flag = print_swift_string(args[1]);
        console.log('Flag: ', flag);
    }
});

function print_swift_string(x1){

    // remove the hight bit of x1 to get the string pointer
    var addr = BigInt(x1) ^ BigInt(0x8 * 16 ** 15); 
    
    // shift 32 bytes, then we can get the true string pointer
    var offset = 32;
    addr = addr + BigInt(offset);
    // convert the addr to NativePointer, then read string value.
    var ptrOfString = ptr(addr.toString())

    return ptrOfString.readCString();
}
```
