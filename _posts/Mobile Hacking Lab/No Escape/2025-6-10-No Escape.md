---
title: No Escape - Mobile Hacking Lab
date: 2025-6-10 00:00:00 +/-TTTT
categories: [Mobile Hacking Lab]
tags: [mobile hacking lab, writeup, mobile penetration testing, ios]     # TAG names should always be lowercase
---



<br />

**Introduction**

Welcome to the **iOS Application Security Lab: Jailbreak Detection Evasion Challenge**. The challenge centers around a fictitious app called No Escape, designed with robust jailbreak detection mechanisms. Your mission is to bypass these mechanisms and gain full access to the app's functionalities using Frida.

<br />

**Objective**

**Bypass Jailbreak Detection**: Your task is to evade the jailbreak detection implemented in the No Escape app to execute arbitrary code and access all app features.





On launch, the app instantly flags the device as jailbroken and terminates.

<br />

![](/assets/img/mhl/NoEscape/5.jpg)

<br />

<br />

I attempted to use Objection and several jailbreak detection bypass scripts from Frida Codeshare, but none of them worked

**Objection**

```
objection -g com.mobilehackinglab.No-Escape explore
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
com.mobilehackinglab.No-Escape on (iPhone: 14.4) [usb] # ios jailbreak disable
```

<br />

**frida CodeShare**

- https://codeshare.frida.re/@incogbyte/ios-jailbreak-bypass/
- https://codeshare.frida.re/@sdcampbell/ios-jailbreak-bypass/
- https://codeshare.frida.re/@patali09/ios-jailbreak-detection-bypass/

<br />





#### Extracting the `.ipa` File

The provided app came in an `.ipa` file essentially a ZIP archive containing the application bundle.

```
unzip No_Escape.ipa -d No_Escape
```

Inside the extracted folder, the binary was located in:

```
Payload/No_Escape.app/No_Escape
```



#### Reverse Engineering with Ghidra

I began reverse engineering the application binary and discovered a function named `isJailbroken`. This function is invoked by two other functions and internally calls four additional functions to perform multiple jailbreak checks. The application relies on the return value of `isJailbroken` to decide whether it is running on a jailbroken device. If the return value is `true`, the app concludes that the device is jailbroken, displays an alert message, and then exits. If the return value is `false`, the app assumes the device is not jailbroken and proceeds to retrieve the flag.



<br />

![](/assets/img/mhl/NoEscape/4.png)

<br /><br />

#### Method 1: Frida

<br />

A Frida script that enumerates all symbols in the main module and searches for any symbol whose name contains the word `jailbroken`.

```javascript
var targetModule = Process.enumerateModules()[0].name;

console.log("[*] Scanning module: " + targetModule);

var symbols = Module.enumerateSymbols(targetModule);

symbols.forEach(function(s) {
    if (s.name.toLowerCase().indexOf("jailbroken") !== -1) {
        console.log("[+] Found function: " + s.name + " at " + s.address);
    }
});
```

output

```
└─# frida -U -f com.mobilehackinglab.No-Escape -l hook.js
     ____
    / _  |   Frida 16.0.0 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to iOS Device (id=00008020-00032D801E32002E)
Spawning `com.mobilehackinglab.No-Escape`...                            
[*] Scanning module: No Escape
[+] Found function: $s9No_Escape12isJailbrokenSbyF at 0x1005a2068
[+] Found function: $s9No_Escape12isJailbrokenSbyF at 0x1005a2068
```



<br /><br />

A Frida script that enumerates all symbols in the main module, hooks any symbol whose name contains `jailbroken`, and forces its return value to `0`.

```javascript
// Handle non-Objective-C functions (C/Swift exports)
var mainModule = Process.enumerateModules()[0];
console.log("[*] Scanning symbols in " + mainModule.name);

var symbols = Module.enumerateSymbols(mainModule.name);

symbols.forEach(function(s) {
    if (s.name.toLowerCase().indexOf("jailbroken") !== -1) {
        console.log("[+] Hooking exported function: " + s.name + " @ " + s.address);

        Interceptor.attach(s.address, {
            onEnter: function (args) {
                console.log("    [*] Called function: " + s.name);
            },
            onLeave: function (retval) {
                console.log("    [*] Original return: " + retval);
                retval.replace(ptr("0"));  // Return false/0
                console.log("    [*] Modified return: " + retval);
            }
        });
    }
});
```

<br />

output

```
└─# frida -U -f com.mobilehackinglab.No-Escape -l hook.js
     ____
    / _  |   Frida 16.0.0 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to iOS Device (id=00008020-00032D801E32002E)
Spawning `com.mobilehackinglab.No-Escape`...                            
[*] Scanning symbols in No Escape
[+] Hooking exported function: $s9No_Escape12isJailbrokenSbyF @ 0x1026e2068
[+] Hooking exported function: $s9No_Escape12isJailbrokenSbyF @ 0x1026e2068
Spawned `com.mobilehackinglab.No-Escape`. Resuming main thread!         
[iOS Device::com.mobilehackinglab.No-Escape ]->     [*] Called function: $s9No_Escape12isJailbrokenSbyF
    [*] Called function: $s9No_Escape12isJailbrokenSbyF
    [*] Original return: 0x1
    [*] Modified return: 0x0
    [*] Original return: 0x0
    [*] Modified return: 0x0
    [*] Called function: $s9No_Escape12isJailbrokenSbyF
    [*] Called function: $s9No_Escape12isJailbrokenSbyF
    [*] Original return: 0x1
    [*] Modified return: 0x0
    [*] Original return: 0x0
    [*] Modified return: 0x0
```

<br /><br />

Another Frida script that hooks a function by its name.

```javascript
var myMethod = Module.findExportByName(null, "$s9No_Escape12isJailbrokenSbyF");
if (myMethod) {
    Interceptor.attach(myMethod, {
        onEnter: function (args) {
            console.log("Hooked Swift method!");
        },
        onLeave: function (retval) {
            console.log("Original return value:", retval.toInt32()); // Log the original return value
            retval.replace(0); // Replace with false
            console.log("Modified return value:", retval.toInt32()); // Log the modified return value
        }
    });
} else {
    console.log("Hooking Swift method failed!");
}
```



<br /><br />





#### Method 2: Application Patching

<br />

![](/assets/img/mhl/NoEscape/1.png)

<br />

Right Click >> Patch Instruction

```
mov w0, #0x0
```



<br />

![](/assets/img/mhl/NoEscape/3.png)



<br /><br />

This function’s return value has been forced to always be false.

<br />

![](/assets/img/mhl/NoEscape/2.png)



<br />

File >> Export Program >> Format: Original File

<br />

push the patched binary to the iphone

```
└─# scp No\ Escape root@192.168.1.6:"/private/var/containers/Bundle/Application/1D3C5998-C8FB-42D6-B2DD-95057797D843/No Escape.app/"
```

<br />



![](/assets/img/mhl/NoEscape/6.jpg)