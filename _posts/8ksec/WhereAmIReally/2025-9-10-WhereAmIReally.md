---
title: WhereAmIReally - 8kSec
date: 2025-9-10 00:00:00 +/-TTTT
categories: [8kSec]
tags: [8kSec, writeup, mobile penetration testing, ios]     # TAG names should always be lowercase
---

<br />

**Description:**

WhereAmIReally is an iOS app that only reveals the flag if you’re in the right place "physically". It checks your GPS coordinates against a geofenced area and validates the authenticity of your location before granting access.
But this app doesn’t just trust what you feed it. It has some additional checks in place.

<br />

**Objective:**

- Convince the app you’re standing in the right spot, even if you’re not.
- Bypass the app’s verification logic and retrieve the flag by simulating a trusted presence at a specific real-world location.

<br />

**Restrictions**:

The flag is revealed only if your location is verified and accepted.

<br />

**Explore the application**

When the app is launched on a jailbroken device, it detects the jailbreak and displays this screen.

<br />

![](/assets/img/8ksec/WhereAmIReally/3.jpg)

<br />

There is a function runs several jailbreak checks. to bypass detection we'll hook that function and force it to return 0.

<br />

![](/assets/img/8ksec/WhereAmIReally/3.png)



<br />

```javascript
const t_module = 'WhereAmIReally.debug.dylib';
const offset = ptr('0x4000'); // jailbroken check

const base = Module.findBaseAddress(t_module);

if (base === null) {
    throw new Error('Module not found: ' + t_module);
}

const target = base.add(offset);
console.log('[*] Hooking address:', target);

Interceptor.attach(target, {
    onEnter: function (args) {

    },
    onLeave: function (retval) {
         console.log('[*] retval =', retval);
         retval.replace(0x0);
    }
});
```



<br />

`-[CLLocation coordinate]` is an instance method provided by Core Location’s `CLLocation` class that returns the point coordinate of a `CLLocation` object. The return type is a C struct.

When an app has a `CLLocation` instance (for example, received from `CLLocationManager`), calling `location.coordinate` yields a `CLLocationCoordinate2D` struct containing the latitude and longitude values.

<br />

**How apps typically obtain location**

There are two common patterns:

1. **Delegate-based updates**
    The app registers a delegate with `CLLocationManager` and receives updates via:

   ```objc
   - (void)locationManager:(CLLocationManager *)manager didUpdateLocations:(NSArray<CLLocation *> *)locations;
   ```

   In this pattern the app reads `locations.lastObject.coordinate` or similar.

2. **Polling / getter calls**
    The app may synchronously call `-[CLLocationManager location]` or call `-[CLLocation coordinate]` on `CLLocation` objects obtained from other APIs (for example `MKUserLocation`), effectively polling the current coordinate.

<br />

**The idea behind location spoofing**

Location spoofing means causing an application to receive fabricated location data instead of the device’s true GPS coordinates. The objective can be testing, QA, or development scenarios where simulating movement or different geographies is required without physically moving the device.

Approaches fall into two categories:

- **Injection of fake delegate updates**
   Intercept or emulate `CLLocationManager` behavior and call the delegate method `locationManager:didUpdateLocations:` with fabricated `CLLocation` objects. This causes the app to behave as if it received genuine location updates.
- **Hooking getters / return values**
   Intercept methods that return location data, such as `-[CLLocation coordinate]`, `-[CLLocationManager location]`, or `-[MKUserLocation location]`, and modify their return values so callers receive spoofed coordinates.

<br />

The script attempts to spoof location coordinates by intercepting `-[CLLocation coordinate]` with Frida and replacing the method’s return value with a new coordinate (the supplied `spoof_latitude` / `spoof_longitude`). After loading the script and calling `spoof_location(lat, lon)`, any code that calls `location.coordinate` should receive the spoofed values.

```javascript
function spoof_location(spoof_latitude, spoof_longitude)
{
	var hook_cllocation = ObjC.classes["CLLocation"]["- coordinate"]
	Interceptor.attach(hook_cllocation.implementation, {
	  onLeave: function(return_value) {
		//console.log(new ObjC.Object(return_value))
		var spoofed_return_value = (new ObjC.Object(return_value)).initWithLatitude_longitude_(spoof_latitude, spoof_longitude)
		return_value.replace(spoofed_return_value)
	  }
	});
}

//Mention latitude and longitude in below function call
spoof_location(46.211275,2.368013)

```

<br />

After spawning the app with the Frida script, the device location was spoofed.

![](/assets/img/8ksec/WhereAmIReally/2.jpg)



<br />

**Method 1:**

We should hook that address so we can inspect x8’s value at instruction: `tbz w8, #0x0, LAB_0000a130`.

![](/assets/img/8ksec/WhereAmIReally/4.png)

<br />

```javascript
const t_module = 'WhereAmIReally.debug.dylib';
const offset = ptr('0x9d18');

const base = Module.findBaseAddress(t_module);
if (base === null) {
    throw new Error('Module not found: ' + t_module);
}

const target = base.add(offset);
console.log('[*] Hooking address:', target);

Interceptor.attach(target, {
    onEnter: function (args) {

	    // this.context.x8 is a NativePointer
	    const x8 = this.context.x8;
	    console.log('[*] x8 =', x8);
    },

    onLeave: function (retval) {
        // optional: log return value if you want
        // console.log('[*] retval =', retval);
    }
});
```

The x8 register holds a value of zero

```
[*] x8 = 0x0
```

<br />

We should patch the instruction `tbz w8, #0x0, LAB_0000a130` and replace it with a NOP so execution continues to the next instruction `b LAB_00009d20`, which is the flag branch.

```javascript
// Replace TBZ at WhereAmIReally.debug.dylib + 0x9d18 with NOP

const t_module = 'WhereAmIReally.debug.dylib';

const instr_offset = ptr('0x9d18');
const INSTR_SIZE = 4;

// find module base
const base = Module.findBaseAddress(t_module);
if (base === null) {
    throw new Error('Module not found: ' + t_module);
}

const instr_addr = base.add(instr_offset);
console.log('[*] module base:   ', base);
console.log('[*] instr address: ', instr_addr);

// Backup original bytes
const origBytes = Memory.readByteArray(instr_addr, INSTR_SIZE);
console.log('[*] original bytes:', hexdump(origBytes, { offset: 0, length: INSTR_SIZE }));

// ARM64 NOP encoding: 0xD503201F (4 bytes: 1F 20 03 D5)
const NOP_WORD = 0xD503201F >>> 0;

try {
    // Make page writable
    Memory.protect(instr_addr, INSTR_SIZE, 'rwx');

    // Write NOP (little-endian)
    instr_addr.writeU32(NOP_WORD);

    // Restore to read+exec
    Memory.protect(instr_addr, INSTR_SIZE, 'r-x');

    console.log('[+] Patched TBZ -> NOP at', instr_addr);
    console.log('[*] new bytes:', hexdump(instr_addr.readByteArray(INSTR_SIZE), { offset: 0, length: INSTR_SIZE }));

} catch (err) {
    console.error('[!] Patch failed:', err.message);
    // Try to restore original bytes if we changed memory
    try {
        Memory.protect(instr_addr, INSTR_SIZE, 'rwx');
        Memory.writeByteArray(instr_addr, origBytes);
        Memory.protect(instr_addr, INSTR_SIZE, 'r-x');
        console.log('[*] Original bytes restored.');
    } catch (restoreErr) {
        console.error('[!] Failed to restore original bytes:', restoreErr.message);
    }
}

// RPC to restore original bytes if needed
rpc.exports = {
    restoreoriginal: function () {
        try {
            Memory.protect(instr_addr, INSTR_SIZE, 'rwx');
            Memory.writeByteArray(instr_addr, origBytes);
            Memory.protect(instr_addr, INSTR_SIZE, 'r-x');
            return 'restored';
        } catch (e) {
            return 'restore failed: ' + e.message;
        }
    }
};
```

Launch the app using this Frida script; you’ll see the app display the flag

```
Spawning `com.8ksec.WhereAmIReally.W46SY5ZJ6Z`...                       
[*] module base:    0x102eb8000
[*] instr address:  0x102ec1d18
[*] original bytes:            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  c8 20 00 36                                      . .6
[+] Patched TBZ -> NOP at 0x102ec1d18
[*] new bytes:            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  1f 20 03 d5   
```

<br />

![](/assets/img/8ksec/WhereAmIReally/1.jpg)





<br /><br />

**Method 2:**

By hooking the `LocationlatitudeLongitude` function, we can read the device's actual latitude and longitude to determine what to spoof

<br />

![](/assets/img/8ksec/WhereAmIReally/2.png)

<br />

```javascript
const t_module = 'WhereAmIReally.debug.dylib';
const offset = ptr('0xbaf0'); // target function (lat, long)

const base = Module.findBaseAddress(t_module);
if (base === null) {
    throw new Error('Module not found: ' + t_module);
}

const target = base.add(offset);
console.log('[*] Hooking address:', target);

Interceptor.attach(target, {
    onEnter: function (args) {
        // args[0] and args[1] are the first two arguments (ARM64: x0, x1)
        const a0 = args[0];
        const a1 = args[1];

        console.log('--- onEnter ---');
        console.log('raw args:');
        console.log('  args[0] (x0) =', a0);
        console.log('  args[1] (x1) =', a1);

        // Also print register view
        try {
            console.log('registers:');
            console.log('  this.context.x0 =', this.context.x0);
            console.log('  this.context.x1 =', this.context.x1);
        } catch (e) {
            // some Frida versions may not expose context the same way
        }

        // Try to interpret as pointer to C string
        try {
            if (!a0.isNull()) {
                const s0 = Memory.readUtf8String(a0);
                console.log('  args[0] as C string:', s0);
            }
        } catch (e) {
            // not a valid string pointer
        }
        try {
            if (!a1.isNull()) {
                const s1 = Memory.readUtf8String(a1);
                console.log('  args[1] as C string:', s1);
            }
        } catch (e) {
            // not a valid string pointer
        }

        // Try to read 8 bytes at pointer as double (if a pointer to a double)
        try {
            if (!a0.isNull()) {
                const d0 = Memory.readDouble(a0);
                console.log('  args[0] -> readDouble @ ptr:', d0);
            }
        } catch (e) {
            // not a pointer to double
        }
        try {
            if (!a1.isNull()) {
                const d1 = Memory.readDouble(a1);
                console.log('  args[1] -> readDouble @ ptr:', d1);
            }
        } catch (e) {
            // not a pointer to double
        }

        // If the values are passed directly as integers (not pointers), print integer interpretations
        try {
            console.log('integer interpretations:');
            console.log('  args[0].toInt32() =', a0.toInt32());
            // toInt64 may not exist on all Frida versions; use toString(10) fallback
            try { console.log('  args[0].toInt64() =', a0.toInt64()); } catch(e) {  }
            console.log('  args[1].toInt32() =', a1.toInt32());
            try { console.log('  args[1].toInt64() =', a1.toInt64()); } catch(e) {  }
        } catch (e) { }

        // Hexdump first 32 bytes at pointer if readable
        try {
            if (!a0.isNull()) {
                console.log('  hexdump @ args[0]:\n' + hexdump(a0, { length: 32 }));
            }
        } catch (e) {  }
        try {
            if (!a1.isNull()) {
                console.log('  hexdump @ args[1]:\n' + hexdump(a1, { length: 32 }));
            }
        } catch (e) {  }

        // If lat/long are floating values passed in SIMD registers (v0/v1), read them too
        try {
            // some Frida builds expose the float registers as d0, d1 (64-bit floats)
            if (this.context.d0 !== undefined) {
                console.log('simd registers:');
                console.log('  d0 =', this.context.d0);
                console.log('  d1 =', this.context.d1);
            } else if (this.context.v0 !== undefined) {
                // v0 may be a buffer-like object — attempt to show raw bytes
                console.log('  v0 =', this.context.v0);
                console.log('  v1 =', this.context.v1);
            }
        } catch (e) {
            // ignore if not available
        }

        console.log('--- end onEnter ---');
    },

    onLeave: function (retval) {
        console.log('[*] onLeave retval =', retval);
    }
});
```

<br />

Latitude: 49.06666666666667, Longitude: 2.325.

```
simd registers:
  d0 = 49.06666666666667
  d1 = 2.325
```

<br />

Now we can use these latitude and longitude values to spoof our location

```javascript
// Base coordinates
var spoof_latitude = 49.06666666666667;
var spoof_longitude = 2.325;

function spoof_location(spoof_latitude, spoof_longitude)
{
	var hook_cllocation = ObjC.classes["CLLocation"]["- coordinate"]
	Interceptor.attach(hook_cllocation.implementation, {
	  onLeave: function(return_value) {
		//console.log(new ObjC.Object(return_value))
		var spoofed_return_value = (new ObjC.Object(return_value)).initWithLatitude_longitude_(spoof_latitude, spoof_longitude)
		return_value.replace(spoofed_return_value)
	  }
	});
}

spoof_location(spoof_latitude, spoof_longitude);
```

<br />

![](/assets/img/8ksec/WhereAmIReally/4.jpg)

<br /><br />

**Method 3:**

the function at offset `0xa84c`  compares our location to Latitude: 49.06666666666667, Longitude: 2.325 and returns `true` if the distance is ≤ 100, otherwise `false`. We need to hook it and force the return value to `true`.

![](/assets/img/8ksec/WhereAmIReally/1.png)

<br />

```javascript
var t_module = 'WhereAmIReally.debug.dylib';
var offset = ptr('0xa84c');
var base = Module.findBaseAddress(t_module);

if (base === null) {
    throw new Error('Module not found: ' + t_module);
}

var target = base.add(offset);
console.log('[*] Hooking address:', target);

Interceptor.attach(target, {
    onLeave: function (retval) {
        try {
	    	retval.replace(0x1);
            // Print raw retval
            console.log(' retval (raw) =', retval);
        } catch (err) {
            console.error('[!] onLeave error:', err.stack || err);
        }
    }
});
```

