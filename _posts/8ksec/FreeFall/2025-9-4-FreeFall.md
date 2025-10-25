---
title: FreeFall - 8kSec
date: 2025-9-4 00:00:00 +/-TTTT
categories: [8kSec]
tags: [8kSec, writeup, mobile penetration testing, ios]     # TAG names should always be lowercase
---

<br />

**Description:**

Experience the thrill of FreeFall, an addictive iOS ball game that challenges your reflexes and precision! Navigate a fast-moving ball through obstacles using intuitive paddle controls and all under a 60-second time limit.
Earn bonus points for destroying obstacles and advancing difficulty levels, and climb the competitive leaderboard. With realistic physics and secure, cheat-proof scoring, only the best rise to the top.

<br />

**Objective:**

- Create a runtime manipulation attack that exploits the FreeFall game to achieve impossibly high scores on the leaderboard without legitimate gameplay.
- Your goal is to bypass the game's scoring validation mechanisms and submit arbitrary scores that would be impossible to achieve through normal play.

<br />

**Restrictions:**

You must perform runtime manipulation to change how the app behaves.

<br />

**Explore the application**

The application is a timed arcade game featuring paddle-based ball control. Players aim to destroy obstacles and accumulate points within a 60-second countdown while progressing through increasing difficulty levels.

<br />

![](/assets/img/8ksec/FreeFall/4.jpg)

<br />



![](/assets/img/8ksec/FreeFall/1.jpg)

<br />

When the 60 seconds are up, the game ends, calculates the player’s score, and prompts them to enter their name for the leaderboard.

<br />

![](/assets/img/8ksec/FreeFall/5.jpg)

<br />

The leaderboard displays all players along with their scores.

![](/assets/img/8ksec/FreeFall/6.jpg)

<br />

```
└─# objection -g  com.eightksec.freefallgame.J8L462KYQ8 explore
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
...htksec.freefallgame.J8L462KYQ8 on (iPhone: 16.0) [usb] # env

Name               Path
-----------------  -------------------------------------------------------------------------------------------
BundlePath         /private/var/containers/Bundle/Application/42032971-6585-4DAB-8B95-7A119959D6B0/Runner.app
CachesDirectory    /var/mobile/Containers/Data/Application/8A0D7292-BFF7-407B-88B1-D25E95396A5C/Library/Caches
DocumentDirectory  /var/mobile/Containers/Data/Application/8A0D7292-BFF7-407B-88B1-D25E95396A5C/Documents
LibraryDirectory   /var/mobile/Containers/Data/Application/8A0D7292-BFF7-407B-88B1-D25E95396A5C/Library
```

<br />

The player’s name and score are saved in a SQLite database file named **freefallgame.db**, located in the app’s Documents directory.

```
iPhone:/var/mobile/Containers/Data/Application/8A0D7292-BFF7-407B-88B1-D25E95396A5C/Documents root# pwd
/var/mobile/Containers/Data/Application/8A0D7292-BFF7-407B-88B1-D25E95396A5C/Documents
iPhone:/var/mobile/Containers/Data/Application/8A0D7292-BFF7-407B-88B1-D25E95396A5C/Documents root# ls
freefallgame.db  security_tokens.db
```

<br />

Download the **freefallgame.db** file using **Objection**.

```
...htksec.freefallgame.J8L462KYQ8 on (iPhone: 16.0) [usb] # file download /var/mobile/Containers/Data/Application/8A0D7292-BFF7-407B-88B1-D25E95396A5C/Documents/freefallgame.db
Downloading /var/mobile/Containers/Data/Application/8A0D7292-BFF7-407B-88B1-D25E95396A5C/Documents/freefallgame.db to freefallgame.db
Streaming file from device...
Writing bytes to destination...
Successfully downloaded /var/mobile/Containers/Data/Application/8A0D7292-BFF7-407B-88B1-D25E95396A5C/Documents/freefallgame.db to freefallgame.db
```

<br />

Open the **freefallgame.db** file using **sqlitebrowser**.

```
└─# sqlitebrowser freefallgame.db
```

<br />

In the **leaderboard** table, the **name** and **score** columns store each player’s data.

![](/assets/img/8ksec/FreeFall/1.png)

<br />

We can hook SQLite functions (for example, `sqlite3_step`) with Frida to see the SQL statements executed when a player’s score is saved. [This](https://codeshare.frida.re/@karim-moftah/ios-sqlite3/) Frida script intercepts SQLite calls.

```javascript
// frida-sqlite-prepare-all.js
// Hooks sqlite3_prepare, sqlite3_prepare_v2, sqlite3_prepare_v3,
// sqlite3_prepare16, sqlite3_prepare16_v2, sqlite3_prepare16_v3
// plus helpful surrounding SQLite functions to make output useful.
//
// Usage:
//   frida -U -f <bundle/id> -l frida-sqlite-prepare-all.js
// or attach:
//   frida -U -n <process> -l frida-sqlite-prepare-all.js

'use strict';

const stmts = {}; // map stmtPtr -> { sql: "...", binds: { idx: val } }

function p(ptr) {
    return ptr ? ptr.toString() : "0x0";
}

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
        if (!stmts[key]) stmts[key] = {
            sql: sql,
            binds: {}
        };
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
        onEnter: function(args) {
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
        onLeave: function(retval) {
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
const prepares = [{
        name: "sqlite3_prepare",
        opts: {
            sqlArgIndex: 1,
            isUtf16: false,
            ppStmtIndex: 3
        }
    },
    {
        name: "sqlite3_prepare_v2",
        opts: {
            sqlArgIndex: 1,
            isUtf16: false,
            ppStmtIndex: 3
        }
    },
    {
        name: "sqlite3_prepare_v3",
        opts: {
            sqlArgIndex: 1,
            isUtf16: false,
            ppStmtIndex: 3
        }
    },

    // 16-bit (UTF-16) variants usually have wchar_t* as sql arg
    {
        name: "sqlite3_prepare16",
        opts: {
            sqlArgIndex: 1,
            isUtf16: true,
            ppStmtIndex: 3
        }
    },
    {
        name: "sqlite3_prepare16_v2",
        opts: {
            sqlArgIndex: 1,
            isUtf16: true,
            ppStmtIndex: 3
        }
    },
    {
        name: "sqlite3_prepare16_v3",
        opts: {
            sqlArgIndex: 1,
            isUtf16: true,
            ppStmtIndex: 3
        }
    }
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
const bindFns = [{
        name: "sqlite3_bind_text",
        handler: function(args) {
            const stmt = args[0];
            const idx = args[1].toInt32();
            const txt = safeReadUtf8(args[2]) || safeReadUtf16(args[2]) || null;
            const key = p(stmt);
            if (stmts[key]) stmts[key].binds[idx] = txt === null ? "NULL" : '"' + txt + '"';
        }
    },
    {
        name: "sqlite3_bind_text16",
        handler: function(args) {
            const stmt = args[0];
            const idx = args[1].toInt32();
            const txt = safeReadUtf16(args[2]) || null;
            const key = p(stmt);
            if (stmts[key]) stmts[key].binds[idx] = txt === null ? "NULL" : '"' + txt + '"';
        }
    },
    {
        name: "sqlite3_bind_int",
        handler: function(args) {
            const stmt = args[0];
            const idx = args[1].toInt32();
            const v = args[2].toInt32();
            const key = p(stmt);
            if (stmts[key]) stmts[key].binds[idx] = v;
        }
    },
    {
        name: "sqlite3_bind_int64",
        handler: function(args) {
            const stmt = args[0];
            const idx = args[1].toInt32();
            const v = args[2].toInt64();
            const key = p(stmt);
            if (stmts[key]) stmts[key].binds[idx] = v.toString();
        }
    },
    {
        name: "sqlite3_bind_double",
        handler: function(args) {
            const stmt = args[0];
            const idx = args[1].toInt32();
            // read double safely
            let v = null;
            try {
                v = args[2].readDouble();
            } catch (e) {
                try {
                    v = args[2].toDouble();
                } catch (e2) {
                    v = "(double?)";
                }
            }
            const key = p(stmt);
            if (stmts[key]) stmts[key].binds[idx] = v;
        }
    },
    {
        name: "sqlite3_bind_null",
        handler: function(args) {
            const stmt = args[0];
            const idx = args[1].toInt32();
            const key = p(stmt);
            if (stmts[key]) stmts[key].binds[idx] = "NULL";
        }
    },
    {
        name: "sqlite3_bind_blob",
        handler: function(args) {
            const stmt = args[0];
            const idx = args[1].toInt32();
            const n = args[3].toInt32();
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
            try {
                item.handler(args);
            } catch (e) {}
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

The output reveals the executed SQL statement and its bound parameters, displaying the player’s name and score.

```
== sqlite3_step ==
STMT: 0x1228d0ca0
SQL: INSERT INTO leaderboard (name, score, timestamp, token) VALUES (?, ?, ?, ?)
Bound params:
  [1] = "test"
  [2] = 945
  [4] = "463549ec2c2d63f75e8659d058fe01e34f2c13910a84e719f2a8354348660596"
```

<br />

To modify the score, the script can be tweaked to spot the `INSERT INTO leaderboard` query before `sqlite3_step` runs, use `sqlite3_bind_int` to change parameter `[2]` to `13333337`, and update the internal record so the log shows the new value.

```javascript
// Adds logic to override param [2] for INSERT INTO leaderboard to 13333337

'use strict';

const stmts = {}; // map stmtPtr -> { sql: "...", binds: { idx: val } }

function p(ptr) {
    return ptr ? ptr.toString() : "0x0";
}

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
        if (!stmts[key]) stmts[key] = {
            sql: sql,
            binds: {}
        };
    } catch (e) {}
}

/* -------------------
   NEW: binder helper
   -------------------
   We will call sqlite3_bind_int(stmt, idx, value) ourselves to overwrite a bind.
   Create a NativeFunction reference if the symbol is available.
*/
let _bind_int_fn = null;
const _bind_int_ptr = Module.findExportByName(null, "sqlite3_bind_int");
if (_bind_int_ptr) {
    try {
        _bind_int_fn = new NativeFunction(_bind_int_ptr, 'int', ['pointer', 'int', 'int']);
        console.log("[frida] found sqlite3_bind_int at " + _bind_int_ptr);
    } catch (e) {
        console.log("[frida] error creating NativeFunction for sqlite3_bind_int: " + e);
    }
} else {
    console.log("[frida] sqlite3_bind_int not found; override-by-rebind will not be available.");
}

/* ------------- end new ------------- */

// Handler generator for prepare variants (same as your original)
function attachPrepare(symName, opts) {
    const ptr = Module.findExportByName(null, symName);
    if (!ptr) {
        // console.log(symName + " not found");
        return;
    }
    Interceptor.attach(ptr, {
        onEnter: function(args) {
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
        onLeave: function(retval) {
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
                console.log("\n== " + this.sym + " (no stmt) ==");
                console.log("SQL: " + sql);
                console.log("Return code: " + retval.toInt32());

            } catch (e) {
                console.log(this.sym + ".onLeave error: " + e);
            }
        }
    });
}

// (attach prepares list - same as your original)
const prepares = [{
        name: "sqlite3_prepare",
        opts: {
            sqlArgIndex: 1,
            isUtf16: false,
            ppStmtIndex: 3
        }
    },
    {
        name: "sqlite3_prepare_v2",
        opts: {
            sqlArgIndex: 1,
            isUtf16: false,
            ppStmtIndex: 3
        }
    },
    {
        name: "sqlite3_prepare_v3",
        opts: {
            sqlArgIndex: 1,
            isUtf16: false,
            ppStmtIndex: 3
        }
    },
    {
        name: "sqlite3_prepare16",
        opts: {
            sqlArgIndex: 1,
            isUtf16: true,
            ppStmtIndex: 3
        }
    },
    {
        name: "sqlite3_prepare16_v2",
        opts: {
            sqlArgIndex: 1,
            isUtf16: true,
            ppStmtIndex: 3
        }
    },
    {
        name: "sqlite3_prepare16_v3",
        opts: {
            sqlArgIndex: 1,
            isUtf16: true,
            ppStmtIndex: 3
        }
    }
];

prepares.forEach(function(pf) {
    attachPrepare(pf.name, pf.opts);
});

// sqlite3_exec hook (same as original)
const execPtr = Module.findExportByName(null, "sqlite3_exec");
if (execPtr) {
    Interceptor.attach(execPtr, {
        onEnter: function(args) {
            this.db = args[0];
            this.sqlPtr = args[1];
            this.sql = safeReadUtf8(this.sqlPtr) || safeReadUtf16(this.sqlPtr) || null;
            this.bt = backtrace(this.context);
            console.log("\n== sqlite3_exec ==");
            console.log("DB: " + p(this.db));
            console.log("SQL: " + (this.sql || "(null)"));
        }
    });
}

/* ---------------------
   sqlite3_step modification
   ---------------------
   Before logging/stepping we check if the tracked SQL is the leaderboard insert.
   If so, and if we have sqlite3_bind_int available, call it to overwrite param [2].
*/
const stepPtr = Module.findExportByName(null, "sqlite3_step");
if (stepPtr) {
    Interceptor.attach(stepPtr, {
        onEnter: function(args) {
            try {
                this.stmt = args[0];
                const key = p(this.stmt);
                const rec = stmts[key];
                if (rec) {
                    // If this is the leaderboard insert, force param 2 -> 13333337
                    // We look for SQL that contains the table name (case-insensitive)
                    const sqlLower = (rec.sql || "").toLowerCase();
                    if (sqlLower.indexOf("insert into leaderboard") !== -1) {
                        const forcedValue = 13333337;
                        if (_bind_int_fn) {
                            try {
                                // call sqlite3_bind_int(stmt, 2, 13333337)
                                const rc = _bind_int_fn(this.stmt, 2, forcedValue);
                                // update our tracked binds so logs reflect the change
                                if (!rec.binds) rec.binds = {};
                                rec.binds[2] = forcedValue;
                                console.log("[frida] Overwrote parameter [2] for leaderboard INSERT -> " + forcedValue + " (sqlite3_bind_int rc=" + rc + ")");
                            } catch (e) {
                                console.log("[frida] Error calling sqlite3_bind_int: " + e);
                            }
                        } else {
                            console.log("[frida] sqlite3_bind_int not available; cannot overwrite param [2].");
                        }
                    }

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

/* Bind functions kept the same as your original script.
   They still populate stmts[..].binds for logging.
*/
const bindFns = [{
        name: "sqlite3_bind_text",
        handler: function(args) {
            const stmt = args[0];
            const idx = args[1].toInt32();
            const txt = safeReadUtf8(args[2]) || safeReadUtf16(args[2]) || null;
            const key = p(stmt);
            if (stmts[key]) stmts[key].binds[idx] = txt === null ? "NULL" : '"' + txt + '"';
        }
    },
    {
        name: "sqlite3_bind_text16",
        handler: function(args) {
            const stmt = args[0];
            const idx = args[1].toInt32();
            const txt = safeReadUtf16(args[2]) || null;
            const key = p(stmt);
            if (stmts[key]) stmts[key].binds[idx] = txt === null ? "NULL" : '"' + txt + '"';
        }
    },
    {
        name: "sqlite3_bind_int",
        handler: function(args) {
            const stmt = args[0];
            const idx = args[1].toInt32();
            const v = args[2].toInt32();
            const key = p(stmt);
            if (stmts[key]) stmts[key].binds[idx] = v;
        }
    },
    {
        name: "sqlite3_bind_int64",
        handler: function(args) {
            const stmt = args[0];
            const idx = args[1].toInt32();
            const v = args[2].toInt64();
            const key = p(stmt);
            if (stmts[key]) stmts[key].binds[idx] = v.toString();
        }
    },
    {
        name: "sqlite3_bind_double",
        handler: function(args) {
            const stmt = args[0];
            const idx = args[1].toInt32();
            let v = null;
            try {
                v = args[2].readDouble();
            } catch (e) {
                try {
                    v = args[2].toDouble();
                } catch (e2) {
                    v = "(double?)";
                }
            }
            const key = p(stmt);
            if (stmts[key]) stmts[key].binds[idx] = v;
        }
    },
    {
        name: "sqlite3_bind_null",
        handler: function(args) {
            const stmt = args[0];
            const idx = args[1].toInt32();
            const key = p(stmt);
            if (stmts[key]) stmts[key].binds[idx] = "NULL";
        }
    },
    {
        name: "sqlite3_bind_blob",
        handler: function(args) {
            const stmt = args[0];
            const idx = args[1].toInt32();
            const n = args[3].toInt32();
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
            try {
                item.handler(args);
            } catch (e) {}
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

console.log("[frida] sqlite3 prepare hooks installed for: sqlite3_prepare, sqlite3_prepare_v2, sqlite3_prepare_v3, sqlite3_prepare16, sqlite3_prepare16_v2, sqlite3_prepare16_v3 (plus exec/step/bind/finalize/reset).");
```

<br />

Spawn the game using this Frida script. At game over, after the score is calculated, you’ll notice the value has been replaced with **13333337**.

```
== sqlite3_step ==
STMT: 0x135fd0ca0
SQL: INSERT INTO leaderboard (name, score, timestamp, token) VALUES (?, ?, ?, ?)
Bound params:
  [1] = "karim"
  [2] = 13333337
  [4] = "93caa299e912be237959e48db7c2024ccdde78ea77f8730e126bee8aa9bbbe90"
```

<br />

The real score was **693**.

![](/assets/img/8ksec/FreeFall/7.jpg)

<br />

The modified score will be displayed in the leaderboard.

<br />

![](/assets/img/8ksec/FreeFall/8.jpg)
