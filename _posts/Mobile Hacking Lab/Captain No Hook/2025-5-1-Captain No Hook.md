---
title: Captain No Hook - Mobile Hacking Lab
date: 2025-5-1 00:00:00 +/-TTTT
categories: [Mobile Hacking Lab]
tags: [mobile hacking lab, writeup, mobile penetration testing, ios]     # TAG names should always be lowercase
---

<br />

**Introduction**

Welcome to the **iOS Application Security Lab: Captain No Hook Anti-Debugging Challenge**. This challenge focuses on a fictitious app called Captain No Hook, which implements advanced anti-debugging / jailbreak detection techniques. Your objective is to bypass these protections and retrieve the hidden flag within the app.

<br />

**Objective**

**Bypass Anti-debugging Protections**: Your task is to overcome the protection mechanisms implemented in the Captain NoHook app to reveal the hidden flag.

<br />

**Explore The App**

<br />

When the app starts, you’ll see a button that says **“Flag ‘ere!”**.

![](/assets/img/mhl/CaptainNoHook/3.jpg)

<br />

When pressed, the button causes the device to display a notification stating it is not compliant. Once you press **OK**, the application terminates.



![](/assets/img/mhl/CaptainNoHook/5.jpg)



<br />

**Reverse Engineering with Ghidra**

<br />

The application performs a variety of security checks:

<br />

| Check Type                    | Function                          |
| ----------------------------- | --------------------------------- |
| Anti-debugging                | `_disable_gdb`                    |
| Reverse-engineering detection | `amIReverseEngineered`            |
| Suspicious file check         | `checkExistenceOfSuspiciousFiles` |
| Open ports scan               | `checkOpenedPorts`                |
| DYLD injection detection      | `checkDYLD`                       |
| App integrity validation      | `is_noncompliant_device`          |
| Process permission check      | `checkPSelectFlag` (PSelect Flag) |

<br /><br />



All checks are invoked from the single entry point `_$s14Captain_Nohook30ReverseEngineeringToolsCheckerC13performChecks33_75B14952DDFE2A78282659A6E004BB4ALLAC0cdE6StatusVyFZ`. 

<br />

![](/assets/img/mhl/CaptainNoHook/1.png)



<br /><br /><br />





![](/assets/img/mhl/CaptainNoHook/2.png)



<br /><br />





```c
undefined1  [16]
_$s14Captain_Nohook30ReverseEngineeringToolsCheckerC13performChecks33_75B14952DDFE2A78282659A6E004BB4ALLAC0cdE6StatusVyFZ
          (void)

{
  byte bVar1;
  char cVar2;
  char *pcVar3;
  undefined4 uVar4;
  uint uVar5;
  long lVar6;
  char *pcVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  undefined1 auVar10 [16];
  char local_88 [8];
  char *local_80;
  undefined8 local_78;
  char local_70;
  char local_69;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  byte local_48 [8];
  char *local_40;
  undefined8 local_38;
  byte local_29;
  
  local_50 = 0;
  local_60 = 0;
  local_58 = 0;
  local_70 = '\0';
  local_29 = 1;
  local_48[0] = 1;
  pcVar7 = "";
  uVar8 = 0;
  uVar9 = 1;
  _$sSS21_builtinStringLiteral17utf8CodeUnitCount7isASCIISSBp_BwBi1_tcfC();
  local_40 = pcVar7;
  local_38 = uVar8;
  lVar6 = ___swift_instantiateConcreteTypeFromMangledName
                    ((long *)&_$s14Captain_Nohook11FailedCheckO5check_SS11failMessagetMD);
  uVar8 = 0;
  _$ss27_allocateUninitializedArrayySayxG_BptBwlF(0,lVar6);
  local_50 = uVar8;
  _$s14Captain_Nohook11FailedCheckO8allCasesSayACGvgZ();
  local_68 = uVar8;
  lVar6 = ___swift_instantiateConcreteTypeFromMangledName
                    ((long *)&_$sSay14Captain_Nohook11FailedCheckOGMD);
  pcVar7 = _$sSay14Captain_Nohook11FailedCheckOGSayxGSlsWl();
  _$sSlss16IndexingIteratorVyxG0B0RtzrlE04makeB0ACyF(&local_60,lVar6);
LAB_10000d760:
  do {
    ___swift_instantiateConcreteTypeFromMangledName
              ((long *)&_$ss16IndexingIteratorVySay14Captain_Nohook11FailedCheckOGGMD);
    _$ss16IndexingIteratorV4next7ElementQzSgyF(&local_69);
    cVar2 = local_69;
    if (local_69 == '\n') {
      _$ss16IndexingIteratorVySay14Captain_Nohook11FailedCheckOGGWOh(&local_60);
      uVar8 = local_50;
      uVar5 = (uint)local_29;
      _swift_bridgeObjectRetain();
      uVar5 = _$s14Captain_Nohook30ReverseEngineeringToolsCheckerC0cdE6StatusV6passed12failedChecksA ESb_SayAA11FailedCheckO5check_SS11failMessagetGtcfC
                        (uVar5 & 1);
      _$sSay14Captain_Nohook11FailedCheckO5check_SS11failMessagetGWOh(&local_50);
      _$sSb6passed_SS11failMessagetWOh((long)local_48);
      auVar10._4_4_ = 0;
      auVar10._0_4_ = uVar5 & 1;
      auVar10._8_8_ = uVar8;
      return auVar10;
    }
    local_70 = local_69;
    switch(local_69) {
    case '\x01':
      uVar4 = _$s14Captain_Nohook30ReverseEngineeringToolsCheckerC31checkExistenceOfSuspiciousFiles3 3_75B14952DDFE2A78282659A6E004BB4ALLSb6passed_SS11failMessagetyFZ
                        ();
      uVar8 = local_38;
      local_48[0] = (byte)uVar4 & 1;
      local_40 = pcVar7;
      local_38 = uVar9;
      _swift_bridgeObjectRelease(uVar8);
      break;
    default:
      goto switchD_10000d7dc_caseD_2;
    case '\x06':
      uVar4 = _$s14Captain_Nohook30ReverseEngineeringToolsCheckerC9checkDYLD33_75B14952DDFE2A7828265 9A6E004BB4ALLSb6passed_SS11failMessagetyFZ
                        ();
      uVar8 = local_38;
      local_48[0] = (byte)uVar4 & 1;
      local_40 = pcVar7;
      local_38 = uVar9;
      _swift_bridgeObjectRelease(uVar8);
      break;
    case '\a':
      uVar4 = _$s14Captain_Nohook30ReverseEngineeringToolsCheckerC16checkOpenedPorts33_75B14952DDFE2 A78282659A6E004BB4ALLSb6passed_SS11failMessagetyFZ
                        ();
      uVar8 = local_38;
      local_48[0] = (byte)uVar4 & 1;
      local_40 = pcVar7;
      local_38 = uVar9;
      _swift_bridgeObjectRelease(uVar8);
      break;
    case '\b':
      local_48[0] = _$s14Captain_Nohook30ReverseEngineeringToolsCheckerC16checkPSelectFlag33_75B1495 2DDFE2A78282659A6E004BB4ALLSb6passed_SS11failMessagetyFZ
                              ();
      uVar8 = local_38;
      local_40 = pcVar7;
      local_38 = uVar9;
      _swift_bridgeObjectRelease(uVar8);
    }
    uVar8 = local_38;
    pcVar3 = local_40;
    bVar1 = local_48[0];
    if ((local_29 & 1) == 0) {
      bVar1 = 0;
    }
    local_29 = bVar1 & 1;
    if ((local_48[0] & 1) == 0) {
      _swift_bridgeObjectRetain();
      local_88[0] = cVar2;
      local_80 = pcVar3;
      local_78 = uVar8;
      pcVar7 = (char *)___swift_instantiateConcreteTypeFromMangledName
                                 ((long *)&
                                          _$sSay14Captain_Nohook11FailedCheckO5check_SS11failMessage tGMD
                                 );
      _$sSa6appendyyxnF(local_88);
    }
  } while( true );
switchD_10000d7dc_caseD_2:
  goto LAB_10000d760;
}
```





<br />

<br />

Instead of instrumenting each individual check (`_disable_gdb`, `amIReverseEngineered`, `checkExistenceOfSuspiciousFiles`, `checkOpenedPorts`, `checkDYLD`, `is_noncompliant_device`, `checkPSelectFlag`), hook the single function `_$s14Captain_Nohook30ReverseEngineeringToolsCheckerC13performChecks33_75B14952DDFE2A78282659A6E004BB4ALLAC0cdE6StatusVyFZ` and make it return `1`.



<br />

Using this Frida script, the app no longer kills the process; our next step is to locate the flag.

```javascript
var targetModule = 'Captain Nohook';
var addr = ptr(0xd6a8);
var newretval = ptr("0x1");
var moduleBase = Module.getBaseAddress(targetModule);
var targetAddress = moduleBase.add(addr);
   Interceptor.attach(targetAddress, {
        onEnter: function(args) {

        },
    	onLeave: function(retval) {  
    		retval.replace(newretval) 
    		console.log("\t[-] New Return Value: " + newretval) 
    	}
    
    });
```



<br /><br />



The function `_$s14Captain_Nohook14ViewControllerC11whereIsflagyySo8UIButtonCF` verifies that all checks pass before revealing the flag.

```c
void _$s14Captain_Nohook14ViewControllerC11whereIsflagyySo8UIButtonCF(long param_1)

{
  void *pvVar1;
  void *pvVar2;
  code *pcVar3;
  long lVar4;
  long lVar5;
  void *pvVar6;
  char *pcVar7;
  undefined *puVar8;
  undefined8 uVar9;
  long lVar10;
  long extraout_x8;
  ulong *unaff_x20;
  undefined1 auStack_150 [8];
  undefined8 uStack_148;
  undefined4 auStack_140 [4];
  char **local_130;
  code *local_128;
  undefined8 local_120;
  uint local_118;
  uint local_114;
  long local_110;
  uint local_104;
  long local_100;
  void *local_f8;
  long local_f0;
  long local_e8;
  long local_e0;
  long local_d8;
  char *local_60;
  undefined8 local_58;
  undefined1 auStack_50 [32];
  
  puVar8 = PTR__swift_isaMask_10016d120;
  lVar4 = 0;
  _$s10Foundation16AttributedStringV13CharacterViewVMa();
  lVar10 = *(long *)(*(long *)(lVar4 + -8) + 0x40);
  (*(code *)PTR____chkstk_darwin_10016c2b0)();
  lVar10 = (long)&local_130 - (lVar10 + 0xfU & 0xfffffffffffffff0);
  lVar5 = ___swift_instantiateConcreteTypeFromMangledName
                    ((long *)&_$sSo8UIButtonC5UIKitE13ConfigurationVSgMD);
  lVar5 = *(long *)(*(long *)(lVar5 + -8) + 0x40);
  (*(code *)PTR____chkstk_darwin_10016c2b0)();
  pvVar1 = (void *)(lVar10 - (lVar5 + 0xfU & 0xfffffffffffffff0));
  (*(code *)PTR____chkstk_darwin_10016c2b0)();
  pvVar2 = (void *)((long)pvVar1 - (extraout_x8 + 0xfU & 0xfffffffffffffff0));
  pvVar6 = pvVar2;
  (**(code **)((*unaff_x20 & *(ulong *)puVar8) + 0x78))();
  if (param_1 == 0) {
    *(undefined1 *)((long)pvVar2 + -0x20) = 2;
    *(undefined8 *)((long)pvVar2 + -0x18) = 0x30;
    *(undefined4 *)((long)pvVar2 + -0x10) = 0;
    _$ss17_assertionFailure__4file4line5flagss5NeverOs12StaticStringV_A2HSus6UInt32VtF
              ("Fatal error",0xb,2,
               "Unexpectedly found nil while implicitly unwrapping an Optional value",0x44,2,
               "Captain_Nohook/ViewController.swift",0x23);
                    /* WARNING: Does not return */
    pcVar3 = (code *)SoftwareBreakpoint(1,0x10000a018);
    (*pcVar3)();
  }
  local_e8 = param_1;
  local_d8 = param_1;
  (**(code **)((*unaff_x20 & *(ulong *)puVar8) + 0x90))();
  local_f8 = pvVar6;
  _$sSS10FoundationE19_bridgeToObjectiveCSo8NSStringCyF();
  local_f0 = param_1;
  _swift_bridgeObjectRelease(local_f8);
  _objc_msgSend(local_e8,"setText:",local_f0);
  _objc_release(local_f0);
  lVar5 = local_e8;
  _objc_release();
  (**(code **)((*unaff_x20 & *(ulong *)puVar8) + 0x78))();
  local_e0 = lVar5;
  if (lVar5 == 0) {
    *(undefined1 *)((long)pvVar2 + -0x20) = 2;
    *(undefined8 *)((long)pvVar2 + -0x18) = 0x31;
    *(undefined4 *)((long)pvVar2 + -0x10) = 0;
    _$ss17_assertionFailure__4file4line5flagss5NeverOs12StaticStringV_A2HSus6UInt32VtF
              ("Fatal error",0xb,2,
               "Unexpectedly found nil while implicitly unwrapping an Optional value",0x44,2,
               "Captain_Nohook/ViewController.swift",0x23);
                    /* WARNING: Does not return */
    pcVar3 = (code *)SoftwareBreakpoint(1,0x10000a108);
    (*pcVar3)();
  }
  local_110 = lVar5;
  local_100 = lVar5;
  _objc_msgSend(lVar5,"isHidden");
  local_104 = (uint)lVar5;
  _objc_release(local_110);
  if ((local_104 & 1) == 0) {
    _$sSo8UIButtonC5UIKitE13configurationAbCE13ConfigurationVSgvg(pvVar2);
    lVar5 = 0;
    _$sSo8UIButtonC5UIKitE13ConfigurationVMa();
    uVar9 = 1;
    pvVar6 = pvVar2;
    (**(code **)(*(long *)(lVar5 + -8) + 0x30))();
    local_114 = (uint)((int)pvVar6 == 0);
    if (local_114 == 0) {
      _$sSo8UIButtonC5UIKitE13ConfigurationVSgWOc(pvVar2,pvVar1);
      _$sSo8UIButtonC5UIKitE13configurationAbCE13ConfigurationVSgvs(pvVar1);
      _$sSo8UIButtonC5UIKitE13ConfigurationVSgWOh(pvVar2);
    }
    else {
      pcVar3 = (code *)auStack_50;
      _$sSo8UIButtonC5UIKitE13ConfigurationV15attributedTitle10Foundation16AttributedStringVSgvM();
      lVar5 = 0;
      local_128 = pcVar3;
      local_120 = uVar9;
      _$s10Foundation16AttributedStringVMa();
      uVar9 = local_120;
      (**(code **)(*(long *)(lVar5 + -8) + 0x30))(local_120,1);
      local_118 = (uint)((int)uVar9 == 0);
      if (local_118 == 0) {
        (*local_128)(auStack_50,0);
        _$sSo8UIButtonC5UIKitE13ConfigurationVSgWOc(pvVar2,pvVar1);
        _$sSo8UIButtonC5UIKitE13configurationAbCE13ConfigurationVSgvs(pvVar1);
        _$sSo8UIButtonC5UIKitE13ConfigurationVSgWOh(pvVar2);
      }
      else {
        pcVar7 = "Arrr, find yerr hidden flag here!";
        uVar9 = 0x21;
        _$sSS21_builtinStringLiteral17utf8CodeUnitCount7isASCIISSBp_BwBi1_tcfC
                  ("Arrr, find yerr hidden flag here!",0x21,1);
        local_130 = &local_60;
        local_60 = pcVar7;
        local_58 = uVar9;
        puVar8 = _$s10Foundation16AttributedStringV13CharacterViewVAESmAAWl();
        _$sSmsEyxqd__cSTRd__7ElementQyd__AARtzlufC
                  (lVar10,local_130,lVar4,PTR__$sSSN_10016c750,puVar8,PTR__$sSSSTsWP_10016c8a8);
        _$s10Foundation16AttributedStringV10charactersAC13CharacterViewVvs(lVar10);
        (*local_128)(auStack_50,0);
        _$sSo8UIButtonC5UIKitE13configurationAbCE13ConfigurationVSgvs(pvVar2);
      }
    }
  }
  return;
}
```

<br />



`_$s14Captain_Nohook14ViewControllerC7getFlagSSyF` shows messages via a `UIAlertController`. That implies the flag could be present in the `UILabel` that presents the alert text.

```c
undefined1  [16] _$s14Captain_Nohook14ViewControllerC7getFlagSSyF(void)

{

  _$sSS10FoundationE8EncodingVMa();
  lVar22 = *(long *)(lVar6 + -8);
  lVar23 = *(long *)(lVar22 + 0x40);
  (*(code *)PTR____chkstk_darwin_10016c2b0)();
  puVar1 = local_440 + -(lVar23 + 0xfU & 0xfffffffffffffff0);
  uVar5 = _$s14Captain_Nohook22is_noncompliant_deviceSbyF();
  if ((uVar5 & 1) != 0) {
    local_1c8 = 0;
    _$sSo17UIAlertControllerCMa();
    pcVar7 = "Noncompliant device detected!";
    lVar23 = 0x1d;
    local_1b4 = 1;
    _$sSS21_builtinStringLiteral17utf8CodeUnitCount7isASCIISSBp_BwBi1_tcfC
              ("Noncompliant device detected!",0x1d,1);
    pcVar8 = "Yerr hook won\'t work!";
    lVar17 = 0x15;
    local_1d8 = pcVar7;
    local_1d0 = lVar23;
    _$sSS21_builtinStringLiteral17utf8CodeUnitCount7isASCIISSBp_BwBi1_tcfC
              ("Yerr hook won\'t work!",0x15,local_1b4 & 1);
    local_1b0 = _$sSo17UIAlertControllerC5title7message14preferredStyleABSSSg_AFSo0abF0VtcfCTO
                          (local_1d8,local_1d0,pcVar8,lVar17);
    _$sSo13UIAlertActionCMa();
    pcVar7 = "OK";
    lVar23 = 2;
    _$sSS21_builtinStringLiteral17utf8CodeUnitCount7isASCIISSBp_BwBi1_tcfC("OK",2,local_1b4 & 1);
    local_1c0 = _$sSo13UIAlertActionC5title5style7handlerABSSSg_So0aB5StyleVyABcSgtcfCTO
                          (pcVar7,lVar23,local_1c8,0x1000097cc,local_1c8);
    _objc_msgSend(local_1b0,"addAction:");
    _objc_release(local_1c0);
    _objc_msgSend(unaff_x20,"presentViewController:animated:completion:",local_1b0,local_1b4 & 1,0);
    _objc_release(local_1b0);
  }
  pcVar7 = "HhRVZ1fdevIW2GfW42oy9J4XrAz330o5amXtNc/t8+s=";
  uVar18 = 0x2c;
  _$sSS21_builtinStringLiteral17utf8CodeUnitCount7isASCIISSBp_BwBi1_tcfC
            ("HhRVZ1fdevIW2GfW42oy9J4XrAz330o5amXtNc/t8+s=",0x2c,1);
  uVar9 = 0x1f;
  puVar10 = puVar21;
  local_230 = pcVar7;
  local_228 = uVar18;
  local_48 = pcVar7;
  local_40 = uVar18;
  _$ss27_allocateUninitializedArrayySayxG_BptBwlF();
  *puVar10 = 0x31;
  puVar10[1] = 0x22;
  puVar10[2] = 0x31;
  puVar10[3] = 0x26;
  puVar10[4] = 0x2d;
  puVar10[5] = 0x37;
  puVar10[6] = 0x3b;
  puVar10[7] = 0x39;
  puVar10[8] = 0x39;
  puVar10[9] = 0x3b;
  puVar10[10] = 0x30;
  puVar10[0xb] = 0x3b;
  puVar10[0xc] = 0x26;
  puVar10[0xd] = 0x31;
  puVar10[0xe] = 0x62;
  local_218 = 0xf;
  puVar10[0xf] = 0x60;
  puVar10[0x10] = 0x37;
  puVar10[0x11] = 0x35;
  puVar10[0x12] = 0x3a;
  puVar10[0x13] = 0x3c;
  puVar10[0x14] = 0x35;
  puVar10[0x15] = 0x37;
  puVar10[0x16] = 0x3f;
  puVar10[0x17] = 0x3d;
  puVar10[0x18] = 0x3a;
  puVar10[0x19] = 0x20;
  puVar10[0x1a] = 0x3b;
  puVar10[0x1b] = 0x3a;
  puVar10[0x1c] = 0x35;
  puVar10[0x1d] = 0x27;
  puVar10[0x1e] = 0x35;
  local_220 = puVar10;
  local_210 = _$ss27_finalizeUninitializedArrayySayxGABnlF(uVar9);
  local_200 = local_218 + 0x11U & 0xfffffffffffffff0;
  local_208 = puVar1;
  local_58 = local_210;
  local_50 = local_210;
  (*(code *)PTR____chkstk_darwin_10016c2b0)();
  local_1f8 = (long)puVar1 - local_200;
  *(undefined1 *)(local_1f8 + 0x10) = 0x54;
  local_1f0 = ___swift_instantiateConcreteTypeFromMangledName((long *)&_$sSays5UInt8VGMD);
  puVar10 = _$sSays5UInt8VGSayxGSlsWl();
  pcVar4 = _$s14Captain_Nohook14ViewControllerC7getFlagSSyFs5UInt8VAFXEfU0_TA;
  _$sSlsE3mapySayqd__Gqd__7ElementQzKXEKlF
            (_$s14Captain_Nohook14ViewControllerC7getFlagSSyFs5UInt8VAFXEfU0_TA,local_1f8,local_1f0,
             puVar21,puVar10);
  puVar3 = local_208;
  local_1e8 = 0;
  uVar19 = 1;
  local_268 = 1;
  uVar11 = 1;
  local_258 = pcVar4;
  local_1e0 = pcVar4;
  local_60 = pcVar4;
  _$ss26DefaultStringInterpolationV15literalCapacity18interpolationCountABSi_SitcfC();
  uVar9 = local_268;
  local_70 = uVar11;
  local_68 = uVar19;
  _$sSS21_builtinStringLiteral17utf8CodeUnitCount7isASCIISSBp_BwBi1_tcfC("!",local_268,1);
  local_260 = uVar9;
  _$ss26DefaultStringInterpolationV13appendLiteralyySSF();
  _swift_bridgeObjectRelease(local_260);
  local_250 = &local_78;
  local_78 = local_258;
  _$sSS10FoundationE8EncodingV4utf8ACvgZ(puVar1);
  local_248 = _$sSays5UInt8VGSayxGSTsWl();
  ppcVar12 = local_250;
  puVar13 = puVar1;
  _$sSS10FoundationE5bytes8encodingSSSgxh_SSAAE8EncodingVtcSTRzs5UInt8V7ElementRtzlufC
            (local_250,puVar1,local_1f0);
  local_240 = ppcVar12;
  local_238 = puVar13;
  if (puVar13 == (undefined1 *)0x0) {
    puVar3[-0x20] = 2;
    *(undefined8 *)(puVar3 + -0x18) = 0x1f;
    *(undefined4 *)(puVar3 + -0x10) = 0;
    _$ss17_assertionFailure__4file4line5flagss5NeverOs12StaticStringV_A2HSus6UInt32VtF
              ("Fatal error",0xb,2,"Unexpectedly found nil while unwrapping an Optional value",0x39,
               2,"Captain_Nohook/ViewController.swift",0x23);
                    /* WARNING: Does not return */
    pcVar4 = (code *)SoftwareBreakpoint(1,0x100008fa0);
    (*pcVar4)();
  }
  local_2c8 = &local_88;
  local_2b8 = &local_70;
  local_278 = ppcVar12;
  local_270 = puVar13;
  local_88 = ppcVar12;
  local_80 = puVar13;
  _$ss26DefaultStringInterpolationV06appendC0yyxs06CustomB11ConvertibleRzs20TextOutputStreamableRzlF
            (local_2c8,puVar15,PTR__$sSSs23CustomStringConvertiblesWP_10016d0a8,
             PTR__$sSSs20TextOutputStreamablesWP_10016d5b0);
  _$sSSWOh((long)local_2c8);
  uVar9 = 0;
  _$sSS21_builtinStringLiteral17utf8CodeUnitCount7isASCIISSBp_BwBi1_tcfC("",0,1);
  local_2c0 = uVar9;
  _$ss26DefaultStringInterpolationV13appendLiteralyySSF();
  _swift_bridgeObjectRelease(local_2c0);
  local_2a8 = local_70;
  local_2b0 = local_68;
  _swift_bridgeObjectRetain();
  _$ss26DefaultStringInterpolationVWOh((long)local_2b8);
  uVar9 = local_2a8;
  uVar11 = local_2b0;
  _$sSS19stringInterpolationSSs013DefaultStringB0V_tcfC();
  local_288 = &local_98;
  local_98 = uVar9;
  local_90 = uVar11;
  _$sSS10FoundationE8EncodingV4utf8ACvgZ(puVar1);
  local_2a0 = _$sS2SSysWl();
  uVar9 = _$sSy10FoundationE4data5using20allowLossyConversionAA4DataVSgSSAAE8EncodingV_SbtFfA0_();
  uVar18 = (ulong)((uint)uVar9 & 1);
  puVar13 = puVar1;
  _$sSy10FoundationE4data5using20allowLossyConversionAA4DataVSgSSAAE8EncodingV_SbtF
            (puVar1,uVar18,puVar15,local_2a0);
  local_290 = *(code **)(lVar22 + 8);
  local_298 = puVar13;
  local_280 = uVar18;
  (*local_290)(puVar1,lVar6);
  _$sSSWOh((long)local_288);
  if ((local_280 & 0xf000000000000000) == 0xf000000000000000) {
    puVar3[-0x20] = 2;
    *(undefined8 *)(puVar3 + -0x18) = 0x1f;
    *(undefined4 *)(puVar3 + -0x10) = 0;
    _$ss17_assertionFailure__4file4line5flagss5NeverOs12StaticStringV_A2HSus6UInt32VtF
              ("Fatal error",0xb,2,"Unexpectedly found nil while unwrapping an Optional value",0x39,
               2,"Captain_Nohook/ViewController.swift",0x23);
                    /* WARNING: Does not return */
    pcVar4 = (code *)SoftwareBreakpoint(1,0x10000912c);
    (*pcVar4)();
  }
  local_2d8 = local_298;
  local_2d0 = local_280;
  local_300 = local_280;
  local_2f8 = local_298;
  local_a8 = local_298;
  local_a0 = local_280;
  pcVar7 = "hackallthethings";
  uVar9 = 0x10;
  _$sSS21_builtinStringLiteral17utf8CodeUnitCount7isASCIISSBp_BwBi1_tcfC("hackallthethings",0x10,1);
  local_2e8 = &local_b8;
  local_b8 = pcVar7;
  local_b0 = uVar9;
  _$sSS10FoundationE8EncodingV4utf8ACvgZ(puVar1);
  uVar9 = _$sSy10FoundationE4data5using20allowLossyConversionAA4DataVSgSSAAE8EncodingV_SbtFfA0_();
  uVar18 = (ulong)((uint)uVar9 & 1);
  puVar13 = puVar1;
  puVar21 = local_2a0;
  _$sSy10FoundationE4data5using20allowLossyConversionAA4DataVSgSSAAE8EncodingV_SbtF
            (puVar1,uVar18,puVar15);
  uVar20 = SUB84(puVar21,0);
  local_2f0 = puVar13;
  local_2e0 = uVar18;
  (*local_290)(puVar1,lVar6);
  _$sSSWOh((long)local_2e8);
  if ((local_2e0 & 0xf000000000000000) == 0xf000000000000000) {
    puVar3[-0x20] = 2;
    *(undefined8 *)(puVar3 + -0x18) = 0x20;
    *(undefined4 *)(puVar3 + -0x10) = 0;
    _$ss17_assertionFailure__4file4line5flagss5NeverOs12StaticStringV_A2HSus6UInt32VtF
              ("Fatal error",0xb,2,"Unexpectedly found nil while unwrapping an Optional value",0x39,
               2,"Captain_Nohook/ViewController.swift",0x23);
                    /* WARNING: Does not return */
    pcVar4 = (code *)SoftwareBreakpoint(1,0x100009248);
    (*pcVar4)();
  }
  local_310 = local_2f0;
  local_308 = local_2e0;
  local_330 = local_2e0;
  local_328 = local_2f0;
  local_c8 = local_2f0;
  local_c0 = local_2e0;
  uVar9 = _$s10Foundation4DataV13base64Encoded7optionsACSgSSh_So27NSDataBase64DecodingOptionsVtcfcfA 0_
                    ();
  pcVar7 = local_230;
  uVar18 = local_228;
  _$s10Foundation4DataV13base64Encoded7optionsACSgSSh_So27NSDataBase64DecodingOptionsVtcfC
            (local_230,local_228,uVar9);
  lVar6 = local_1e8;
  local_320 = pcVar7;
  local_318 = uVar18;
  if ((uVar18 & 0xf000000000000000) == 0xf000000000000000) {
    puVar3[-0x20] = 2;
    *(undefined8 *)(puVar3 + -0x18) = 0x21;
    *(undefined4 *)(puVar3 + -0x10) = 0;
    _$ss17_assertionFailure__4file4line5flagss5NeverOs12StaticStringV_A2HSus6UInt32VtF
              ("Fatal error",0xb,2,"Unexpectedly found nil while unwrapping an Optional value",0x39,
               2,"Captain_Nohook/ViewController.swift",0x23);
                    /* WARNING: Does not return */
    pcVar4 = (code *)SoftwareBreakpoint(1,0x1000092fc);
    (*pcVar4)();
  }
  uVar9 = 0;
  local_3a0 = uVar18;
  local_398 = pcVar7;
  local_340 = pcVar7;
  local_338 = uVar18;
  local_d8 = pcVar7;
  local_d0 = uVar18;
  _$s11CryptoSwift3AESCMa();
  puVar13 = local_2f8;
  local_390 = uVar9;
  _$s10Foundation4DataV11CryptoSwiftE5bytesSays5UInt8VGvg(local_2f8,local_300);
  puVar14 = local_328;
  uVar18 = local_330;
  local_360 = puVar13;
  _$s10Foundation4DataV11CryptoSwiftE5bytesSays5UInt8VGvg(local_328,local_330);
  local_388 = _$s11CryptoSwift3CBCV2ivACSays5UInt8VG_tcfC(puVar14);
  local_368 = local_100;
  local_e8 = &_$s11CryptoSwift3CBCVN;
  local_e0 = &_$s11CryptoSwift3CBCVAA9BlockModeAAWP;
  puVar15 = &DAT_10016d648;
  local_380 = uVar18;
  local_378 = puVar13;
  local_36c = uVar20;
  _swift_allocObject(&DAT_10016d648,0x29,7);
  *(undefined8 *)(puVar15 + 0x10) = local_388;
  *(ulong *)(puVar15 + 0x18) = local_380;
  *(undefined1 **)(puVar15 + 0x20) = local_378;
  puVar15[0x28] = (byte)local_36c & 1;
  local_100[0] = puVar15;
  local_3c0 = _$s11CryptoSwift3AESC3key9blockMode7paddingACSays5UInt8VG_AA05BlockF0_pAA7PaddingOtKcf C
                        (local_360,local_368,2);
  local_358 = lVar6;
  local_348 = lVar6;
  local_350 = local_3c0;
  if (lVar6 == 0) {
    pcVar7 = local_398;
    local_110 = local_3c0;
    _$s10Foundation4DataV11CryptoSwiftE5bytesSays5UInt8VGvg(local_398,local_3a0);
    local_3b8 = pcVar7;
    local_3e8 = _$s11CryptoSwift6CipherPAAE7decryptySays5UInt8VGAGKF
                          ((long)pcVar7,local_390,0x10016dd08);
    local_3a8 = lVar6;
    local_3b0 = local_3e8;
    _swift_bridgeObjectRelease(local_3b8);
    local_118 = local_3e8;
    _swift_bridgeObjectRetain();
    plVar16 = &local_120;
    local_120 = local_3e8;
    uVar18 = local_1f0;
    _$s10Foundation4DataVyACxcSTRzs5UInt8V7ElementRtzlufC(plVar16,local_1f0,local_248);
    local_3e0 = plVar16;
    local_3d8 = uVar18;
    _$sSS10FoundationE8EncodingV4utf8ACvgZ(puVar1);
    plVar16 = local_3e0;
    uVar18 = local_3d8;
    _$sSS10FoundationE4data8encodingSSSgAA4DataVh_SSAAE8EncodingVtcfC(local_3e0,local_3d8,puVar1);
    local_3d0 = plVar16;
    local_3c8 = uVar18;
    if (uVar18 == 0) {
      puVar3[-0x20] = 2;
      *(undefined8 *)(puVar3 + -0x18) = 0x27;
      *(undefined4 *)(puVar3 + -0x10) = 0;
      _$ss17_assertionFailure__4file4line5flagss5NeverOs12StaticStringV_A2HSus6UInt32VtF
                ("Fatal error",0xb,2,"Unexpectedly found nil while unwrapping an Optional value",
                 0x39,2,"Captain_Nohook/ViewController.swift",0x23);
                    /* WARNING: Does not return */
      pcVar4 = (code *)SoftwareBreakpoint(1,0x100009520);
      (*pcVar4)();
    }
    local_418 = plVar16;
    local_410 = uVar18;
    local_3f8 = plVar16;
    local_3f0 = uVar18;
    _$s10Foundation4DataV15_RepresentationOWOe(local_3e0,local_3d8);
    _swift_bridgeObjectRelease(local_3e8);
    _swift_release(local_3c0);
    _$s10Foundation4DataV15_RepresentationOWOe(local_398,local_3a0);
    _$s10Foundation4DataV15_RepresentationOWOe(local_328,local_330);
    _$s10Foundation4DataV15_RepresentationOWOe(local_2f8,local_300);
    _swift_bridgeObjectRelease(local_258);
    _swift_bridgeObjectRelease(local_210);
    _swift_bridgeObjectRelease(local_228);
    local_408 = local_418;
    local_400 = local_410;
  }
  else {
    local_438 = lVar6;
    local_430 = lVar6;
    _swift_errorRetain();
    local_108 = local_430;
    _swift_errorRelease();
    _swift_errorRelease(local_430);
    pcVar7 = "";
    uVar18 = 0;
    _$sSS21_builtinStringLiteral17utf8CodeUnitCount7isASCIISSBp_BwBi1_tcfC("",0,1);
    local_428 = (long *)pcVar7;
    local_420 = uVar18;
    _$s10Foundation4DataV15_RepresentationOWOe(local_398,local_3a0);
    _$s10Foundation4DataV15_RepresentationOWOe(local_328,local_330);
    _$s10Foundation4DataV15_RepresentationOWOe(local_2f8,local_300);
    _swift_bridgeObjectRelease(local_258);
    _swift_bridgeObjectRelease(local_210);
    _swift_bridgeObjectRelease(local_228);
    local_408 = local_428;
    local_400 = local_420;
  }
  auVar2._8_8_ = local_400;
  auVar2._0_8_ = local_408;
  return auVar2;
}
```



<br /><br />

This Frida script monitors changes to a specific `UILabel` in the `Captain_Nohook.ViewController` class. It first checks that the Objective-C runtime is available, then locates running instances of the target view controller. Using Key-Value Coding, it accesses the `UILabel` identified by the key `flag`. The script hooks the label’s `-setText:` method via an interceptor so that whenever the label’s text is updated, it logs the new value along with the label’s class name. This allows real-time observation of the flag as it appears in the app’s UI.

```javascript
console.log("Monitoring UILabel text changes in Captain Nohook...");

if (typeof ObjC === "undefined" || !ObjC.available) {
    throw new Error("Objective-C runtime is not available.");
}

ObjC.schedule(ObjC.mainQueue, function () {
    const vcClass = "Captain_Nohook.ViewController";

    // Find running instances of the target ViewController
    const instances = ObjC.chooseSync(ObjC.classes[vcClass]);
    if (instances.length === 0) {
        console.error("No ViewController instance found.");
        return;
    }

    const viewController = instances[0];
    console.log("ViewController instance found:", viewController);

    // Access the UILabel holding the flag using KVC
    const flagLabel = viewController.valueForKey_("flag");
    if (!flagLabel) {
        console.error("Could not access UILabel with key 'flag'.");
        return;
    }

    console.log("Monitoring UILabel:", flagLabel);

    // Hook UILabel's -setText: to detect changes
    const setTextImpl = ObjC.classes.UILabel["- setText:"].implementation;

    Interceptor.attach(setTextImpl, {
        onEnter: function (args) {
            const self = new ObjC.Object(args[0]);
            const newText = new ObjC.Object(args[2]).toString();

            // Only log if this is our target label
            if (self.isEqual_(flagLabel)) {
                console.log("UILabel text updated:");
                console.log("   Class:", self.$className);
                console.log("   New text:", newText);
            }
        }
    });

    console.log("Hook installed on UILabel -setText:");
});
```

output

```
Spawning `com.mobilehackinglab.Captain-Nohook.J8L462KYQ8`...            
Monitoring UILabel text changes in Captain Nohook...
Spawned `com.mobilehackinglab.Captain-Nohook.J8L462KYQ8`. Resuming main thread!
[iOS Device::com.mobilehackinglab.Captain-Nohook.J8L462KYQ8 ]-> ViewController instance found: <Captain_Nohook.ViewController: 0x10553fcb0>
Monitoring UILabel: <UILabel: 0x105541dd0; frame = (52 507; 288 46); text = ''; hidden = YES; opaque = NO; autoresize = RM+BM; userInteractionEnabled = NO; backgroundColor = UIExtendedGrayColorSpace 1 1; layer = <_UILabelLayer: 0x282952670>>
Hook installed on UILabel -setText:
[iOS Device::com.mobilehackinglab.Captain-Nohook.J8L462KYQ8 ]->
[iOS Device::com.mobilehackinglab.Captain-Nohook.J8L462KYQ8 ]-> UILabel text updated:
   Class: UILabel
   New text: MHL{H00k_1n_Y0ur_D3bUgg3r}
```

Note: Using this script, we were able to retrieve the flag; however, the app terminates immediately afterward.

<br /><br />



By combining the previous two Frida scripts, the application continues running without terminating the process. Additionally, a `UIAlert` was added so that when the flag is captured, it will be displayed in the alert whenever the user taps the button.

```javascript
var targetModule = 'Captain Nohook';
var addr = ptr(0xd6a8);
var newretval = ptr("0x1");
var moduleBase = Module.getBaseAddress(targetModule);
var targetAddress = moduleBase.add(addr);
   Interceptor.attach(targetAddress, {
        onEnter: function(args) {

        },
    	onLeave: function(retval) {  
    		retval.replace(newretval) 
    		console.log("\t[-] New Return Value: " + newretval) 
    	}
    
    });


// monitor_label_text_alert.js
console.log("Monitoring UILabel text changes in Captain Nohook...");

if (typeof ObjC === "undefined" || !ObjC.available) {
    throw new Error("Objective-C runtime is not available.");
}

ObjC.schedule(ObjC.mainQueue, function () {
    const vcClass = "Captain_Nohook.ViewController";

    // Find running instances of the target ViewController
    const instances = ObjC.chooseSync(ObjC.classes[vcClass]);
    if (instances.length === 0) {
        console.error("No ViewController instance found.");
        return;
    }

    const viewController = instances[0];
    console.log("ViewController instance found:", viewController);

    // Access the UILabel holding the flag using KVC
    const flagLabel = viewController.valueForKey_("flag");
    if (!flagLabel) {
        console.error("Could not access UILabel with key 'flag'.");
        return;
    }

    console.log("Monitoring UILabel:", flagLabel);

    // Hook UILabel's -setText: to detect changes
    const setTextImpl = ObjC.classes.UILabel["- setText:"].implementation;

    Interceptor.attach(setTextImpl, {
        onEnter: function (args) {
            const self = new ObjC.Object(args[0]);
            const newText = new ObjC.Object(args[2]).toString();

            // Only log if this is our target label
            if (self.isEqual_(flagLabel)) {
                console.log("UILabel text updated:");
                console.log("   Class:", self.$className);
                console.log("   New text:", newText);

                // Show alert with the flag
                ObjC.schedule(ObjC.mainQueue, function () {
                    try {
                        const UIAlertController = ObjC.classes.UIAlertController;
                        const UIAlertAction = ObjC.classes.UIAlertAction;

                        // Create alert
                        const alert = UIAlertController.alertControllerWithTitle_message_preferredStyle_(
                            "Flag Found",
                            newText,
                            1 // UIAlertControllerStyleAlert
                        );

                        // Create "OK" action
                        const okAction = UIAlertAction.actionWithTitle_style_handler_(
                            "OK",
                            0, // UIAlertActionStyleDefault
                            NULL
                        );

                        // Add action to alert
                        alert.addAction_(okAction);

                        // Present alert from ViewController
                        viewController.presentViewController_animated_completion_(alert, true, NULL);

                        console.log("Alert displayed with flag:", newText);
                    } catch (e) {
                        console.error("Error displaying alert:", e);
                    }
                });
            }
        }
    });

    console.log("Hook installed on UILabel -setText:");
});
```

output

```
Spawned `com.mobilehackinglab.Captain-Nohook.J8L462KYQ8`. Resuming main thread!
[iOS Device::com.mobilehackinglab.Captain-Nohook.J8L462KYQ8 ]-> ViewController instance found: <Captain_Nohook.ViewController: 0x1007150d0>
Monitoring UILabel: <UILabel: 0x100717b80; frame = (52 507; 288 46); text = ''; hidden = YES; opaque = NO; autoresize = RM+BM; userInteractionEnabled = NO; backgroundColor = UIExtendedGrayColorSpace 1 1; layer = <_UILabelLayer: 0x281037b60>>
Hook installed on UILabel -setText:
[iOS Device::com.mobilehackinglab.Captain-Nohook.J8L462KYQ8 ]->
[iOS Device::com.mobilehackinglab.Captain-Nohook.J8L462KYQ8 ]->         [-] New Return Value: 0x1
UILabel text updated:
   Class: UILabel
   New text: MHL{H00k_1n_Y0ur_D3bUgg3r}

Alert displayed with flag: MHL{H00k_1n_Y0ur_D3bUgg3r}
```



<br />

![](/assets/img/mhl/CaptainNoHook/4.jpg)





<br />

Dump the memory and get the flag with Objection

```
└─# objection -g com.mobilehackinglab.Captain-Nohook.J8L462KYQ8 explore  
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
...glab.Captain-Nohook.J8L462KYQ8 on (iPhone: 16.0) [usb] # memory search MHL{ --string
Searching for: 4d 48 4c 7b
28209c421  4d 48 4c 7b 48 30 30 6b 5f 31 6e 5f 59 30 75 72  MHL{H00k_1n_Y0ur
28209c431  5f 44 33 62 55 67 67 33 72 7d 0a 00 00 00 00 03  _D3bUgg3r}......
28209c441  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 d1  ................
283bf8220  4d 48 4c 7b 48 30 30 6b 5f 31 6e 5f 59 30 75 72  MHL{H00k_1n_Y0ur
283bf8230  5f 44 33 62 55 67 67 33 72 7d 0a 00 cf ed f3 eb  _D3bUgg3r}......
283bf8240  07 00 00 00 00 00 00 00 f8 8e 46 21 02 00 00 00  ..........F!....
Pattern matched at 2 addresses
...glab.Captain-Nohook.J8L462KYQ8 on (iPhone: 16.0) [usb] # 
```

**Flag:** MHL{H00k_1n_Y0ur_D3bUgg3r}

