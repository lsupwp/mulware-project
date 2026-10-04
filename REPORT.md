# Malware Analysis Report — DarkComet RAT v5 (Persistence Deep-Dive)

## 0. ข้อมูลตัวอย่าง (Sample)

| รายการ | ค่า |
|---|---|
| ไฟล์ | `b9b052dfb2f19bf15aaba81f07861234f91a72a5c38d83c176a7a4dcdbb2e8c1.exe` |
| MD5 | `ef5fb48c0f5d26272002fb779dec0c47` |
| SHA1 | `9aa83c470353c448750b5cee34a1a7034a76d3c4` |
| SHA256 | `b9b052dfb2f19bf15aaba81f07861234f91a72a5c38d83c176a7a4dcdbb2e8c1` |
| ประเภท | PE32 executable (Windows GUI), Intel i386, 9 sections |
| ขนาด | 762,880 bytes (≈745 KB) |
| Compilation Timestamp | 2012-01-15 16:49:40 UTC (น่าจะปลอม) |
| Packer/Obfuscation | ไม่พบ packer (Delphi/Borland, entropy `.text` ≈ 6.55) |
| ภาษา | Delphi / Object Pascal (native, ไม่ใช่ .NET) |
| ตระกูล | **DarkComet RAT v5** (RC4 key `#KCMDDC5#-890`) |
| Campaign | `Guest16` |
| Version info ปลอม | `Remote Service Application` / `Microsoft Corp.` / `MSRSAAP.EXE` |

---

## 1. Persistence — กลไกที่สร้าง

มัลแวร์สร้าง persistence หลายชั้น ทั้งตอนติดตั้งอัตโนมัติ (`entry`) และเมื่อได้รับคำสั่งจาก C2

| # | กลไก | Registry / Path | ค่า | Function | API ที่ใช้ |
|---|---|---|---|---|---|
| 1 | **Run key (HKCU)** ✓active | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | value `F168Service` = `<install>\f168pro.exe` | `FUN_00481410` | `RegOpenKeyA`(`0x80000001`=HKCU) + `RegSetValueExA` |
| 2 | **Winlogon Userinit** ✓active | `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` | `Userinit` = `<ของเดิม>,<install path>` | `FUN_00481508` | `RegOpenKeyExA`(`0x80000002`=HKLM) + `RegQueryValueExA` + `RegSetValueExA` |
| 3 | **Service (auto-start)** on-demand | `HKLM\System\CurrentControlSet\Services\<name>` | Binary = ตัวเอง, `dwStartType=2` (AUTO_START), type `0x110`; เพิ่ม `Description` | `FUN_00473bb4`, `FUN_00473608` | `OpenSCManagerA(0xf003f)` + `CreateServiceA` |
| 4 | **Startup shortcut** on-demand | `...\Start Menu\Programs\Startup\<name>.lnk` | `.lnk` ชี้ไปไฟล์ exe | คำสั่ง `%ShortCut#` ใน `FUN_0047440c` | `IShellLink` / `SHGetFolderPathA` |
| 5 | **Run key (HKLM)** on-demand | `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | value `F168Service` | `FUN_00481280` (generic) / คำสั่ง `InstallHKEY` | `RegSetValueExA` (ไม่ได้ทำใน build นี้) |
| 6 | **Marker (ไม่ใช่ persist โดยตรง)** | `HKCU\Software\DC2_USERS`, `HKCU\Software\DC3_FEXEC` | campaign / จำนวนครั้งที่รัน | `FUN_004884f8`, `FUN_00488614`, `FUN_00489254`, `FUN_004893a4` | `RegCreateKeyExA` + `RegSetValueExA` |

**เงื่อนไขการเปิดใช้:** `INSTALL=1` (ติดตั้ง), `PERSINST=1` (persist), `KEYNAME=F168Service`
หาก `PERSINST` ถูกตั้ง มัลแวร์จะสร้าง thread เฝ้าคงอยู่ (`CreateThread → LAB_0048b92c`)

### ลำดับการสร้าง persistence ตอนรัน (`entry` @ `0x48c87c`)

```
 1. FUN_004817cc(COMBOPATH, EDTPATH)   -> สร้าง install path (Documents\F168Pro\f168pro.exe)
 2. FUN_00472eb0()                     -> เช็คว่ารันจาก path ที่ติดตั้งแล้วหรือยัง
    ถ้ายัง (first run):
 3. FUN_004893a4(...)                  -> เขียน DC3_FEXEC (exec marker)
 4. Set INSTALL = "1"
 5. GetModuleFileNameA + CopyFileA     -> copy ตัวเองไป target
 6. FUN_00481410(KEYNAME, path)        -> persist: HKCU\...\Run\F168Service
 7. FUN_00481508(path)                 -> persist: Winlogon\Userinit += ,path
 8. FUN_00489608(path, EDTDATE)        -> timestomp ไฟล์
 9. Set FILEATTRIB / DIRATTRIB         -> hidden + system
10. MessageBoxA (FAKEMSG)              -> หลอกผู้ใช้ด้วย error ปลอม
11. attrib +s +h ; CHIDEF / CHIDED
12. PERSINST -> CreateThread(LAB_0048b92c)  -> thread เฝ้าคงอยู่
13. CreateMutexA(mutex = f168pro_mutex); ถ้ามีอยู่ (0xB7) -> ExitProcess(0)
14. FUN_0047d2f8() -> เข้า loop ต่อ C2
```

---

## 2. Stealth ของ Persistence

| Function | การทำงาน |
|---|---|
| `FUN_00468090` | **CleanMsConfig** — ลบ/เคลียร์รายการใน `HKLM\SOFTWARE\Microsoft\Shared Tools\MSConfig\startupreg` + `startupfolder` (เรียกโดยคำสั่ง C2 `CleanMsConfig`; `FUN_00421a84` ใช้ `RegEnumKeyExA`+`RegDeleteKeyA`/`RegDeleteValueA`) |
| `FUN_004677e8` | enumerate startup list (Run + MSConfig) |
| `FUN_00489608` | timestomp ไฟล์เป็น `EDTDATE` = `15/06/2024` |
| `attrib "..." +s +h` | ตั้ง attribute hidden + system ให้ไฟล์ exe (`DIRATTRIB=2`, `FILEATTRIB=6`) |

---

## 3. สิทธิ์ (Privileges) ที่ร้องขอ

| สิทธิ์ | Function | วิธีร้องขอ | ใช้ทำอะไร |
|---|---|---|---|
| `SeShutdownPrivilege` | `FUN_00487650` | `OpenProcessToken(GetCurrentProcess(), 0x28 = TOKEN_ADJUST_PRIVILEGES \| TOKEN_QUERY)` + `LookupPrivilegeValueA` + `AdjustTokenPrivileges` → `ExitWindowsEx` | shutdown / reboot / logoff / poweroff |
| **privilege ใดก็ได้** (คำสั่ง `GetPrivilege`) | `FUN_0047440c` (dispatcher) | `LookupPrivilegeValueA` + `AdjustTokenPrivileges` | เช่น `SeDebugPrivilege` (inject process), `SeTakeOwnership`, ฯลฯ |
| `SC_MANAGER_ALL_ACCESS` (`0xf003f`) | `FUN_00473bb4` | `OpenSCManagerA(NULL, NULL, 0xf003f)` | ติดตั้งและควบคุม service |
| `SERVICE_ALL_ACCESS` (`0xf01ff`) | `FUN_00473bb4` | `CreateServiceA(..., 0xf01ff, ...)` | สร้าง service แบบ auto-start |
| Registry write | `FUN_00481410` (HKCU Run), `FUN_00481508` (HKLM Winlogon) | `RegSetValueExA` | เขียน Run (user) / Winlogon (machine) |
| Process access | `OpenProcess` / `OpenProcessToken` / `OpenThreadToken` | `OpenProcessToken` | ฉีดโค้ด / เข้าถึง process |

**จุดสำคัญ:** Winlogon + Services อยู่บน `HKLM` และ `OpenSCManagerA` แบบ ALL_ACCESS จึงต้องใช้สิทธิ์ **Administrator** (ส่วน Run key เป็น `HKCU` ไม่ต้อง admin).
มัลแวร์มีคำสั่ง `RunSelectedAsAdmin` เพื่อยกระดับสิทธิ์ และมี FWB (ปิด firewall) ซึ่งก็ต้องใช้ admin เช่นกัน

---

## 4. สิ่งที่ทำได้หลังได้สิทธิ์

| ความสามารถ | Function / Module |
|---|---|
| เขียน/ลบ registry ทั้งระบบ | `UntRegEdit` (`FUN_00481280`) |
| ติดตั้ง/ลบ/สตาร์ท service | `UntServices` (`FUN_00473bb4`, `FUN_00473608`) |
| ปิด Firewall + แจ้งเตือน AV (FWB) | `UntFWB` (`FirewallPolicy\EnableFirewall`, `AntiVirusDisableNotify`) |
| แก้ไฟล์ `drivers\etc\hosts` | `GetHostsFile` |
| shutdown / reboot / logoff | `FUN_00487650` + `ExitWindowsEx` |
| ฉีดเข้า process / ขโมยข้อมูล | `UntProcess`, `UntPasswordAndData` (ต้อง `SeDebugPrivilege` ผ่าน `GetPrivilege`) |
| keylogger (global hook) | `FUN_0047f98c` — `SetWindowsHookExA(WH_KEYBOARD_LL)` |
| เพิ่ม/ซ่อน startup | `FUN_00468090` (ลบจาก msconfig) |

---

## 5. การลบ Persistence (Uninstall)

`FUN_00473dfc`:

- `FUN_00467fb4("HKCU", <Run>, KEYNAME)` → ลบ `HKCU\...\Run\F168Service`
- `FUN_00481698()` → ลบ path ตัวเองออกจาก Winlogon `Userinit` (StringReplace)
- ปิด socket (`closesocket`), ระบุ PID (`GetCurrentProcessId` + `FUN_004837f4`)
- self-delete: `ping 127.0.0.1 -n 5 > NUL && del "<self>"`
- ถ้า `MELT=1` → ลบไฟล์ต้นฉบับ

---

## 6. ไฟล์/โฟลเดอร์ที่สร้าง (Artifacts)

| Artifact | Path เต็ม | หมายเหตุ |
|---|---|---|
| ไฟล์มัลแวร์ | `C:\Users\<user>\Documents\F168Pro\f168pro.exe` | จาก `COMBOPATH=7` (CSIDL_PERSONAL) |
| keylog (offline) | `C:\Users\<user>\AppData\Local\Temp\dclogs\` | สร้างจาก `GetTempPathA` + `dclogs\` (ยืนยันจาก `FUN_0047ec24`, `FUN_0047f98c`) |
| plugin | `C:\Users\<user>\AppData\Local\Temp\DCPlugs\` | **สร้าง on-demand** เมื่อได้คำสั่ง `%PLUG` จาก C2 |
| ไฟล์อัปเดต/ดาวน์โหลด | `%TEMP%\__tmp.exe` | จาก `#BOT#URLUpdate` / `URLDownload` |
| งานพิมพ์ | `%TEMP%\tmpprint.txt` | ฟีเจอร์ `PrintText` |
| helper สแกนพอร์ต | `lstports.dll`, `out.txt`, `tmp.txt` | ฟีเจอร์ `GetActivePorts` (`netstat -a -n -o`) |
| แก้ hosts | `%windir%\System32\drivers\etc\hosts` | บล็อก AV/update |
| shortcut | `...\Start Menu\Programs\Startup\<name>.lnk` | persist |

---

## 7. Indicators of Compromise (IOCs)

**ค่า config จริง (resource `NETDATA`, ถอดด้วย RC4 `#KCMDDC5#-890`):**

```
f168.name:1604
f168.com.co:1604
f168hi.com:1604
```

- DNS override (จาก `PDNS`): `8.8.8.8`
- ค่า default ที่ฝังในโค้ด: `127.0.0.1:1604` (ใช้เฉพาะกรณี resource `NETDATA` ว่าง)
- การเชื่อมต่อ: `FUN_00483d5c` — `socket` → `htons` → `inet_addr`/`gethostbyname` → `connect` (`0x483f0f`) → `recv` → RC4 (`FUN_0046153c`) → dispatch (`FUN_0047440c`)
- การ rotate โดเมน: re-parse `NETDATA` แล้วเลือกตัวถัดไป (`Sleep(1000)` + `closesocket`)
- IP ปัจจุบันที่ resolve: Cloudflare edge (`104.21.*`, `172.67.*`) — ไม่ใช่ origin

**IOC:**

### File Hashes
| Hash | ค่า |
|---|---|
| MD5 | `ef5fb48c0f5d26272002fb779dec0c47` |
| SHA1 | `9aa83c470353c448750b5cee34a1a7034a76d3c4` |
| SHA256 | `b9b052dfb2f19bf15aaba81f07861234f91a72a5c38d83c176a7a4dcdbb2e8c1` |

### Network
| ประเภท | ค่า |
|---|---|
| IP Address | **ไม่พบ IP ในไฟล์** (C2 เป็น domain ไม่ใช่ IP); default ในโค้ด = `127.0.0.1:1604` |
| C2 Domain | `f168.name`, `f168.com.co`, `f168hi.com` |
| C2 Port | `1604` (default ตระกูล DarkComet) |
| DNS override | `8.8.8.8` (จาก `PDNS`) |
| Protocol | raw TCP socket (C2) + wininet HTTP/FTP (`URLDownloadToFileA`, `InternetOpenA`/`InternetConnectA`/`InternetOpenUrlA`, `FtpPutFileA`) ตามคำสั่ง |
| URL | ไม่ hardcode; โหลดผ่านคำสั่ง `URLUpdate`/`URLDownload` (`URLDownloadToFileA`) |
| User-Agent | ไม่ตั้งเอง (ใช้ค่า default ของ wininet) |
| FTP | `FtpPutFileA` (exfil เมื่อ operator ตั้งค่า) |
| Resolved (ปัจจุบัน) | Cloudflare edge (`104.21.*`, `172.67.*`) — ไม่ใช่ origin |
| Note | ไม่มี `146.19.49.35` / `33474` ในไฟล์นี้ |

### Host-based
| ประเภท | ค่า |
|---|---|
| Mutex | `f168pro_mutex` |
| Registry — persistence | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\F168Service` |
| Registry — persistence | `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` (value `Userinit`) |
| Registry — marker | `HKCU\Software\DC2_USERS`, `HKCU\Software\DC3_FEXEC` |
| Service name | `F168Service` |
| File — malware | `C:\Users\<user>\Documents\F168Pro\f168pro.exe` |
| File — keylog | `C:\Users\<user>\AppData\Local\Temp\dclogs\` |
| File — plugin | `C:\Users\<user>\AppData\Local\Temp\DCPlugs\` |
| File — dropper | `%TEMP%\__tmp.exe` |
| File — hosts | `%windir%\System32\drivers\etc\hosts` (แก้ไข) |
| Campaign ID | `Guest16` |
| Password | `f168pro` |
| RC4 key | `#KCMDDC5#-890` |
| Family | DarkComet RAT v5 (aka DarkComet FWB) |

---

## 8. บทสรุป

- Persistence **ที่ active จริงใน build นี้ = 2 กลไก**: `HKCU\...\Run\F168Service` และ `HKLM\...\Winlogon\Userinit` (ตรงกับที่พบใน registry จริง)
- กลไกอื่น (**Service auto-start**, **Startup `.lnk`**, **HKLM Run**, **Fake Uninstall key**) = ความสามารถที่โค้ดมี แต่ทำงานเมื่อ operator สั่งเท่านั้น (on-demand) ไม่ได้สร้างอัตโนมัติ
- MSConfig (`FUN_00468090`, คำสั่ง `CleanMsConfig`) = ลบ/เคลียร์รายการ startup (ไม่ใช่สร้าง persist)
- สิทธิ์ที่ร้องขอ: `SeShutdownPrivilege` (ตายตัว) + `GetPrivilege` (ขอ privilege ใดก็ได้) + Winlogon/Services ต้องเป็น **Administrator** (Run key เป็น HKCU ไม่ต้อง)
- ลบ persistence เองได้ผ่านคำสั่ง Uninstall (`FUN_00473dfc`) + self-delete

> หมายเหตุความปลอดภัย: ห้ามรันบนเครื่องจริงหรือเครื่องที่ต่ออินเทอร์เน็ตจริง ใช้ VM ที่แยกเครือข่ายและ snapshot เท่านั้น
