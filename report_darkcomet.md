# DarkComet RAT v5 — วิเคราะห์ไบนารี

## 1. ข้อมูลไฟล์

| หัวข้อ | ค่า |
|---|---|
| SHA-256 | `b9b052dfb2f19bf15aaba81f07861234f91a72a5c38d83c176a7a4dcdbb2e8c1` |
| ชนิด | PE32 GUI, Intel i386, 9 sections |
| คอมไพเลอร์ | Delphi/Borland (VCL, FastMM, `RUntRC4`) |
| Packed | ไม่ (entropy ~6.5, imports ครบ) |
| TimeDateStamp | 2012-01-15 16:49:40 (ปลอม) |
| Version info | `Remote Service Application` / `Microsoft Corp.` / `MSRSAAP.EXE` (ปลอม) |
| EntryPoint | RVA `0x8c87c` (`.itext`) |
| TLS callback | มี (VA `0x4a0010`) |
| Family | **DarkComet RAT v5** (RC4 key `#KCMDDC5#-890`) |
| Campaign | `Guest16` |

หลักฐาน family: string `#KCMDDC5#-`, `DC2_USERS`, `DC3_FEXEC`, `#BOT#`, `clWebSeashell`, `TServerReaderSV`, unit `UntServerReader`.

## 2. Config ถอดได้ (RT_RCDATA + RC4)

วิธี: อ่าน resource → ASCII-hex → unhex → RC4 key `#KCMDDC5#-890`

| Field | ค่า |
|---|---|
| SID (campaign) | `Guest16` |
| PWD | `f168pro` |
| MUTEX | `f168pro_mutex` |
| KEYNAME | `F168Service` |
| EDTPATH | `F168Pro\f168pro.exe` |
| EDTDATE | `15/06/2024` |
| GENCODE | `sp%dJ1*aBGM2` |
| OFFLINEK | `1` |
| NETDATA (C2) | `f168.name:1604` \| `f168.com.co:1604` \| `f168hi.com :1604` |
| PDNS | `f168.name:8.8.8.8` \| `f168.com.co:8.8.8.8` \| `f168hi.com:8.8.8.8` |
| INSTALL/MELT/PERSINST/FWB/SH3/SH4 | `1` |
| CHANGEDATE/CHIDED/CHIDEF | `1` |
| COMBOPATH | `7` |
| DIRATTRIB | `2` |
| FILEATTRIB | `6` |

RC4 key เต็มประกอบ runtime: `#KCMDDC5#-` + `890` (offset +8 ของ config object)

## 3. Function → พฤติกรรม (Ghidra)

| ที่อยู่ | ชื่อเดา | ทำอะไร |
|---|---|---|
| `0048c87c` | `entry` | Delphi entry: RTL init, `CoInitialize`, โหลด/ถอด config, ติดตั้ง+persist, โชว์ fake msg, สตาร์ท thread, mutex, เข้า GUI loop |
| `0048b548` | `DecodeSetting` | อ่าน resource ตามชื่อ + RC4 (`#KCMDDC5#-`+pwd) → config |
| `0046153c` | `RC4/Crypt` | ถอด/เข้ารหัส packet + config |
| `0048b490` | `ConfigObj.New` | สร้าง object เก็บ config |
| `004882e8` | `EarlyInit` | init ช่วงต้น/anti-analysis |
| `004817cc` | `BuildInstallPath` | ต่อ COMBOPATH + EDTPATH |
| `00481410` | `PersistRun` | `HKLM\...\CurrentVersion\Run` → value `F168Service` = path |
| `00481280` | `RegSetVal` | เขียน registry (HKLM/HKCU ตาม arg) |
| `00473dfc` | `Uninstall/SelfDestruct` | ลบ Run key, ปิด socket, `ping -n 5 && del "<self>"`, exit |
| `004677e8` | `EnumRunKey` | อ่าน/ล้าง startup (msconfig) |
| `004884f8`/`00488614` | `DC2_USERS get/set` | `HKLM\Software\DC2_USERS` — marker ติดเชื้อ + campaign |
| `00489254`/`004893a4` | `DC3_FEXEC get/set` | `HKLM\Software\DC3_FEXEC` — จำนวนครั้งรัน |
| `00487650` | `Shutdown` | `SeShutdownPrivilege` + `ExitWindowsEx` |
| `0048747c` | `SetWallpaper` | `SystemParametersInfo` + HKCU Wallpaper |
| `00486464` | `RunCmd` | `ShellExecute cmd.exe` / `taskmgr.exe` |
| `00465414`/`004873e8` | `ShellCmd` | `ShellExecuteA cmd.exe <params>` (remote shell) |
| `0047d2f8` | `MainServerInit` | สร้าง thread, message loop หลัก |
| `00483d5c` | `C2ConnectLoop` | `socket/connect` C2, `recv`, decrypt, dispatch |
| `0047d994` | `DataFluxLoop` | ส่ง `UPFLUX` conn สำรอง |
| `004741b4`/`0047424c` | `SendEncrypted` | เข้ารหัสแล้ว `send` |
| `0047440c` | `CommandDispatcher` | switch คำสั่งขนาดยักษ์ (decompile ไม่ผ่าน — ใหญ่เกิน) |
| `0040ffa4` | `URLDownloadWrapper` | `URLDownloadToFileA` |
| `0040849c` | `KeyHook` | `SetWindowsHookExA` (keylogger) |
| `0045f638` | `MicCapture` | `waveInOpen` |
| `0048a16c` | `WebcamEnum` | `capGetDriverDescriptionA` |
| `0045f70c` | `ScreenCapture` | `GdipCreateBitmapFromHBITMAP` |
| `0042fa24`/`0042fa3c` | `Ftp/Http` | `FtpPutFileA`, `InternetOpenA` (exfil) |
| `004667b4` | `NetShareEnum` | list share |
| `00460910` | `InstallService` | `CreateServiceA` |

## 4. Module map (จาก PACKAGEINFO)

| Unit | หน้าที่ |
|---|---|
| UntMain / UntCore / UntMainConnectionThread | แกนหลัก / C2 |
| UntServerReader / TServerReaderSV | อ่าน packet |
| UntRemoteShell | remote shell |
| UntKeylogger | keylogger online/offline |
| UntScreenCapture / UntScreenThumb / UntRemoteDesktop | จอภาพ |
| UntCaptureWebcam / UntWebCam / UntResizePic | กล้อง |
| UntSound / ACMConvertor | ไมค์/เสียง |
| UntPluginsData / DLLMemory | โหลด plugin DLL ในหน่วยความจำ |
| UntSendFileThread / UntReceiveFileThread / TSendFileThreadU | ไฟล์ขึ้น/ลง |
| UntFTP | exfil FTP |
| UntUDPFlood / UntSynFlood / UntHTTPFlood | DDoS |
| UntScanPorts / UntRPCScan | สแกนพอร์ต/RPC |
| UntActivePorts / UntNetShareLister | recon |
| UntRegEdit / UntMsConfig / untstartup / UntServices | registry/persist/service |
| UntWindowManager / UntInputsControls / UntControlKey | คุม UI / บล็อก input |
| UntMClipboard / UntMSN | clipboard / MSN |
| UntAntiSB | anti-sandbox |
| RUntRC4 / GMD5Api / MD5Core / CryptApi | crypto |
| UntSocks5 | proxy |
| UntBot | bot (`#BOT#`) |
| UntInfections | แพร่ทาง removable drive |
| UntProcess / UntPasswordAndData / UntRootKit | process / ขโมยรหัส / ซ่อนตัว |

## 5. ลำดับการทำงานตั้งแต่กดรัน

1. `entry` → Delphi RTL init + `CoInitialize(0)` + TLS callback.
2. เปิด config object, อ่านทุก field (SID, MUTEX, NETDATA, EDTPATH, PERSINST, FTP, ...) → `DecodeSetting` + RC4 `#KCMDDC5#-890` ถอด.
3. ตั้ง default ถ้าว่าง: SID=`Guest`, MUTEX=`TMPMUTEX`.
4. `CreateMutex(f168pro_mutex)`; ถ้า mutex มีอยู่ (`ERROR_ALREADY_EXISTS=0xB7`) → `ExitProcess(0)` (instance เดียว).
5. เช็คว่ารันจาก install path `F168Pro\f168pro.exe` หรือยัง (`FUN_00472eb0`). ถ้ายัง:
   - `GetModuleFileName` เอาตัวเอง → `CopyFileA` ไป target.
   - ตั้ง attribute (hidden/system), timestomp ไฟล์เป็น `EDTDATE` = 15/06/2024.
   - `PersistRun`: `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` ค่า `F168Service` = path.
   - (เลือกได้) ติดตั้งเป็น service (`CreateServiceA`).
   - โชว์ `MessageBoxA` หลอก (FAKEMSG/MSGTITLE/MSGCORE/MSGICON).
   - รัน `cmd /c attrib +s +h <file>` ซ่อนไฟล์.
   - ถ้า MELT=1: self-delete ผ่าน `ping 127.0.0.1 -n 5 > NUL && del "<self>"`.
6. ติด marker ลง `HKLM\Software\DC2_USERS` + `DC3_FEXEC`.
7. สตาร์ท thread เฝ้า/คงอยู่ (PERSINST).
8. `MainServerInit` → สร้าง thread + message loop.
9. `C2ConnectLoop`: parse `NETDATA` → host:port (`f168.name:1604`, `f168.com.co:1604`, `f168hi.com:1604`), DNS override `8.8.8.8` (PDNS); `socket→connect`; `recv`; RC4 ถอดด้วย key+pwd; ส่งเข้า `CommandDispatcher`.
10. `CommandDispatcher` ทำงานตามคำสั่ง: remote shell (`cmd.exe`), file manager (up/down/del/attrib), keylogger online/offline, จอภาพ, กล้อง, ไมค์, clipboard, process list/kill, registry, service, shutdown/reboot/logoff, DDoS (HTTP/SYN/UDP), port scan, RPC scan, LAN share, SOCKS5, URL download/update, plugin, uninstall, fake message, ซ่อน taskbar/desktop, บล็อก input, MSN.
11. เมื่อสั่ง uninstall/close → `Uninstall`: ลบ Run key, ปิด socket, ลบไฟล์ตัวเอง, ออก.

## 6. IOC

- C2: `f168.name:1604`, `f168.com.co:1604`, `f168hi.com:1604`
- DNS: `8.8.8.8`
- Mutex: `f168pro_mutex`
- Registry: `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\F168Service`; `HKLM\Software\DC2_USERS`; `HKLM\Software\DC3_FEXEC`
- Files: `F168Pro\f168pro.exe`
- Campaign: `Guest16`; Password: `f168pro`
- RC4 key: `#KCMDDC5#-890`
