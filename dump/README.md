# dump/ — DarkComet RAT v5 static-analysis artifacts

Sample: `b9b052dfb2f19bf15aaba81f07861234f91a72a5c38d83c176a7a4dcdbb2e8c1.exe`
SHA256: `b9b052dfb2f19bf15aaba81f07861234f91a72a5c38d83c176a7a4dcdbb2e8c1`
Family: DarkComet RAT v5 (Delphi, RC4 key `#KCMDDC5#-890`)

## โครงสร้าง

```
dump/
├── README.md
├── decompiled/
│   ├── decompiled_all.c      # Ghidra decompile ทุกฟังก์ชัน (~3167 ฟังก์ชัน)
│   └── functions_index.txt   # VA / ชื่อ / ขนาด ทุกฟังก์ชัน
├── resources/
│   ├── resources_index.txt   # ตาราง resource (type/name/lang/size/offset)
│   ├── RT_ICON__*.bin        # ไอคอน
│   ├── RT_ICONGROUP__*.bin   # กลุ่มไอคอน
│   ├── RT_STRING__*.bin      # string table
│   ├── RT_RCDATA__*.bin      # config (hex) + *.decoded.txt (ถอด RC4 แล้ว)
│   ├── RT_GROUP_CURSOR__*.bin
│   ├── RT_GROUP_ICON__*.bin
│   └── RT_VERSION__*.bin     # version info (ปลอมเป็น Microsoft)
└── raw/
    ├── disasm.asm            # objdump disassembly ทั้งไฟล์ (Intel syntax)
    ├── strings_ascii.txt     # ASCII strings (len >= 5)
    ├── strings_utf16le.txt   # UTF-16LE strings
    ├── pe_info.txt           # rabin2 -I/-S/-i/-E/-e
    ├── config_decoded.txt    # config ที่ถอด RC4 แล้ว
    ├── packageinfo_units.txt # รายชื่อ Delphi unit (จาก PACKAGEINFO)
    ├── version_info.txt      # PE version resource
    └── dos_header.hex        # DOS header / stub
```

## หมายเหตุ
- `decompiled_all.c` รวมทุกฟังก์ชัน ค้นหาด้วย `// ==================== <addr>  <name>` หรือใช้ `functions_index.txt`.
- **decompile ครบ 3166/3167 ฟังก์ชัน**. ตัวที่ไม่ผ่าน = `FUN_0047440c` (command dispatcher, size=29568) ซึ่งมี `// <decompile failed>` — ใช้ `raw/disasm.asm` (ช่วง VA `0x47440c`–`0x47b78c`) แทน.
- config ใน `RT_RCDATA__*` ถอดด้วย RC4 key `#KCMDDC5#-890`.
- `raw/disasm.asm` = disassembly ทั้งไฟล์ (Intel syntax) จาก objdump.
- อย่ารันไบนารี; dump นี้เป็น static เท่านั้น.
