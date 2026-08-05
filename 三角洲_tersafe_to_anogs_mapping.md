# Tersafe → Anogs 偏移映射文档

> 基于两个 `.so` 文件的 IDA 伪 C 代码分析得出
> 分析日期: 2026-08-05

---

## 目录

1. [20 项函数表映射 (Hash/CRC 表)](#1-20-项函数表映射-hashcrc-表)
2. [VTable 初始化函数映射](#2-vtable-初始化函数映射)
3. [独立函数映射](#3-独立函数映射)
4. [特殊地址说明](#4-特殊地址说明)
5. [附录：函数体对比](#5-附录函数体对比)

---

## 1. 20 项函数表映射 (Hash/CRC 表)

这是一个包含 20 个函数指针的表，用于 CRC/Hash 计算。

| 索引 | tersafe 偏移 | tersafe 函数 | anogs 偏移 | anogs 函数 |
|:---:|:---:|:---:|:---:|:---:|
| 0 | 0x2AA3B0 | sub_2AA3B0 | 0x29F7D0 | sub_29F7D0 |
| 1 | 0x2AA44C | sub_2AA44C | 0x29F84C | sub_29F84C |
| **2** | **0x2AA4CC** | **sub_2AA4CC** | **0x29F8CC** | **sub_29F8CC** |
| **3** | **0x2AA4F8** | **sub_2AA4F8** | **0x29F8F8** | **sub_29F8F8** |
| 4 | 0x2AA524 | sub_2AA524 | 0x29F924 | sub_29F924 |
| 5 | 0x2AA5B4 | sub_2AA5B4 | 0x29F9B4 | sub_29F9B4 |
| **6** | **0x2AA654** | **sub_2AA654** | **0x29FA44** | **sub_29FA44** |
| **7** | **0x2AA680** | **sub_2AA680** | **0x29FA70** | **sub_29FA70** |
| 8 | 0x2AA6AC | sub_2AA6AC | 0x29FA9C | sub_29FA9C |
| 9 | 0x2AA72C | sub_2AA72C | 0x29FB2C | sub_29FB2C |
| 10 | 0x2AA7CC | sub_2AA7CC | 0x29FBBC | sub_29FBBC |
| 11 | 0x2AA85C | sub_2AA85C | 0x29FC5C | sub_29FC5C |
| **12** | **0x2AA8EC** | **sub_2AA8EC** | **0x29FCEC** | **sub_29FCEC** |
| **13** | **0x2AA918** | **sub_2AA918** | **0x29FD18** | **sub_29FD18** |
| 14 | 0x2AA944 | sub_2AA944 | 0x29FD44 | sub_29FD44 |
| 15 | 0x2AA9C4 | sub_2AA9C4 | 0x29FDC4 | sub_29FDC4 |
| **16** | **0x2AAA44** | **sub_2AAA44** | **0x29FE54** | **sub_29FE54** |
| **17** | **0x2AAA70** | **sub_2AAA70** | **0x29FE80** | **sub_29FE80** |
| 18 | 0x2AAA9C | sub_2AAA9C | 0x29FEAC | sub_29FEAC |
| 19 | 0x2AAB3C | sub_2AAB3C | 0x29FF2C | sub_29FF2C |

**说明：**
- 表中 `tersafe` 的 `off_5151D8[20]` 对应 `anogs` 的 `off_507910[20]`
- **加粗**的行是用户提供的偏移
- 函数功能：CRC-like hash 计算，接受 `(buffer, length, init_value, table)` 参数

---

## 2. VTable 初始化函数映射

### 2.1 基本信息

| 属性 | tersafe | anogs |
|:---|:---:|:---:|
| 初始化函数 | `sub_326E28` | `sub_3D1AAC` |
| 分配大小 | 0x320 字节 | 0x320 字节 |
| 分配函数 | sub_5081C0 | sub_4FABA0 |
| 全局变量 | qword_5646E0 | qword_5586C0 |

### 2.2 VTable 函数指针对应

| 对号 | 偏移 | tersafe 对 (低, 高) | anogs 对 (低, 高) |
|:---:|:---:|:---|:---|
| 0 | 0x00 | sub_2F1868, j__dlclose | sub_39C6E0, j__dlclose |
| 1 | 0x10 | j__dlopen, j__dlsym | j__dlopen, j__dlsym |
| 2 | 0x20 | sub_322DF4, sub_2F02F0 | sub_3CDA78, sub_39B168 |
| 3 | 0x30 | sub_2F02AC, sub_2F013C | sub_39B124, sub_39AFB4 |
| 4 | 0x40 | sub_2F0390, sub_2F03A8 | sub_39B208, sub_39B220 |
| 5 | 0x50 | sub_2F0450, sub_2F04E4 | sub_39B2C8, sub_39B35C |
| 6 | 0x60 | sub_2F04FC, sub_2F0570 | sub_39B374, sub_39B3E8 |
| **7** | **0x70** | **sub_2F0D30, sub_2F0D70** | **sub_39BBA8, sub_39BBE8** |
| 8 | 0x80 | sub_2F0E40, sub_2F0FC0 | sub_39BCB8, sub_39BE38 |
| 9 | 0x90 | sub_2F0FE4, sub_2F1124 | sub_39BE5C, sub_39BF9C |
| 10 | 0xA0 | sub_2F118C, sub_2F1050 | sub_39C004, sub_39BEC8 |
| 11 | 0xB0 | sub_2F0F08, sub_2F1228 | sub_39BD80, sub_39C0A0 |
| 12 | 0xC0 | sub_2F1344, &loc_2F1364 | sub_39C1BC, &loc_39C1DC |
| 13 | 0xD0 | sub_2F1360, sub_2F158C | sub_39C1D8, sub_39C404 |
| 14 | 0xE0 | sub_2F1794, sub_2F4EF0 | sub_39C60C, sub_39FD70 |
| 15 | 0xF0 | sub_2F4C64, sub_2F4D2C | sub_39FADC, sub_39FBA4 |
| 16 | 0x100 | sub_323074, sub_3272F4 | sub_3CDCF8, sub_3D1F78 |
| 17 | 0x110 | sub_31FB2C, sub_31FBD4 | sub_3CA9AC, sub_3CAA54 |
| 18 | 0x120 | sub_31F9A8, sub_31FAC8 | sub_3CA828, sub_3CA948 |
| 19 | 0x130 | sub_31F9F0, sub_31F8C8 | sub_3CA870, sub_3CA748 |
| 20 | 0x140 | sub_31F864, sub_320DF4 | sub_3CA6E4, sub_3CBC74 |
| 21 | 0x150 | sub_321DA8, sub_328AE4 | sub_3CCC28, sub_3D3768 |
| 22 | 0x160 | sub_328C1C, sub_3289C0 | sub_3D38A0, sub_3D3644 |

**说明：**
- 每对占 16 字节 (2 个 8 字节指针)
- **加粗**行是映射的关键函数对
- `sub_2F0D70` (tersafe) → `sub_39BBE8` (anogs)：memcpy-like 函数

---

## 3. 独立函数映射

### 3.1 已确认的对应关系

| 序号 | tersafe 偏移 | tersafe 函数 | anogs 偏移 | anogs 函数 | 功能 |
|:---:|:---:|:---:|:---:|:---:|:---|
| 1 | **0x416DF4** | sub_416DF4 | **0x36E10C** | sub_36E10C | 从内存中读取数据块 |
| 2 | **0x4A1D58** | sub_4A1D58 | **0x4948D8** | sub_4948D8 | gettimeofday → double |
| 3 | **0x48924C** | sub_48924C | **0x494964** | sub_494964 | 时间格式化 `%02d:%02d:%02d` |
| 4 | **0x4A4658** | sub_4A4658 | **0x4971D8** | sub_4971D8 | memcmp (定长内存比较) |

### 3.2 函数体对比

#### sub_416DF4 (tersafe) ↔ sub_36E10C (anogs) — **完全相同**

```c
// tersafe: sub_416DF4     →  anogs: sub_36E10C
__int64 __fastcall sub_416DF4(__int64 a1, __int64 a2, void **a3, unsigned int *a4)
{
    // ... 栈保护检查 ...
    if ( a2 && a3 && a4 ) {
        if ( (*(_BYTE *)(a1 + 528) & 1) != 0 ) {  // 64位模式
            *a4 = *(_QWORD *)(a2 + 32);
            v8 = *(_QWORD *)(a2 + 24);
        } else {                                     // 32位模式
            *a4 = *(_DWORD *)(a2 + 20);
            v8 = *(unsigned int *)(a2 + 16);
        }
        v4 = malloc((int)*a4);
        *a3 = v4;
        if ( *a3 ) {
            // 解密/验证 → 复制 → 结束
            sub_3AAFFC();                          // sub_44861C (anogs)
            sub_3AB01C(v12, ptr, size);            // sub_44863C (anogs)
            memcpy(*a3, ptr, size);
            sub_3AB00C();                          // sub_44862C (anogs)
        } else {
            *(_DWORD *)(a1 + 532) = -errno;
        }
    } else {
        *(_DWORD *)(a1 + 532) = -999;
    }
    return v11;
}
```

#### sub_4A1D58 (tersafe) ↔ sub_4948D8 (anogs) — **完全相同**

```c
double sub_4A1D58() {
    struct timeval v2 = {0, 0};
    int v0 = gettimeofday(&v2, 0);
    if ( !v0 )
        return (double)v2.tv_usec / 1000000.0 + (double)v2.tv_sec;
    return 0.0;
}
```

#### sub_48924C (tersafe) ↔ sub_494964 (anogs) — **完全相同**

```c
__int64 sub_48924C(_BYTE *a1, unsigned __int64 a2) {
    if ( a1 && a2 >= 0x14 ) {
        time_t v5 = time(0);
        struct tm *v4 = localtime(&v5);
        if ( v4 ) {
            sub_4A559C(a1, "%02d:%02d:%02d", v4->tm_hour, v4->tm_min, v4->tm_sec);
            return 0;
        }
    }
    return -1;
}
```

#### sub_4A4658 (tersafe) ↔ sub_4971D8 (anogs) — **完全相同**

```c
__int64 sub_4A4658(unsigned __int8 *a1, unsigned __int8 *a2, __int64 a3) {
    if ( a3 ) {
        while ( 1 ) {
            unsigned int v3 = *a1 - *a2;
            if ( v3 ) break;
            if ( !--a3 ) return 0;
            ++a1; ++a2;
        }
        return v3;
    }
    return 0;
}
```

---

## 4. 特殊地址说明

以下地址在 tersafe 伪代码中**不是函数起始地址**，需注意：

| tersafe 偏移 | 实际含义 | 状态 |
|:---:|:---|:---:|
| **0x2F0D74** | `sub_2F0D70 + 4`，函数内部地址，但该函数在 vtable 中映射为 `sub_39BBE8` (anogs) | ✅ 已映射 |
| **0x323390** | `sub_32337C + 0x14`，函数内部地址 | ⚠️ 待确认 |
| **0x325B84** | `sub_325B48 + 0x3C`，两个函数之间的数据区域 | ⚠️ 待确认 |
| **0x325BA0** | `sub_325B8C + 0x14`，函数内部地址 | ⚠️ 待确认 |
| **0x44120C** | 在 tersafe 伪代码中**不存在**此地址 | ❓ 来源不明 |
| **0x441214** | 在 tersafe 伪代码中**不存在**此地址 | ❓ 来源不明 |
| **0x460720** | `sub_460744 - 0x24`，函数之前的数据区域 | ⚠️ 待确认 |

### 关于 `0x44120C` 和 `0x441214`

这两个地址在 `libtersafe.so.c` 文件中搜索不到任何匹配，可能来自：
- 其他分析工具的输出（如 `readelf`、`objdump` 等）
- 二进制文件中的数据段地址，而非代码段
- 不同版本的 tersafe 文件

---

## 5. 附录：关键数据结构

### 5.1 20 项函数表声明

```c
// tersafe
__int64 (__fastcall *off_5151D8[20])() = {
    &sub_2AA3B0, &sub_2AA44C, &sub_2AA4CC, &sub_2AA4F8,
    &sub_2AA524, &sub_2AA5B4, &sub_2AA654, &sub_2AA680,
    &sub_2AA6AC, &sub_2AA72C, &sub_2AA7CC, &sub_2AA85C,
    &sub_2AA8EC, &sub_2AA918, &sub_2AA944, &sub_2AA9C4,
    &sub_2AAA44, &sub_2AAA70, &sub_2AAA9C, &sub_2AAB3C
};

// anogs
__int64 (__fastcall *off_507910[20])() = {
    &sub_29F7D0, &sub_29F84C, &sub_29F8CC, &sub_29F8F8,
    &sub_29F924, &sub_29F9B4, &sub_29FA44, &sub_29FA70,
    &sub_29FA9C, &sub_29FB2C, &sub_29FBBC, &sub_29FC5C,
    &sub_29FCEC, &sub_29FD18, &sub_29FD44, &sub_29FDC4,
    &sub_29FE54, &sub_29FE80, &sub_29FEAC, &sub_29FF2C
};
```

### 5.2 VTable 初始化函数

```c
// tersafe: sub_326E28 @ 0x326E28
// anogs:   sub_3D1AAC @ 0x3D1AAC
// 功能: 分配 0x320 字节并填充 46 对函数指针
```

### 5.3 快速查询表

| 用户提供的 tersafe 偏移 | anogs 偏移 | 匹配方法 |
|:---:|:---:|:---|
| 0x1F9660 | **待确认** | 函数体模式匹配 |
| 0x2AA4CC | **0x29F8CC** | 函数表索引 2 |
| 0x2AA4F8 | **0x29F8F8** | 函数表索引 3 |
| 0x2AA654 | **0x29FA44** | 函数表索引 6 |
| 0x2AA680 | **0x29FA70** | 函数表索引 7 |
| 0x2AA8EC | **0x29FCEC** | 函数表索引 12 |
| 0x2AA918 | **0x29FD18** | 函数表索引 13 |
| 0x2AAA44 | **0x29FE54** | 函数表索引 16 |
| 0x2AAA70 | **0x29FE80** | 函数表索引 17 |
| 0x2F0D74 | **0x39BBE8** | VTable 对 7 高位 |
| 0x323390 | **待确认** | 函数内部地址 |
| 0x325B84 | **待确认** | 数据区域 |
| 0x325BA0 | **待确认** | 数据区域 |
| 0x416DF4 | **0x36E10C** | 函数体完全匹配 |
| 0x44120C | **不存在** | 来源不明 |
| 0x441214 | **不存在** | 来源不明 |
| 0x460720 | **待确认** | 数据区域 |
| 0x48924C | **0x494964** | 函数体完全匹配 |
| 0x4A1D58 | **0x4948D8** | 函数体完全匹配 |
| 0x4A4658 | **0x4971D8** | 函数体完全匹配 |

---

### 5.4 文件信息

| 文件 | 路径 | 行数 |
|:---|:---|---:|
| tersafe | `libtersafe.so.c` | 719,175 行 |
| anogs | `libanogs.so.c` | 706,674 行 |
