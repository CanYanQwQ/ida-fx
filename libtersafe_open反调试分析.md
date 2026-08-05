# libtersafe.so 中 open 系列函数的反调试分析

> **快速说明**: `open`/`fopen`/`opendir` 确实被用于反调试和反注入检测  
> **目标文件**: libtersafe.so (TSS 安全 SDK)  
> **分析日期**: 2026-08-05

---

## 1. 检测机制（一句话版）

`libtersafe.so` 通过读取 Linux 的 `/proc/` 文件系统来检测调试器和注入：

| 检测方式 | 用的函数 | 检测什么 |
|---------|---------|---------|
| 读 `/proc/<pid>/maps` | `fopen` + `fgets` | 检查加载的 SO 列表，看有没有异常的库被注入 |
| 扫描 `/proc/<pid>/fd/` | `opendir` + `readdir` | 检查打开的文件描述符，调试器会留下痕迹 |
| 读 `/proc/<pid>/status` | `fopen` + `fgets` | 检查 `TracerPid`，不为 0 说明被调试 |
| 读 `/proc/<pid>/task/` | `opendir` + `readdir` | 检查线程数，调试器注入会创建额外线程 |

---

## 2. 关键函数

| 函数 | 地址 | 干了什么 |
|------|------|---------|
| `sub_3F6E24` | 0x3F6E24 | 打开 `/proc/<pid>/maps`，读取所有行，找到 `libtersafe.so` 的路径并缓存 |
| `sub_3FE7AC` | 0x3FE7AC | 打开目录扫描文件，计数文件描述符或检查特定模式 |
| `sub_41AE68` | 0x41AE68 | 同上，遍历目录项，统计信息上报 |

> 所有路径字符串都是 XOR 混淆的，运行时才解码，直接搜 `/proc/` 搜不到。

---

## 3. 怎么绕过

### 方法一：Hook 系统调用（最简单有效）

```c
// 思路：拦截 open/openat，过滤掉对 /proc/ 的访问
// 或者让 open 返回一个"干净"的数据

// 如果使用 Frida：
//   Interceptor.attach(Module.findExportByName("libc.so", "open"), {
//     onEnter: function(args) {
//       var path = args[0].readCString();
//       if (path.includes("/proc/")) {
//         // 返回伪造的 /proc/ 内容
//         // 或者重定向到我们自己准备的文件
//       }
//     }
//   });
```

**具体做法**：

1. **Hook `open`/`openat`**：拦截所有对 `/proc/` 的访问
2. **伪造 `/proc/<pid>/maps`**：把注入的 SO 从 maps 里删掉，只保留合法的 SO
3. **伪造 `/proc/<pid>/status`**：把 `TracerPid` 改成 `0`
4. **伪造 `/proc/<pid>/fd/`**：删掉调试器相关的文件描述符

### 方法二：LD_PRELOAD 劫持（有 root 的情况）

写一个自己的 SO，用 `LD_PRELOAD` 优先加载，劫持 `open`、`fopen`、`opendir`：

```c
// my_hook.c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>

int open(const char *pathname, int flags, ...) {
    static int (*real_open)(const char *, int, ...) = NULL;
    if (!real_open) real_open = dlsym(RTLD_NEXT, "open");
    
    // 拦截对 /proc/ 的访问
    if (strstr(pathname, "/proc/")) {
        // 返回一个伪造的文件描述符
        // 或者直接返回 -1（但可能被检测到）
        return -1;  // 简单粗暴，但可能触发检测
    }
    return real_open(pathname, flags);
}
```

### 方法三：直接 Patch 二进制（最简单）

找到 `sub_3F6E24` 中调用 `fopen` 的地方，直接 NOP 掉，或者让函数直接返回成功：

```
文件: libtersafe.so
地址: 0x3F7050  (BL .fopen)
修改: 替换为 NOP (0xD503201F)，并让函数直接返回 0
```

---

## 4. 注意事项

| 问题 | 说明 |
|------|------|
| **多线程检测** | 反调试可能有多个线程同时运行，只 Hook 一个地方不够 |
| **服务端验证** | 检测结果可能上报到服务器，客户端改了也没用 |
| **完整性校验** | Patch 二进制可能被 TSS 的完整性校验检测到 |
| **Frida 检测** | TSS 本身也会检测 Frida 等工具，用 Frida Hook 可能会被反制 |

---

## 5. 总结

| 项目 | 内容 |
|------|------|
| open 有没有反调试？ | ✅ **有**，而且是核心检测手段之一 |
| 检测什么？ | 读 `/proc/` 下的文件检查调试器、注入 SO、异常文件描述符 |
| 最简单绕过？ | Hook `open`/`openat` 系统调用，伪造 `/proc/` 返回数据 |
| 最难绕过？ | TSS 有多个检测层，互相兜底，单点突破可能不够 |

> **一句话**: `open` 是用来读 `/proc/` 查调试器和注入的，Hook 掉它就能绕过大部分检测，但要注意 TSS 还有其他检测手段。