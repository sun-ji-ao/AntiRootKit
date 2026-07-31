# AntiRootKit

Windows 内核态 + 用户态联动的反 Rootkit 检测工具，通过**多视图交叉比对**发现隐藏进程、隐藏内核模块与隐藏网络端口。

> 仅供安全研究、取证分析与防御学习使用。请在隔离实验环境中运行，并自行承担风险。

## 功能概览

| 检测目标 | 用户态视图 | 内核态视图 | 判定逻辑 |
|---|---|---|---|
| 隐藏进程 | Toolhelp / 常规进程枚举 (View A) | CID 表查找 (View B)、系统句柄中的 Process/Thread 对象 (View C) | 内核可见但用户态不可见 → 可疑隐藏 |
| 隐藏模块 | `SystemModuleInformation` 等 (R3) | `PsLoadedModuleList` / DriverSection (View A)、`\Driver` 对象目录 (View B)、BigPool 残留痕迹 (View C) | 多源差集定位卸链/残留模块 |
| 隐藏端口 | 常规网络 API 枚举 (R3) | AFD 句柄视图 (View B)、NSI TCP/UDP 直调 (View C) | 内核表存在但用户态缺失 → 可疑隐藏 |

检测结果会打印到控制台，并分别写入：

- `hidden_processes.json`
- `hidden_modules.json`
- `hidden_ports.json`

## 仓库结构

```text
AntiRootKitApp/
├── AntiRootKitApp.sln          # Visual Studio 解决方案
├── include/Common.h            # 用户态/内核态共享 IOCTL 与数据结构
├── AntiRootKitApp/             # 用户态控制台程序
│   ├── main.cpp
│   ├── DetectHiddenProcess.*
│   ├── DetectHiddenModule.*
│   ├── DetectHiddenPort.*
│   ├── DriveRelated.*          # 驱动加载/通信
│   └── json_report_writer.*
└── AntiRootKitDriver/          # 内核驱动 (WDM)
    ├── DriverEntry.*
    ├── DetectHiddenProcess.*
    ├── DetectHiddenModule.*
    └── DetectHiddenPort.*
```

## 环境要求

- Windows 10/11 x64（建议测试机，不要在生产机直接加载未签名驱动）
- Visual Studio 2022（含 C++ 桌面开发）
- Windows Driver Kit (WDK)
- 管理员权限运行用户态程序以加载驱动

## 编译

1. 用 Visual Studio 打开 `AntiRootKitApp.sln`
2. 配置选择 **x64 | Release**（或 Debug）
3. 先编译 `AntiRootKitDriver`，再编译 `AntiRootKitApp`
4. 将生成的 `AntiRootKitDriver.sys` 与 `AntiRootKitApp.exe` 放到同一目录（程序按可执行文件目录查找驱动）

驱动默认服务/设备名：`ARK`（设备路径 `\\.\ARK`）。

## 使用方法

以管理员身份在输出目录运行：

```bat
AntiRootKitApp.exe
```

可选参数：

```bat
AntiRootKitApp.exe -keep
```

- 默认：检测结束后卸载驱动
- `-keep`：检测完成后保持驱动加载，便于调试

## 检测原理（简要）

### 隐藏进程

1. **View A**：用户态枚举进程快照  
2. **View B**：内核按 PID 调用 `PsLookupProcessByProcessId` 扫描 CID  
3. **View C**：系统句柄表中的 Process/Thread 对象  
4. 取内核并集，减去用户态集合，得到候选隐藏进程，并附带 `EPROCESS` 地址与映像名

### 隐藏模块

1. **R3**：用户态系统模块列表  
2. **View A**：已加载模块链表 / DriverSection  
3. **View B**：`\Driver` 对象目录中的 `DRIVER_OBJECT`  
4. **View C**：BigPool 等残留结构中的 PE/Tag 痕迹  
5. 交叉比对发现卸链但仍存在、或仅有残留痕迹的模块

### 隐藏端口

1. **R3**：用户态网络连接/端口枚举  
2. **View B**：系统句柄中的 `\Device\Afd` 文件对象（按 PID 聚合）  
3. **View C**：内核 NSI TCP/UDP 表直读  
4. 比对发现被隐藏的监听或连接

## IOCTL 接口

定义见 `include/Common.h`：

| IOCTL | 作用 |
|---|---|
| `IOCTL_ARK_QUERY_KERNEL_VIEWS` | 查询内核进程 View B/C |
| `IOCTL_ARK_QUERY_KERNEL_MODULE_VIEWS` | 查询内核模块 View A/B/C |
| `IOCTL_ARK_QUERY_KERNEL_PORT_VIEWS` | 查询内核端口 View B/C |

## 限制与说明

- 当前实现面向 x64；内核结构偏移/未文档接口可能随 Windows 版本变化
- 模块 View C 目前以 BigPool 痕迹为主；`PiDDBCacheTable` / `MmUnloadedDrivers` / CI HashBucket 等为预留标志
- 高级对抗（伪造池头、拆解 PE、hypervisor 级隐藏）可能绕过部分视图，需结合页表扫描、回调回溯等进一步增强
- 加载内核驱动有系统稳定性风险；测试前请做好快照/备份

## 许可证

本仓库默认按学习与研究用途提供。若需商用或再分发，请自行补充明确许可证并遵守当地法律法规。
