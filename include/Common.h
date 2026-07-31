#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <Windows.h>
#endif

/** @brief 驱动/服务名称（宽字符）。 */
#define ARK_DRIVER_NAME         L"ARK"
/** @brief 用户态打开设备的路径（\\.\ARK）。 */
#define ARK_USER_DEVICE_NAME    L"\\\\.\\" ARK_DRIVER_NAME

/** @brief 进程映像短名最大长度（含结尾符）。 */
#define ARK_IMAGE_NAME_MAX      16
/** @brief 进程完整映像路径最大长度（含结尾符）。 */
#define ARK_IMAGE_PATH_MAX      260
/** @brief 单次 IOCTL 可返回的最大进程条目数。 */
#define ARK_MAX_PROCESS_ENTRIES 512
/** @brief 内核暴力扫描 PID/TID 上限。 */
#define ARK_MAX_SCAN_PID        65535UL
/** @brief 扫描循环中每 N 次让出 CPU 一次。 */
#define ARK_SCAN_YIELD_INTERVAL 256UL

/** @brief 模块短名最大长度（含结尾符）。 */
#define ARK_MODULE_NAME_MAX     64
/** @brief 模块完整路径最大长度（含结尾符）。 */
#define ARK_MODULE_PATH_MAX     260
/** @brief 单次 IOCTL 可返回的最大模块条目数。 */
#define ARK_MAX_MODULE_ENTRIES  512

/** @brief 查询内核 View B/C 进程列表的 IOCTL（METHOD_BUFFERED）。 */
#define IOCTL_ARK_QUERY_KERNEL_VIEWS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA01, METHOD_BUFFERED, FILE_ANY_ACCESS)

/** @brief 查询内核模块 View A/B/C 的 IOCTL（METHOD_BUFFERED）。 */
#define IOCTL_ARK_QUERY_KERNEL_MODULE_VIEWS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA02, METHOD_BUFFERED, FILE_ANY_ACCESS)

/** @brief 查询内核端口 View（NSI 直调）的 IOCTL（METHOD_BUFFERED）。 */
#define IOCTL_ARK_QUERY_KERNEL_PORT_VIEWS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA03, METHOD_BUFFERED, FILE_ANY_ACCESS)

/** @brief 单次 IOCTL 可返回的最大端口条目数。 */
#define ARK_MAX_PORT_ENTRIES    1024
/** @brief 端口协议：TCP。 */
#define ARK_PORT_PROTO_TCP      6UL
/** @brief 端口协议：UDP。 */
#define ARK_PORT_PROTO_UDP      17UL
/** @brief 端口 View：内核 NSI TCP 表命中标志。 */
#define ARK_FLAG_VIEW_PORT_TCP  0x00000001UL
/** @brief 端口 View：内核 NSI UDP 表命中标志。 */
#define ARK_FLAG_VIEW_PORT_UDP  0x00000002UL
/** @brief 端口 View B：系统句柄快照中 \\Device\\Afd 文件对象命中标志。 */
#define ARK_FLAG_VIEW_PORT_AFD  0x00000004UL
/** @brief 端口协议未知（AFD 未能解析协议时）。 */
#define ARK_PORT_PROTO_UNKNOWN  0UL

#pragma pack(push, 1)

/**
 * @brief 内核返回的单条进程记录（View B 或 View C）。
 */
typedef struct _ARK_KERNEL_PROCESS_ENTRY {
    ULONG ProcessId;                    /**< 进程 PID */
    ULONG ViewFlags;                    /**< 视图标志位（ARK_FLAG_VIEW_*） */
    ULONG64 EprocessAddress;            /**< 内核 EPROCESS 对象地址 */
    CHAR ImageName[ARK_IMAGE_NAME_MAX]; /**< 进程映像短名（ANSI） */
} ARK_KERNEL_PROCESS_ENTRY;

/** @brief View B：PsLookupProcessByProcessId 命中标志。 */
#define ARK_FLAG_VIEW_CID       0x00000002UL
/** @brief View C：系统句柄快照中 Process/Thread 对象命中标志。 */
#define ARK_FLAG_VIEW_THREAD    0x00000004UL

/**
 * @brief 驱动 IOCTL 返回的内核进程视图汇总数据。
 */
typedef struct _ARK_KERNEL_VIEWS_RESPONSE {
    ULONG Status;                                           /**< NTSTATUS 状态码（ULONG 形式） */
    ULONG MaxPidScanned;                                    /**< 实际扫描的 PID 上限 */
    ULONG CidCount;                                         /**< View B 命中条目计数 */
    ULONG ThreadCount;                                      /**< View C：系统句柄快照命中条目计数 */
    ULONG EntryCount;                                       /**< Entries 有效条目数（B|C 去重合并） */
    ARK_KERNEL_PROCESS_ENTRY Entries[ARK_MAX_PROCESS_ENTRIES]; /**< 进程条目数组 */
} ARK_KERNEL_VIEWS_RESPONSE;

/** @brief 模块 View A：DriverSection / PsLoadedModuleList 命中标志。 */
#define ARK_FLAG_VIEW_SECTION   0x00000001UL
/** @brief 模块 View B：\\Driver 对象目录枚举命中标志。 */
#define ARK_FLAG_VIEW_DRIVEROBJ 0x00000002UL
/** @brief 模块 View C：残留结构命中总标志（当前实现为 BigPool）。 */
#define ARK_FLAG_VIEW_RESIDUAL  0x00000004UL
/** @brief View C 子源预留：PiDDBCacheTable（暂未启用）。 */
#define ARK_FLAG_RESIDUAL_PIDDB 0x00000010UL
/** @brief View C 子源预留：MmUnloadedDrivers（暂未启用）。 */
#define ARK_FLAG_RESIDUAL_UNLOAD 0x00000020UL
/** @brief View C 子源预留：CI g_KernelHashBucketList（暂未启用）。 */
#define ARK_FLAG_RESIDUAL_CI    0x00000040UL
/** @brief View C 子源：SystemBigPool PE/Tag 痕迹（当前启用）。 */
#define ARK_FLAG_RESIDUAL_POOL  0x00000080UL

/**
 * @brief 内核返回的单条模块记录（View A/B/C）。
 */
typedef struct _ARK_KERNEL_MODULE_ENTRY {
    ULONG ViewFlags;                          /**< 视图标志位（含 residual 子标志） */
    ULONG ImageSize;                          /**< 映像大小 */
    ULONG64 ImageBase;                        /**< 映像基址（DllBase / DriverStart / PoolVA） */
    ULONG64 DriverObjectAddress;              /**< DRIVER_OBJECT 地址（仅 View B 有值） */
    CHAR ModuleName[ARK_MODULE_NAME_MAX];     /**< 模块短名（ANSI） */
    CHAR ModulePath[ARK_MODULE_PATH_MAX];     /**< 模块完整路径或残留来源标签 */
} ARK_KERNEL_MODULE_ENTRY;

/**
 * @brief 驱动 IOCTL 返回的内核模块视图汇总数据。
 */
typedef struct _ARK_KERNEL_MODULE_VIEWS_RESPONSE {
    ULONG Status;                                             /**< NTSTATUS 状态码（ULONG 形式） */
    ULONG SectionCount;                                       /**< View A：DriverSection 命中数 */
    ULONG DriverCount;                                        /**< View B：\\Driver 对象命中数 */
    ULONG ResidualCount;                                      /**< View C：残留结构命中数 */
    ULONG EntryCount;                                         /**< Entries 有效条目数（A|B|C 去重合并） */
    ARK_KERNEL_MODULE_ENTRY Entries[ARK_MAX_MODULE_ENTRIES];  /**< 模块条目数组 */
} ARK_KERNEL_MODULE_VIEWS_RESPONSE;

/**
 * @brief 内核返回的单条端口/连接记录（NSI 或 AFD View）。
 */
typedef struct _ARK_KERNEL_PORT_ENTRY {
    ULONG Protocol;              /**< ARK_PORT_PROTO_* */
    ULONG State;                 /**< TCP 状态；AFD 视图为 SOCKET_STATE */
    ULONG OwningPid;             /**< 所属进程 PID */
    ULONG ViewFlags;             /**< ARK_FLAG_VIEW_PORT_* */
    ULONG LocalAddr;             /**< 本地 IPv4（网络字节序）；AFD 经 IOCTL 解析，未绑定为 0 */
    ULONG RemoteAddr;            /**< 远端 IPv4（网络字节序）；AFD 未连接 UDP 等为 0 */
    USHORT LocalPort;            /**< 本地端口（主机字节序）；AFD 经 IOCTL_AFD_GET_ADDRESS 解析 */
    USHORT RemotePort;           /**< 远端端口（主机字节序）；AFD 经 IOCTL_AFD_GET_REMOTE_ADDRESS 解析 */
    ULONG64 EndpointObject;      /**< AFD FILE_OBJECT 地址（NSI 视图为 0） */
} ARK_KERNEL_PORT_ENTRY;

/**
 * @brief 驱动 IOCTL 返回的内核端口视图汇总数据。
 *
 * View B：系统句柄中 \\Device\\Afd 文件对象（按 PID 聚合）。
 * View C：netio NSI 直调 TCP/UDP 表。
 */
typedef struct _ARK_KERNEL_PORT_VIEWS_RESPONSE {
    ULONG Status;                                           /**< NTSTATUS 状态码（ULONG 形式） */
    ULONG TcpCount;                                         /**< View C：内核 TCP 条目数 */
    ULONG UdpCount;                                         /**< View C：内核 UDP 条目数 */
    ULONG AfdCount;                                         /**< View B：持有 AFD 句柄的 PID 数 */
    ULONG AfdHandleCount;                                   /**< View B：AFD 文件句柄总数 */
    ULONG EntryCount;                                       /**< Entries 有效条目数 */
    ARK_KERNEL_PORT_ENTRY Entries[ARK_MAX_PORT_ENTRIES];    /**< 端口/AFD 条目数组 */
} ARK_KERNEL_PORT_VIEWS_RESPONSE;

#ifndef _KERNEL_MODE

/**
 * @brief 应用层隐藏进程详情（含路径与原因，用于 JSON 输出）。
 */
typedef struct _ARK_HIDDEN_PROCESS_ENTRY {
    ULONG ProcessId;                        /**< 进程 PID */
    ULONG ParentProcessId;                  /**< 父进程 PID */
    ULONG ViewFlags;                        /**< 内核视图标志位 */
    ULONG64 EprocessAddress;                /**< 内核 EPROCESS 地址 */
    CHAR ImageName[ARK_IMAGE_NAME_MAX];     /**< 进程映像短名 */
    CHAR ImagePath[ARK_IMAGE_PATH_MAX];     /**< 进程完整映像路径 */
    CHAR Reason[128];                       /**< 判定为隐藏的原因描述 */
} ARK_HIDDEN_PROCESS_ENTRY;

/**
 * @brief 应用层跨视图检测结果（C 结构体版本，当前由 C++ CrossDetectResult 替代）。
 */
typedef struct _ARK_CROSS_DETECT_RESULT {
    ULONG Status;                                           /**< 操作状态码 */
    ULONG R3Count;                                          /**< View A：R3 枚举进程数 */
    ULONG CidCount;                                         /**< View B 命中数 */
    ULONG ThreadCount;                                      /**< View C 命中数 */
    ULONG KernelUnionCount;                                 /**< 内核 B|C 合并去重数 */
    ULONG HiddenCount;                                      /**< 隐藏进程数量 */
    ULONG MaxPidScanned;                                    /**< 内核扫描 PID 上限 */
    ARK_HIDDEN_PROCESS_ENTRY HiddenProcesses[ARK_MAX_PROCESS_ENTRIES]; /**< 隐藏进程数组 */
} ARK_CROSS_DETECT_RESULT;

/**
 * @brief 应用层隐藏模块详情（用于 JSON 输出）。
 */
typedef struct _ARK_HIDDEN_MODULE_ENTRY {
    ULONG ViewFlags;                          /**< 内核视图标志位 */
    ULONG ImageSize;                          /**< 映像大小 */
    ULONG64 ImageBase;                        /**< 映像基址 */
    ULONG64 DriverObjectAddress;              /**< DRIVER_OBJECT 地址 */
    CHAR ModuleName[ARK_MODULE_NAME_MAX];     /**< 模块短名 */
    CHAR ModulePath[ARK_MODULE_PATH_MAX];     /**< 模块完整路径 */
    CHAR Reason[128];                         /**< 判定为隐藏的原因描述 */
} ARK_HIDDEN_MODULE_ENTRY;

/**
 * @brief 应用层跨视图隐藏模块检测结果（C 结构体版本）。
 */
typedef struct _ARK_CROSS_DETECT_MODULE_RESULT {
    ULONG Status;                                             /**< 操作状态码 */
    ULONG R3Count;                                            /**< R3 枚举模块数 */
    ULONG SectionCount;                                       /**< 内核 View A 命中数 */
    ULONG DriverCount;                                        /**< 内核 View B 命中数 */
    ULONG ResidualCount;                                      /**< 内核 View C 命中数 */
    ULONG KernelUnionCount;                                   /**< 内核 A|B|C 合并去重数 */
    ULONG HiddenCount;                                        /**< 隐藏模块数量 */
    ARK_HIDDEN_MODULE_ENTRY HiddenModules[ARK_MAX_MODULE_ENTRIES]; /**< 隐藏模块数组 */
} ARK_CROSS_DETECT_MODULE_RESULT;

/**
 * @brief 应用层隐藏端口详情（用于 JSON 输出）。
 */
typedef struct _ARK_HIDDEN_PORT_ENTRY {
    ULONG Protocol;                           /**< ARK_PORT_PROTO_* */
    ULONG State;                              /**< TCP 状态；AFD 为句柄数 */
    ULONG OwningPid;                          /**< 所属进程 PID */
    ULONG ViewFlags;                          /**< 内核视图标志位 */
    ULONG LocalAddr;                          /**< 本地 IPv4（网络字节序） */
    ULONG RemoteAddr;                         /**< 远端 IPv4（网络字节序） */
    USHORT LocalPort;                         /**< 本地端口（主机字节序） */
    USHORT RemotePort;                        /**< 远端端口（主机字节序） */
    ULONG64 EndpointObject;                   /**< AFD FILE_OBJECT 地址 */
    CHAR LocalAddrStr[16];                    /**< 本地 IP 字符串 */
    CHAR RemoteAddrStr[16];                   /**< 远端 IP 字符串 */
    CHAR Reason[160];                         /**< 判定为隐藏的原因描述 */
} ARK_HIDDEN_PORT_ENTRY;

/**
 * @brief 应用层跨视图隐藏端口检测结果（C 结构体版本）。
 */
typedef struct _ARK_CROSS_DETECT_PORT_RESULT {
    ULONG Status;                                             /**< 操作状态码 */
    ULONG R3Count;                                            /**< R3 API 枚举端口数 */
    ULONG TcpCount;                                           /**< 内核 NSI TCP 命中数 */
    ULONG UdpCount;                                           /**< 内核 NSI UDP 命中数 */
    ULONG AfdCount;                                           /**< 内核 AFD PID 数 */
    ULONG AfdHandleCount;                                     /**< 内核 AFD 句柄总数 */
    ULONG KernelUnionCount;                                   /**< 内核 B|C 合并数 */
    ULONG HiddenCount;                                        /**< 隐藏端口数量 */
    ARK_HIDDEN_PORT_ENTRY HiddenPorts[ARK_MAX_PORT_ENTRIES];  /**< 隐藏端口数组 */
} ARK_CROSS_DETECT_PORT_RESULT;

#endif

#pragma pack(pop)
