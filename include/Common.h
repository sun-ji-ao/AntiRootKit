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

/** @brief 查询内核模块 View A/B 的 IOCTL（METHOD_BUFFERED）。 */
#define IOCTL_ARK_QUERY_KERNEL_MODULE_VIEWS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA02, METHOD_BUFFERED, FILE_ANY_ACCESS)

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

/**
 * @brief 内核返回的单条模块记录（View A 或 View B）。
 */
typedef struct _ARK_KERNEL_MODULE_ENTRY {
    ULONG ViewFlags;                          /**< 视图标志位（ARK_FLAG_VIEW_SECTION/DRIVEROBJ） */
    ULONG ImageSize;                          /**< 映像大小 */
    ULONG64 ImageBase;                        /**< 映像基址（DllBase / DriverStart） */
    ULONG64 DriverObjectAddress;              /**< DRIVER_OBJECT 地址（仅 View B 有值） */
    CHAR ModuleName[ARK_MODULE_NAME_MAX];     /**< 模块短名（ANSI） */
    CHAR ModulePath[ARK_MODULE_PATH_MAX];     /**< 模块完整路径（ANSI） */
} ARK_KERNEL_MODULE_ENTRY;

/**
 * @brief 驱动 IOCTL 返回的内核模块视图汇总数据。
 */
typedef struct _ARK_KERNEL_MODULE_VIEWS_RESPONSE {
    ULONG Status;                                             /**< NTSTATUS 状态码（ULONG 形式） */
    ULONG SectionCount;                                       /**< View A：DriverSection 命中数 */
    ULONG DriverCount;                                        /**< View B：\\Driver 对象命中数 */
    ULONG EntryCount;                                         /**< Entries 有效条目数（A|B 去重合并） */
    ARK_KERNEL_MODULE_ENTRY Entries[ARK_MAX_MODULE_ENTRIES];  /**< 模块条目数组 */
} ARK_KERNEL_MODULE_VIEWS_RESPONSE;

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
    ULONG KernelUnionCount;                                   /**< 内核 A|B 合并去重数 */
    ULONG HiddenCount;                                        /**< 隐藏模块数量 */
    ARK_HIDDEN_MODULE_ENTRY HiddenModules[ARK_MAX_MODULE_ENTRIES]; /**< 隐藏模块数组 */
} ARK_CROSS_DETECT_MODULE_RESULT;

#endif

#pragma pack(pop)
