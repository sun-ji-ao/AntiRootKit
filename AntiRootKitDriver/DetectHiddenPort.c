#include "DetectHiddenPort.h"
#include "undocument.h"
#include "Log.h"

#include <ntimage.h>
#include <ntstrsafe.h>

/** @brief NSI TCP 全表（含监听与已建立连接）。 */
#define ARK_NSI_TCP_ALL_TABLE       3UL
/** @brief NSI UDP 端点表。 */
#define ARK_NSI_UDP_ENDPOINT_TABLE  1UL
/** @brief NSI 地址条目大小（与 nsiproxy NET_INFO 一致）。 */
#define ARK_NSI_ADDR_ENTRY_SIZE     0x38UL
/** @brief NSI TCP 状态条目大小。 */
#define ARK_NSI_STATE_ENTRY_SIZE    0x10UL
/** @brief NSI 属主条目大小。 */
#define ARK_NSI_OWNER_ENTRY_SIZE    0x20UL
/** @brief NSI UDP 属主条目大小。 */
#define ARK_NSI_UDP_OWNER_SIZE      0x20UL

#define ARK_HTONS(value) ((USHORT)((((value) & 0x00FFU) << 8) | (((value) & 0xFF00U) >> 8)))

/** @brief ObQueryNameString 名称缓冲（含 OBJECT_NAME_INFORMATION 头）。 */
#define ARK_AFD_NAME_INFO_BYTES     0x400UL
/** @brief AFD View B 按 PID 聚合的最大槽位数。 */
#define ARK_AFD_MAX_PID_SLOTS       512UL
/** @brief 单次扫描最多对 AFD 句柄发起地址查询的次数。 */
#define ARK_AFD_MAX_ADDRESS_QUERIES 2048UL
/** @brief AFD GET_ADDRESS / GET_REMOTE_ADDRESS 输出缓冲大小。 */
#define ARK_AFD_ADDRESS_BUFFER_BYTES 256UL
/** @brief AFD GET_CONTEXT 输出缓冲大小（SOCK_SHARED_INFO）。 */
#define ARK_AFD_CONTEXT_BUFFER_BYTES 512UL

/** @brief AFD IOCTL：获取本地地址（METHOD_NEITHER，输出 AFD_ADDRESS）。 */
#define ARK_IOCTL_AFD_GET_ADDRESS         0x0001202FUL
/** @brief AFD IOCTL：获取远端地址（METHOD_NEITHER，输出 AFD_ADDRESS）。 */
#define ARK_IOCTL_AFD_GET_REMOTE_ADDRESS  0x0001203FUL
/** @brief AFD IOCTL：获取套接字上下文（METHOD_NEITHER，输出 SOCK_SHARED_INFO）。 */
#define ARK_IOCTL_AFD_GET_CONTEXT         0x00012043UL

/** @brief IPv4 地址族。 */
#define ARK_AF_INET                 2UL
/** @brief TDI IPv4 地址类型。 */
#define ARK_TDI_ADDRESS_TYPE_IP     2UL
/** @brief IPPROTO_TCP。 */
#define ARK_IPPROTO_TCP             6UL
/** @brief IPPROTO_UDP。 */
#define ARK_IPPROTO_UDP             17UL

#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE          0x0040UL
#endif

/** @brief 最小 IPv4 SOCKADDR_IN（内核侧布局）。 */
typedef struct _ARK_SOCKADDR_IN {
    USHORT sin_family;
    USHORT sin_port;
    ULONG sin_addr;
    UCHAR sin_zero[8];
} ARK_SOCKADDR_IN;

/** @brief TDI IPv4 地址体。 */
typedef struct _ARK_TDI_ADDRESS_IP {
    USHORT sin_port;
    ULONG in_addr;
} ARK_TDI_ADDRESS_IP;

/** @brief TA_ADDRESS 头（后跟 AddressLength 字节地址体）。 */
typedef struct _ARK_TA_ADDRESS {
    USHORT AddressLength;
    USHORT AddressType;
    UCHAR Address[1];
} ARK_TA_ADDRESS;

/** @brief TDI TRANSPORT_ADDRESS 头。 */
typedef struct _ARK_TDI_ADDRESS {
    ULONG TAAddressCount;
    ARK_TA_ADDRESS Address[1];
} ARK_TDI_ADDRESS;

/** @brief TDI_ADDRESS_INFO（TDI/hybrid 套接字 GET_ADDRESS 输出）。 */
typedef struct _ARK_TDI_ADDRESS_INFO {
    ULONG ActivityCount;
    ARK_TDI_ADDRESS Address;
} ARK_TDI_ADDRESS_INFO;

/** @brief AFD GET_CONTEXT 返回的套接字共享信息（仅使用前几字段）。 */
typedef struct _ARK_SOCK_SHARED_INFO {
    LONG State;
    LONG AddressFamily;
    LONG SocketType;
    LONG Protocol;
} ARK_SOCK_SHARED_INFO;

/**
 * @brief 从 AFD 句柄解析出的端点地址与协议。
 */
typedef struct _ARK_AFD_PARSED_ENDPOINT {
    ULONG Protocol;
    ULONG State;
    ULONG LocalAddr;
    ULONG RemoteAddr;
    USHORT LocalPort;
    USHORT RemotePort;
    BOOLEAN HasLocal;
    BOOLEAN HasRemote;
} ARK_AFD_PARSED_ENDPOINT;

/** @brief 文件对象类型，用于句柄快照中 File 对象过滤。 */
extern POBJECT_TYPE* IoFileObjectType;

/**
 * @brief SystemHandleInformation 单条句柄记录。
 */
typedef struct _ARK_PORT_SYSTEM_HANDLE_ENTRY {
    USHORT UniqueProcessId;       /**< 持有该句柄的进程 PID（USHORT） */
    USHORT CreatorBackTraceIndex; /**< 创建回溯索引 */
    UCHAR ObjectTypeIndex;        /**< 对象类型索引 */
    UCHAR HandleAttributes;       /**< 句柄属性 */
    USHORT HandleValue;           /**< 句柄值 */
    PVOID Object;                 /**< 内核对象指针 */
    ULONG GrantedAccess;          /**< 授予的访问权限 */
} ARK_PORT_SYSTEM_HANDLE_ENTRY;

/**
 * @brief SystemHandleInformation 返回缓冲区头。
 */
typedef struct _ARK_PORT_SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;                    /**< 句柄条目数量 */
    ARK_PORT_SYSTEM_HANDLE_ENTRY Handles[1];  /**< 可变长句柄数组 */
} ARK_PORT_SYSTEM_HANDLE_INFORMATION;

/**
 * @brief AFD View B：按 PID 聚合的槽位。
 */
typedef struct _ARK_AFD_PID_SLOT {
    ULONG Pid;              /**< 持有 AFD 句柄的进程 PID */
    ULONG HandleCount;      /**< 该 PID 下匹配到的 AFD 文件句柄数 */
    ULONG64 FirstObject;    /**< 首次命中的 FILE_OBJECT 地址 */
} ARK_AFD_PID_SLOT;

/**
 * @brief NPI 模块标识（与 netiodef.h 布局一致）。
 */
typedef struct _ARK_NPI_MODULEID {
    USHORT Length;   /**< 结构长度（sizeof） */
    USHORT Padding;  /**< 对齐填充 */
    ULONG Type;      /**< MIT_GUID = 1 */
    GUID Guid;       /**< 模块 GUID */
} ARK_NPI_MODULEID;

/**
 * @brief NSI 地址条目（IPv4，与 RootKit NET_INFO 同布局）。
 */
typedef struct _ARK_NSI_ADDR_ENTRY {
    USHORT Family;           /**< AF_INET = 2 */
    USHORT LocalPort;        /**< 本地端口（网络字节序） */
    ULONG LocalAddr;         /**< 本地 IPv4（网络字节序） */
    UCHAR Reserved1[0x16];   /**< 保留 */
    USHORT RemotePort;       /**< 远端端口（网络字节序） */
    ULONG RemoteAddr;        /**< 远端 IPv4（网络字节序） */
    UCHAR Reserved2[0x14];   /**< 保留 */
} ARK_NSI_ADDR_ENTRY;

/**
 * @brief NSI TCP 状态条目。
 */
typedef struct _ARK_NSI_STATE_ENTRY {
    ULONG State;      /**< MIB_TCP_STATE_* */
    ULONG Reserved1;  /**< 保留 */
    ULONG Reserved2;  /**< 可能含 offload */
    ULONG Reserved3;  /**< 保留 */
} ARK_NSI_STATE_ENTRY;

/**
 * @brief NSI TCP/UDP 属主条目。
 */
typedef struct _ARK_NSI_OWNER_ENTRY {
    ULONG Reserved1[3];          /**< 保留 */
    ULONG OwningPid;             /**< 所属 PID */
    LARGE_INTEGER CreateTime;    /**< 创建时间 */
    ULONGLONG OwningModuleInfo;  /**< 模块信息 */
} ARK_NSI_OWNER_ENTRY;

/**
 * @brief SystemModuleInformation 单模块描述。
 */
typedef struct _ARK_RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;           /**< 节句柄 */
    PVOID MappedBase;         /**< 映射基址 */
    PVOID ImageBase;          /**< 映像基址 */
    ULONG ImageSize;          /**< 映像大小 */
    ULONG Flags;              /**< 标志 */
    USHORT LoadOrderIndex;    /**< 加载顺序 */
    USHORT InitOrderIndex;    /**< 初始化顺序 */
    USHORT LoadCount;         /**< 引用计数 */
    USHORT OffsetToFileName;  /**< FullPathName 内短名偏移 */
    UCHAR FullPathName[256];  /**< 完整路径 */
} ARK_RTL_PROCESS_MODULE_INFORMATION;

/**
 * @brief SystemModuleInformation 返回头。
 */
typedef struct _ARK_RTL_PROCESS_MODULES {
    ULONG NumberOfModules;                         /**< 模块数 */
    ARK_RTL_PROCESS_MODULE_INFORMATION Modules[1]; /**< 可变长 */
} ARK_RTL_PROCESS_MODULES;

typedef NTSTATUS (NTAPI *PFN_NSI_ALLOCATE_AND_GET_TABLE)(
    _In_ ULONG FirstArg,
    _In_ const ARK_NPI_MODULEID* ModuleId,
    _In_ ULONG Table,
    _Out_ PVOID* KeyData,
    _In_ ULONG KeySize,
    _Out_opt_ PVOID* RwData,
    _In_ ULONG RwSize,
    _Out_opt_ PVOID* DynamicData,
    _In_ ULONG DynamicSize,
    _Out_opt_ PVOID* StaticData,
    _In_ ULONG StaticSize,
    _Out_ PULONG Count,
    _In_ ULONG Reserved);

typedef VOID (NTAPI *PFN_NSI_FREE_TABLE)(
    _In_opt_ PVOID KeyData,
    _In_opt_ PVOID RwData,
    _In_opt_ PVOID DynamicData,
    _In_opt_ PVOID StaticData);

/** @brief TCP 模块 ID：{EB004A03-9B1A-11D4-9123-0050047759BC}。 */
static const ARK_NPI_MODULEID g_TcpModuleId = {
    sizeof(ARK_NPI_MODULEID),
    0,
    1,
    { 0xEB004A03UL, 0x9B1A, 0x11D4, { 0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC } }
};

/** @brief UDP 模块 ID：{EB004A02-9B1A-11D4-9123-0050047759BC}。 */
static const ARK_NPI_MODULEID g_UdpModuleId = {
    sizeof(ARK_NPI_MODULEID),
    0,
    1,
    { 0xEB004A02UL, 0x9B1A, 0x11D4, { 0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC } }
};

/**
 * @brief 按 ASCII 比较两个 C 字符串是否相等。
 * @param left 左侧字符串。
 * @param right 右侧字符串。
 * @return 相等返回 TRUE。
 * @irql PASSIVE_LEVEL
 */
static BOOLEAN ArkStringEquals(
    _In_ PCSTR left,
    _In_ PCSTR right
) {
    SIZE_T index = 0;
    if (left == NULL || right == NULL) {
        return FALSE;
    }
    while (left[index] != '\0' && right[index] != '\0') {
        if (left[index] != right[index]) {
            return FALSE;
        }
        index += 1;
    }
    return (BOOLEAN)(left[index] == right[index]);
}

/**
 * @brief 按 ASCII 大小写不敏感比较文件短名。
 * @param left 左侧字符串。
 * @param right 右侧字符串。
 * @return 相等返回 TRUE。
 * @irql PASSIVE_LEVEL
 */
static BOOLEAN ArkStringEqualsIgnoreCase(
    _In_ PCSTR left,
    _In_ PCSTR right
) {
    SIZE_T index = 0;
    if (left == NULL || right == NULL) {
        return FALSE;
    }
    while (left[index] != '\0' && right[index] != '\0') {
        UCHAR a = (UCHAR)left[index];
        UCHAR b = (UCHAR)right[index];
        if (a >= 'A' && a <= 'Z') {
            a = (UCHAR)(a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'Z') {
            b = (UCHAR)(b - 'A' + 'a');
        }
        if (a != b) {
            return FALSE;
        }
        index += 1;
    }
    return (BOOLEAN)(left[index] == right[index]);
}

/**
 * @brief 在已映射 PE 映像中按导出名解析函数地址。
 * @param imageBase 映像基址。
 * @param exportName 导出名（ANSI）。
 * @return 成功返回函数地址，失败返回 NULL。
 * @irql PASSIVE_LEVEL
 */
static PVOID ArkGetExportAddress(
    _In_ PVOID imageBase,
    _In_ PCSTR exportName
) {
    PIMAGE_DOS_HEADER dosHeader = NULL;
    PIMAGE_NT_HEADERS ntHeaders = NULL;
    PIMAGE_DATA_DIRECTORY exportDirInfo = NULL;
    PIMAGE_EXPORT_DIRECTORY exportDir = NULL;
    PULONG nameRvas = NULL;
    PULONG funcRvas = NULL;
    PUSHORT ordinals = NULL;
    ULONG index = 0;
    if (imageBase == NULL || exportName == NULL || exportName[0] == '\0') {
        return NULL;
    }
    dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)imageBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }
    exportDirInfo = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDirInfo->VirtualAddress == 0 || exportDirInfo->Size == 0) {
        return NULL;
    }
    exportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)imageBase + exportDirInfo->VirtualAddress);
    nameRvas = (PULONG)((PUCHAR)imageBase + exportDir->AddressOfNames);
    funcRvas = (PULONG)((PUCHAR)imageBase + exportDir->AddressOfFunctions);
    ordinals = (PUSHORT)((PUCHAR)imageBase + exportDir->AddressOfNameOrdinals);
    for (index = 0; index < exportDir->NumberOfNames; ++index) {
        PCSTR currentName = (PCSTR)((PUCHAR)imageBase + nameRvas[index]);
        if (ArkStringEquals(currentName, exportName)) {
            USHORT ordinal = ordinals[index];
            ULONG funcRva = funcRvas[ordinal];
            if (funcRva == 0) {
                return NULL;
            }
            return (PVOID)((PUCHAR)imageBase + funcRva);
        }
    }
    return NULL;
}

/**
 * @brief 定位 netio.sys 映像基址。
 * @param imageBase 输出映像基址。
 * @return 成功返回 STATUS_SUCCESS。
 * @irql PASSIVE_LEVEL
 */
static NTSTATUS ArkFindNetioBase(
    _Out_ PVOID* imageBase
) {
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bufferSize = 0;
    ULONG returnLength = 0;
    ARK_RTL_PROCESS_MODULES* modules = NULL;
    ULONG index = 0;
    if (imageBase == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *imageBase = NULL;
    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &returnLength);
    if (status != STATUS_INFO_LENGTH_MISMATCH || returnLength == 0) {
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    }
    bufferSize = returnLength + 0x1000UL;
#pragma warning(push)
#pragma warning(disable: 4996)
    modules = (ARK_RTL_PROCESS_MODULES*)ExAllocatePoolWithTag(
        NonPagedPool,
        bufferSize,
        ARK_PORT_TAG);
#pragma warning(pop)
    if (modules == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = ZwQuerySystemInformation(SystemModuleInformation, modules, bufferSize, &returnLength);
    if (!NT_SUCCESS(status)) {
        ExFreePool(modules);
        return status;
    }
    for (index = 0; index < modules->NumberOfModules; ++index) {
        PCHAR fileName = (PCHAR)&modules->Modules[index].FullPathName[
            modules->Modules[index].OffsetToFileName];
        if (ArkStringEqualsIgnoreCase(fileName, "netio.sys")) {
            *imageBase = modules->Modules[index].ImageBase;
            break;
        }
    }
    ExFreePool(modules);
    if (*imageBase == NULL) {
        return STATUS_NOT_FOUND;
    }
    return STATUS_SUCCESS;
}

/**
 * @brief 解析 netio NSI 分配/释放函数指针。
 * @param allocateFn 输出 NsiAllocateAndGetTable。
 * @param freeFn 输出 NsiFreeTable。
 * @return 成功返回 STATUS_SUCCESS。
 * @irql PASSIVE_LEVEL
 */
static NTSTATUS ArkResolveNsiApis(
    _Out_ PFN_NSI_ALLOCATE_AND_GET_TABLE* allocateFn,
    _Out_ PFN_NSI_FREE_TABLE* freeFn
) {
    NTSTATUS status = STATUS_SUCCESS;
    PVOID netioBase = NULL;
    if (allocateFn == NULL || freeFn == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *allocateFn = NULL;
    *freeFn = NULL;
    status = ArkFindNetioBase(&netioBase);
    if (!NT_SUCCESS(status)) {
        LOGE("Find netio.sys failed: 0x%lx", status);
        return status;
    }
    *allocateFn = (PFN_NSI_ALLOCATE_AND_GET_TABLE)ArkGetExportAddress(
        netioBase,
        "NsiAllocateAndGetTable");
    *freeFn = (PFN_NSI_FREE_TABLE)ArkGetExportAddress(netioBase, "NsiFreeTable");
    if (*allocateFn == NULL || *freeFn == NULL) {
        LOGE("Resolve NSI exports failed alloc=%p free=%p", *allocateFn, *freeFn);
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    return STATUS_SUCCESS;
}

/**
 * @brief 向响应追加一条端口记录（容量不足时截断）。
 * @param response 输出响应。
 * @param entry 待追加条目。
 * @irql PASSIVE_LEVEL
 */
static VOID ArkAppendPortEntry(
    _Inout_ ARK_KERNEL_PORT_VIEWS_RESPONSE* response,
    _In_ const ARK_KERNEL_PORT_ENTRY* entry
) {
    if (response == NULL || entry == NULL) {
        return;
    }
    if (response->EntryCount >= ARK_MAX_PORT_ENTRIES) {
        return;
    }
    response->Entries[response->EntryCount] = *entry;
    response->EntryCount += 1UL;
}

/**
 * @brief 枚举 TCP 全表并写入响应。
 * @param allocateFn NsiAllocateAndGetTable。
 * @param freeFn NsiFreeTable。
 * @param response 输出响应。
 * @return 成功返回 STATUS_SUCCESS（无条目也算成功）。
 * @irql PASSIVE_LEVEL
 */
static NTSTATUS ArkEnumerateTcpPorts(
    _In_ PFN_NSI_ALLOCATE_AND_GET_TABLE allocateFn,
    _In_ PFN_NSI_FREE_TABLE freeFn,
    _Inout_ ARK_KERNEL_PORT_VIEWS_RESPONSE* response
) {
    NTSTATUS status = STATUS_SUCCESS;
    PVOID addrTable = NULL;
    PVOID stateTable = NULL;
    PVOID ownerTable = NULL;
    ULONG count = 0;
    ULONG index = 0;
    status = allocateFn(
        1UL,
        &g_TcpModuleId,
        ARK_NSI_TCP_ALL_TABLE,
        &addrTable,
        ARK_NSI_ADDR_ENTRY_SIZE,
        NULL,
        0UL,
        &stateTable,
        ARK_NSI_STATE_ENTRY_SIZE,
        &ownerTable,
        ARK_NSI_OWNER_ENTRY_SIZE,
        &count,
        0UL);
    if (!NT_SUCCESS(status)) {
        LOGE("NsiAllocateAndGetTable(TCP) failed: 0x%lx", status);
        return status;
    }
    for (index = 0; index < count; ++index) {
        const ARK_NSI_ADDR_ENTRY* addrEntry =
            &((const ARK_NSI_ADDR_ENTRY*)addrTable)[index];
        const ARK_NSI_STATE_ENTRY* stateEntry =
            &((const ARK_NSI_STATE_ENTRY*)stateTable)[index];
        const ARK_NSI_OWNER_ENTRY* ownerEntry =
            &((const ARK_NSI_OWNER_ENTRY*)ownerTable)[index];
        ARK_KERNEL_PORT_ENTRY portEntry = { 0 };
        if (addrEntry->Family != 2) {
            continue;
        }
        portEntry.Protocol = ARK_PORT_PROTO_TCP;
        portEntry.State = stateEntry->State;
        portEntry.OwningPid = ownerEntry->OwningPid;
        portEntry.ViewFlags = ARK_FLAG_VIEW_PORT_TCP;
        portEntry.LocalAddr = addrEntry->LocalAddr;
        portEntry.RemoteAddr = addrEntry->RemoteAddr;
        portEntry.LocalPort = ARK_HTONS(addrEntry->LocalPort);
        portEntry.RemotePort = ARK_HTONS(addrEntry->RemotePort);
        ArkAppendPortEntry(response, &portEntry);
        response->TcpCount += 1UL;
    }
    freeFn(addrTable, NULL, stateTable, ownerTable);
    return STATUS_SUCCESS;
}

/**
 * @brief 枚举 UDP 端点表并写入响应。
 * @param allocateFn NsiAllocateAndGetTable。
 * @param freeFn NsiFreeTable。
 * @param response 输出响应。
 * @return 成功返回 STATUS_SUCCESS（无条目也算成功）。
 * @irql PASSIVE_LEVEL
 */
static NTSTATUS ArkEnumerateUdpPorts(
    _In_ PFN_NSI_ALLOCATE_AND_GET_TABLE allocateFn,
    _In_ PFN_NSI_FREE_TABLE freeFn,
    _Inout_ ARK_KERNEL_PORT_VIEWS_RESPONSE* response
) {
    NTSTATUS status = STATUS_SUCCESS;
    PVOID addrTable = NULL;
    PVOID ownerTable = NULL;
    ULONG count = 0;
    ULONG index = 0;
    status = allocateFn(
        1UL,
        &g_UdpModuleId,
        ARK_NSI_UDP_ENDPOINT_TABLE,
        &addrTable,
        ARK_NSI_ADDR_ENTRY_SIZE,
        NULL,
        0UL,
        NULL,
        0UL,
        &ownerTable,
        ARK_NSI_UDP_OWNER_SIZE,
        &count,
        0UL);
    if (!NT_SUCCESS(status)) {
        LOGE("NsiAllocateAndGetTable(UDP) failed: 0x%lx", status);
        return status;
    }
    for (index = 0; index < count; ++index) {
        const ARK_NSI_ADDR_ENTRY* addrEntry =
            &((const ARK_NSI_ADDR_ENTRY*)addrTable)[index];
        const ARK_NSI_OWNER_ENTRY* ownerEntry =
            &((const ARK_NSI_OWNER_ENTRY*)ownerTable)[index];
        ARK_KERNEL_PORT_ENTRY portEntry = { 0 };
        if (addrEntry->Family != 2) {
            continue;
        }
        portEntry.Protocol = ARK_PORT_PROTO_UDP;
        portEntry.State = 0UL;
        portEntry.OwningPid = ownerEntry->OwningPid;
        portEntry.ViewFlags = ARK_FLAG_VIEW_PORT_UDP;
        portEntry.LocalAddr = addrEntry->LocalAddr;
        portEntry.RemoteAddr = 0UL;
        portEntry.LocalPort = ARK_HTONS(addrEntry->LocalPort);
        portEntry.RemotePort = 0;
        ArkAppendPortEntry(response, &portEntry);
        response->UdpCount += 1UL;
    }
    freeFn(addrTable, NULL, NULL, ownerTable);
    return STATUS_SUCCESS;
}

/**
 * @brief 从 SOCKADDR_IN 提取 IPv4 与端口。
 * @param buffer 地址缓冲。
 * @param bufferLength 缓冲长度。
 * @param ipv4NetworkOrder 输出 IPv4（网络字节序）。
 * @param portHostOrder 输出端口（主机字节序）。
 * @return 解析成功返回 TRUE。
 * @irql PASSIVE_LEVEL
 */
static BOOLEAN ArkParseSockaddrIn(
    _In_reads_bytes_(bufferLength) PVOID buffer,
    _In_ ULONG bufferLength,
    _Out_ PULONG ipv4NetworkOrder,
    _Out_ PUSHORT portHostOrder
) {
    const ARK_SOCKADDR_IN* sockaddrIn = NULL;
    if (buffer == NULL || ipv4NetworkOrder == NULL || portHostOrder == NULL) {
        return FALSE;
    }
    if (bufferLength < sizeof(ARK_SOCKADDR_IN)) {
        return FALSE;
    }
    sockaddrIn = (const ARK_SOCKADDR_IN*)buffer;
    if (sockaddrIn->sin_family != ARK_AF_INET) {
        return FALSE;
    }
    *ipv4NetworkOrder = sockaddrIn->sin_addr;
    *portHostOrder = ARK_HTONS(sockaddrIn->sin_port);
    return TRUE;
}

/**
 * @brief 解析 AFD GET_ADDRESS / GET_REMOTE_ADDRESS 输出（TLI 或 TDI 布局）。
 * @param buffer AFD 输出缓冲。
 * @param bufferLength 缓冲长度。
 * @param ipv4NetworkOrder 输出 IPv4（网络字节序）。
 * @param portHostOrder 输出端口（主机字节序）。
 * @return 解析成功返回 TRUE。
 * @irql PASSIVE_LEVEL
 */
static BOOLEAN ArkParseAfdAddressBuffer(
    _In_reads_bytes_(bufferLength) PUCHAR buffer,
    _In_ ULONG bufferLength,
    _Out_ PULONG ipv4NetworkOrder,
    _Out_ PUSHORT portHostOrder
) {
    USHORT family = 0;
    const ARK_TDI_ADDRESS_INFO* tdiInfo = NULL;
    const ARK_TA_ADDRESS* taAddress = NULL;
    const ARK_TDI_ADDRESS_IP* tdiIp = NULL;
    if (buffer == NULL || ipv4NetworkOrder == NULL || portHostOrder == NULL) {
        return FALSE;
    }
    if (bufferLength < sizeof(USHORT)) {
        return FALSE;
    }
    family = *(const USHORT*)buffer;
    if (family == ARK_AF_INET) {
        return ArkParseSockaddrIn(buffer, bufferLength, ipv4NetworkOrder, portHostOrder);
    }
    if (bufferLength < FIELD_OFFSET(ARK_TDI_ADDRESS_INFO, Address.Address[0].Address) + sizeof(ARK_TDI_ADDRESS_IP)) {
        return FALSE;
    }
    tdiInfo = (const ARK_TDI_ADDRESS_INFO*)buffer;
    if (tdiInfo->Address.TAAddressCount == 0UL) {
        return FALSE;
    }
    taAddress = &tdiInfo->Address.Address[0];
    if (taAddress->AddressType != ARK_TDI_ADDRESS_TYPE_IP) {
        return FALSE;
    }
    if (taAddress->AddressLength < sizeof(ARK_TDI_ADDRESS_IP)) {
        return FALSE;
    }
    if (bufferLength < FIELD_OFFSET(ARK_TDI_ADDRESS_INFO, Address.Address[0].Address) +
        (ULONG)taAddress->AddressLength) {
        return FALSE;
    }
    tdiIp = (const ARK_TDI_ADDRESS_IP*)taAddress->Address;
    *ipv4NetworkOrder = tdiIp->in_addr;
    *portHostOrder = ARK_HTONS(tdiIp->sin_port);
    return TRUE;
}

/**
 * @brief 打开 AFD 端点句柄：优先 ObOpenObjectByPointer，失败则 ZwDuplicateObject。
 * @param fileObject 句柄快照中的 FILE_OBJECT。
 * @param pid 持有句柄的进程 PID。
 * @param handleValue 用户态句柄值。
 * @param afdHandle 输出内核句柄（OBJ_KERNEL_HANDLE）。
 * @return 成功返回 STATUS_SUCCESS。
 * @irql PASSIVE_LEVEL
 */
static NTSTATUS ArkOpenAfdHandle(
    _In_opt_ PVOID fileObject,
    _In_ ULONG pid,
    _In_ USHORT handleValue,
    _Out_ PHANDLE afdHandle
) {
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE processHandle = NULL;
    OBJECT_ATTRIBUTES objectAttributes = { 0 };
    CLIENT_ID clientId = { 0 };
    if (afdHandle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *afdHandle = NULL;
    if (fileObject != NULL && IoFileObjectType != NULL && *IoFileObjectType != NULL) {
		// 优先尝试 ObOpenObjectByPointer（内核对象指针已知时更安全）
        status = ObOpenObjectByPointer(
            fileObject,
            OBJ_KERNEL_HANDLE,
            NULL,
            FILE_READ_DATA | SYNCHRONIZE,
            *IoFileObjectType,
            KernelMode,
            afdHandle);
        if (NT_SUCCESS(status)) {
            return status;
        }
    }
    if (pid == 0UL || handleValue == 0) {
        return STATUS_INVALID_HANDLE;
    }
    InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    clientId.UniqueThread = NULL;
	// ZwOpenProcess 需要 PROCESS_DUP_HANDLE 权限才能成功打开目标进程句柄
    status = ZwOpenProcess(&processHandle, PROCESS_DUP_HANDLE, &objectAttributes, &clientId);
    if (!NT_SUCCESS(status)) {
        return status;
    }
	// ZwDuplicateObject 将目标进程的 AFD 句柄复制到当前内核进程
    status = ZwDuplicateObject(
        processHandle,
        (HANDLE)(ULONG_PTR)handleValue,
        NtCurrentProcess(),
        afdHandle,
        0,
        0,
        DUPLICATE_SAME_ACCESS);
    ZwClose(processHandle);
    return status;
}

/**
 * @brief 对 AFD 句柄发送 IOCTL。
 * @irql PASSIVE_LEVEL
 */
static NTSTATUS ArkAfdDeviceIoControl(
    _In_ HANDLE afdHandle,
    _In_ ULONG ioControlCode,
    _In_opt_ PVOID inputBuffer,
    _In_ ULONG inputLength,
    _Out_writes_bytes_(outputLength) PVOID outputBuffer,
    _In_ ULONG outputLength
) {
    IO_STATUS_BLOCK ioStatus = { 0 };
    NTSTATUS status = STATUS_SUCCESS;
    if (afdHandle == NULL || outputBuffer == NULL || outputLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    status = ZwDeviceIoControlFile(
        afdHandle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        ioControlCode,
        inputBuffer,
        inputLength,
        outputBuffer,
        outputLength);
    if (NT_SUCCESS(status)) {
        status = ioStatus.Status;
    }
    return status;
}

/**
 * @brief 通过 AFD IOCTL 查询单条套接字的本地/远端地址与协议。
 * @param afdHandle 已打开的 AFD 端点句柄。
 * @param endpoint 输出解析结果。
 * @return 至少解析到本地或远端地址时返回 STATUS_SUCCESS。
 * @irql PASSIVE_LEVEL
 */
static NTSTATUS ArkQueryAfdEndpoint(
    _In_ HANDLE afdHandle,
    _Out_ ARK_AFD_PARSED_ENDPOINT* endpoint
) {
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS remoteStatus = STATUS_SUCCESS;
    ARK_SOCK_SHARED_INFO sharedInfo = { 0 };
    UCHAR localBuffer[ARK_AFD_ADDRESS_BUFFER_BYTES] = { 0 };
    UCHAR remoteBuffer[ARK_AFD_ADDRESS_BUFFER_BYTES] = { 0 };
    if (afdHandle == NULL || endpoint == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(endpoint, sizeof(*endpoint));
	// 初始化默认值
    endpoint->Protocol = ARK_PORT_PROTO_UNKNOWN;
	// 查询套接字共享信息（协议、状态等）
    status = ArkAfdDeviceIoControl(
        afdHandle,
        ARK_IOCTL_AFD_GET_CONTEXT,
        NULL,
        0UL,
        &sharedInfo,
        sizeof(sharedInfo));
    if (NT_SUCCESS(status)) {
        endpoint->State = (ULONG)sharedInfo.State;
		// 协议映射：AFD 的 ARK_IPPROTO_TCP/UDP 转为 ARK_PORT_PROTO_TCP/UDP
        if (sharedInfo.Protocol == ARK_IPPROTO_TCP) {
            endpoint->Protocol = ARK_PORT_PROTO_TCP;
        } else if (sharedInfo.Protocol == ARK_IPPROTO_UDP) {
            endpoint->Protocol = ARK_PORT_PROTO_UDP;
        }
    }
	// 查询本地地址
    status = ArkAfdDeviceIoControl(
        afdHandle,
        ARK_IOCTL_AFD_GET_ADDRESS,
        NULL,
        0UL,
        localBuffer,
        sizeof(localBuffer));
    if (NT_SUCCESS(status)) {
		// 解析 AFD 输出缓冲为 IPv4 + 端口
        endpoint->HasLocal = ArkParseAfdAddressBuffer(
            localBuffer,
            sizeof(localBuffer),
            &endpoint->LocalAddr,
            &endpoint->LocalPort);
    }
	// 查询远端地址
    remoteStatus = ArkAfdDeviceIoControl(
        afdHandle,
        ARK_IOCTL_AFD_GET_REMOTE_ADDRESS,
        NULL,
        0UL,
        remoteBuffer,
        sizeof(remoteBuffer));
    if (NT_SUCCESS(remoteStatus)) {
		// 解析 AFD 输出缓冲为 IPv4 + 端口
        endpoint->HasRemote = ArkParseAfdAddressBuffer(
            remoteBuffer,
            sizeof(remoteBuffer),
            &endpoint->RemoteAddr,
            &endpoint->RemotePort);
    }
    if (endpoint->HasLocal || endpoint->HasRemote) {
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_FOUND;
}

/**
 * @brief 判断对象名是否以 \\Device\\Afd 为前缀（含 \\Device\\Afd\\Endpoint 等）。
 * @param objectName 对象名称。
 * @return 匹配返回 TRUE。
 * @irql PASSIVE_LEVEL
 */
static BOOLEAN ArkIsAfdDeviceName(
    _In_ const UNICODE_STRING* objectName
) {
    UNICODE_STRING afdPrefix;
    UNICODE_STRING left = { 0 };
    if (objectName == NULL || objectName->Buffer == NULL || objectName->Length == 0) {
        return FALSE;
    }
    RtlInitUnicodeString(&afdPrefix, L"\\Device\\Afd");
    if (objectName->Length < afdPrefix.Length) {
        return FALSE;
    }
    left.Buffer = objectName->Buffer;
    left.Length = afdPrefix.Length;
    left.MaximumLength = afdPrefix.Length;
    return (BOOLEAN)(RtlCompareUnicodeString(&left, &afdPrefix, TRUE) == 0);
}

/**
 * @brief 在 AFD PID 槽位表中查找或新增 PID。
 * @param slots 槽位数组。
 * @param slotCount 当前槽位数（输入输出）。
 * @param maxSlots 槽位容量。
 * @param pid 目标 PID。
 * @return 槽位指针；容量满且未命中时返回 NULL。
 * @irql PASSIVE_LEVEL
 */
static ARK_AFD_PID_SLOT* ArkFindOrAddAfdPidSlot(
    _Inout_updates_(maxSlots) ARK_AFD_PID_SLOT* slots,
    _Inout_ PULONG slotCount,
    _In_ ULONG maxSlots,
    _In_ ULONG pid
) {
    ULONG index = 0;
    if (slots == NULL || slotCount == NULL || pid == 0UL) {
        return NULL;
    }
    for (index = 0; index < *slotCount; ++index) {
        if (slots[index].Pid == pid) {
            return &slots[index];
        }
    }
    if (*slotCount >= maxSlots) {
        return NULL;
    }
    slots[*slotCount].Pid = pid;
    slots[*slotCount].HandleCount = 0UL;
    slots[*slotCount].FirstObject = 0ULL;
    *slotCount += 1UL;
    return &slots[*slotCount - 1UL];
}

/**
 * @brief 查询系统句柄快照（供 AFD View B 使用）。
 * @param handleInfo 输出句柄信息缓冲（调用方 ExFreePoolWithTag）。
 * @return 成功返回 STATUS_SUCCESS。
 * @irql PASSIVE_LEVEL
 */
static NTSTATUS ArkQuerySystemHandleInformation(
    _Outptr_result_maybenull_ ARK_PORT_SYSTEM_HANDLE_INFORMATION** handleInfo
) {
    ULONG bufferSize = 0;
    ULONG returnLength = 0;
    NTSTATUS status = STATUS_SUCCESS;
    ARK_PORT_SYSTEM_HANDLE_INFORMATION* buffer = NULL;
    ULONG retryCount = 0;
    if (handleInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *handleInfo = NULL;
    status = ZwQuerySystemInformation(SystemHandleInformation, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        LOGE("AFD handle size probe failed: 0x%lx", status);
        return status;
    }
    do {
        if (buffer != NULL) {
            ExFreePoolWithTag(buffer, ARK_PORT_TAG);
            buffer = NULL;
        }
        if (returnLength > bufferSize) {
            bufferSize = returnLength;
        }
        bufferSize += PAGE_SIZE;
#pragma warning(push)
#pragma warning(disable: 4996)
        buffer = (ARK_PORT_SYSTEM_HANDLE_INFORMATION*)ExAllocatePoolWithTag(
            NonPagedPool,
            bufferSize,
            ARK_PORT_TAG);
#pragma warning(pop)
        if (buffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(buffer, bufferSize);
        status = ZwQuerySystemInformation(
            SystemHandleInformation,
            buffer,
            bufferSize,
            &returnLength);
        retryCount += 1UL;
    } while (status == STATUS_INFO_LENGTH_MISMATCH && retryCount < 8UL);
    if (!NT_SUCCESS(status)) {
        LOGE("AFD ZwQuerySystemInformation failed: 0x%lx", status);
        ExFreePoolWithTag(buffer, ARK_PORT_TAG);
        return status;
    }
    *handleInfo = buffer;
    return STATUS_SUCCESS;
}

/**
 * @brief View B：枚举系统句柄中 \\Device\\Afd 文件对象，逐句柄 IOCTL 解析地址。
 *
 * 对每个 AFD 句柄尝试 ObOpenObjectByPointer / ZwDuplicateObject 后调用
 * IOCTL_AFD_GET_CONTEXT、GET_ADDRESS、GET_REMOTE_ADDRESS 解析五元组。
 * AfdCount 为持有 AFD 句柄的去重 PID 数；AfdHandleCount 为扫描到的 AFD 句柄总数。
 *
 * @param response 输出响应。
 * @return 成功返回 STATUS_SUCCESS（无命中也算成功）。
 * @irql PASSIVE_LEVEL
 */
static NTSTATUS ArkEnumerateAfdHandleView(
    _Inout_ ARK_KERNEL_PORT_VIEWS_RESPONSE* response
) {
    NTSTATUS status = STATUS_SUCCESS;
    ARK_PORT_SYSTEM_HANDLE_INFORMATION* handleInfo = NULL;
    POBJECT_NAME_INFORMATION nameInfo = NULL;
    ARK_AFD_PID_SLOT* pidSlots = NULL;
    ULONG pidSlotCount = 0;
    ULONG index = 0;
    ULONG nameReturnLength = 0;
    ULONG afdHandleScanned = 0UL;
    ULONG afdAddressQueries = 0UL;
    ULONG afdAddressHits = 0UL;
    if (response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (IoFileObjectType == NULL || *IoFileObjectType == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
#pragma warning(push)
#pragma warning(disable: 4996)
    nameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(
        NonPagedPool,
        ARK_AFD_NAME_INFO_BYTES,
        ARK_PORT_TAG);
    pidSlots = (ARK_AFD_PID_SLOT*)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(ARK_AFD_PID_SLOT) * ARK_AFD_MAX_PID_SLOTS,
        ARK_PORT_TAG);
#pragma warning(pop)
    if (nameInfo == NULL || pidSlots == NULL) {
        if (nameInfo != NULL) {
            ExFreePoolWithTag(nameInfo, ARK_PORT_TAG);
        }
        if (pidSlots != NULL) {
            ExFreePoolWithTag(pidSlots, ARK_PORT_TAG);
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(pidSlots, sizeof(ARK_AFD_PID_SLOT) * ARK_AFD_MAX_PID_SLOTS);
    status = ArkQuerySystemHandleInformation(&handleInfo);
    if (!NT_SUCCESS(status) || handleInfo == NULL) {
        ExFreePoolWithTag(nameInfo, ARK_PORT_TAG);
        ExFreePoolWithTag(pidSlots, ARK_PORT_TAG);
        return status;
    }
    for (index = 0; index < handleInfo->NumberOfHandles; ++index) {
        PVOID object = handleInfo->Handles[index].Object;
        ULONG pid = (ULONG)handleInfo->Handles[index].UniqueProcessId;
        USHORT handleValue = handleInfo->Handles[index].HandleValue;
        ARK_AFD_PID_SLOT* pidSlot = NULL;
        HANDLE afdHandle = NULL;
        ARK_AFD_PARSED_ENDPOINT endpoint = { 0 };
        ARK_KERNEL_PORT_ENTRY portEntry = { 0 };
        if (object == NULL || pid == 0UL) {
            continue;
        }
        // 引用内核对象，防止它在使用期间被意外释放
        status = ObReferenceObjectByPointer(
            object,
            FILE_READ_ATTRIBUTES,
            *IoFileObjectType,
            KernelMode);
        if (!NT_SUCCESS(status)) {
            continue;
        }
        RtlZeroMemory(nameInfo, ARK_AFD_NAME_INFO_BYTES);
        nameReturnLength = 0;
		// 查询对象名，判断是否为 AFD 设备
        status = ObQueryNameString(
            object,
            nameInfo,
            ARK_AFD_NAME_INFO_BYTES,
            &nameReturnLength);
        if (!NT_SUCCESS(status) || !ArkIsAfdDeviceName(&nameInfo->Name)) {
            ObDereferenceObject(object);
            continue;
        }
		// 统计扫描到的 AFD 句柄总数
        afdHandleScanned += 1UL;
		// 统计持有 AFD 句柄的去重 PID
        pidSlot = ArkFindOrAddAfdPidSlot(pidSlots, &pidSlotCount, ARK_AFD_MAX_PID_SLOTS, pid);
        if (pidSlot != NULL) {
            pidSlot->HandleCount += 1UL;
            if (pidSlot->FirstObject == 0ULL) {
                pidSlot->FirstObject = (ULONG64)(ULONG_PTR)object;
            }
        }
        if (afdAddressQueries >= ARK_AFD_MAX_ADDRESS_QUERIES) {
            ObDereferenceObject(object);
            continue;
        }
        if (response->EntryCount >= ARK_MAX_PORT_ENTRIES) {
            ObDereferenceObject(object);
            continue;
        }
        // 查询 AFD 句柄的地址信息
        afdAddressQueries += 1UL;
        status = ArkOpenAfdHandle(object, pid, handleValue, &afdHandle);
        if (NT_SUCCESS(status) && afdHandle != NULL) {
            status = ArkQueryAfdEndpoint(afdHandle, &endpoint);
            ZwClose(afdHandle);
            afdHandle = NULL;
        }
        ObDereferenceObject(object);
        if (!NT_SUCCESS(status)) {
            continue;
        }
        afdAddressHits += 1UL;
        portEntry.Protocol = endpoint.Protocol;
        portEntry.State = endpoint.State;
        portEntry.OwningPid = pid;
        portEntry.ViewFlags = ARK_FLAG_VIEW_PORT_AFD;
        portEntry.LocalAddr = endpoint.LocalAddr;
        portEntry.RemoteAddr = endpoint.RemoteAddr;
        portEntry.LocalPort = endpoint.LocalPort;
        portEntry.RemotePort = endpoint.RemotePort;
        portEntry.EndpointObject = (ULONG64)(ULONG_PTR)object;
        ArkAppendPortEntry(response, &portEntry);
    }
    response->AfdCount = pidSlotCount;
    response->AfdHandleCount = afdHandleScanned;
    {
        ULONG handleCount = handleInfo->NumberOfHandles;
        ExFreePoolWithTag(handleInfo, ARK_PORT_TAG);
        ExFreePoolWithTag(nameInfo, ARK_PORT_TAG);
        ExFreePoolWithTag(pidSlots, ARK_PORT_TAG);
        LOGI("AFD view handles=%lu scanned=%lu queries=%lu addrHits=%lu pids=%lu entries=%lu",
             handleCount,
             afdHandleScanned,
             afdAddressQueries,
             afdAddressHits,
             response->AfdCount,
             response->EntryCount);
    }
    return STATUS_SUCCESS;
}

/**
 * @brief 收集内核端口视图（实现）。
 * @param response 输出缓冲区。
 * @return 成功返回 STATUS_SUCCESS。
 * @irql PASSIVE_LEVEL
 */
NTSTATUS QueryKernelPortViews(
    _Out_ ARK_KERNEL_PORT_VIEWS_RESPONSE* response
) {
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS afdStatus = STATUS_SUCCESS;
    NTSTATUS tcpStatus = STATUS_SUCCESS;
    NTSTATUS udpStatus = STATUS_SUCCESS;
    PFN_NSI_ALLOCATE_AND_GET_TABLE allocateFn = NULL;
    PFN_NSI_FREE_TABLE freeFn = NULL;
    if (response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    RtlZeroMemory(response, sizeof(*response));
    afdStatus = ArkEnumerateAfdHandleView(response);
    status = ArkResolveNsiApis(&allocateFn, &freeFn);
    if (!NT_SUCCESS(status)) {
        if (NT_SUCCESS(afdStatus) && response->AfdCount > 0UL) {
            response->Status = (ULONG)STATUS_SUCCESS;
            LOGI("Port views AFD-only afdPids=%lu (NSI resolve failed: 0x%lx)",
                 response->AfdCount,
                 status);
            return STATUS_SUCCESS;
        }
        response->Status = (ULONG)status;
        return status;
    }
    tcpStatus = ArkEnumerateTcpPorts(allocateFn, freeFn, response);
    udpStatus = ArkEnumerateUdpPorts(allocateFn, freeFn, response);
    if (!NT_SUCCESS(afdStatus) && !NT_SUCCESS(tcpStatus) && !NT_SUCCESS(udpStatus)) {
        status = tcpStatus;
        response->Status = (ULONG)status;
        return status;
    }
    response->Status = (ULONG)STATUS_SUCCESS;
    LOGI("Port views ready afdPids=%lu tcp=%lu udp=%lu total=%lu",
         response->AfdCount,
         response->TcpCount,
         response->UdpCount,
         response->EntryCount);
    return STATUS_SUCCESS;
}
