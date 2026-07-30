#include "DetectHiddenModule.h"
#include "undocument.h"
#include "Log.h"

#include <ntimage.h>
#include <ntstrsafe.h>

/** @brief BigPool 残留：可接受的最大节区数量上界。 */
#define ARK_BIGPOOL_MAX_SECTIONS        96UL
/** @brief BigPool 残留：PE 映像最小 SizeOfImage（覆盖至少一页）。 */
#define ARK_BIGPOOL_MIN_IMAGE_SIZE      0x1000UL
/** @brief BigPool 与已加载模块指纹比对时最多扫描的 View A 条目数。 */
#define ARK_BIGPOOL_DUP_SCAN_MAX        512UL

typedef BOOLEAN (*PFN_MM_IS_SESSION_ADDRESS)(_In_ PVOID VirtualAddress);

/** @brief DRIVER_OBJECT 类型指针，用于 ObReferenceObjectByName。 */
extern POBJECT_TYPE* IoDriverObjectType;

/**
 * @brief 模块收集累加器，合并 View A/B/C 扫描结果。
 */
typedef struct _ARK_MODULE_ACCUMULATOR {
    ARK_KERNEL_MODULE_ENTRY* entries; /**< 模块条目数组 */
    ULONG entryCount;                 /**< 当前条目数 */
    ULONG sectionCount;               /**< View A 命中计数 */
    ULONG driverCount;                /**< View B 命中计数 */
    ULONG residualCount;              /**< View C：BigPool 命中计数 */
} ARK_MODULE_ACCUMULATOR;

/**
 * @brief SystemBigPoolInformation 单条记录。
 */
typedef struct _ARK_SYSTEM_BIGPOOL_ENTRY {
    PVOID VirtualAddress; /**< 池虚址；最低位表示 NonPaged */
    SIZE_T SizeInBytes;   /**< 分配大小 */
    ULONG TagUlong;       /**< PoolTag 整型 */
} ARK_SYSTEM_BIGPOOL_ENTRY;

/**
 * @brief SystemBigPoolInformation 返回缓冲区头。
 */
typedef struct _ARK_SYSTEM_BIGPOOL_INFORMATION {
    ULONG Count;                              /**< 条目数 */
    ARK_SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1]; /**< 可变长数组 */
} ARK_SYSTEM_BIGPOOL_INFORMATION;

/**
 * @brief KLDR_DATA_TABLE_ENTRY（仅保留枚举所需字段）。
 */
typedef struct _ARK_KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks; /**< PsLoadedModuleList 双向链表节点 */
    PVOID ExceptionTable;        /**< 异常表 */
    ULONG ExceptionTableSize;    /**< 异常表大小 */
    PVOID GpValue;               /**< GP 值 */
    PVOID NonPagedDebugInfo;     /**< 非分页调试信息 */
    PVOID DllBase;               /**< 映像基址 */
    PVOID EntryPoint;            /**< 入口点 */
    ULONG SizeOfImage;           /**< 映像大小 */
    UNICODE_STRING FullDllName;  /**< 完整路径 */
    UNICODE_STRING BaseDllName;  /**< 短文件名 */
} ARK_KLDR_DATA_TABLE_ENTRY, *PARK_KLDR_DATA_TABLE_ENTRY;

/**
 * @brief OBJECT_DIRECTORY_INFORMATION（ZwQueryDirectoryObject 返回项）。
 */
typedef struct _ARK_OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;     /**< 对象名 */
    UNICODE_STRING TypeName; /**< 类型名 */
} ARK_OBJECT_DIRECTORY_INFORMATION;

NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(
    _In_ PUNICODE_STRING ObjectName,
    _In_ ULONG Attributes,
    _In_opt_ PACCESS_STATE AccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID ParseContext,
    _Out_ PVOID* Object);

NTSYSAPI NTSTATUS NTAPI ZwOpenDirectoryObject(
    _Out_ PHANDLE DirectoryHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI NTSTATUS NTAPI ZwQueryDirectoryObject(
    _In_ HANDLE DirectoryHandle,
    _Out_opt_ PVOID Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_ BOOLEAN RestartScan,
    _Inout_ PULONG Context,
    _Out_opt_ PULONG ReturnLength);

/**
 * @brief 将 UNICODE_STRING 安全转换为 ANSI 并写入定长缓冲区。
 * @param dest 目标 ANSI 缓冲区。
 * @param destBytes 目标缓冲区字节数。
 * @param source 源 UNICODE_STRING，可为 NULL。
 * @irql PASSIVE_LEVEL
 */
static VOID CopyUnicodeToAnsi(
    _Out_writes_bytes_(destBytes) CHAR* dest,
    _In_ SIZE_T destBytes,
    _In_opt_ PCUNICODE_STRING source
) {
    ANSI_STRING ansiString = { 0 };
    NTSTATUS status = STATUS_SUCCESS;
    if (dest == NULL || destBytes == 0) {
        return;
    }
    RtlZeroMemory(dest, destBytes);
    if (source == NULL || source->Buffer == NULL || source->Length == 0) {
        RtlStringCbCopyA(dest, destBytes, "unknown");
        return;
    }
    status = RtlUnicodeStringToAnsiString(&ansiString, source, TRUE);
    if (!NT_SUCCESS(status) || ansiString.Buffer == NULL) {
        RtlStringCbCopyA(dest, destBytes, "unknown");
        return;
    }
    RtlStringCbCopyA(dest, destBytes, ansiString.Buffer);
    RtlFreeAnsiString(&ansiString);
}

/**
 * @brief 大小写不敏感比较两个 ANSI 字符串。
 * @param left 左操作数。
 * @param right 右操作数。
 * @return 相等返回 0，否则返回非 0。
 */
static int CompareAnsiNoCase(
    _In_opt_ const CHAR* left,
    _In_opt_ const CHAR* right
) {
    CHAR leftChar = 0;
    CHAR rightChar = 0;
    if (left == NULL || right == NULL) {
        return (left == right) ? 0 : 1;
    }
    while (*left != '\0' && *right != '\0') {
        leftChar = *left;
        rightChar = *right;
        if (leftChar >= 'A' && leftChar <= 'Z') {
            leftChar = (CHAR)(leftChar - 'A' + 'a');
        }
        if (rightChar >= 'A' && rightChar <= 'Z') {
            rightChar = (CHAR)(rightChar - 'A' + 'a');
        }
        if (leftChar != rightChar) {
            return (int)(leftChar - rightChar);
        }
        left++;
        right++;
    }
    return (int)(*left - *right);
}

/**
 * @brief 扫描循环中周期性让出 CPU，降低长时间占用导致的卡顿。
 * @param loopIndex 当前循环序号，每 ARK_SCAN_YIELD_INTERVAL 次休眠一次。
 * @irql PASSIVE_LEVEL
 */
static VOID YieldScanProgress(_In_ ULONG loopIndex) {
    LARGE_INTEGER interval = { 0 };
    if (loopIndex == 0UL || (loopIndex % ARK_SCAN_YIELD_INTERVAL) != 0UL) {
        return;
    }
    interval.QuadPart = -10LL * 1000LL;
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

/**
 * @brief 按 ImageBase 查找累加器中已有条目下标。
 * @param accumulator 累加器。
 * @param imageBase 映像基址，0 视为无效。
 * @return 找到返回下标，否则返回 -1。
 */
static LONG FindModuleByBase(
    _In_ const ARK_MODULE_ACCUMULATOR* accumulator,
    _In_ ULONG64 imageBase
) {
    ULONG index = 0;
    if (accumulator == NULL || accumulator->entries == NULL || imageBase == 0ULL) {
        return -1;
    }
    for (index = 0; index < accumulator->entryCount; index++) {
        if (accumulator->entries[index].ImageBase == imageBase) {
            return (LONG)index;
        }
    }
    return -1;
}

/**
 * @brief 按短名（大小写不敏感）查找累加器中已有条目下标。
 * @param accumulator 累加器。
 * @param moduleName 模块短名 ANSI。
 * @return 找到返回下标，否则返回 -1。
 */
static LONG FindModuleByName(
    _In_ const ARK_MODULE_ACCUMULATOR* accumulator,
    _In_opt_ const CHAR* moduleName
) {
    ULONG index = 0;
    if (accumulator == NULL || accumulator->entries == NULL || moduleName == NULL || moduleName[0] == '\0') {
        return -1;
    }
    for (index = 0; index < accumulator->entryCount; index++) {
        if (CompareAnsiNoCase(accumulator->entries[index].ModuleName, moduleName) == 0) {
            return (LONG)index;
        }
    }
    return -1;
}

/**
 * @brief 将模块加入累加器，按 ImageBase/名称去重并合并视图标志。
 * @param accumulator 累加器（输入输出）。
 * @param viewFlag 视图标志（可含 residual 子标志）。
 * @param imageBase 映像基址；非残留采样要求非 0。
 * @param imageSize 映像大小。
 * @param driverObjectAddress DRIVER_OBJECT 地址（View B）。
 * @param moduleName 短名 ANSI。
 * @param modulePath 完整路径或残留来源标签。
 * @return STATUS_SUCCESS 或 STATUS_BUFFER_OVERFLOW。
 * @irql PASSIVE_LEVEL
 */
static NTSTATUS AddModuleToAccumulator(
    _Inout_ ARK_MODULE_ACCUMULATOR* accumulator,
    _In_ ULONG viewFlag,
    _In_ ULONG64 imageBase,
    _In_ ULONG imageSize,
    _In_ ULONG64 driverObjectAddress,
    _In_opt_ const CHAR* moduleName,
    _In_opt_ const CHAR* modulePath
) {
    LONG index = -1;
    ARK_KERNEL_MODULE_ENTRY* entry = NULL;
    const BOOLEAN isResidual = (viewFlag & ARK_FLAG_VIEW_RESIDUAL) != 0;
    if (accumulator == NULL || accumulator->entries == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (imageBase == 0ULL && !isResidual) {
        return STATUS_SUCCESS;
    }
    if (moduleName == NULL || moduleName[0] == '\0' || CompareAnsiNoCase(moduleName, "unknown") == 0) {
        return STATUS_SUCCESS;
    }
    if (imageBase != 0ULL) {
        index = FindModuleByBase(accumulator, imageBase);
    }
    if (index < 0) {
        index = FindModuleByName(accumulator, moduleName);
    }
    if (index >= 0) {
        entry = &accumulator->entries[index];
        if ((entry->ViewFlags & viewFlag) != viewFlag) {
            const ULONG oldFlags = entry->ViewFlags;
            entry->ViewFlags |= viewFlag;
            if ((oldFlags & ARK_FLAG_VIEW_SECTION) == 0 && (viewFlag & ARK_FLAG_VIEW_SECTION) != 0) {
                accumulator->sectionCount++;
            }
            if ((oldFlags & ARK_FLAG_VIEW_DRIVEROBJ) == 0 && (viewFlag & ARK_FLAG_VIEW_DRIVEROBJ) != 0) {
                accumulator->driverCount++;
            }
            if ((oldFlags & ARK_FLAG_VIEW_RESIDUAL) == 0 && (viewFlag & ARK_FLAG_VIEW_RESIDUAL) != 0) {
                accumulator->residualCount++;
            }
        }
        if (entry->ImageBase == 0ULL && imageBase != 0ULL) {
            entry->ImageBase = imageBase;
        }
        if (entry->ImageSize == 0UL && imageSize != 0UL) {
            entry->ImageSize = imageSize;
        }
        if (entry->DriverObjectAddress == 0ULL && driverObjectAddress != 0ULL) {
            entry->DriverObjectAddress = driverObjectAddress;
        }
        if ((entry->ModuleName[0] == '\0' || CompareAnsiNoCase(entry->ModuleName, "unknown") == 0)) {
            RtlStringCbCopyA(entry->ModuleName, sizeof(entry->ModuleName), moduleName);
        }
        if ((entry->ModulePath[0] == '\0' || CompareAnsiNoCase(entry->ModulePath, "unknown") == 0) &&
            modulePath != NULL && modulePath[0] != '\0') {
            RtlStringCbCopyA(entry->ModulePath, sizeof(entry->ModulePath), modulePath);
        }
        return STATUS_SUCCESS;
    }
    if (accumulator->entryCount >= ARK_MAX_MODULE_ENTRIES) {
        return STATUS_BUFFER_OVERFLOW;
    }
    entry = &accumulator->entries[accumulator->entryCount];
    RtlZeroMemory(entry, sizeof(*entry));
    entry->ViewFlags = viewFlag;
    entry->ImageBase = imageBase;
    entry->ImageSize = imageSize;
    entry->DriverObjectAddress = driverObjectAddress;
    RtlStringCbCopyA(entry->ModuleName, sizeof(entry->ModuleName), moduleName);
    if (modulePath != NULL && modulePath[0] != '\0') {
        RtlStringCbCopyA(entry->ModulePath, sizeof(entry->ModulePath), modulePath);
    } else {
        RtlStringCbCopyA(entry->ModulePath, sizeof(entry->ModulePath), "unknown");
    }
    if ((viewFlag & ARK_FLAG_VIEW_SECTION) != 0) {
        accumulator->sectionCount++;
    }
    if ((viewFlag & ARK_FLAG_VIEW_DRIVEROBJ) != 0) {
        accumulator->driverCount++;
    }
    if ((viewFlag & ARK_FLAG_VIEW_RESIDUAL) != 0) {
        accumulator->residualCount++;
    }
    accumulator->entryCount++;
    return STATUS_SUCCESS;
}

/**
 * @brief 判断 LDR 链表节点是否为有效已加载模块。
 *
 * 用于过滤 PsLoadedModuleList 头节点等非 KLDR 结构，避免 imageBase=0 误报。
 *
 * @param entry 当前按 KLDR 解释的节点。
 * @return 有效模块返回 TRUE。
 */
static BOOLEAN IsValidLdrModuleEntry(_In_opt_ const ARK_KLDR_DATA_TABLE_ENTRY* entry) {
    if (entry == NULL) {
        return FALSE;
    }
    if (entry->DllBase == NULL || entry->SizeOfImage == 0UL) {
        return FALSE;
    }
    if (entry->BaseDllName.Buffer == NULL || entry->BaseDllName.Length == 0) {
        return FALSE;
    }
    return TRUE;
}

/**
 * @brief View A：从当前驱动 DriverSection 遍历 InLoadOrderLinks。
 * @param accumulator 累加器（输入输出）。
 * @return STATUS_SUCCESS 或设备状态错误。
 * @irql PASSIVE_LEVEL
 */
static NTSTATUS CollectDriverSectionView(
    _Inout_ ARK_MODULE_ACCUMULATOR* accumulator
) {
    PARK_KLDR_DATA_TABLE_ENTRY current = NULL;
    PARK_KLDR_DATA_TABLE_ENTRY first = NULL;
    ULONG loopIndex = 0;
    CHAR moduleName[ARK_MODULE_NAME_MAX] = { 0 };
    CHAR modulePath[ARK_MODULE_PATH_MAX] = { 0 };
    if (accumulator == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (g_pMyDriverObject == NULL || g_pMyDriverObject->DriverSection == NULL) {
        LOGE("DriverSection is NULL");
        return STATUS_INVALID_DEVICE_STATE;
    }
    current = (PARK_KLDR_DATA_TABLE_ENTRY)g_pMyDriverObject->DriverSection;
    first = current;
    do {
        if (IsValidLdrModuleEntry(current)) {
            ULONG64 imageBase = (ULONG64)(ULONG_PTR)current->DllBase;
            CopyUnicodeToAnsi(moduleName, sizeof(moduleName), &current->BaseDllName);
            CopyUnicodeToAnsi(modulePath, sizeof(modulePath), &current->FullDllName);
            AddModuleToAccumulator(
                accumulator,
                ARK_FLAG_VIEW_SECTION,
                imageBase,
                current->SizeOfImage,
                0ULL,
                moduleName,
                modulePath);
        }
        loopIndex++;
        YieldScanProgress(loopIndex);
        current = (PARK_KLDR_DATA_TABLE_ENTRY)current->InLoadOrderLinks.Flink;
    } while (current != NULL && current != first && loopIndex < ARK_MAX_MODULE_ENTRIES * 2UL);
    LOGI("driver section view hits=%lu", accumulator->sectionCount);
    return STATUS_SUCCESS;
}

/**
 * @brief 构造 \\Driver\\Name 完整对象路径。
 * @param fullNameBuffer 输出宽字符缓冲。
 * @param fullNameBytes 缓冲字节数。
 * @param objectName 目录项对象名。
 * @return STATUS_SUCCESS 或长度不足等错误。
 * @irql PASSIVE_LEVEL
 */
static NTSTATUS BuildDriverObjectPath(
    _Out_writes_bytes_(fullNameBytes) WCHAR* fullNameBuffer,
    _In_ SIZE_T fullNameBytes,
    _In_ PCUNICODE_STRING objectName
) {
    SIZE_T prefixBytes = 0;
    NTSTATUS status = STATUS_SUCCESS;
    if (fullNameBuffer == NULL || objectName == NULL || objectName->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    status = RtlStringCbCopyW(fullNameBuffer, fullNameBytes, L"\\Driver\\");
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = RtlStringCbLengthW(fullNameBuffer, fullNameBytes, &prefixBytes);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if ((prefixBytes + objectName->Length + sizeof(WCHAR)) > fullNameBytes) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlCopyMemory((PUCHAR)fullNameBuffer + prefixBytes, objectName->Buffer, objectName->Length);
    *((WCHAR*)((PUCHAR)fullNameBuffer + prefixBytes + objectName->Length)) = L'\0';
    return STATUS_SUCCESS;
}

/**
 * @brief View B：枚举 \\Driver 对象目录并解析 DRIVER_OBJECT。
 * @param accumulator 累加器（输入输出）。
 * @return STATUS_SUCCESS 或打开/枚举失败状态。
 * @irql PASSIVE_LEVEL
 */
static NTSTATUS CollectDriverObjectView(
    _Inout_ ARK_MODULE_ACCUMULATOR* accumulator
) {
    UNICODE_STRING directoryName = { 0 };
    OBJECT_ATTRIBUTES objectAttributes = { 0 };
    HANDLE directoryHandle = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG context = 0;
    BOOLEAN restartScan = TRUE;
    ULONG loopIndex = 0;
    UCHAR queryBuffer[512] = { 0 };
    if (accumulator == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (IoDriverObjectType == NULL || *IoDriverObjectType == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    RtlInitUnicodeString(&directoryName, L"\\Driver");
    InitializeObjectAttributes(
        &objectAttributes,
        &directoryName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);
    status = ZwOpenDirectoryObject(&directoryHandle, DIRECTORY_QUERY, &objectAttributes);
    if (!NT_SUCCESS(status)) {
        LOGE("ZwOpenDirectoryObject(\\Driver) failed,status:%lx", status);
        return status;
    }
    for (;;) {
        ARK_OBJECT_DIRECTORY_INFORMATION* dirInfo = NULL;
        UNICODE_STRING typeDriver = { 0 };
        UNICODE_STRING fullName = { 0 };
        WCHAR fullNameBuffer[128] = { 0 };
        PDRIVER_OBJECT driverObject = NULL;
        CHAR moduleName[ARK_MODULE_NAME_MAX] = { 0 };
        CHAR modulePath[ARK_MODULE_PATH_MAX] = { 0 };
        ULONG64 imageBase = 0ULL;
        ULONG imageSize = 0UL;
        status = ZwQueryDirectoryObject(
            directoryHandle,
            queryBuffer,
            sizeof(queryBuffer),
            TRUE,
            restartScan,
            &context,
            NULL);
        restartScan = FALSE;
        if (status == STATUS_NO_MORE_ENTRIES) {
            status = STATUS_SUCCESS;
            break;
        }
        if (!NT_SUCCESS(status)) {
            LOGE("ZwQueryDirectoryObject failed,status:%lx", status);
            break;
        }
        dirInfo = (ARK_OBJECT_DIRECTORY_INFORMATION*)queryBuffer;
        if (dirInfo->Name.Buffer == NULL || dirInfo->Name.Length == 0) {
            continue;
        }
        RtlInitUnicodeString(&typeDriver, L"Driver");
        if (RtlCompareUnicodeString(&dirInfo->TypeName, &typeDriver, TRUE) != 0) {
            continue;
        }
        status = BuildDriverObjectPath(fullNameBuffer, sizeof(fullNameBuffer), &dirInfo->Name);
        if (!NT_SUCCESS(status)) {
            continue;
        }
        RtlInitUnicodeString(&fullName, fullNameBuffer);
        status = ObReferenceObjectByName(
            &fullName,
            OBJ_CASE_INSENSITIVE,
            NULL,
            0,
            *IoDriverObjectType,
            KernelMode,
            NULL,
            (PVOID*)&driverObject);
        if (!NT_SUCCESS(status) || driverObject == NULL) {
            continue;
        }
        imageBase = (ULONG64)(ULONG_PTR)driverObject->DriverStart;
        imageSize = driverObject->DriverSize;
        CopyUnicodeToAnsi(moduleName, sizeof(moduleName), &dirInfo->Name);
        if (driverObject->DriverSection != NULL) {
            PARK_KLDR_DATA_TABLE_ENTRY ldr =
                (PARK_KLDR_DATA_TABLE_ENTRY)driverObject->DriverSection;
            if (IsValidLdrModuleEntry(ldr)) {
                imageBase = (ULONG64)(ULONG_PTR)ldr->DllBase;
                imageSize = ldr->SizeOfImage;
                CopyUnicodeToAnsi(modulePath, sizeof(modulePath), &ldr->FullDllName);
                CopyUnicodeToAnsi(moduleName, sizeof(moduleName), &ldr->BaseDllName);
            } else {
                RtlStringCbCopyA(modulePath, sizeof(modulePath), "N/A");
            }
        } else {
            RtlStringCbCopyA(modulePath, sizeof(modulePath), "N/A");
        }
        AddModuleToAccumulator(
            accumulator,
            ARK_FLAG_VIEW_DRIVEROBJ,
            imageBase,
            imageSize,
            (ULONG64)(ULONG_PTR)driverObject,
            moduleName,
            modulePath);
        ObDereferenceObject(driverObject);
        loopIndex++;
        YieldScanProgress(loopIndex);
        if (accumulator->entryCount >= ARK_MAX_MODULE_ENTRIES) {
            break;
        }
    }
    ZwClose(directoryHandle);
    LOGI("driver object view hits=%lu", accumulator->driverCount);
    return STATUS_SUCCESS;
}

/**
 * @brief 释放模块累加器条目数组。
 * @param accumulator 累加器（输入输出）。
 */
static VOID FreeModuleAccumulator(_Inout_ ARK_MODULE_ACCUMULATOR* accumulator) {
    if (accumulator == NULL) {
        return;
    }
    if (accumulator->entries != NULL) {
        ExFreePoolWithTag(accumulator->entries, ARK_MODULE_TAG);
        accumulator->entries = NULL;
    }
    accumulator->entryCount = 0;
}

/**
 * @brief 初始化模块累加器并分配条目池。
 * @param accumulator 累加器（输出）。
 * @return STATUS_SUCCESS 或内存不足。
 * @irql PASSIVE_LEVEL
 */
static NTSTATUS InitModuleAccumulator(_Out_ ARK_MODULE_ACCUMULATOR* accumulator) {
    SIZE_T entryBytes = 0;
    if (accumulator == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(accumulator, sizeof(*accumulator));
    entryBytes = (SIZE_T)ARK_MAX_MODULE_ENTRIES * sizeof(ARK_KERNEL_MODULE_ENTRY);
#pragma warning(push)
#pragma warning(disable: 4996)
    accumulator->entries = (ARK_KERNEL_MODULE_ENTRY*)ExAllocatePoolWithTag(
        NonPagedPool,
        entryBytes,
        ARK_MODULE_TAG);
#pragma warning(pop)
    if (accumulator->entries == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(accumulator->entries, entryBytes);
    return STATUS_SUCCESS;
}

/**
 * @brief 判断地址是否位于会话空间（动态解析 MmIsSessionAddress）。
 * @param address 待检测虚址。
 * @return TRUE 表示会话空间或无法排除的会话映射。
 * @irql PASSIVE_LEVEL
 */
static BOOLEAN IsSessionSpaceAddress(_In_ PVOID address) {
    static PFN_MM_IS_SESSION_ADDRESS s_mmIsSessionAddress = NULL;
    static BOOLEAN s_resolved = FALSE;
    if (address == NULL) {
        return FALSE;
    }
    if (!s_resolved) {
        UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"MmIsSessionAddress");
        s_mmIsSessionAddress = (PFN_MM_IS_SESSION_ADDRESS)MmGetSystemRoutineAddress(&routineName);
        s_resolved = TRUE;
    }
    if (s_mmIsSessionAddress != NULL) {
        return s_mmIsSessionAddress(address) ? TRUE : FALSE;
    }
    return FALSE;
}

/**
 * @brief 判断 PoolTag 是否为已知易误报噪声标签。
 *
 * Driver Verifier / 内存管理相关 Vi* 标签常在大池中缓存带 MZ 的缓冲，
 * 即使 Verifier 未开启也可能残留（如 ViMm）。
 *
 * @param tagUlong PoolTag 整型。
 * @return TRUE 表示应忽略。
 */
static BOOLEAN IsNoiseBigPoolTag(_In_ ULONG tagUlong) {
    const UCHAR* tagBytes = (const UCHAR*)&tagUlong;
    /* Verifier 内部标签族：Vi??（含 ViMm） */
    if (tagBytes[0] == (UCHAR)'V' && tagBytes[1] == (UCHAR)'i') {
        return TRUE;
    }
    return FALSE;
}

/**
 * @brief 从映像基址安全读取 PE32+ 的 TimeDateStamp / CheckSum / SizeOfImage。
 * @param imageBase 映像基址。
 * @param outTimeDateStamp 输出时间戳。
 * @param outCheckSum 输出校验和。
 * @param outSizeOfImage 输出 SizeOfImage。
 * @return TRUE 读取成功。
 * @irql PASSIVE_LEVEL
 */
static BOOLEAN ReadPeIdentityFingerprint(
    _In_ PVOID imageBase,
    _Out_ PULONG outTimeDateStamp,
    _Out_ PULONG outCheckSum,
    _Out_ PULONG outSizeOfImage
) {
    IMAGE_DOS_HEADER* dosHeader = NULL;
    IMAGE_NT_HEADERS64* ntHeaders = NULL;
    ULONG eLfanew = 0;
    if (outTimeDateStamp == NULL || outCheckSum == NULL || outSizeOfImage == NULL) {
        return FALSE;
    }
    *outTimeDateStamp = 0;
    *outCheckSum = 0;
    *outSizeOfImage = 0;
    if (imageBase == NULL || !MmIsAddressValid(imageBase)) {
        return FALSE;
    }
    __try {
        dosHeader = (IMAGE_DOS_HEADER*)imageBase;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return FALSE;
        }
        eLfanew = (ULONG)dosHeader->e_lfanew;
        if (eLfanew < sizeof(IMAGE_DOS_HEADER) || (eLfanew & 3UL) != 0UL) {
            return FALSE;
        }
        if (!MmIsAddressValid((PUCHAR)imageBase + eLfanew)) {
            return FALSE;
        }
        ntHeaders = (IMAGE_NT_HEADERS64*)((PUCHAR)imageBase + eLfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE ||
            ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            return FALSE;
        }
        *outTimeDateStamp = ntHeaders->FileHeader.TimeDateStamp;
        *outCheckSum = ntHeaders->OptionalHeader.CheckSum;
        *outSizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

/**
 * @brief 判断 BigPool PE 是否为 View A 已加载模块的池内拷贝。
 *
 * 以 SizeOfImage + TimeDateStamp + CheckSum 三元组匹配 PsLoadedModuleList 视图。
 *
 * @param accumulator 已填充 View A/B 的累加器。
 * @param timeDateStamp 候选 PE 时间戳。
 * @param checkSum 候选 PE 校验和。
 * @param sizeOfImage 候选 PE SizeOfImage。
 * @return TRUE 表示与已加载模块指纹重复，应丢弃。
 * @irql PASSIVE_LEVEL
 */
static BOOLEAN IsBigPoolDuplicateOfKnownModule(
    _In_ const ARK_MODULE_ACCUMULATOR* accumulator,
    _In_ ULONG timeDateStamp,
    _In_ ULONG checkSum,
    _In_ ULONG sizeOfImage
) {
    ULONG index = 0;
    ULONG scanned = 0;
    if (accumulator == NULL || accumulator->entries == NULL || sizeOfImage == 0UL) {
        return FALSE;
    }
    for (index = 0;
         index < accumulator->entryCount && scanned < ARK_BIGPOOL_DUP_SCAN_MAX;
         index++) {
        const ARK_KERNEL_MODULE_ENTRY* entry = &accumulator->entries[index];
        ULONG knownTime = 0;
        ULONG knownCheckSum = 0;
        ULONG knownSize = 0;
        if ((entry->ViewFlags & ARK_FLAG_VIEW_SECTION) == 0) {
            continue;
        }
        if (entry->ImageBase == 0ULL || entry->ImageSize == 0UL) {
            continue;
        }
        if (entry->ImageSize != sizeOfImage) {
            continue;
        }
        scanned++;
        if (!ReadPeIdentityFingerprint(
                (PVOID)(ULONG_PTR)entry->ImageBase,
                &knownTime,
                &knownCheckSum,
                &knownSize)) {
            continue;
        }
        if (knownSize == sizeOfImage &&
            knownTime == timeDateStamp &&
            knownCheckSum == checkSum) {
            return TRUE;
        }
    }
    return FALSE;
}

/**
 * @brief 校验 BigPool 块是否为可信的完整 Native PE 映像（去误报）。
 *
 * 关键条件：PE32+/AMD64、Native 子系统、SizeOfImage 落在池块内，
 * 数据目录与节表不越界，且映像末页可访问。
 *
 * @param imageBase 池块起始虚址。
 * @param poolSize 池分配字节数。
 * @param outSizeOfImage 输出 PE SizeOfImage；不可为 NULL。
 * @param outTimeDateStamp 输出 TimeDateStamp；不可为 NULL。
 * @param outCheckSum 输出 CheckSum；不可为 NULL。
 * @return TRUE 表示结构可信；FALSE 应跳过。
 * @irql PASSIVE_LEVEL
 */
static BOOLEAN IsCredibleBigPoolPeImage(
    _In_ PVOID imageBase,
    _In_ SIZE_T poolSize,
    _Out_ PULONG outSizeOfImage,
    _Out_ PULONG outTimeDateStamp,
    _Out_ PULONG outCheckSum
) {
    IMAGE_DOS_HEADER* dosHeader = NULL;
    IMAGE_NT_HEADERS64* ntHeaders = NULL;
    IMAGE_SECTION_HEADER* sectionHeader = NULL;
    IMAGE_DATA_DIRECTORY* dataDirectory = NULL;
    ULONG eLfanew = 0;
    ULONG sizeOfImage = 0;
    ULONG sizeOfHeaders = 0;
    ULONG entryPoint = 0;
    ULONG directoryIndex = 0;
    ULONG numberOfSections = 0;
    ULONG sectionIndex = 0;
    ULONG sectionTableBytes = 0;
    if (outSizeOfImage == NULL || outTimeDateStamp == NULL || outCheckSum == NULL) {
        return FALSE;
    }
    *outSizeOfImage = 0;
    *outTimeDateStamp = 0;
    *outCheckSum = 0;
    if (imageBase == NULL || poolSize < ARK_BIGPOOL_MIN_IMAGE_SIZE) {
        return FALSE;
    }
    if (!MmIsAddressValid(imageBase)) {
        return FALSE;
    }
    __try {
        dosHeader = (IMAGE_DOS_HEADER*)imageBase;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return FALSE;
        }
        eLfanew = (ULONG)dosHeader->e_lfanew;
        if (eLfanew < sizeof(IMAGE_DOS_HEADER) ||
            eLfanew > (poolSize - sizeof(IMAGE_NT_HEADERS64)) ||
            (eLfanew & 3UL) != 0UL) {
            return FALSE;
        }
        if (!MmIsAddressValid((PUCHAR)imageBase + eLfanew)) {
            return FALSE;
        }
        ntHeaders = (IMAGE_NT_HEADERS64*)((PUCHAR)imageBase + eLfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return FALSE;
        }
        if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
            return FALSE;
        }
        numberOfSections = (ULONG)ntHeaders->FileHeader.NumberOfSections;
        if (numberOfSections == 0UL || numberOfSections > ARK_BIGPOOL_MAX_SECTIONS) {
            return FALSE;
        }
        if ((ntHeaders->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0) {
            return FALSE;
        }
        if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            return FALSE;
        }
        if (ntHeaders->OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_NATIVE) {
            return FALSE;
        }
        sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
        sizeOfHeaders = ntHeaders->OptionalHeader.SizeOfHeaders;
        entryPoint = ntHeaders->OptionalHeader.AddressOfEntryPoint;
        if (sizeOfImage < ARK_BIGPOOL_MIN_IMAGE_SIZE ||
            sizeOfImage > poolSize ||
            sizeOfHeaders == 0UL ||
            sizeOfHeaders > sizeOfImage ||
            sizeOfHeaders > poolSize) {
            return FALSE;
        }
        if (entryPoint != 0UL && entryPoint >= sizeOfImage) {
            return FALSE;
        }
        sectionTableBytes = numberOfSections * (ULONG)sizeof(IMAGE_SECTION_HEADER);
        if ((eLfanew + (ULONG)sizeof(IMAGE_NT_HEADERS64) + sectionTableBytes) > sizeOfHeaders ||
            (eLfanew + (ULONG)sizeof(IMAGE_NT_HEADERS64) + sectionTableBytes) > poolSize) {
            return FALSE;
        }
        sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (sectionIndex = 0; sectionIndex < numberOfSections; sectionIndex++) {
            ULONG sectionVa = sectionHeader[sectionIndex].VirtualAddress;
            ULONG sectionVs = sectionHeader[sectionIndex].Misc.VirtualSize;
            if (sectionVa >= sizeOfImage) {
                return FALSE;
            }
            if (sectionVs != 0UL &&
                (sectionVa > sizeOfImage || sectionVs > sizeOfImage ||
                 (sectionVa + sectionVs) > sizeOfImage)) {
                return FALSE;
            }
        }
        dataDirectory = ntHeaders->OptionalHeader.DataDirectory;
        for (directoryIndex = 0;
             directoryIndex < IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
             directoryIndex++) {
            ULONG virtualAddress = dataDirectory[directoryIndex].VirtualAddress;
            ULONG directorySize = dataDirectory[directoryIndex].Size;
            if (virtualAddress == 0UL || directorySize == 0UL) {
                continue;
            }
            if (virtualAddress >= sizeOfImage ||
                directorySize > sizeOfImage ||
                (virtualAddress + directorySize) > sizeOfImage ||
                (virtualAddress + directorySize) > poolSize) {
                return FALSE;
            }
        }
        /* 要求映像末页可读，避免 SizeOfImage 声称完整但实际未映射 */
        if (!MmIsAddressValid((PUCHAR)imageBase + (sizeOfImage - 1UL))) {
            return FALSE;
        }
        *outSizeOfImage = sizeOfImage;
        *outTimeDateStamp = ntHeaders->FileHeader.TimeDateStamp;
        *outCheckSum = ntHeaders->OptionalHeader.CheckSum;
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

/**
 * @brief 初步校验池块是否同时具备合法 "MZ" 与 "PE\0\0" 标识。
 *
 * 仅做签名与 e_lfanew 边界检查，作为 CollectBigPoolResiduals 的快速去误报门槛。
 *
 * @param imageBase 池块起始虚址。
 * @param poolSize 池分配字节数。
 * @return TRUE 表示 MZ/PE 标识均合法；FALSE 应跳过。
 * @irql PASSIVE_LEVEL
 */
static BOOLEAN HasValidMzPeSignature(
    _In_ PVOID imageBase,
    _In_ SIZE_T poolSize
) {
    IMAGE_DOS_HEADER* dosHeader = NULL;
    PULONG peSignature = NULL;
    ULONG eLfanew = 0;
    if (imageBase == NULL || poolSize < (sizeof(IMAGE_DOS_HEADER) + sizeof(ULONG))) {
        return FALSE;
    }
    if (!MmIsAddressValid(imageBase)) {
        return FALSE;
    }
    __try {
        dosHeader = (IMAGE_DOS_HEADER*)imageBase;
        /* "MZ" = 0x5A4D */
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return FALSE;
        }
        eLfanew = (ULONG)dosHeader->e_lfanew;
        if (eLfanew < sizeof(IMAGE_DOS_HEADER) ||
            (eLfanew & 3UL) != 0UL ||
            eLfanew > (poolSize - sizeof(ULONG))) {
            return FALSE;
        }
        if (!MmIsAddressValid((PUCHAR)imageBase + eLfanew)) {
            return FALSE;
        }
        peSignature = (PULONG)((PUCHAR)imageBase + eLfanew);
        /* "PE\0\0" = 0x00004550 */
        if (*peSignature != IMAGE_NT_SIGNATURE) {
            return FALSE;
        }
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

/**
 * @brief View C：枚举 SystemBigPool 中可信完整 Native PE 大池痕迹。
 *
 * 额外去误报：MZ/PE 标识初筛、忽略会话空间、Vi* 噪声 Tag、与 View A 指纹重复的池内拷贝。
 *
 * @param accumulator 累加器（输入输出）。
 * @return STATUS_SUCCESS 或查询失败状态。
 * @irql PASSIVE_LEVEL
 */
static NTSTATUS CollectBigPoolResiduals(
    _Inout_ ARK_MODULE_ACCUMULATOR* accumulator
) {
    ULONG bufferSize = 0;
    ULONG returnLength = 0;
    ULONG retry = 0;
    NTSTATUS status = STATUS_SUCCESS;
    ARK_SYSTEM_BIGPOOL_INFORMATION* info = NULL;
    ULONG index = 0;
    ULONG hitCount = 0;
    ULONG skippedCount = 0;
    if (accumulator == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    status = ZwQuerySystemInformation(SystemBigPoolInformation, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH && bufferSize == 0) {
        return status;
    }
    do {
        if (info != NULL) {
            ExFreePoolWithTag(info, ARK_MODULE_TAG);
            info = NULL;
        }
        if (returnLength > bufferSize) {
            bufferSize = returnLength;
        }
        bufferSize += PAGE_SIZE;
#pragma warning(push)
#pragma warning(disable: 4996)
        info = (ARK_SYSTEM_BIGPOOL_INFORMATION*)ExAllocatePoolWithTag(
            NonPagedPool,
            bufferSize,
            ARK_MODULE_TAG);
#pragma warning(pop)
        if (info == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(info, bufferSize);
        status = ZwQuerySystemInformation(SystemBigPoolInformation, info, bufferSize, &returnLength);
        retry++;
    } while (status == STATUS_INFO_LENGTH_MISMATCH && retry < 8UL);
    if (!NT_SUCCESS(status) || info == NULL) {
        if (info != NULL) {
            ExFreePoolWithTag(info, ARK_MODULE_TAG);
        }
        return status;
    }
    __try {
        for (index = 0; index < info->Count && hitCount < ARK_MAX_MODULE_ENTRIES; index++) {
            ARK_SYSTEM_BIGPOOL_ENTRY* poolEntry = &info->AllocatedInfo[index];
            PVOID address = (PVOID)((ULONG_PTR)poolEntry->VirtualAddress & ~1ULL);
            ULONG peSizeOfImage = 0;
            ULONG peTimeDateStamp = 0;
            ULONG peCheckSum = 0;
            CHAR moduleName[ARK_MODULE_NAME_MAX] = { 0 };
            CHAR tagName[8] = { 0 };
            const UCHAR* tagBytes = (const UCHAR*)&poolEntry->TagUlong;
            if (address == NULL || poolEntry->SizeInBytes < ARK_BIGPOOL_MIN_IMAGE_SIZE) {
                continue;
            }
            /* 初步筛选：必须同时具备 "MZ" 与 "PE\0\0" 标识 */
            if (!HasValidMzPeSignature(address, poolEntry->SizeInBytes)) {
                skippedCount++;
                continue;
            }
            /* 会话空间大池中的 PE 拷贝不是典型隐藏内核驱动 */
            if (IsSessionSpaceAddress(address)) {
                skippedCount++;
                continue;
            }
            if (IsNoiseBigPoolTag(poolEntry->TagUlong)) {
                skippedCount++;
                continue;
            }
            if (!IsCredibleBigPoolPeImage(
                    address,
                    poolEntry->SizeInBytes,
                    &peSizeOfImage,
                    &peTimeDateStamp,
                    &peCheckSum)) {
                skippedCount++;
                continue;
            }
            if (IsBigPoolDuplicateOfKnownModule(
                    accumulator,
                    peTimeDateStamp,
                    peCheckSum,
                    peSizeOfImage)) {
                skippedCount++;
                continue;
            }
            tagName[0] = (CHAR)tagBytes[0];
            tagName[1] = (CHAR)tagBytes[1];
            tagName[2] = (CHAR)tagBytes[2];
            tagName[3] = (CHAR)tagBytes[3];
            tagName[4] = '\0';
            if (tagName[0] == '\0') {
                RtlStringCbCopyA(moduleName, sizeof(moduleName), "bigpool_mz");
            } else {
                RtlStringCbPrintfA(moduleName, sizeof(moduleName), "pool_%s", tagName);
            }
            AddModuleToAccumulator(
                accumulator,
                ARK_FLAG_VIEW_RESIDUAL | ARK_FLAG_RESIDUAL_POOL,
                (ULONG64)(ULONG_PTR)address,
                peSizeOfImage,
                0ULL,
                moduleName,
                "residual:bigpool");
            hitCount++;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LOGE("BigPool walk exception:%lx", GetExceptionCode());
        ExFreePoolWithTag(info, ARK_MODULE_TAG);
        return GetExceptionCode();
    }
    ExFreePoolWithTag(info, ARK_MODULE_TAG);
    LOGI("BigPool residual hits=%lu skipped=%lu", hitCount, skippedCount);
    return STATUS_SUCCESS;
}

/**
 * @brief View C 总入口：SystemBigPool 残留采集（含多层去误报）。
 *
 * PiDDBCacheTable / MmUnloadedDrivers / CI HashBucket 暂不启用。
 *
 * @param accumulator 累加器（输入输出）。
 * @return 始终返回 STATUS_SUCCESS（BigPool 失败时软跳过）。
 * @irql PASSIVE_LEVEL
 */
static NTSTATUS CollectResidualModuleViews(
    _Inout_ ARK_MODULE_ACCUMULATOR* accumulator
) {
    NTSTATUS status = STATUS_SUCCESS;
    if (accumulator == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    /*
     * 以下三类残留结构暂不使用：
     * - PiDDBCacheTable
     * - MmUnloadedDrivers
     * - g_KernelHashBucketList / CI 缓存
     * BigPool：MZ/PE 初筛 / 会话地址 / Vi* Tag / PE 完整度 / View A 指纹去重。
     */
    status = CollectBigPoolResiduals(accumulator);
    if (!NT_SUCCESS(status)) {
        LOGI("CollectBigPoolResiduals skipped,status:%lx", status);
    }
    return STATUS_SUCCESS;
}

/**
 * @brief 收集内核模块 View A/B/C 并填充 IOCTL 响应。
 * @param response 输出缓冲区，不可为 NULL。
 * @return STATUS_SUCCESS 或相应错误码。
 * @irql PASSIVE_LEVEL
 */
NTSTATUS QueryKernelModuleViews(
    _Out_ ARK_KERNEL_MODULE_VIEWS_RESPONSE* response
) {
    ULONG index = 0;
    NTSTATUS status = STATUS_SUCCESS;
    ARK_MODULE_ACCUMULATOR accumulator = { 0 };
    if (response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    RtlZeroMemory(response, sizeof(*response));
    status = InitModuleAccumulator(&accumulator);
    if (!NT_SUCCESS(status)) {
        response->Status = (ULONG)status;
        return status;
    }
    status = CollectDriverSectionView(&accumulator);
    if (!NT_SUCCESS(status)) {
        FreeModuleAccumulator(&accumulator);
        response->Status = (ULONG)status;
        return status;
    }
    status = CollectDriverObjectView(&accumulator);
    if (!NT_SUCCESS(status)) {
        FreeModuleAccumulator(&accumulator);
        response->Status = (ULONG)status;
        return status;
    }
    status = CollectResidualModuleViews(&accumulator);
    if (!NT_SUCCESS(status)) {
        LOGI("residual view soft-fail status:%lx", status);
    }
    response->SectionCount = accumulator.sectionCount;
    response->DriverCount = accumulator.driverCount;
    response->ResidualCount = accumulator.residualCount;
    response->EntryCount = accumulator.entryCount;
    for (index = 0; index < accumulator.entryCount && index < ARK_MAX_MODULE_ENTRIES; index++) {
        response->Entries[index] = accumulator.entries[index];
    }
    response->Status = (ULONG)STATUS_SUCCESS;
    FreeModuleAccumulator(&accumulator);
    LOGI("kernel module views section=%lu driver=%lu residual=%lu union=%lu",
         response->SectionCount,
         response->DriverCount,
         response->ResidualCount,
         response->EntryCount);
    return STATUS_SUCCESS;
}
