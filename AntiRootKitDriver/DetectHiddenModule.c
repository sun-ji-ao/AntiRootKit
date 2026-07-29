#include "DetectHiddenModule.h"
#include "undocument.h"
#include "Log.h"

#include <ntstrsafe.h>

/** @brief DRIVER_OBJECT 类型指针，用于 ObReferenceObjectByName。 */
extern POBJECT_TYPE* IoDriverObjectType;

/**
 * @brief Win10 KLDR_DATA_TABLE_ENTRY（仅使用枚举所需字段）。
 */
typedef struct _ARK_KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;   /**< PsLoadedModuleList 双向链表节点 */
    PVOID ExceptionTable;          /**< 异常表 */
    ULONG ExceptionTableSize;      /**< 异常表大小 */
    PVOID GpValue;                 /**< GP 值 */
    PVOID NonPagedDebugInfo;       /**< 非分页调试信息 */
    PVOID DllBase;                 /**< 映像基址 */
    PVOID EntryPoint;              /**< 入口点 */
    ULONG SizeOfImage;             /**< 映像大小 */
    UNICODE_STRING FullDllName;    /**< 完整路径 */
    UNICODE_STRING BaseDllName;    /**< 短文件名 */
} ARK_KLDR_DATA_TABLE_ENTRY, *PARK_KLDR_DATA_TABLE_ENTRY;

/**
 * @brief OBJECT_DIRECTORY_INFORMATION（ZwQueryDirectoryObject 返回项）。
 */
typedef struct _ARK_OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;     /**< 对象名 */
    UNICODE_STRING TypeName; /**< 类型名 */
} ARK_OBJECT_DIRECTORY_INFORMATION;

/**
 * @brief 模块收集累加器，合并 View A/B 扫描结果。
 */
typedef struct _ARK_MODULE_ACCUMULATOR {
    ARK_KERNEL_MODULE_ENTRY* entries; /**< 模块条目数组 */
    ULONG entryCount;                 /**< 当前条目数 */
    ULONG sectionCount;               /**< View A 命中计数 */
    ULONG driverCount;                /**< View B 命中计数 */
} ARK_MODULE_ACCUMULATOR;

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
 * @param viewFlag 视图标志（ARK_FLAG_VIEW_SECTION 或 ARK_FLAG_VIEW_DRIVEROBJ）。
 * @param imageBase 映像基址。
 * @param imageSize 映像大小。
 * @param driverObjectAddress DRIVER_OBJECT 地址（View B）。
 * @param moduleName 短名 ANSI。
 * @param modulePath 完整路径 ANSI。
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
    if (accumulator == NULL || accumulator->entries == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    /* ImageBase 为空无法与 R3 可靠对齐，视为无效采样直接丢弃。 */
    if (imageBase == 0ULL) {
        return STATUS_SUCCESS;
    }
    if (moduleName == NULL || moduleName[0] == '\0' || CompareAnsiNoCase(moduleName, "unknown") == 0) {
        return STATUS_SUCCESS;
    }
    if (imageBase != 0ULL) {
        index = FindModuleByBase(accumulator, imageBase);
    }
    if (index < 0 && moduleName != NULL && moduleName[0] != '\0') {
        index = FindModuleByName(accumulator, moduleName);
    }
    if (index >= 0) {
        entry = &accumulator->entries[index];
        if ((entry->ViewFlags & viewFlag) == 0) {
            entry->ViewFlags |= viewFlag;
            if (viewFlag == ARK_FLAG_VIEW_SECTION) {
                accumulator->sectionCount++;
            } else if (viewFlag == ARK_FLAG_VIEW_DRIVEROBJ) {
                accumulator->driverCount++;
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
        if ((entry->ModuleName[0] == '\0' || CompareAnsiNoCase(entry->ModuleName, "unknown") == 0) &&
            moduleName != NULL && moduleName[0] != '\0') {
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
    if (moduleName != NULL && moduleName[0] != '\0') {
        RtlStringCbCopyA(entry->ModuleName, sizeof(entry->ModuleName), moduleName);
    } else {
        RtlStringCbCopyA(entry->ModuleName, sizeof(entry->ModuleName), "unknown");
    }
    if (modulePath != NULL && modulePath[0] != '\0') {
        RtlStringCbCopyA(entry->ModulePath, sizeof(entry->ModulePath), modulePath);
    } else {
        RtlStringCbCopyA(entry->ModulePath, sizeof(entry->ModulePath), "unknown");
    }
    if (viewFlag == ARK_FLAG_VIEW_SECTION) {
        accumulator->sectionCount++;
    } else if (viewFlag == ARK_FLAG_VIEW_DRIVEROBJ) {
        accumulator->driverCount++;
    }
    accumulator->entryCount++;
    return STATUS_SUCCESS;
}

/**
 * @brief 判断 LDR 链表节点是否为有效已加载模块（过滤 PsLoadedModuleList 头节点误报）。
 * @param entry 当前按 KLDR 解释的节点。
 * @return 有效模块返回 TRUE。
 */
static BOOLEAN IsValidLdrModuleEntry(_In_opt_ const ARK_KLDR_DATA_TABLE_ENTRY* entry) {
    if (entry == NULL) {
        return FALSE;
    }
    /* 链表头不是 KLDR 结构：DllBase/SizeOfImage/名称均为空。 */
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
        /* 环形链表会经过 PsLoadedModuleList 头，必须跳过无效节点。 */
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
        if ((loopIndex % ARK_SCAN_YIELD_INTERVAL) == 0UL) {
            LARGE_INTEGER interval = { 0 };
            interval.QuadPart = -10LL * 1000LL;
            KeDelayExecutionThread(KernelMode, FALSE, &interval);
        }
        /* InLoadOrderLinks 位于结构体首字段，Flink 即下一 entry 指针。 */
        current = (PARK_KLDR_DATA_TABLE_ENTRY)current->InLoadOrderLinks.Flink;
    } while (current != NULL && current != first && loopIndex < ARK_MAX_MODULE_ENTRIES * 2UL);
    LOGI("driver section view hits=%lu", accumulator->sectionCount);
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
        {
            SIZE_T prefixBytes = 0;
            status = RtlStringCbCopyW(fullNameBuffer, sizeof(fullNameBuffer), L"\\Driver\\");
            if (!NT_SUCCESS(status)) {
                continue;
            }
            status = RtlStringCbLengthW(fullNameBuffer, sizeof(fullNameBuffer), &prefixBytes);
            if (!NT_SUCCESS(status)) {
                continue;
            }
            if ((prefixBytes + dirInfo->Name.Length + sizeof(WCHAR)) > sizeof(fullNameBuffer)) {
                continue;
            }
            RtlCopyMemory(
                (PUCHAR)fullNameBuffer + prefixBytes,
                dirInfo->Name.Buffer,
                dirInfo->Name.Length);
            *((WCHAR*)((PUCHAR)fullNameBuffer + prefixBytes + dirInfo->Name.Length)) = L'\0';
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
            if (ldr->DllBase != NULL) {
                imageBase = (ULONG64)(ULONG_PTR)ldr->DllBase;
            }
            if (ldr->SizeOfImage != 0UL) {
                imageSize = ldr->SizeOfImage;
            }
            CopyUnicodeToAnsi(modulePath, sizeof(modulePath), &ldr->FullDllName);
            if (ldr->BaseDllName.Buffer != NULL && ldr->BaseDllName.Length != 0) {
                CopyUnicodeToAnsi(moduleName, sizeof(moduleName), &ldr->BaseDllName);
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
        if ((loopIndex % ARK_SCAN_YIELD_INTERVAL) == 0UL) {
            LARGE_INTEGER interval = { 0 };
            interval.QuadPart = -10LL * 1000LL;
            KeDelayExecutionThread(KernelMode, FALSE, &interval);
        }
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
 * @brief 收集内核模块 View A/B 并填充 IOCTL 响应（实现）。
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
    response->SectionCount = accumulator.sectionCount;
    response->DriverCount = accumulator.driverCount;
    response->EntryCount = accumulator.entryCount;
    for (index = 0; index < accumulator.entryCount && index < ARK_MAX_MODULE_ENTRIES; index++) {
        response->Entries[index] = accumulator.entries[index];
    }
    response->Status = (ULONG)STATUS_SUCCESS;
    FreeModuleAccumulator(&accumulator);
    LOGI("kernel module views section=%lu driver=%lu union=%lu",
         response->SectionCount,
         response->DriverCount,
         response->EntryCount);
    return STATUS_SUCCESS;
}
