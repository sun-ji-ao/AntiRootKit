#include "DetectHidden.h"
#include "undocument.h"
#include "Log.h"

#include <ntstrsafe.h>

/** @brief 获取进程映像短名（内核未文档化导出）。 */
NTKERNELAPI CHAR* PsGetProcessImageFileName(_In_ PEPROCESS Process);
/** @brief 进程对象类型，用于 ObOpenObjectByPointer / 句柄对象过滤。 */
extern POBJECT_TYPE* PsProcessType;
/** @brief 线程对象类型，用于句柄快照 Thread 对象过滤。 */
extern POBJECT_TYPE* PsThreadType;

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#endif


/**
 * @brief SystemHandleInformation 单条句柄记录。
 */
typedef struct _ARK_SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;         /**< 持有该句柄的进程 PID（USHORT） */
    USHORT CreatorBackTraceIndex;   /**< 创建回溯索引 */
    UCHAR ObjectTypeIndex;          /**< 对象类型索引 */
    UCHAR HandleAttributes;         /**< 句柄属性 */
    USHORT HandleValue;             /**< 句柄值 */
    PVOID Object;                   /**< 内核对象指针 */
    ULONG GrantedAccess;            /**< 授予的访问权限 */
} ARK_SYSTEM_HANDLE_TABLE_ENTRY_INFO;

/**
 * @brief SystemHandleInformation 返回缓冲区头。
 */
typedef struct _ARK_SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;                          /**< 句柄条目数量 */
    ARK_SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];   /**< 可变长句柄数组 */
} ARK_SYSTEM_HANDLE_INFORMATION;

/** @brief ZwQueryInformationProcess(ProcessTimes) 返回的进程时间结构。 */
typedef struct _ARK_KERNEL_USER_TIMES {
    LARGE_INTEGER CreateTime;  /**< 进程创建时间 */
    LARGE_INTEGER ExitTime;    /**< 进程退出时间，非 0 表示已退出/僵尸 */
    LARGE_INTEGER KernelTime;  /**< 内核态累计 CPU 时间 */
    LARGE_INTEGER UserTime;    /**< 用户态累计 CPU 时间 */
} ARK_KERNEL_USER_TIMES;

/**
 * @brief PID 收集累加器，合并 View B/C 扫描结果。
 */
typedef struct _ARK_PID_ACCUMULATOR {
    UCHAR* bitmap;                       /**< PID 位图，标记已收录 PID */
    SIZE_T bitmapBytes;                  /**< 位图字节数 */
    ARK_KERNEL_PROCESS_ENTRY* entries;     /**< 进程条目数组 */
    ULONG entryCount;                    /**< 当前条目数 */
    ULONG cidCount;                      /**< View B 命中计数 */
    ULONG threadCount;                   /**< View C：系统句柄快照命中计数 */
} ARK_PID_ACCUMULATOR;

/**
 * @brief 判断进程是否为已退出/僵尸进程。
 *
 * 判定顺序：
 * 1) 若有 EPROCESS：PsGetProcessExitStatus != STATUS_PENDING 视为已退出
 * 2) ZwOpenProcess + ProcessTimes：ExitTime != 0 视为已退出（直接返回，不再查句柄数）
 * 3) ExitTime == 0 时再查 ProcessHandleCount：HandleCount == 0 视为已退出
 *
 * @param pid 进程 PID。
 * @param process 可选 EPROCESS 指针，非空时优先检查退出状态。
 * @return TRUE 表示已死亡应跳过，FALSE 表示仍存活或无法判定为死亡。
 * @irql PASSIVE_LEVEL
 */
static BOOLEAN IsDeadProcess(
    _In_ ULONG pid,
    _In_opt_ PEPROCESS process
) {
    HANDLE processHandle = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ARK_KERNEL_USER_TIMES processTimes = { 0 };
    CLIENT_ID clientId = { 0 };
    OBJECT_ATTRIBUTES objectAttributes = { 0 };
    ULONG handleCount = 0;
    BOOLEAN isDead = FALSE;
    if (pid == 0UL) {
        return TRUE;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return TRUE;
    }
    /* 直接读 EPROCESS 退出状态，避免 ProcessTimes 与 ExitTime 字段不一致导致漏判。 */
    if (process != NULL) {
        status = PsGetProcessExitStatus(process);
        if (status != STATUS_PENDING) {
            return TRUE;
        }
    }
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    clientId.UniqueThread = NULL;
    InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);
    status = ZwOpenProcess(
        &processHandle,
        PROCESS_QUERY_LIMITED_INFORMATION,
        &objectAttributes,
        &clientId);
    if (!NT_SUCCESS(status) || processHandle == NULL) {
        LOGE("ZwOpenProcess failed,pid=%lu status:%lx", pid, status);
        return FALSE;
    }
    status = ZwQueryInformationProcess(
        processHandle,
        ProcessTimes,
        &processTimes,
        sizeof(processTimes),
        NULL);
    if (!NT_SUCCESS(status)) {
        LOGE("ZwQueryInformationProcess(ProcessTimes) failed,pid=%lu status:%lx", pid, status);
        ZwClose(processHandle);
        return FALSE;
    }
    /* ExitTime != 0：已退出，不再做 HandleCount 判定。 */
    if (processTimes.ExitTime.QuadPart != 0LL) {
        ZwClose(processHandle);
        return TRUE;
    }
    /* ExitTime == 0：再根据句柄数量判断。 */
    status = ZwQueryInformationProcess(
        processHandle,
        ProcessHandleCount,
        &handleCount,
        sizeof(handleCount),
        NULL);
    if (!NT_SUCCESS(status)) {
        LOGE("ZwQueryInformationProcess(ProcessHandleCount) failed,pid=%lu status:%lx", pid, status);
        ZwClose(processHandle);
        return FALSE;
    }
    isDead = (handleCount == 0UL);
    ZwClose(processHandle);
    return isDead;
}

/**
 * @brief 扫描过程中周期性让出 CPU，避免长时间占用导致系统卡顿。
 * @param index 当前循环序号，每 ARK_SCAN_YIELD_INTERVAL 次休眠一次。
 * @irql PASSIVE_LEVEL
 */
static VOID YieldScanProgress(_In_ ULONG index) {
    LARGE_INTEGER interval = { 0 };
    if (index == 0UL || (index % ARK_SCAN_YIELD_INTERVAL) != 0UL) {
        return;
    }
    interval.QuadPart = -10LL * 1000LL;
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

/**
 * @brief 检查 PID 是否在位图中已标记。
 * @param bitmap PID 位图缓冲区。
 * @param bitmapBytes 位图字节长度。
 * @param pid 待检查 PID。
 * @return 已标记返回 TRUE，否则 FALSE。
 */
static BOOLEAN IsPidBitSet(
    _In_reads_bytes_(bitmapBytes) const UCHAR* bitmap,
    _In_ SIZE_T bitmapBytes,
    _In_ ULONG pid
) {
    SIZE_T byteIndex = 0;
    UCHAR bitMask = 0;
    if (bitmap == NULL || pid == 0) {
        return FALSE;
    }
    byteIndex = (SIZE_T)pid >> 3;
    if (byteIndex >= bitmapBytes) {
        return FALSE;
    }
    bitMask = (UCHAR)(1U << (pid & 7U));
    return (bitmap[byteIndex] & bitMask) != 0;
}

/**
 * @brief 在位图中标记指定 PID。
 * @param bitmap PID 位图缓冲区（输入输出）。
 * @param bitmapBytes 位图字节长度。
 * @param pid 待标记 PID，0 会被忽略。
 */
static VOID SetPidBit(
    _Inout_updates_bytes_(bitmapBytes) UCHAR* bitmap,
    _In_ SIZE_T bitmapBytes,
    _In_ ULONG pid) {
    SIZE_T byteIndex = 0;
    UCHAR bitMask = 0;
    if (bitmap == NULL || pid == 0) {
        return;
    }
    byteIndex = (SIZE_T)pid >> 3;
    if (byteIndex >= bitmapBytes) {
        return;
    }
    bitMask = (UCHAR)(1U << (pid & 7U));
    bitmap[byteIndex] |= bitMask;
}

/**
 * @brief 安全复制进程映像短名到目标缓冲区。
 * @param dest 目标缓冲区，长度 ARK_IMAGE_NAME_MAX。
 * @param source 源字符串，NULL 时写入 "unknown"。
 */
static VOID CopyImageName(
    _Out_writes_(ARK_IMAGE_NAME_MAX) CHAR* dest,
    _In_opt_ const CHAR* source) {
    if (dest == NULL) {
        return;
    }
    RtlZeroMemory(dest, ARK_IMAGE_NAME_MAX);
    if (source == NULL) {
        RtlStringCbCopyA(dest, ARK_IMAGE_NAME_MAX, "unknown");
        return;
    }
    RtlStringCbCopyA(dest, ARK_IMAGE_NAME_MAX, source);
}

/**
 * @brief 将进程加入累加器，自动合并重复 PID 的视图标志。
 * @param accumulator 累加器（输入输出）。
 * @param pid 进程 PID。
 * @param viewFlag 视图标志（ARK_FLAG_VIEW_CID 或 ARK_FLAG_VIEW_THREAD）。
 * @param process 可选 EPROCESS，用于填充映像名与地址。
 * @return STATUS_SUCCESS 成功；STATUS_BUFFER_OVERFLOW 条目已满。
 */
static NTSTATUS AddProcessToAccumulator(
    _Inout_ ARK_PID_ACCUMULATOR* accumulator,
    _In_ ULONG pid,
    _In_ ULONG viewFlag,
    _In_opt_ PEPROCESS process
) {

    LONG index = -1;
    if (accumulator == NULL || pid == 0 || accumulator->entries == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    for (index = 0; index < (LONG)accumulator->entryCount; index++) {
        if (accumulator->entries[index].ProcessId == pid) {
            if ((accumulator->entries[index].ViewFlags & viewFlag) == 0) {
                accumulator->entries[index].ViewFlags |= viewFlag;
                if (viewFlag == ARK_FLAG_VIEW_CID) {
                    accumulator->cidCount++;
                } else if (viewFlag == ARK_FLAG_VIEW_THREAD) {
                    accumulator->threadCount++;
                }
            }
            if (process != NULL && accumulator->entries[index].EprocessAddress == 0ULL) {
                accumulator->entries[index].EprocessAddress = (ULONG64)(ULONG_PTR)process;
                CopyImageName(
                    accumulator->entries[index].ImageName,
                    PsGetProcessImageFileName(process));
            }
            return STATUS_SUCCESS;
        }
    }
    if (accumulator->entryCount >= ARK_MAX_PROCESS_ENTRIES) {
        return STATUS_BUFFER_OVERFLOW;
    }
    if (!IsPidBitSet(accumulator->bitmap, accumulator->bitmapBytes, pid)) {
        SetPidBit(accumulator->bitmap, accumulator->bitmapBytes, pid);
    }
    accumulator->entries[accumulator->entryCount].ProcessId = pid;
    accumulator->entries[accumulator->entryCount].ViewFlags = viewFlag;
    accumulator->entries[accumulator->entryCount].EprocessAddress =
        process != NULL ? (ULONG64)(ULONG_PTR)process : 0ULL;
    if (process != NULL) {
        CopyImageName(
            accumulator->entries[accumulator->entryCount].ImageName,
            PsGetProcessImageFileName(process));
    } else {
        CopyImageName(accumulator->entries[accumulator->entryCount].ImageName, NULL);
    }
    if (viewFlag == ARK_FLAG_VIEW_CID) {
        accumulator->cidCount++;
    } else if (viewFlag == ARK_FLAG_VIEW_THREAD) {
        accumulator->threadCount++;
    }
    accumulator->entryCount++;
    return STATUS_SUCCESS;
}

/**
 * @brief View B：通过 PsLookupProcessByProcessId 暴力扫描 CID。
 *
 * 步进 4 遍历 PID，过滤 ExitTime!=0 的僵尸进程后入表。
 *
 * @param accumulator 累加器（输入输出）。
 * @param scanLimit PID 扫描上限。
 * @return STATUS_SUCCESS。
 * @irql PASSIVE_LEVEL
 */
static NTSTATUS CollectCidView(
    _Inout_ ARK_PID_ACCUMULATOR* accumulator,
    _In_ ULONG scanLimit) {
    ULONG pid = 0;
    ULONG loopIndex = 0;
    for (pid = 4UL; pid <= scanLimit; pid += 4UL) {
        PEPROCESS process = NULL;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        loopIndex++;
        YieldScanProgress(loopIndex);
        if (!NT_SUCCESS(status) || process == NULL) {
            continue;
        }
        /* 跳过已退出进程（ExitTime != 0）。 */
        if (!IsDeadProcess(pid, process)) {
            AddProcessToAccumulator(accumulator, pid, ARK_FLAG_VIEW_CID, process);
        }
        ObDereferenceObject(process);
    }
    return STATUS_SUCCESS;
}

/**
 * @brief 将存活进程写入系统句柄视图累加器。
 * @param accumulator 累加器（输入输出）。
 * @param process 已引用的 EPROCESS，函数内不额外引用。
 * @irql PASSIVE_LEVEL
 */
static VOID AddAliveProcessFromHandleView(
    _Inout_ ARK_PID_ACCUMULATOR* accumulator,
    _In_ PEPROCESS process
) {
    ULONG pid = 0;
    if (accumulator == NULL || process == NULL) {
        return;
    }
    pid = HandleToULong(PsGetProcessId(process));
    if (pid == 0UL) {
        return;
    }
    /* 必须先做死亡判定，禁止因位图已标记而跳过 ExitTime 检查。 */
    if (IsDeadProcess(pid, process)) {
        return;
    }
    AddProcessToAccumulator(accumulator, pid, ARK_FLAG_VIEW_THREAD, process);
}

/**
 * @brief 查询系统句柄快照，失败时释放已有缓冲。
 * @param handleInfo 输出句柄信息缓冲（调用方释放）。
 * @return STATUS_SUCCESS 或相应错误码。
 * @irql PASSIVE_LEVEL
 */
static NTSTATUS QuerySystemHandleInformation(
    _Outptr_result_maybenull_ ARK_SYSTEM_HANDLE_INFORMATION** handleInfo
) {
    ULONG bufferSize = 0;
    ULONG returnLength = 0;
    NTSTATUS status = STATUS_SUCCESS;
    ARK_SYSTEM_HANDLE_INFORMATION* buffer = NULL;
    ULONG retryCount = 0;
    if (handleInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *handleInfo = NULL;
    status = ZwQuerySystemInformation(SystemHandleInformation, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        LOGE("ZwQuerySystemInformation size probe failed,status:%lx", status);
        return status;
    }
    do {
        if (buffer != NULL) {
            ExFreePoolWithTag(buffer, ARK_HANDLE_TAG);
            buffer = NULL;
        }
        if (returnLength > bufferSize) {
            bufferSize = returnLength;
        }
        bufferSize += PAGE_SIZE;
#pragma warning(push)
#pragma warning(disable: 4996)
        buffer = (ARK_SYSTEM_HANDLE_INFORMATION*)ExAllocatePoolWithTag(
            NonPagedPool,
            bufferSize,
            ARK_HANDLE_TAG);
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
        retryCount++;
    } while (status == STATUS_INFO_LENGTH_MISMATCH && retryCount < 8UL);
    if (!NT_SUCCESS(status)) {
        LOGE("ZwQuerySystemInformation failed,status:%lx", status);
        ExFreePoolWithTag(buffer, ARK_HANDLE_TAG);
        return status;
    }
    *handleInfo = buffer;
    return STATUS_SUCCESS;
}

/**
 * @brief View C：遍历 SystemHandleInformation 全部句柄，筛选 Process/Thread 对象。
 *
 * 对快照中每一项做类型引用校验；Process 直接入表，Thread 经 IoThreadToProcess 反推所属进程。
 * 无 PID 扫描上限，以 NumberOfHandles 为准完整遍历。
 *
 * @param accumulator 累加器（输入输出）。
 * @return STATUS_SUCCESS 或查询失败状态。
 * @irql PASSIVE_LEVEL
 */
static NTSTATUS CollectSystemHandleView(
    _Inout_ ARK_PID_ACCUMULATOR* accumulator) {
    ARK_SYSTEM_HANDLE_INFORMATION* handleInfo = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG index = 0;
    ULONG loopIndex = 0;
    if (accumulator == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (PsProcessType == NULL || *PsProcessType == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    status = QuerySystemHandleInformation(&handleInfo);
    if (!NT_SUCCESS(status) || handleInfo == NULL) {
        return status;
    }
    for (index = 0; index < handleInfo->NumberOfHandles; index++) {
        PVOID object = handleInfo->Handles[index].Object;
        PVOID referenced = NULL;
        loopIndex++;
        YieldScanProgress(loopIndex);
        if (object == NULL) {
            continue;
        }
        status = ObReferenceObjectByPointer(
            object,
            PROCESS_QUERY_LIMITED_INFORMATION,
            *PsProcessType,
            KernelMode);
        if (NT_SUCCESS(status)) {
            AddAliveProcessFromHandleView(accumulator, (PEPROCESS)object);
            ObDereferenceObject(object);
            continue;
        }
        if (PsThreadType == NULL || *PsThreadType == NULL) {
            continue;
        }
        status = ObReferenceObjectByPointer(
            object,
            THREAD_QUERY_LIMITED_INFORMATION,
            *PsThreadType,
            KernelMode);
        if (!NT_SUCCESS(status)) {
            continue;
        }
        referenced = object;
        {
            PEPROCESS ownerProcess = IoThreadToProcess((PETHREAD)referenced);
            if (ownerProcess != NULL) {
                AddAliveProcessFromHandleView(accumulator, ownerProcess);
            }
        }
        ObDereferenceObject(referenced);
    }
    {
        ULONG handleCount = handleInfo->NumberOfHandles;
        ExFreePoolWithTag(handleInfo, ARK_HANDLE_TAG);
        LOGI("system handle view handles=%lu hits=%lu", handleCount, accumulator->threadCount);
    }
    return STATUS_SUCCESS;
}

/**
 * @brief 释放累加器分配的位图与条目数组。
 * @param accumulator 累加器（输入输出），释放后 entryCount 置 0。
 */
static VOID FreePidAccumulator(_Inout_ ARK_PID_ACCUMULATOR* accumulator) {
    if (accumulator == NULL) {
        return;
    }
    if (accumulator->bitmap != NULL) {
        ExFreePoolWithTag(accumulator->bitmap, ARK_BITMAP_TAG);
        accumulator->bitmap = NULL;
    }
    if (accumulator->entries != NULL) {
        ExFreePoolWithTag(accumulator->entries, ARK_POOL_TAG);
        accumulator->entries = NULL;
    }
    accumulator->entryCount = 0;
}

/**
 * @brief 初始化 PID 累加器，分配位图与条目池内存。
 * @param accumulator 累加器（输出）。
 * @param scanLimit PID 扫描上限，用于计算位图大小。
 * @return STATUS_SUCCESS 或内存不足等错误码。
 */
static NTSTATUS InitPidAccumulator(
    _Out_ ARK_PID_ACCUMULATOR* accumulator,
    _In_ ULONG scanLimit
) {

    SIZE_T entryBytes = 0;
    if (accumulator == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(accumulator, sizeof(*accumulator));
	// 位图字节数 = (scanLimit / 8) + 1，确保能容纳 scanLimit 的 PID 位
    accumulator->bitmapBytes = ((SIZE_T)scanLimit / 8UL) + 1UL;
    entryBytes = (SIZE_T)ARK_MAX_PROCESS_ENTRIES * sizeof(ARK_KERNEL_PROCESS_ENTRY);
#pragma warning(push)
#pragma warning(disable: 4996)
	// 分配位图与条目数组
    accumulator->bitmap = (UCHAR*)ExAllocatePoolWithTag(
        NonPagedPool,
        accumulator->bitmapBytes,
        ARK_BITMAP_TAG);
    if (accumulator->bitmap == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    accumulator->entries = (ARK_KERNEL_PROCESS_ENTRY*)ExAllocatePoolWithTag(
        NonPagedPool,
        entryBytes,
        ARK_POOL_TAG);
#pragma warning(pop)
    if (accumulator->entries == NULL) {
        ExFreePoolWithTag(accumulator->bitmap, ARK_BITMAP_TAG);
        accumulator->bitmap = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(accumulator->bitmap, accumulator->bitmapBytes);
    RtlZeroMemory(accumulator->entries, entryBytes);
    return STATUS_SUCCESS;
}

/**
 * @brief 收集内核 View B/C 并填充 IOCTL 响应（实现）。
 *
 * 依次执行 CollectCidView、CollectSystemHandleView（系统句柄快照 Process/Thread），结果写入 response。
 * 接口说明见 DetectHidden.h。
 *
 * @param response 输出缓冲区，不可为 NULL。
 * @return STATUS_SUCCESS 或相应错误码。
 * @irql PASSIVE_LEVEL
 */
NTSTATUS QueryKernelProcessViews(
    _Out_ ARK_KERNEL_VIEWS_RESPONSE* response
) {

    ULONG index = 0;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG scanLimit = ARK_MAX_SCAN_PID;
    ARK_PID_ACCUMULATOR accumulator = { 0 };

    if (response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    RtlZeroMemory(response, sizeof(*response));
    response->MaxPidScanned = scanLimit;
    
	// 初始化累加器，分配位图与条目数组
    status = InitPidAccumulator(&accumulator, scanLimit);
    if (!NT_SUCCESS(status)) {
        response->Status = (ULONG)status;
        return status;
    }
	// 执行 View B 扫描
    status = CollectCidView(&accumulator, scanLimit);
    if (!NT_SUCCESS(status)) {
        FreePidAccumulator(&accumulator);
        response->Status = (ULONG)status;
        return status;
    }
	// 执行 View C：系统句柄快照全量扫描
    status = CollectSystemHandleView(&accumulator);
    if (!NT_SUCCESS(status)) {
        FreePidAccumulator(&accumulator);
        response->Status = (ULONG)status;
        return status;
    }
    response->CidCount = accumulator.cidCount;
    response->ThreadCount = accumulator.threadCount;
    response->EntryCount = accumulator.entryCount;
    for (index = 0; index < accumulator.entryCount && index < ARK_MAX_PROCESS_ENTRIES; index++) {
        response->Entries[index] = accumulator.entries[index];
    }
    response->Status = (ULONG)STATUS_SUCCESS;
    FreePidAccumulator(&accumulator);
    LOGI("kernel views cid=%lu thread=%lu union=%lu maxPid=%lu",
         response->CidCount,
         response->ThreadCount,
         response->EntryCount,
         scanLimit);
    return STATUS_SUCCESS;
}
