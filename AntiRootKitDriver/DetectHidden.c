#include "DetectHidden.h"
#include "Log.h"

#include <ntstrsafe.h>

/** @brief 获取进程映像短名（内核未文档化导出）。 */
NTKERNELAPI CHAR* PsGetProcessImageFileName(_In_ PEPROCESS Process);
/** @brief 进程对象类型，用于 ObOpenObjectByPointer。 */
extern POBJECT_TYPE* PsProcessType;

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

/* ProcessInformationClass=ProcessTimes(4)，用于读取 ExitTime。 */
#define ARK_PROCESS_TIMES ((PROCESSINFOCLASS)4)
/* ProcessInformationClass=ProcessHandleCount(20)，用于读取句柄数量。 */
#define ARK_PROCESS_HANDLE_COUNT ((PROCESSINFOCLASS)20)

/** @brief ZwQueryInformationProcess(ProcessTimes) 返回的进程时间结构。 */
typedef struct _ARK_KERNEL_USER_TIMES {
    LARGE_INTEGER CreateTime;  /**< 进程创建时间 */
    LARGE_INTEGER ExitTime;    /**< 进程退出时间，非 0 表示已退出/僵尸 */
    LARGE_INTEGER KernelTime;  /**< 内核态累计 CPU 时间 */
    LARGE_INTEGER UserTime;    /**< 用户态累计 CPU 时间 */
} ARK_KERNEL_USER_TIMES;

/** @brief 内核态 ZwQueryInformationProcess 声明（未导出到头文件）。 */
NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);

/**
 * @brief PID 收集累加器，合并 View B/C 扫描结果。
 */
typedef struct _ARK_PID_ACCUMULATOR {
    UCHAR* bitmap;                       /**< PID 位图，标记已收录 PID */
    SIZE_T bitmapBytes;                  /**< 位图字节数 */
    ARK_KERNEL_PROCESS_ENTRY* entries;     /**< 进程条目数组 */
    ULONG entryCount;                    /**< 当前条目数 */
    ULONG cidCount;                      /**< View B 命中计数 */
    ULONG threadCount;                   /**< View C 命中计数 */
} ARK_PID_ACCUMULATOR;

/**
 * @brief 判断进程是否为已退出/僵尸进程。
 *
 * 判定条件（满足其一即为死亡）：
 * 1) ExitTime != 0（ProcessTimes）
 * 2) HandleCount == 0（ProcessHandleCount）
 *
 * 优先使用已有 EPROCESS 经 ObOpenObjectByPointer 打开句柄；
 * 打开或任一查询失败时按已死亡处理。
 *
 * @param pid 进程 PID。
 * @param process 可选 EPROCESS 指针，非空时优先使用。
 * @return TRUE 表示已死亡应跳过，FALSE 表示仍存活。
 * @irql PASSIVE_LEVEL
 */
static BOOLEAN IsDeadProcess(
    _In_ ULONG pid,
    _In_opt_ PEPROCESS process
) {
    HANDLE processHandle = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ARK_KERNEL_USER_TIMES processTimes = { 0 };
    ULONG handleCount = 0;
    BOOLEAN isDead = TRUE;
    if (pid == 0UL) {
        return TRUE;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return TRUE;
    }
    if (process != NULL && PsProcessType != NULL && *PsProcessType != NULL) {
        status = ObOpenObjectByPointer(
            process,
            OBJ_KERNEL_HANDLE,
            NULL,
            PROCESS_QUERY_LIMITED_INFORMATION,
            *PsProcessType,
            KernelMode,
            &processHandle);
    } else {
        CLIENT_ID clientId = { 0 };
        OBJECT_ATTRIBUTES objectAttributes = { 0 };
        clientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
        clientId.UniqueThread = NULL;
        InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);
        status = ZwOpenProcess(
            &processHandle,
            PROCESS_QUERY_LIMITED_INFORMATION,
            &objectAttributes,
            &clientId);
    }
    if (!NT_SUCCESS(status) || processHandle == NULL) {
        return TRUE;
    }
    status = ZwQueryInformationProcess(
        processHandle,
        ARK_PROCESS_TIMES,
        &processTimes,
        sizeof(processTimes),
        NULL);
    if (!NT_SUCCESS(status)) {
        ZwClose(processHandle);
        return TRUE;
    }
    if (processTimes.ExitTime.QuadPart != 0LL) {
        ZwClose(processHandle);
        return TRUE;
    }
    status = ZwQueryInformationProcess(
        processHandle,
        ARK_PROCESS_HANDLE_COUNT,
        &handleCount,
        sizeof(handleCount),
        NULL);
    if (!NT_SUCCESS(status)) {
        ZwClose(processHandle);
        return TRUE;
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
 * @brief View C：通过 PsLookupThreadByThreadId 获取线程归属进程。
 *
 * 步进 4 遍历 TID，已在 View B 入表的 PID 跳过重复 ExitTime 检测。
 *
 * @param accumulator 累加器（输入输出）。
 * @param scanLimit PID/TID 扫描上限。
 * @return STATUS_SUCCESS。
 * @irql PASSIVE_LEVEL
 */
static NTSTATUS CollectThreadView(
    _Inout_ ARK_PID_ACCUMULATOR* accumulator,
    _In_ ULONG scanLimit) {
    ULONG tid = 0;
    ULONG loopIndex = 0;
    for (tid = 4UL; tid <= scanLimit; tid += 4UL) {
        PETHREAD thread = NULL;
        PEPROCESS process = NULL;
        PEPROCESS refProcess = NULL;
        ULONG pid = 0;
        NTSTATUS status = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)tid, &thread);
        loopIndex++;
        YieldScanProgress(loopIndex);
        if (!NT_SUCCESS(status) || thread == NULL) {
            continue;
        }
        process = IoThreadToProcess(thread);
        if (process != NULL) {
            pid = HandleToULong(PsGetProcessId(process));
            if (pid != 0UL && pid <= scanLimit) {
                status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &refProcess);
                if (NT_SUCCESS(status) && refProcess != NULL) {
                    /* View B 已收录则跳过 ExitTime 重复查询。 */
                    if (IsPidBitSet(accumulator->bitmap, accumulator->bitmapBytes, pid) ||
                        !IsDeadProcess(pid, refProcess)) {
                        AddProcessToAccumulator(
                            accumulator,
                            pid,
                            ARK_FLAG_VIEW_THREAD,
                            refProcess);
                    }
                    ObDereferenceObject(refProcess);
                }
            }
        }
        ObDereferenceObject(thread);
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
 * 依次执行 CollectCidView、CollectThreadView，结果写入 response。
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
	// 执行 View B/C 扫描
    status = CollectCidView(&accumulator, scanLimit);
    if (!NT_SUCCESS(status)) {
        FreePidAccumulator(&accumulator);
        response->Status = (ULONG)status;
        return status;
    }
	// 执行 View C 扫描
    status = CollectThreadView(&accumulator, scanLimit);
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
