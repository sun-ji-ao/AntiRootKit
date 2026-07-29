#pragma once

#include "DriverEntry.h"

/**
 * @brief 收集内核 View B/C 进程列表（CID + 系统句柄快照）。
 *
 * View B：PsLookupProcessByProcessId 暴力扫描 CID。
 * View C：ZwQuerySystemInformation(SystemHandleInformation) 全量句柄筛选 Process/Thread。
 * PID 上限固定为 ARK_MAX_SCAN_PID (65535)。
 *
 * @param response 输出缓冲区，填充 ARK_KERNEL_VIEWS_RESPONSE。
 * @return 成功返回 STATUS_SUCCESS；参数无效或 IRQL 不正确时返回相应 NTSTATUS。
 * @irql PASSIVE_LEVEL
 */
NTSTATUS QueryKernelProcessViews(
    _Out_ ARK_KERNEL_VIEWS_RESPONSE* response);