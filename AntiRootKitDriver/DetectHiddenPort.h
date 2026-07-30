#pragma once

#include "DriverEntry.h"

/**
 * @brief 收集内核端口视图：View B（AFD 句柄）+ View C（NSI TCP/UDP）。
 *
 * View B：SystemHandleInformation 中 \\Device\\Afd 文件对象，按 PID 聚合。
 * View C：直接调用 netio!NsiAllocateAndGetTable，绕过 nsiproxy IRP Hook。
 * 检测公式由应用层完成：Hidden = (B ∪ C) − R3(GetExtendedTcp/UdpTable)。
 *
 * @param response 输出缓冲区，填充 ARK_KERNEL_PORT_VIEWS_RESPONSE。
 * @return 成功返回 STATUS_SUCCESS；参数无效或解析失败时返回相应 NTSTATUS。
 * @irql PASSIVE_LEVEL
 */
NTSTATUS QueryKernelPortViews(
    _Out_ ARK_KERNEL_PORT_VIEWS_RESPONSE* response);
