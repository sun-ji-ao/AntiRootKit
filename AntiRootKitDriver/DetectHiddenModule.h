#pragma once

#include "DriverEntry.h"

/**
 * @brief 收集内核模块 View A/B 列表（DriverSection + \\Driver 对象）。
 *
 * View A：遍历当前驱动 DriverSection->InLoadOrderLinks（PsLoadedModuleList）。
 * View B：枚举 \\Driver 对象目录，经 ObReferenceObjectByName 取得 DRIVER_OBJECT。
 *
 * @param response 输出缓冲区，填充 ARK_KERNEL_MODULE_VIEWS_RESPONSE。
 * @return 成功返回 STATUS_SUCCESS；参数无效或 IRQL 不正确时返回相应 NTSTATUS。
 * @irql PASSIVE_LEVEL
 */
NTSTATUS QueryKernelModuleViews(
    _Out_ ARK_KERNEL_MODULE_VIEWS_RESPONSE* response);
