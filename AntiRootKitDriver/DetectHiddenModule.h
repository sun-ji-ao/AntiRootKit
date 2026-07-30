#pragma once

#include "DriverEntry.h"

/**
 * @brief 收集内核模块多视图列表并填充 IOCTL 输出缓冲。
 *
 * View A：从当前驱动 DriverSection 遍历 PsLoadedModuleList。
 * View B：枚举 \\Driver 对象目录并解析 DRIVER_OBJECT。
 * View C：SystemBigPool 完整 Native PE 残留（SizeOfImage/目录校验去误报，软失败）。
 *
 * @param response 输出缓冲区，填充 ARK_KERNEL_MODULE_VIEWS_RESPONSE。
 * @return 成功返回 STATUS_SUCCESS；参数无效或 IRQL 不正确时返回相应 NTSTATUS。
 * @irql PASSIVE_LEVEL
 */
NTSTATUS QueryKernelModuleViews(
    _Out_ ARK_KERNEL_MODULE_VIEWS_RESPONSE* response);
