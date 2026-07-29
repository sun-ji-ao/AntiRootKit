#pragma once

#ifndef ARK_LOG_H
#define ARK_LOG_H

#include <ntddk.h>

/** @brief 输出错误级别内核调试日志。 */
#define LOGE(format, ...) DbgPrint("[ARK]Error: " format "\n", ##__VA_ARGS__)
/** @brief 输出警告级别内核调试日志。 */
#define LOGW(format, ...) DbgPrint("[ARK]Warn: " format "\n", ##__VA_ARGS__)
/** @brief 输出信息级别内核调试日志。 */
#define LOGI(format, ...) DbgPrint("[ARK]Infor: " format "\n", ##__VA_ARGS__)

#endif