#pragma once

#include <cstdint>
#include <string>
#include <vector>

/**
 * @brief 单条隐藏模块记录。
 */
struct HiddenModuleEntry {
    std::uint32_t viewFlags = 0;       /**< 内核视图标志位（ARK_FLAG_VIEW_*） */
    std::uint32_t imageSize = 0;       /**< 映像大小 */
    std::uint64_t imageBase = 0;       /**< 映像基址 */
    std::uint64_t driverObjectAddress = 0; /**< DRIVER_OBJECT 地址 */
    std::string moduleName;            /**< 模块短名 */
    std::string modulePath;            /**< 模块完整路径 */
    std::string reason;                /**< 判定为隐藏的原因描述 */
};

/**
 * @brief 跨视图隐藏模块检测结果。
 */
struct CrossDetectModuleResult {
    std::uint32_t status = 0;           /**< 操作状态码，ERROR_SUCCESS 表示成功 */
    std::uint32_t r3Count = 0;          /**< R3 枚举模块数 */
    std::uint32_t sectionCount = 0;     /**< View A：DriverSection 命中数 */
    std::uint32_t driverCount = 0;      /**< View B：\\Driver 对象命中数 */
    std::uint32_t kernelUnionCount = 0; /**< 内核 A|B 合并去重后的模块数 */
    std::vector<HiddenModuleEntry> hiddenModules; /**< 隐藏模块列表，公式：(A union B)-R3 */
};

/**
 * @brief 执行跨视图隐藏模块检测。
 *
 * 先通过驱动收集内核 View A/B，再枚举 R3 模块列表，按公式 Hidden=(A union B)-R3 计算。
 *
 * @return 检测结果；失败时 status 为 Win32 错误码，hiddenModules 可能为空。
 */
CrossDetectModuleResult crossDetectHiddenModules();
