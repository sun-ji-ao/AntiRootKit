#pragma once

#include <cstdint>
#include <string>
#include <vector>

/**
 * @brief 单条隐藏进程记录。
 */
struct HiddenProcessEntry {
    std::uint32_t pid = 0;              /**< 进程 PID */
    std::uint32_t parentPid = 0;        /**< 父进程 PID */
    std::uint32_t viewFlags = 0;        /**< 内核视图标志位（ARK_FLAG_VIEW_*） */
    std::uint64_t eprocessAddress = 0;  /**< 内核 EPROCESS 地址 */
    std::string imageName;              /**< 进程映像短名 */
    std::string imagePath;              /**< 进程完整映像路径 */
    std::string reason;                 /**< 判定为隐藏的原因描述 */
};

/**
 * @brief 跨视图隐藏进程检测结果。
 */
struct CrossDetectResult {
    std::uint32_t status = 0;           /**< 操作状态码，ERROR_SUCCESS 表示成功 */
    std::uint32_t r3Count = 0;          /**< View A：R3 枚举进程数 */
    std::uint32_t cidCount = 0;         /**< View B：内核 CID 命中数 */
    std::uint32_t threadCount = 0;      /**< View C：内核线程归属命中数 */
    std::uint32_t kernelUnionCount = 0; /**< 内核 B|C 合并去重后的进程数 */
    std::uint32_t maxPidScanned = 0;    /**< 内核扫描 PID 上限 */
    std::vector<HiddenProcessEntry> hiddenProcesses; /**< 隐藏进程列表，公式：(B union C)-A */
};

/**
 * @brief 执行跨视图隐藏进程检测。
 *
 * 先通过驱动收集内核 View B/C，再枚举 R3 View A，按公式 Hidden=(B union C)-A 计算结果。
 *
 * @return 检测结果；失败时 status 为 Win32 错误码，hiddenProcesses 可能为空。
 */
CrossDetectResult crossDetectHiddenProcesses();
