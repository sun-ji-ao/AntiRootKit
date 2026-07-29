#pragma once

#include "DetectHidden.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>

/**
 * @brief JSON 检测报告写入器。
 *
 * 每种检测结果对应一个 writeXxxResult 方法，公共格式化逻辑由私有静态方法复用。
 */
class JsonReportWriter {
public:
    /**
     * @brief 构造并打开目标 JSON 文件。
     * @param jsonPath 输出 JSON 文件路径。
     */
    explicit JsonReportWriter(const std::filesystem::path& jsonPath);

    /**
     * @brief 判断输出文件是否已成功打开。
     * @return 文件已打开返回 true，否则返回 false。
     */
    bool isOpen() const;

    /**
     * @brief 将隐藏进程检测结果写入 JSON 文件。
     * @param result 跨视图检测输出结果。
     * @return 写入成功返回 true，文件未打开或写入失败返回 false。
     */
    bool writeHiddenProcessResult(const CrossDetectResult& result);

private:
    /** @brief 转义 JSON 字符串中的特殊字符。 */
    static std::string escapeJsonString(const std::string& value);
    /** @brief 生成当前本地时间戳字符串。 */
    static std::string formatTimestamp();
    /** @brief 向输出流写入指定层级缩进。 */
    static void writeIndent(std::ostream& stream, int level);
    /** @brief 写入 JSON 字符串字段行。 */
    static void writeStringField(
        std::ostream& stream,
        int level,
        const char* key,
        const std::string& value,
        bool trailingComma);
    /** @brief 写入 JSON 无符号整数字段行。 */
    static void writeUIntField(
        std::ostream& stream,
        int level,
        const char* key,
        std::uint32_t value,
        bool trailingComma);

    std::ofstream stream_; /**< JSON 输出文件流 */
};