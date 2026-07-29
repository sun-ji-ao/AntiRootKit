#include "json_report_writer.h"

#include "../include/Common.h"

#include <chrono>
#include <cstdio>
#include <iomanip>
#include <sstream>

/** @brief 构造并打开 JSON 输出文件，见 json_report_writer.h。 */
JsonReportWriter::JsonReportWriter(const std::filesystem::path& jsonPath) {
    stream_.open(jsonPath, std::ios::binary);
    if (!stream_.is_open()) {
        printf("[ARK] failed to open json: %s\n", jsonPath.string().c_str());
    }
}

/** @brief 判断文件流是否已打开。 */
bool JsonReportWriter::isOpen() const {
    return stream_.is_open();
}

/** @brief 写入指定层级缩进（每层 2 空格）。 */
void JsonReportWriter::writeIndent(std::ostream& stream, int level) {
    for (int index = 0; index < level; ++index) {
        stream << "  ";
    }
}

/** @brief 写入一行 JSON 字符串字段。 */
void JsonReportWriter::writeStringField(
    std::ostream& stream,
    int level,
    const char* key,
    const std::string& value,
    bool trailingComma) {
    writeIndent(stream, level);
    stream << "\"" << key << "\": \"" << escapeJsonString(value) << "\"";
    if (trailingComma) {
        stream << ",";
    }
    stream << "\r\n";
}

/** @brief 写入一行 JSON 无符号整数字段。 */
void JsonReportWriter::writeUIntField(
    std::ostream& stream,
    int level,
    const char* key,
    std::uint32_t value,
    bool trailingComma) {
    writeIndent(stream, level);
    stream << "\"" << key << "\": " << value;
    if (trailingComma) {
        stream << ",";
    }
    stream << "\r\n";
}

/** @brief 转义 JSON 特殊字符（引号、反斜杠、控制字符）。 */
std::string JsonReportWriter::escapeJsonString(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size() + 8);
    for (char ch : value) {
        if (ch == '"' || ch == '\\') {
            escaped.push_back('\\');
            escaped.push_back(ch);
        } else if (static_cast<unsigned char>(ch) < 0x20) {
            escaped.push_back(' ');
        } else {
            escaped.push_back(ch);
        }
    }
    return escaped;
}

/** @brief 生成 "YYYY-MM-DD HH:MM:SS" 格式本地时间戳。 */
std::string JsonReportWriter::formatTimestamp() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t timeValue = std::chrono::system_clock::to_time_t(now);
    std::tm localTm = {};
    localtime_s(&localTm, &timeValue);
    std::ostringstream stream;
    stream << std::put_time(&localTm, "%Y-%m-%d %H:%M:%S");
    return stream.str();
}

/** @brief 将 CrossDetectResult 序列化为 JSON 并写入文件。 */
bool JsonReportWriter::writeHiddenProcessResult(const CrossDetectResult& result) {
    if (!stream_.is_open()) {
        return false;
    }
    stream_ << "{\r\n";
    writeStringField(stream_, 1, "timestamp", formatTimestamp(), true);
    writeStringField(stream_, 1, "formula", "Hidden = (B union C) - A(r3_enum)", true);
    writeUIntField(stream_, 1, "status", result.status, true);
    writeUIntField(stream_, 1, "r3CountA", result.r3Count, true);
    writeUIntField(stream_, 1, "cidCountB", result.cidCount, true);
    writeUIntField(stream_, 1, "threadCountC", result.threadCount, true);
    writeUIntField(stream_, 1, "kernelUnionCount", result.kernelUnionCount, true);
    writeUIntField(stream_, 1, "hiddenCount", static_cast<std::uint32_t>(result.hiddenProcesses.size()), true);
    writeUIntField(stream_, 1, "maxPidScanned", result.maxPidScanned, true);
    writeIndent(stream_, 1);
    stream_ << "\"hiddenProcesses\": [\r\n";
    for (std::size_t index = 0; index < result.hiddenProcesses.size(); ++index) {
        const HiddenProcessEntry& entry = result.hiddenProcesses[index];
        writeIndent(stream_, 2);
        stream_ << "{\r\n";
        writeUIntField(stream_, 3, "pid", entry.pid, true);
        writeUIntField(stream_, 3, "parentPid", entry.parentPid, true);
        writeStringField(stream_, 3, "imageName", entry.imageName, true);
        writeStringField(stream_, 3, "imagePath", entry.imagePath, true);
        writeIndent(stream_, 3);
        stream_ << "\"eprocess\": \"0x" << std::hex << std::uppercase
                << entry.eprocessAddress << std::dec << "\",\r\n";
        writeUIntField(stream_, 3, "flags", entry.viewFlags, true);
        writeIndent(stream_, 3);
        stream_ << "\"views\": {";
        stream_ << "\"cidB\": " << (((entry.viewFlags & ARK_FLAG_VIEW_CID) != 0) ? "true" : "false") << ", ";
        stream_ << "\"threadC\": " << (((entry.viewFlags & ARK_FLAG_VIEW_THREAD) != 0) ? "true" : "false");
        stream_ << "},\r\n";
        writeStringField(stream_, 3, "reason", entry.reason, false);
        writeIndent(stream_, 2);
        stream_ << "}";
        if (index + 1 < result.hiddenProcesses.size()) {
            stream_ << ",\r\n";
        } else {
            stream_ << "\r\n";
        }
    }
    writeIndent(stream_, 1);
    stream_ << "]\r\n";
    stream_ << "}\r\n";
    return true;
}