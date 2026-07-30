#include "DetectHiddenModule.h"

#include "../include/Common.h"

#include <cctype>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>
#include <Windows.h>
#include <Psapi.h>

#pragma comment(lib, "psapi.lib")

namespace {

/**
 * @brief R3 枚举到的单条模块信息。
 */
struct R3ModuleEntry {
    ULONG64 imageBase = 0;  /**< 映像基址 */
    std::string moduleName; /**< 模块短名 */
    std::string modulePath; /**< 模块完整路径 */
};

/**
 * @brief 将字符串转为小写副本，用于大小写不敏感比较。
 * @param value 原始字符串。
 * @return 小写字符串。
 */
std::string toLowerCopy(const std::string& value) {
    std::string lower = value;
    for (char& ch : lower) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return lower;
}

/**
 * @brief 从完整路径提取文件名。
 * @param path 完整路径。
 * @return 文件名；无路径分隔符时返回原串。
 */
std::string extractFileName(const std::string& path) {
    const std::size_t slash = path.find_last_of("\\/");
    if (slash == std::string::npos) {
        return path;
    }
    return path.substr(slash + 1);
}

/**
 * @brief 判断 R3 模块集合是否已包含指定基址或同名模块。
 * @param modules R3 模块列表。
 * @param imageBase 待匹配基址，0 表示仅按名称。
 * @param moduleName 待匹配短名。
 * @return 已存在返回 true。
 */
bool isModuleInR3Set(
    const std::vector<R3ModuleEntry>& modules,
    ULONG64 imageBase,
    const std::string& moduleName
) {
    const std::string lowerName = toLowerCopy(moduleName);
    for (const R3ModuleEntry& entry : modules) {
        if (imageBase != 0 && entry.imageBase == imageBase) {
            return true;
        }
        if (!lowerName.empty() && toLowerCopy(entry.moduleName) == lowerName) {
            return true;
        }
    }
    return false;
}

/**
 * @brief View R3：通过 EnumDeviceDrivers 枚举用户态可见内核模块。
 * @param modules 输出模块列表，调用前会被清空。
 * @return 枚举成功返回 true。
 */
bool enumerateR3Modules(std::vector<R3ModuleEntry>& modules) {
    DWORD bytesNeeded = 0;
    modules.clear();
    if (!EnumDeviceDrivers(NULL, 0, &bytesNeeded) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        if (bytesNeeded == 0) {
            return false;
        }
    }
    if (bytesNeeded == 0) {
        return false;
    }
    const DWORD driverCount = bytesNeeded / static_cast<DWORD>(sizeof(LPVOID));
    std::vector<LPVOID> drivers(driverCount);
    DWORD bytesReturned = 0;
    if (!EnumDeviceDrivers(drivers.data(), bytesNeeded, &bytesReturned)) {
        return false;
    }
    const DWORD actualCount = bytesReturned / static_cast<DWORD>(sizeof(LPVOID));
    for (DWORD index = 0; index < actualCount && modules.size() < ARK_MAX_MODULE_ENTRIES; ++index) {
        if (drivers[index] == NULL) {
            continue;
        }
        R3ModuleEntry entry;
        entry.imageBase = static_cast<ULONG64>(reinterpret_cast<ULONG_PTR>(drivers[index]));
        char pathBuffer[ARK_MODULE_PATH_MAX] = {};
        char nameBuffer[ARK_MODULE_NAME_MAX] = {};
        if (GetDeviceDriverFileNameA(drivers[index], pathBuffer, ARK_MODULE_PATH_MAX) > 0) {
            entry.modulePath = pathBuffer;
        } else {
            entry.modulePath = "N/A";
        }
        if (GetDeviceDriverBaseNameA(drivers[index], nameBuffer, ARK_MODULE_NAME_MAX) > 0) {
            entry.moduleName = nameBuffer;
        } else if (!entry.modulePath.empty() && entry.modulePath != "N/A") {
            entry.moduleName = extractFileName(entry.modulePath);
        } else {
            entry.moduleName = "unknown";
        }
        modules.push_back(std::move(entry));
    }
    return true;
}

/**
 * @brief 判断内核模块条目是否为交叉对比中的无效/误报样本。
 *
 * 当前 View C 仅 BigPool：要求有效短名；非残留条目还要求 ImageBase/ImageSize 有效。
 *
 * @param entry 内核返回的模块条目。
 * @return 应过滤返回 true。
 */
bool isFalsePositiveKernelModule(const ARK_KERNEL_MODULE_ENTRY& entry) {
    const bool hasResidual = (entry.ViewFlags & ARK_FLAG_VIEW_RESIDUAL) != 0;
    if (entry.ModuleName[0] == '\0' || _stricmp(entry.ModuleName, "unknown") == 0) {
        return true;
    }
    if (entry.ImageBase == 0) {
        return true;
    }
    if (entry.ImageSize == 0 && !hasResidual) {
        return true;
    }
    return false;
}

/**
 * @brief 根据视图标志生成隐藏模块原因描述。
 * @param viewFlags 内核视图标志位。
 * @return 可读原因字符串。
 */
std::string buildHiddenModuleReason(ULONG viewFlags) {
    std::string reason;
    if ((viewFlags & ARK_FLAG_VIEW_SECTION) != 0) {
        reason += "section+";
    }
    if ((viewFlags & ARK_FLAG_VIEW_DRIVEROBJ) != 0) {
        reason += "driverobj+";
    }
    if ((viewFlags & ARK_FLAG_RESIDUAL_POOL) != 0) {
        reason += "bigpool+";
    } else if ((viewFlags & ARK_FLAG_VIEW_RESIDUAL) != 0) {
        reason += "residual+";
    }
    if (!reason.empty() && reason.back() == '+') {
        reason.pop_back();
    }
    reason += " present in kernel A|B|C but missing in r3_enum";
    return reason;
}

/**
 * @brief 通过 IOCTL 向驱动查询内核模块 View A/B/C。
 * @param response 驱动返回的内核模块视图数据（输出）。
 * @return 查询成功返回 true。
 */
bool queryKernelModuleViews(ARK_KERNEL_MODULE_VIEWS_RESPONSE& response) {
    ZeroMemory(&response, sizeof(response));
    HANDLE device = CreateFileW(
        ARK_USER_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (device == INVALID_HANDLE_VALUE) {
        printf("[ARK] CreateFile failed: %lu\n", GetLastError());
        return false;
    }
    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(
        device,
        IOCTL_ARK_QUERY_KERNEL_MODULE_VIEWS,
        NULL,
        0,
        &response,
        static_cast<DWORD>(sizeof(response)),
        &bytesReturned,
        NULL);
    CloseHandle(device);
    if (!ok) {
        printf("[ARK] DeviceIoControl(module) failed: %lu\n", GetLastError());
        return false;
    }
    if (bytesReturned < sizeof(ARK_KERNEL_MODULE_VIEWS_RESPONSE)) {
        printf("[ARK] incomplete module kernel response, bytes=%lu\n", bytesReturned);
        return false;
    }
    return true;
}

/**
 * @brief 将内核条目转换为隐藏模块输出记录。
 * @param kernelEntry 内核返回条目。
 * @return 填充后的 HiddenModuleEntry。
 */
HiddenModuleEntry buildHiddenModuleEntry(const ARK_KERNEL_MODULE_ENTRY& kernelEntry) {
    HiddenModuleEntry hiddenEntry;
    hiddenEntry.viewFlags = kernelEntry.ViewFlags;
    hiddenEntry.imageSize = kernelEntry.ImageSize;
    hiddenEntry.imageBase = kernelEntry.ImageBase;
    hiddenEntry.driverObjectAddress = kernelEntry.DriverObjectAddress;
    hiddenEntry.moduleName = kernelEntry.ModuleName;
    hiddenEntry.modulePath = kernelEntry.ModulePath;
    hiddenEntry.reason = buildHiddenModuleReason(kernelEntry.ViewFlags);
    return hiddenEntry;
}

} // namespace

/**
 * @brief 执行跨视图隐藏模块检测（实现）。
 *
 * 流程：IOCTL 获取内核 View A/B/C -> R3 枚举 -> Hidden=(A|B|C)-R3。
 *
 * @return CrossDetectModuleResult；失败时 status 为 Win32 错误码。
 */
CrossDetectModuleResult crossDetectHiddenModules() {
    CrossDetectModuleResult result;
    auto kernelViews = std::make_unique<ARK_KERNEL_MODULE_VIEWS_RESPONSE>();
    std::vector<R3ModuleEntry> r3Modules;
    if (!queryKernelModuleViews(*kernelViews)) {
        result.status = GetLastError();
        return result;
    }
    if (!enumerateR3Modules(r3Modules)) {
        printf("[ARK] EnumerateR3Modules failed: %lu\n", GetLastError());
        result.status = GetLastError();
        return result;
    }
    result.status = kernelViews->Status;
    result.r3Count = static_cast<std::uint32_t>(r3Modules.size());
    result.sectionCount = kernelViews->SectionCount;
    result.driverCount = kernelViews->DriverCount;
    result.residualCount = kernelViews->ResidualCount;
    result.kernelUnionCount = kernelViews->EntryCount;
    for (ULONG index = 0; index < kernelViews->EntryCount && index < ARK_MAX_MODULE_ENTRIES; ++index) {
        const ARK_KERNEL_MODULE_ENTRY& kernelEntry = kernelViews->Entries[index];
        if (isFalsePositiveKernelModule(kernelEntry)) {
            continue;
        }
        if (isModuleInR3Set(r3Modules, kernelEntry.ImageBase, kernelEntry.ModuleName)) {
            continue;
        }
        if (result.hiddenModules.size() >= ARK_MAX_MODULE_ENTRIES) {
            break;
        }
        result.hiddenModules.push_back(buildHiddenModuleEntry(kernelEntry));
    }
    return result;
}
