#include "DetectHidden.h"

#include "../include/Common.h"

#include <algorithm>
#include <cstdio>
#include <memory>
#include <vector>
#include <Windows.h>
#include <TlHelp32.h>

#pragma comment(lib, "kernel32.lib")

namespace {

/** @brief NtQueryInformationProcess 函数指针类型。 */
using NtQueryInformationProcessFn = LONG(WINAPI*)(
    HANDLE processHandle,
    ULONG processInformationClass,
    PVOID processInformation,
    ULONG processInformationLength,
    PULONG returnLength);

/**
 * @brief NtQueryInformationProcess(ProcessBasicInformation) 返回结构。
 */
struct ProcessBasicInformation {
    PVOID reserved1;                      /**< 保留字段 */
    PVOID pebBaseAddress;                 /**< 进程 PEB 地址 */
    PVOID reserved2[2];                   /**< 保留字段 */
    ULONG_PTR uniqueProcessId;            /**< 当前进程 PID */
    ULONG_PTR inheritedFromUniqueProcessId; /**< 父进程 PID */
};

/**
 * @brief 判断 PID 是否已存在于集合中。
 * @param pids R3 进程 PID 列表。
 * @param pid 待查询的进程 PID。
 * @return 已存在返回 true，否则返回 false。
 */
bool isPidInSet(const std::vector<ULONG>& pids, ULONG pid) {
    return std::find(pids.begin(), pids.end(), pid) != pids.end();
}

/**
 * @brief 将 PID 加入 R3 进程集合（自动去重）。
 * @param pids R3 进程 PID 列表（输入输出）。
 * @param pid 待添加的进程 PID，0 会被忽略。
 * @return 添加成功返回 true；集合已满返回 false。
 */
bool addPidToSet(std::vector<ULONG>& pids, ULONG pid) {
    if (pid == 0) {
        return true;
    }
    if (isPidInSet(pids, pid)) {
        return true;
    }
    if (pids.size() >= ARK_MAX_PROCESS_ENTRIES) {
        return false;
    }
    pids.push_back(pid);
    return true;
}

/**
 * @brief View A：通过 CreateToolhelp32Snapshot 枚举 R3 可见进程。
 * @param pids 输出 PID 列表，调用前会被清空。
 * @return 枚举成功返回 true，快照创建或遍历失败返回 false。
 */
bool enumerateR3Processes(std::vector<ULONG>& pids) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    pids.clear();
    if (!Process32FirstW(snapshot, &entry)) {
        CloseHandle(snapshot);
        return false;
    }
    do {
        if (!addPidToSet(pids, entry.th32ProcessID)) {
            CloseHandle(snapshot);
            return false;
        }
    } while (Process32NextW(snapshot, &entry));
    CloseHandle(snapshot);
    return true;
}

/**
 * @brief 根据视图标志生成隐藏原因描述字符串。
 * @param viewFlags 内核视图标志位（ARK_FLAG_VIEW_CID / ARK_FLAG_VIEW_THREAD）。
 * @return 可读的原因描述，例如 "cid+thread present in kernel B|C but missing in r3_enum(A)"。
 */
std::string buildHiddenReason(ULONG viewFlags) {
    std::string reason;
    if ((viewFlags & ARK_FLAG_VIEW_CID) != 0) {
        reason += "cid+";
    }
    if ((viewFlags & ARK_FLAG_VIEW_THREAD) != 0) {
        reason += "handle+";
    }
    if (!reason.empty() && reason.back() == '+') {
        reason.pop_back();
    }
    reason += " present in kernel B|C but missing in r3_enum(A)";
    return reason;
}

/**
 * @brief 补充隐藏进程的映像路径与父进程 PID。
 *
 * 通过 OpenProcess / QueryFullProcessImageNameA / NtQueryInformationProcess 获取信息。
 *
 * @param entry 隐藏进程记录（输入输出）；打开失败时 imagePath 设为 "N/A"。
 */
void enrichProcessInfo(HiddenProcessEntry& entry) {
	// 通过 OpenProcess 获取进程句柄，尝试使用 PROCESS_QUERY_LIMITED_INFORMATION 权限。
    HANDLE process = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        entry.pid);
    if (process == NULL) {
		// 兼容 Windows 7 / Server 2008 R2，尝试使用 PROCESS_QUERY_INFORMATION | PROCESS_VM_READ 打开进程。 
        process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.pid);
    }
    if (process == NULL) {
        if (entry.imagePath.empty()) {
            entry.imagePath = "N/A";
        }
        return;
    }
    char pathBuffer[ARK_IMAGE_PATH_MAX] = {};
    DWORD pathChars = ARK_IMAGE_PATH_MAX;
    // 尝试获取完整的进程映像路径
    if (!QueryFullProcessImageNameA(process, 0, pathBuffer, &pathChars)) {
        entry.imagePath = "N/A";
    } else {
        entry.imagePath = pathBuffer;
        if (entry.imageName.empty() || _stricmp(entry.imageName.c_str(), "unknown") == 0) {
            const char* slash = strrchr(pathBuffer, '\\');
            if (slash != NULL && slash[1] != '\0') {
                entry.imageName = slash + 1;
            }
        }
    }
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll != NULL) {
        auto ntQuery = reinterpret_cast<NtQueryInformationProcessFn>(
            GetProcAddress(ntdll, "NtQueryInformationProcess"));
        if (ntQuery != NULL) {
            ProcessBasicInformation pbi = {};
            LONG status = ntQuery(process, 0, &pbi, sizeof(pbi), NULL);
            if (status >= 0) {
                entry.parentPid = static_cast<std::uint32_t>(pbi.inheritedFromUniqueProcessId);
            }
        }
    }
    CloseHandle(process);
}

/**
 * @brief 通过 IOCTL 向驱动查询内核 View B/C 进程列表。
 * @param response 驱动返回的内核视图数据（输出）。
 * @return 查询成功返回 true，设备打开或 IOCTL 失败返回 false。
 */
bool queryKernelProcessViews(ARK_KERNEL_VIEWS_RESPONSE& response) {
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
        IOCTL_ARK_QUERY_KERNEL_VIEWS,
        NULL,
        0,
        &response,
        static_cast<DWORD>(sizeof(response)),
        &bytesReturned,
        NULL);
    CloseHandle(device);
    if (!ok) {
        printf("[ARK] DeviceIoControl failed: %lu\n", GetLastError());
        return false;
    }
    if (bytesReturned < sizeof(ARK_KERNEL_VIEWS_RESPONSE)) {
        printf("[ARK] incomplete kernel response, bytes=%lu\n", bytesReturned);
        return false;
    }
    return true;
}

} // namespace

/**
 * @brief 执行跨视图隐藏进程检测（实现）。
 *
 * 流程：IOCTL 获取内核 View B/C -> R3 枚举 View A -> 计算 Hidden=(B union C)-A。
 * 对每条隐藏记录补充映像路径、父进程 PID 与原因描述。
 *
 * @return CrossDetectResult；失败时 status 为 Win32 错误码。
 */
CrossDetectResult crossDetectHiddenProcesses() {
    CrossDetectResult result;
    auto kernelViews = std::make_unique<ARK_KERNEL_VIEWS_RESPONSE>();
    std::vector<ULONG> r3Pids;
    if (!queryKernelProcessViews(*kernelViews)) {
        result.status = GetLastError();
        return result;
    }
    if (!enumerateR3Processes(r3Pids)) {
        printf("[ARK] EnumerateR3Processes failed: %lu\n", GetLastError());
        result.status = GetLastError();
        return result;
    }
    result.status = kernelViews->Status;
    result.r3Count = static_cast<std::uint32_t>(r3Pids.size());
    result.cidCount = kernelViews->CidCount;
    result.threadCount = kernelViews->ThreadCount;
    result.kernelUnionCount = kernelViews->EntryCount;
    result.maxPidScanned = kernelViews->MaxPidScanned;
    for (ULONG index = 0; index < kernelViews->EntryCount && index < ARK_MAX_PROCESS_ENTRIES; ++index) {
        const ARK_KERNEL_PROCESS_ENTRY& kernelEntry = kernelViews->Entries[index];
        if (isPidInSet(r3Pids, kernelEntry.ProcessId)) {
            continue;
        }
        if (result.hiddenProcesses.size() >= ARK_MAX_PROCESS_ENTRIES) {
            break;
        }
        HiddenProcessEntry hiddenEntry;
        hiddenEntry.pid = kernelEntry.ProcessId;
        hiddenEntry.parentPid = 0;
        hiddenEntry.viewFlags = kernelEntry.ViewFlags;
        hiddenEntry.eprocessAddress = kernelEntry.EprocessAddress;
        hiddenEntry.imageName = kernelEntry.ImageName;
        hiddenEntry.reason = buildHiddenReason(kernelEntry.ViewFlags);
        enrichProcessInfo(hiddenEntry);
        result.hiddenProcesses.push_back(std::move(hiddenEntry));
    }
    return result;
}
