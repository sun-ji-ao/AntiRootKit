#include "DetectHiddenPort.h"

#include <algorithm>
#include <cstdio>
#include <cctype>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <Winsock2.h>
#include <Ws2tcpip.h>
#include <Windows.h>
#include <wintrust.h>
#include <softpub.h>

#include "../include/Common.h"

#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace {

/** @brief 同一 PID 隐藏条目超过该次数视为批量误报并整组剔除。 */
constexpr std::uint32_t kMaxHiddenEntriesPerPid = 3;
/** @brief 任意地址。 */
constexpr const char* kAnyAddress = "0.0.0.0";
/** @brief 回环地址。 */
constexpr const char* kLoopbackAddress = "127.0.0.1";

/** @brief IPHLPAPI!InternalGetBoundTcpEndpointTable 函数指针类型。 */
using PFN_InternalGetBoundTcpEndpointTable = DWORD(WINAPI*)(
    PMIB_TCPTABLE2* tcpTable,
    HANDLE heap,
    DWORD flags);
/** @brief IPHLPAPI!InternalGetBoundTcp6EndpointTable 函数指针类型。 */
using PFN_InternalGetBoundTcp6EndpointTable = DWORD(WINAPI*)(
    PMIB_TCP6TABLE2* tcp6Table,
    HANDLE heap,
    DWORD flags);

/**
 * @brief R3 可见的单条端口记录。
 */
struct R3PortEntry {
    std::uint32_t protocol = 0;   /**< ARK_PORT_PROTO_TCP / UDP */
    std::uint32_t state = 0;      /**< TCP 状态；UDP 为 0 */
    std::uint32_t owningPid = 0;  /**< 所属进程 PID */
    std::uint32_t localAddr = 0;  /**< 本地 IPv4（网络字节序） */
    std::uint32_t remoteAddr = 0; /**< 远端 IPv4（网络字节序） */
    std::uint16_t localPort = 0;  /**< 本地端口（主机字节序） */
    std::uint16_t remotePort = 0; /**< 远端端口（主机字节序） */
};

/**
 * @brief Bound 端点表中的单条记录（IPv4/IPv6 统一为字符串）。
 */
struct BoundNetInfo {
    std::uint32_t processId = 0;  /**< 所属进程 PID */
    std::uint32_t localPort = 0;  /**< 本地端口（主机字节序） */
    std::uint32_t remotePort = 0; /**< 远端端口（主机字节序） */
    std::string localAddress;     /**< 本地地址字符串 */
    std::string remoteAddress;    /**< 远端地址字符串 */
};

/**
 * @brief 将 16 位网络字节序端口转换为主机字节序（等价 ntohs）。
 * @param value 网络字节序端口值。
 * @return 主机字节序端口值。
 */
USHORT arkNtohs(USHORT value) {
    return static_cast<USHORT>(((value & 0x00FFU) << 8) | ((value & 0xFF00U) >> 8));
}

/**
 * @brief 将 IPv4 网络字节序地址格式化为点分十进制字符串。
 * @param addrNetworkOrder 网络字节序 IPv4 地址。
 * @return 点分十进制字符串（如 "127.0.0.1"）。
 */
std::string formatIpv4(ULONG addrNetworkOrder) {
    char buffer[16] = {};
    const unsigned char* bytes = reinterpret_cast<const unsigned char*>(&addrNetworkOrder);
    sprintf_s(buffer, "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
    return buffer;
}

/**
 * @brief 确保当前进程已调用 WSAStartup；进程生命周期内不调用 WSACleanup。
 * @return 初始化成功或此前已成功返回 true；失败返回 false。
 */
bool ensureWinsockStarted() {
    static bool started = false;
    static bool failed = false;
    if (started) {
        return true;
    }
    if (failed) {
        return false;
    }
    WSADATA wsaData = {};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        failed = true;
        return false;
    }
    started = true;
    return true;
}

/**
 * @brief 通过 RtlGetVersion 判断当前系统是否为 Windows 10 及以上。
 * @return Win10+ 返回 true；否则或查询失败返回 false。
 */
bool isWindows10OrLater() {
    using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL) {
        return false;
    }
    auto rtlGetVersion = reinterpret_cast<RtlGetVersionFn>(GetProcAddress(ntdll, "RtlGetVersion"));
    if (rtlGetVersion == NULL) {
        return false;
    }
    RTL_OSVERSIONINFOW versionInfo = {};
    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
    if (rtlGetVersion(&versionInfo) != 0) {
        return false;
    }
    return versionInfo.dwMajorVersion >= 10UL;
}

/**
 * @brief 判断左侧 R3 记录与右侧协议/地址/端口是否为同一端点。
 * @param left 左侧 R3 端口记录。
 * @param rightProto 右侧协议（ARK_PORT_PROTO_*）。
 * @param rightLocalAddr 右侧本地地址（网络字节序）。
 * @param rightRemoteAddr 右侧远端地址（网络字节序）。
 * @param rightLocalPort 右侧本地端口（主机字节序）。
 * @param rightRemotePort 右侧远端端口（主机字节序）。
 * @return 视为同一端点返回 true（UDP 仅比较本地侧）。
 */
bool isSamePortEndpoint(
    const R3PortEntry& left,
    ULONG rightProto,
    ULONG rightLocalAddr,
    ULONG rightRemoteAddr,
    USHORT rightLocalPort,
    USHORT rightRemotePort
) {
    if (left.protocol != rightProto) {
        return false;
    }
    if (left.localAddr != rightLocalAddr || left.localPort != rightLocalPort) {
        return false;
    }
    if (rightProto == ARK_PORT_PROTO_UDP) {
        return true;
    }
    return left.remoteAddr == rightRemoteAddr && left.remotePort == rightRemotePort;
}

/**
 * @brief 判断 R3 端口集合中是否已包含指定端点。
 * @param ports R3 端口列表。
 * @param protocol 协议。
 * @param localAddr 本地地址（网络字节序）。
 * @param remoteAddr 远端地址（网络字节序）。
 * @param localPort 本地端口（主机字节序）。
 * @param remotePort 远端端口（主机字节序）。
 * @return 已存在返回 true。
 */
bool isPortInR3Set(
    const std::vector<R3PortEntry>& ports,
    ULONG protocol,
    ULONG localAddr,
    ULONG remoteAddr,
    USHORT localPort,
    USHORT remotePort
) {
    for (const R3PortEntry& entry : ports) {
        if (isSamePortEndpoint(entry, protocol, localAddr, remoteAddr, localPort, remotePort)) {
            return true;
        }
    }
    return false;
}

/**
 * @brief 将 after 快照中未出现在 front 的条目并入 front，形成 R3 并集以降低时序误报。
 * @param front 前快照（输入输出，并集结果写回此处）。
 * @param after 后快照（只读）。
 */
void integrateR3PortSnapshots(
    std::vector<R3PortEntry>& front,
    const std::vector<R3PortEntry>& after
) {
    for (const R3PortEntry& entry : after) {
        if (isPortInR3Set(
                front,
                entry.protocol,
                entry.localAddr,
                entry.remoteAddr,
                entry.localPort,
                entry.remotePort)) {
            continue;
        }
        if (front.size() >= ARK_MAX_PORT_ENTRIES) {
            break;
        }
        front.push_back(entry);
    }
}

/**
 * @brief 通过 GetExtendedTcpTable 枚举 R3 可见 IPv4 TCP 端点并追加到列表。
 * @param ports 输出列表（追加写入）。
 * @return 枚举成功返回 true。
 */
bool enumerateR3TcpPorts(std::vector<R3PortEntry>& ports) {
    ULONG tableSize = 0;
    DWORD status = GetExtendedTcpTable(
        NULL,
        &tableSize,
        FALSE,
        AF_INET,
        TCP_TABLE_OWNER_PID_ALL,
        0);
    if (status != ERROR_INSUFFICIENT_BUFFER || tableSize == 0) {
        return false;
    }
    std::vector<unsigned char> buffer(tableSize);
    status = GetExtendedTcpTable(
        buffer.data(),
        &tableSize,
        FALSE,
        AF_INET,
        TCP_TABLE_OWNER_PID_ALL,
        0);
    if (status != NO_ERROR) {
        return false;
    }
    const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
    for (DWORD index = 0; index < table->dwNumEntries; ++index) {
        if (ports.size() >= ARK_MAX_PORT_ENTRIES) {
            break;
        }
        const MIB_TCPROW_OWNER_PID& row = table->table[index];
        R3PortEntry entry;
        entry.protocol = ARK_PORT_PROTO_TCP;
        entry.state = row.dwState;
        entry.owningPid = row.dwOwningPid;
        entry.localAddr = row.dwLocalAddr;
        entry.remoteAddr = row.dwRemoteAddr;
        entry.localPort = arkNtohs(static_cast<USHORT>(row.dwLocalPort & 0xFFFFUL));
        entry.remotePort = arkNtohs(static_cast<USHORT>(row.dwRemotePort & 0xFFFFUL));
        ports.push_back(entry);
    }
    return true;
}

/**
 * @brief 通过 GetExtendedUdpTable 枚举 R3 可见 IPv4 UDP 端点并追加到列表。
 * @param ports 输出列表（追加写入）。
 * @return 枚举成功返回 true。
 */
bool enumerateR3UdpPorts(std::vector<R3PortEntry>& ports) {
    ULONG tableSize = 0;
    DWORD status = GetExtendedUdpTable(
        NULL,
        &tableSize,
        FALSE,
        AF_INET,
        UDP_TABLE_OWNER_PID,
        0);
    if (status != ERROR_INSUFFICIENT_BUFFER || tableSize == 0) {
        return false;
    }
    std::vector<unsigned char> buffer(tableSize);
    status = GetExtendedUdpTable(
        buffer.data(),
        &tableSize,
        FALSE,
        AF_INET,
        UDP_TABLE_OWNER_PID,
        0);
    if (status != NO_ERROR) {
        return false;
    }
    const auto* table = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buffer.data());
    for (DWORD index = 0; index < table->dwNumEntries; ++index) {
        if (ports.size() >= ARK_MAX_PORT_ENTRIES) {
            break;
        }
        const MIB_UDPROW_OWNER_PID& row = table->table[index];
        R3PortEntry entry;
        entry.protocol = ARK_PORT_PROTO_UDP;
        entry.state = 0;
        entry.owningPid = row.dwOwningPid;
        entry.localAddr = row.dwLocalAddr;
        entry.remoteAddr = 0;
        entry.localPort = arkNtohs(static_cast<USHORT>(row.dwLocalPort & 0xFFFFUL));
        entry.remotePort = 0;
        ports.push_back(entry);
    }
    return true;
}

/**
 * @brief 枚举 R3 全部可见端口（先清空再追加 TCP+UDP）。
 * @param ports 输出列表。
 * @return 至少一种协议枚举成功返回 true。
 */
bool enumerateR3Ports(std::vector<R3PortEntry>& ports) {
    ports.clear();
    const bool tcpOk = enumerateR3TcpPorts(ports);
    const bool udpOk = enumerateR3UdpPorts(ports);
    return tcpOk || udpOk;
}

/**
 * @brief 根据内核视图标志生成隐藏端口原因描述字符串。
 * @param viewFlags ARK_FLAG_VIEW_PORT_* 标志组合。
 * @return 可读原因描述。
 */
std::string buildHiddenPortReason(ULONG viewFlags) {
    std::string reason;
    if ((viewFlags & ARK_FLAG_VIEW_PORT_TCP) != 0) {
        reason += "tcp+";
    }
    if ((viewFlags & ARK_FLAG_VIEW_PORT_UDP) != 0) {
        reason += "udp+";
    }
    if (!reason.empty() && reason.back() == '+') {
        reason.pop_back();
    }
    reason += " present in kernel NSI but missing in r3_api union(GetExtendedTcp/UdpTable)";
    return reason;
}

/**
 * @brief 通过 IOCTL_ARK_QUERY_KERNEL_PORT_VIEWS 查询内核 AFD/NSI 端口视图。
 * @param response 输出响应结构（调用前会被清零）。
 * @return 成功返回 true；打开设备或 IOCTL 失败返回 false。
 */
bool queryKernelPortViews(ARK_KERNEL_PORT_VIEWS_RESPONSE& response) {
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
        IOCTL_ARK_QUERY_KERNEL_PORT_VIEWS,
        NULL,
        0,
        &response,
        static_cast<DWORD>(sizeof(response)),
        &bytesReturned,
        NULL);
    CloseHandle(device);
    if (!ok) {
        printf("[ARK] DeviceIoControl(port) failed: %lu\n", GetLastError());
        return false;
    }
    if (bytesReturned < sizeof(ARK_KERNEL_PORT_VIEWS_RESPONSE)) {
        printf("[ARK] incomplete port response, bytes=%lu\n", bytesReturned);
        return false;
    }
    return true;
}

/**
 * @brief 查询进程映像完整路径。
 * @param pid 进程 PID。
 * @return 路径；失败返回空串。
 */
std::string queryProcessImagePath(ULONG pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == NULL) {
        process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    }
    if (process == NULL) {
        return std::string();
    }
    char pathBuffer[MAX_PATH * 2] = {};
    DWORD pathChars = static_cast<DWORD>(sizeof(pathBuffer));
    std::string path;
    if (QueryFullProcessImageNameA(process, 0, pathBuffer, &pathChars)) {
        path = pathBuffer;
    }
    CloseHandle(process);
    return path;
}

/**
 * @brief Authenticode 签名校验是否有效。
 * @param processPathA 进程路径（ANSI）。
 * @return 签名有效返回 true。
 */
bool verifySignatureValidA(const std::string& processPathA) {
    if (processPathA.empty()) {
        return false;
    }
    wchar_t widePath[MAX_PATH * 2] = {};
    if (MultiByteToWideChar(
            CP_ACP,
            0,
            processPathA.c_str(),
            -1,
            widePath,
            static_cast<int>(sizeof(widePath) / sizeof(widePath[0]))) <= 0) {
        return false;
    }
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = widePath;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trustData = {};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    const LONG status = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &trustData);
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &trustData);
    return status == ERROR_SUCCESS;
}

/**
 * @brief 尝试 bind 探测指定本地地址与端口是否已被占用。
 * @param localAddress 点分十进制 IPv4 地址字符串。
 * @param port 主机字节序端口（1..65535）。
 * @return 绑定返回 WSAEADDRINUSE 时视为占用并返回 true；否则返回 false。
 */
bool isPortInUse(const char* localAddress, ULONG port) {
    if (localAddress == NULL || port == 0UL || port > 65535UL) {
        return false;
    }
    if (!ensureWinsockStarted()) {
        return false;
    }
    SOCKET testSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (testSocket == INVALID_SOCKET) {
        return false;
    }
    sockaddr_in service = {};
    service.sin_family = AF_INET;
    service.sin_port = htons(static_cast<u_short>(port));
    if (InetPtonA(AF_INET, localAddress, &service.sin_addr) != 1) {
        closesocket(testSocket);
        return false;
    }
    const int bindResult = bind(testSocket, reinterpret_cast<SOCKADDR*>(&service), sizeof(service));
    if (bindResult == SOCKET_ERROR) {
        const int error = WSAGetLastError();
        closesocket(testSocket);
        return error == WSAEADDRINUSE;
    }
    closesocket(testSocket);
    return false;
}

/**
 * @brief 通过 IPHLPAPI 未文档化导出拉取 Bound TCP/TCP6 端点表。
 * @param boundNetInfo 输出 Bound 端点列表（先清空）。
 * @return ERROR_SUCCESS；加载 DLL 失败返回 Win32 错误；导出缺失时返回成功且列表为空。
 */
DWORD getBoundStateNetInfo(std::vector<BoundNetInfo>& boundNetInfo) {
    boundNetInfo.clear();
    HMODULE ipHelper = LoadLibraryW(L"iphlpapi.dll");
    if (ipHelper == NULL) {
        return GetLastError();
    }
    auto getBoundTcp = reinterpret_cast<PFN_InternalGetBoundTcpEndpointTable>(
        GetProcAddress(ipHelper, "InternalGetBoundTcpEndpointTable"));
    auto getBoundTcp6 = reinterpret_cast<PFN_InternalGetBoundTcp6EndpointTable>(
        GetProcAddress(ipHelper, "InternalGetBoundTcp6EndpointTable"));
    if (getBoundTcp == NULL || getBoundTcp6 == NULL) {
        FreeLibrary(ipHelper);
        return ERROR_SUCCESS;
    }
    PMIB_TCPTABLE2 boundTcpTable = NULL;
    if (getBoundTcp(&boundTcpTable, GetProcessHeap(), 0) == ERROR_SUCCESS && boundTcpTable != NULL) {
        for (DWORD index = 0; index < boundTcpTable->dwNumEntries; ++index) {
            BoundNetInfo info;
            const MIB_TCPROW2& row = boundTcpTable->table[index];
            info.processId = row.dwOwningPid;
            info.localPort = arkNtohs(static_cast<USHORT>(row.dwLocalPort & 0xFFFFUL));
            info.remotePort = arkNtohs(static_cast<USHORT>(row.dwRemotePort & 0xFFFFUL));
            info.localAddress = formatIpv4(row.dwLocalAddr);
            info.remoteAddress = formatIpv4(row.dwRemoteAddr);
            boundNetInfo.push_back(std::move(info));
        }
        HeapFree(GetProcessHeap(), 0, boundTcpTable);
    }
    PMIB_TCP6TABLE2 boundTcp6Table = NULL;
    if (getBoundTcp6(&boundTcp6Table, GetProcessHeap(), 0) == ERROR_SUCCESS && boundTcp6Table != NULL) {
        for (DWORD index = 0; index < boundTcp6Table->dwNumEntries; ++index) {
            char ipv6Local[INET6_ADDRSTRLEN] = {};
            char ipv6Remote[INET6_ADDRSTRLEN] = {};
            BoundNetInfo info;
            const MIB_TCP6ROW2& row = boundTcp6Table->table[index];
            info.processId = row.dwOwningPid;
            info.localPort = arkNtohs(static_cast<USHORT>(row.dwLocalPort & 0xFFFFUL));
            info.remotePort = arkNtohs(static_cast<USHORT>(row.dwRemotePort & 0xFFFFUL));
            InetNtopA(AF_INET6, &row.LocalAddr, ipv6Local, sizeof(ipv6Local));
            InetNtopA(AF_INET6, &row.RemoteAddr, ipv6Remote, sizeof(ipv6Remote));
            info.localAddress = ipv6Local;
            info.remoteAddress = ipv6Remote;
            boundNetInfo.push_back(std::move(info));
        }
        HeapFree(GetProcessHeap(), 0, boundTcp6Table);
    }
    FreeLibrary(ipHelper);
    return ERROR_SUCCESS;
}

/**
 * @brief 判断隐藏条目是否与 Bound 表中的监听/回环误报形态匹配。
 * @param hideEntry 待检查的隐藏端口条目。
 * @param boundNetInfo Bound 端点列表。
 * @return 匹配误报形态返回 true。
 */
bool isBoundStateFalsePositive(
    const HiddenPortEntry& hideEntry,
    const std::vector<BoundNetInfo>& boundNetInfo
) {
    for (const BoundNetInfo& bound : boundNetInfo) {
        if (hideEntry.owningPid != bound.processId || hideEntry.localPort != bound.localPort) {
            continue;
        }
        if (hideEntry.remotePort == 0 &&
            (hideEntry.remoteAddrStr.empty() || hideEntry.localAddrStr == kAnyAddress)) {
            return true;
        }
        if (hideEntry.localAddrStr == kLoopbackAddress && hideEntry.remoteAddrStr == kLoopbackAddress) {
            return true;
        }
    }
    return false;
}

/**
 * @brief 去除隐藏端口误报（移植自 FilterHiddenPorts，去掉厂商私有信任逻辑）。
 *
 * 规则顺序：
 * 1) 剔除纯 AFD 视图条目（无端口五元组，易误报）
 * 2) 同一 PID 隐藏条数 > 3 整组剔除
 * 3) Win10+ Bound 表匹配的监听/回环
 * 4) 未连接形态（RemotePort==0 / 空远端）
 * 5) ANY / LOOPBACK / 本地==远端
 * 6) bind 探测端口仍被占用
 * 7) 进程 Authenticode 签名有效
 *
 * @param hiddenPorts 输入输出隐藏列表。
 * @return 被剔除的条数。
 */
std::uint32_t filterHiddenPorts(std::vector<HiddenPortEntry>& hiddenPorts) {
    const std::size_t originalCount = hiddenPorts.size();
    if (hiddenPorts.empty()) {
        return 0;
    }
    /* 1) AFD 仅作内核统计，不作为隐藏端口结论。 */
    hiddenPorts.erase(
        std::remove_if(
            hiddenPorts.begin(),
            hiddenPorts.end(),
            [](const HiddenPortEntry& entry) {
                return (entry.viewFlags & ARK_FLAG_VIEW_PORT_AFD) != 0;
            }),
        hiddenPorts.end());
    std::unordered_map<ULONG, int> pidCount;
    for (const HiddenPortEntry& entry : hiddenPorts) {
        pidCount[entry.owningPid] += 1;
    }
    /* 2) 同 PID 批量条目。 */
    hiddenPorts.erase(
        std::remove_if(
            hiddenPorts.begin(),
            hiddenPorts.end(),
            [&pidCount](const HiddenPortEntry& entry) {
                return pidCount[entry.owningPid] > static_cast<int>(kMaxHiddenEntriesPerPid);
            }),
        hiddenPorts.end());
    std::vector<BoundNetInfo> boundNetInfo;
    const bool win10OrLater = isWindows10OrLater();
    if (win10OrLater) {
        const DWORD boundStatus = getBoundStateNetInfo(boundNetInfo);
        if (boundStatus != ERROR_SUCCESS) {
            printf("[ARK] GetBoundStateNetInfo failed: %lu\n", boundStatus);
        }
    }
    for (HiddenPortEntry& entry : hiddenPorts) {
        if (entry.processPath.empty()) {
            entry.processPath = queryProcessImagePath(entry.owningPid);
        }
    }
    std::size_t index = 0;
    while (index < hiddenPorts.size()) {
        HiddenPortEntry& entry = hiddenPorts[index];
        bool shouldDrop = false;
        if (win10OrLater && isBoundStateFalsePositive(entry, boundNetInfo)) {
            shouldDrop = true;
        } else if (entry.remotePort == 0 || entry.remoteAddrStr.empty()) {
            shouldDrop = true;
        } else if (entry.remoteAddrStr == kAnyAddress ||
                   entry.remoteAddrStr == kLoopbackAddress ||
                   entry.localAddrStr == entry.remoteAddrStr) {
            shouldDrop = true;
        } else if (isPortInUse(entry.localAddrStr.c_str(), entry.localPort)) {
            shouldDrop = true;
        } else if (verifySignatureValidA(entry.processPath)) {
            shouldDrop = true;
        }
        if (shouldDrop) {
            hiddenPorts.erase(hiddenPorts.begin() + static_cast<std::ptrdiff_t>(index));
        } else {
            ++index;
        }
    }
    if (originalCount < hiddenPorts.size()) {
        return 0;
    }
    return static_cast<std::uint32_t>(originalCount - hiddenPorts.size());
}

} // namespace

/**
 * @brief 执行跨视图隐藏端口检测。
 *
 * 流程：R3 前快照 → 内核 AFD/NSI → R3 后快照并集 → Hidden = NSI − R3 → FilterHiddenPorts。
 * View B（AFD）仅计入统计，不参与隐藏差分。
 *
 * @return CrossDetectPortResult；失败时 status 为 Win32 错误码。
 */
CrossDetectPortResult crossDetectHiddenPorts() {
    CrossDetectPortResult result;
    auto kernelViews = std::make_unique<ARK_KERNEL_PORT_VIEWS_RESPONSE>();
    std::vector<R3PortEntry> r3Front;
    std::vector<R3PortEntry> r3After;
    if (!enumerateR3Ports(r3Front)) {
        printf("[ARK] EnumerateR3Ports(front) failed: %lu\n", GetLastError());
        result.status = GetLastError();
        if (result.status == ERROR_SUCCESS) {
            result.status = ERROR_INVALID_FUNCTION;
        }
        return result;
    }
    if (!queryKernelPortViews(*kernelViews)) {
        result.status = GetLastError();
        if (result.status == ERROR_SUCCESS) {
            result.status = ERROR_INVALID_FUNCTION;
        }
        return result;
    }
    if (!enumerateR3Ports(r3After)) {
        printf("[ARK] EnumerateR3Ports(after) failed: %lu\n", GetLastError());
        result.status = GetLastError();
        if (result.status == ERROR_SUCCESS) {
            result.status = ERROR_INVALID_FUNCTION;
        }
        return result;
    }
    integrateR3PortSnapshots(r3Front, r3After);
    result.status = ERROR_SUCCESS;
    result.r3Count = static_cast<std::uint32_t>(r3Front.size());
    result.tcpCount = kernelViews->TcpCount;
    result.udpCount = kernelViews->UdpCount;
    result.afdCount = kernelViews->AfdCount;
    result.afdHandleCount = kernelViews->AfdHandleCount;
    result.kernelUnionCount = kernelViews->EntryCount;
    for (ULONG index = 0; index < kernelViews->EntryCount && index < ARK_MAX_PORT_ENTRIES; ++index) {
        const ARK_KERNEL_PORT_ENTRY& kernelEntry = kernelViews->Entries[index];
        /* AFD 不参与隐藏差分，避免句柄视图误报；仍保留内核计数供报告。 */
        if ((kernelEntry.ViewFlags & ARK_FLAG_VIEW_PORT_AFD) != 0) {
            continue;
        }
        if (isPortInR3Set(
                r3Front,
                kernelEntry.Protocol,
                kernelEntry.LocalAddr,
                kernelEntry.RemoteAddr,
                kernelEntry.LocalPort,
                kernelEntry.RemotePort)) {
            continue;
        }
        if (result.hiddenPorts.size() >= ARK_MAX_PORT_ENTRIES) {
            break;
        }
        HiddenPortEntry hiddenEntry;
        hiddenEntry.protocol = kernelEntry.Protocol;
        hiddenEntry.state = kernelEntry.State;
        hiddenEntry.owningPid = kernelEntry.OwningPid;
        hiddenEntry.viewFlags = kernelEntry.ViewFlags;
        hiddenEntry.localAddr = kernelEntry.LocalAddr;
        hiddenEntry.remoteAddr = kernelEntry.RemoteAddr;
        hiddenEntry.localPort = kernelEntry.LocalPort;
        hiddenEntry.remotePort = kernelEntry.RemotePort;
        hiddenEntry.endpointObject = kernelEntry.EndpointObject;
        hiddenEntry.localAddrStr = formatIpv4(kernelEntry.LocalAddr);
        hiddenEntry.remoteAddrStr = formatIpv4(kernelEntry.RemoteAddr);
        hiddenEntry.reason = buildHiddenPortReason(kernelEntry.ViewFlags);
        result.hiddenPorts.push_back(std::move(hiddenEntry));
    }
    result.filteredCount = filterHiddenPorts(result.hiddenPorts);
    return result;
}
