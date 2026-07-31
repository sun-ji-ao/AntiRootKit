#pragma once

#include <cstdint>
#include <string>
#include <vector>

/**
 * @brief 单条隐藏端口/套接字记录（跨视图检测输出）。
 */
struct HiddenPortEntry {
    std::uint32_t protocol = 0;       /**< ARK_PORT_PROTO_* */
    std::uint32_t state = 0;          /**< TCP 状态；AFD 视图为 SOCKET_STATE */
    std::uint32_t owningPid = 0;      /**< 所属进程 PID */
    std::uint32_t viewFlags = 0;      /**< 内核视图标志位 */
    std::uint32_t localAddr = 0;      /**< 本地 IPv4（网络字节序） */
    std::uint32_t remoteAddr = 0;     /**< 远端 IPv4（网络字节序） */
    std::uint16_t localPort = 0;      /**< 本地端口（主机字节序） */
    std::uint16_t remotePort = 0;     /**< 远端端口（主机字节序） */
    std::uint64_t endpointObject = 0; /**< AFD FILE_OBJECT 地址（NSI 为 0） */
    std::string localAddrStr;         /**< 本地 IP 字符串 */
    std::string remoteAddrStr;        /**< 远端 IP 字符串 */
    std::string processPath;          /**< 进程映像路径（过滤阶段填充） */
    std::string reason;               /**< 判定为隐藏的原因描述 */
};

/**
 * @brief 跨视图隐藏端口检测结果汇总。
 *
 * 检测公式：Hidden = (ViewC_NSI ∪ ViewB_AFD) − R3_union(前后两次 GetExtendedTcp/UdpTable)，
 * 再经 FilterHiddenPorts 去除 bound/回环/签名等误报；无地址的 AFD 条目不参与隐藏结论。
 */
struct CrossDetectPortResult {
    std::uint32_t status = 0;           /**< 操作状态码，ERROR_SUCCESS 表示成功 */
    std::uint32_t r3Count = 0;          /**< R3 并集端口数 */
    std::uint32_t tcpCount = 0;         /**< 内核 NSI TCP 命中数 */
    std::uint32_t udpCount = 0;         /**< 内核 NSI UDP 命中数 */
    std::uint32_t afdCount = 0;         /**< 内核 AFD 持有套接字的 PID 数（仅统计） */
    std::uint32_t afdHandleCount = 0;   /**< 内核 AFD 文件句柄总数（仅统计） */
    std::uint32_t kernelUnionCount = 0; /**< 内核条目数 */
    std::uint32_t filteredCount = 0;    /**< 误报过滤剔除条数 */
    std::vector<HiddenPortEntry> hiddenPorts; /**< 过滤后的隐藏端口列表 */
};

/**
 * @brief 执行跨视图隐藏端口检测。
 *
 * 流程：R3前快照 → 内核视图 → R3后快照并集 → NSI−R3 → FilterHiddenPorts。
 *
 * @return 检测结果；失败时 status 为 Win32 错误码。
 */
CrossDetectPortResult crossDetectHiddenPorts();
