#include <cstdio>
#include <filesystem>
#include <Windows.h>

#include "DriveRelated.h"
#include "DetectHiddenProcess.h"
#include "DetectHiddenModule.h"
#include "DetectHiddenPort.h"
#include "json_report_writer.h"
#include "../include/Common.h"

/**
 * @brief 程序入口：加载驱动、执行隐藏进程/模块/端口检测、输出结果并写 JSON。
 *
 * 支持命令行参数 -keep：检测完成后保持驱动加载状态不卸载。
 *
 * @param argc 参数个数。
 * @param argv 参数列表，argv[1] 可为 "-keep"。
 * @return 成功返回 0，失败返回非零错误码。
 */
int main(int argc, char* argv[]) {

    const bool keepLoaded = (argc >= 2 && _stricmp(argv[1], "-keep") == 0);
    const std::filesystem::path exeDir = getExecutableDirectory();
    int exitCode = 0;

    if (exeDir.empty()) {
        printf("getExecutableDirectory failed\n");
        return 1;
    }
    if (!loadDriver(exeDir)) {
        printf("loadDriver failed\n");
        return 1;
    }

    const CrossDetectResult processResult = crossDetectHiddenProcesses();
    if (processResult.status != ERROR_SUCCESS) {
        printf("[ARK] crossDetectHiddenProcesses failed: 0x%lX\n", processResult.status);
        exitCode = static_cast<int>(processResult.status);
    } else {
        printf("[ARK] process A(r3)=%u B(cid)=%u C(thread)=%u union=%u hidden=%zu maxPid=%u status=0x%X\n",
               processResult.r3Count,
               processResult.cidCount,
               processResult.threadCount,
               processResult.kernelUnionCount,
               processResult.hiddenProcesses.size(),
               processResult.maxPidScanned,
               processResult.status);
        for (const HiddenProcessEntry& entry : processResult.hiddenProcesses) {
            printf("[ARK] HIDDEN_PROC pid=%u ppid=%u name=%s path=%s eprocess=0x%llX flags=0x%X\n",
                   entry.pid,
                   entry.parentPid,
                   entry.imageName.c_str(),
                   entry.imagePath.c_str(),
                   static_cast<unsigned long long>(entry.eprocessAddress),
                   entry.viewFlags);
        }
        const std::filesystem::path processJsonPath = exeDir / "hidden_processes.json";
        JsonReportWriter processJsonWriter(processJsonPath);
        if (!processJsonWriter.isOpen() || !processJsonWriter.writeHiddenProcessResult(processResult)) {
            printf("[ARK] write process json failed: %s\n", processJsonPath.string().c_str());
            exitCode = 1;
        } else {
            printf("[ARK] process result written: %s\n", processJsonPath.string().c_str());
        }
    }

    const CrossDetectModuleResult moduleResult = crossDetectHiddenModules();
    if (moduleResult.status != ERROR_SUCCESS) {
        printf("[ARK] crossDetectHiddenModules failed: 0x%lX\n", moduleResult.status);
        if (exitCode == 0) {
            exitCode = static_cast<int>(moduleResult.status);
        }
    } else {
        printf("[ARK] module R3=%u A(section)=%u B(driver)=%u C(bigpool)=%u union=%u hidden=%zu status=0x%X\n",
               moduleResult.r3Count,
               moduleResult.sectionCount,
               moduleResult.driverCount,
               moduleResult.residualCount,
               moduleResult.kernelUnionCount,
               moduleResult.hiddenModules.size(),
               moduleResult.status);
        for (const HiddenModuleEntry& entry : moduleResult.hiddenModules) {
            printf("[ARK] HIDDEN_MOD name=%s path=%s base=0x%llX size=%u drvobj=0x%llX flags=0x%X\n",
                   entry.moduleName.c_str(),
                   entry.modulePath.c_str(),
                   static_cast<unsigned long long>(entry.imageBase),
                   entry.imageSize,
                   static_cast<unsigned long long>(entry.driverObjectAddress),
                   entry.viewFlags);
        }
        const std::filesystem::path moduleJsonPath = exeDir / "hidden_modules.json";
        JsonReportWriter moduleJsonWriter(moduleJsonPath);
        if (!moduleJsonWriter.isOpen() || !moduleJsonWriter.writeHiddenModuleResult(moduleResult)) {
            printf("[ARK] write module json failed: %s\n", moduleJsonPath.string().c_str());
            if (exitCode == 0) {
                exitCode = 1;
            }
        } else {
            printf("[ARK] module result written: %s\n", moduleJsonPath.string().c_str());
        }
    }

    const CrossDetectPortResult portResult = crossDetectHiddenPorts();
    if (portResult.status != ERROR_SUCCESS) {
        printf("[ARK] crossDetectHiddenPorts failed: 0x%lX\n", portResult.status);
        if (exitCode == 0) {
            exitCode = static_cast<int>(portResult.status);
        }
    } else {
        printf("[ARK] port R3=%u AFD(pids=%u handles=%u) KernelTCP=%u KernelUDP=%u union=%u filtered=%u hidden=%zu status=0x%X\n",
               portResult.r3Count,
               portResult.afdCount,
               portResult.afdHandleCount,
               portResult.tcpCount,
               portResult.udpCount,
               portResult.kernelUnionCount,
               portResult.filteredCount,
               portResult.hiddenPorts.size(),
               portResult.status);
        for (const HiddenPortEntry& entry : portResult.hiddenPorts) {
            printf("[ARK] HIDDEN_PORT %s %s:%u -> %s:%u pid=%u state=%u flags=0x%X path=%s\n",
                   (entry.protocol == ARK_PORT_PROTO_TCP) ? "TCP" : "UDP",
                   entry.localAddrStr.c_str(),
                   entry.localPort,
                   entry.remoteAddrStr.c_str(),
                   entry.remotePort,
                   entry.owningPid,
                   entry.state,
                   entry.viewFlags,
                   entry.processPath.c_str());
        }
        const std::filesystem::path portJsonPath = exeDir / "hidden_ports.json";
        JsonReportWriter portJsonWriter(portJsonPath);
        if (!portJsonWriter.isOpen() || !portJsonWriter.writeHiddenPortResult(portResult)) {
            printf("[ARK] write port json failed: %s\n", portJsonPath.string().c_str());
            if (exitCode == 0) {
                exitCode = 1;
            }
        } else {
            printf("[ARK] port result written: %s\n", portJsonPath.string().c_str());
        }
    }
    if (!keepLoaded) {
        unloadDriver();
    }
    return exitCode;
}
