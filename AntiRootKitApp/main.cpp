#include <cstdio>
#include <filesystem>
#include <Windows.h>

#include "DriveRelated.h"
#include "DetectHidden.h"
#include "json_report_writer.h"

/**
 * @brief 程序入口：加载驱动、执行隐藏进程检测、输出结果并写 JSON。
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

    if (exeDir.empty()) {
        printf("getExecutableDirectory failed\n");
        return 1;
    }
    if (!loadDriver(exeDir)) {
        printf("loadDriver failed\n");
        return 1;
    }
    const CrossDetectResult result = crossDetectHiddenProcesses();
    if (result.status != ERROR_SUCCESS) {
        printf("[ARK] crossDetectHiddenProcesses failed: 0x%lX\n", result.status);
        if (!keepLoaded) {
            unloadDriver();
        }
        return static_cast<int>(result.status);
    }
    printf("[ARK] A(r3)=%u B(cid)=%u C(thread)=%u union=%u hidden=%zu maxPid=%u status=0x%X\n",
           result.r3Count,
           result.cidCount,
           result.threadCount,
           result.kernelUnionCount,
           result.hiddenProcesses.size(),
           result.maxPidScanned,
           result.status);
    for (const HiddenProcessEntry& entry : result.hiddenProcesses) {
        printf("[ARK] HIDDEN pid=%u ppid=%u name=%s path=%s eprocess=0x%llX flags=0x%X\n",
               entry.pid,
               entry.parentPid,
               entry.imageName.c_str(),
               entry.imagePath.c_str(),
               static_cast<unsigned long long>(entry.eprocessAddress),
               entry.viewFlags);
    }

    const std::filesystem::path jsonPath = exeDir / "hidden_processes.json";
    JsonReportWriter jsonWriter(jsonPath);
    if (!jsonWriter.isOpen() || !jsonWriter.writeHiddenProcessResult(result)) {
        printf("[ARK] write json failed: %s\n", jsonPath.string().c_str());
        if (!keepLoaded) {
            unloadDriver();
        }
        return 1;
    }
    printf("[ARK] result written: %s\n", jsonPath.string().c_str());

    if (!keepLoaded) {
        unloadDriver();
    }

    return 0;
}
