#include "DriveRelated.h"

#include <cstdarg>
#include <cstdio>
#include <filesystem>
#include <Shlwapi.h>
#include <Windows.h>

/** @brief 驱动 sys 文件名（相对目录）。 */
#define ARK_DRIVER_FILE "AntiRootKitDriver.sys"
/** @brief Windows 服务名称。 */
#define SERVICENAME     "ARK"
/** @brief 停止服务时每次轮询间隔（毫秒）。 */
#define STOP_WAIT_MS    100
/** @brief 停止服务最大轮询次数。 */
#define STOP_WAIT_COUNT 50

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")

namespace {

/**
 * @brief 输出错误级别日志到控制台。
 * @param format printf 风格格式化字符串。
 * @param ... 格式化参数。
 */
void logError(const char* format, ...) {
    va_list args;
    va_start(args, format);
    printf("[ARK]Error: ");
    vprintf(format, args);
    printf("\n");
    va_end(args);
}

/**
 * @brief 输出信息级别日志到控制台。
 * @param format printf 风格格式化字符串。
 * @param ... 格式化参数。
 */
void logInfo(const char* format, ...) {
    va_list args;
    va_start(args, format);
    printf("[ARK]Infor: ");
    vprintf(format, args);
    printf("\n");
    va_end(args);
}

/**
 * @brief 注册并启动 ARK 内核驱动服务。
 *
 * 若服务不存在则创建，已运行则直接返回成功。
 *
 * @param driverPath 驱动 sys 文件完整路径。
 * @return 成功返回 ERROR_SUCCESS，失败返回 Win32 错误码。
 */
DWORD installDriver(const std::filesystem::path& driverPath) {
    DWORD status = ERROR_SUCCESS;
    SC_HANDLE serviceManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (serviceManager == NULL) {
        status = GetLastError();
        logError("InstallDriver Failed to OpenSCManager LastError: 0x%x.", status);
        return status;
    }
    SC_HANDLE service = OpenServiceA(serviceManager, SERVICENAME, SERVICE_ALL_ACCESS);
    if (service == NULL) {
        status = GetLastError();
        if (status != ERROR_SERVICE_DOES_NOT_EXIST) {
            logError("InstallDriver Failed to OpenService %s LastError: 0x%x.", SERVICENAME, status);
            CloseServiceHandle(serviceManager);
            return status;
        }
        const std::string driverPathA = driverPath.string();
        service = CreateServiceA(
            serviceManager,
            SERVICENAME,
            SERVICENAME,
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            driverPathA.c_str(),
            NULL,
            NULL,
            NULL,
            NULL,
            NULL);
        if (service == NULL) {
            status = GetLastError();
            logError("InstallDriver Failed to CreateService %s LastError: 0x%x.", SERVICENAME, status);
            CloseServiceHandle(serviceManager);
            return status;
        }
    } else {
        /* 服务已存在时同步更新 ImagePath，避免仍加载旧路径下的 sys。 */
        const std::string driverPathA = driverPath.string();
        if (!ChangeServiceConfigA(
            service,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            driverPathA.c_str(),
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            SERVICENAME)) {
            status = GetLastError();
            logError("InstallDriver Failed to ChangeServiceConfig %s LastError: 0x%x.", SERVICENAME, status);
            CloseServiceHandle(service);
            CloseServiceHandle(serviceManager);
            return status;
        }
    }
    SERVICE_STATUS_PROCESS serviceStatus = {};
    DWORD bytesNeeded = 0;
    if (!QueryServiceStatusEx(
        service,
        SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&serviceStatus),
        sizeof(serviceStatus),
        &bytesNeeded)) {
        status = GetLastError();
        logError("InstallDriver Failed to QueryServiceStatusEx %s LastError: 0x%x.", SERVICENAME, status);
        CloseServiceHandle(service);
        CloseServiceHandle(serviceManager);
        return status;
    }
    if (serviceStatus.dwCurrentState == SERVICE_RUNNING) {
        logInfo("InstallDriver The service: %s already running.", SERVICENAME);
        CloseServiceHandle(service);
        CloseServiceHandle(serviceManager);
        return ERROR_SUCCESS;
    }
    if (serviceStatus.dwCurrentState != SERVICE_STOPPED &&
        serviceStatus.dwCurrentState != SERVICE_STOP_PENDING) {
        logError("InstallDriver Cannot start the service: %s state:%lu.",
            SERVICENAME, serviceStatus.dwCurrentState);
        CloseServiceHandle(service);
        CloseServiceHandle(serviceManager);
        return ERROR_SERVICE_ALREADY_RUNNING;
    }
    if (!StartServiceA(service, 0, NULL)) {
        status = GetLastError();
        if (status == ERROR_SERVICE_ALREADY_RUNNING) {
            logInfo("InstallDriver The service: %s already running.", SERVICENAME);
            status = ERROR_SUCCESS;
        } else {
            logError("InstallDriver Failed to StartService %s LastError: 0x%x.", SERVICENAME, status);
        }
    } else {
        logInfo("InstallDriver StartService %s success.", SERVICENAME);
        status = ERROR_SUCCESS;
    }
    CloseServiceHandle(service);
    CloseServiceHandle(serviceManager);
    return status;
}

/**
 * @brief 停止并删除 ARK 内核驱动服务。
 *
 * 发送 SERVICE_CONTROL_STOP 后轮询等待服务停止，最后调用 DeleteService。
 *
 * @return 成功返回 ERROR_SUCCESS，失败返回 Win32 错误码。
 */
DWORD uninstallDriver() {
    DWORD status = ERROR_SUCCESS;
    SC_HANDLE serviceManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (serviceManager == NULL) {
        status = GetLastError();
        logError("UnInstallDriver Failed to OpenSCManager LastError: 0x%x.", status);
        return status;
    }
    SC_HANDLE service = OpenServiceA(serviceManager, SERVICENAME, SERVICE_ALL_ACCESS);
    if (service == NULL) {
        status = GetLastError();
        if (status == ERROR_SERVICE_DOES_NOT_EXIST) {
            CloseServiceHandle(serviceManager);
            return ERROR_SUCCESS;
        }
        logError("UnInstallDriver Failed to OpenService %s LastError: 0x%x.", SERVICENAME, status);
        CloseServiceHandle(serviceManager);
        return status;
    }
    SERVICE_STATUS controlStatus = {};
    if (!ControlService(service, SERVICE_CONTROL_STOP, &controlStatus)) {
        status = GetLastError();
        if (status != ERROR_SERVICE_NOT_ACTIVE) {
            logError("UnInstallDriver Failed to ControlService STOP %s LastError: 0x%x.",
                SERVICENAME, status);
            CloseServiceHandle(service);
            CloseServiceHandle(serviceManager);
            return status;
        }
        status = ERROR_SUCCESS;
    }
    SERVICE_STATUS_PROCESS serviceStatus = {};
    DWORD bytesNeeded = 0;
    for (ULONG waitIndex = 0; waitIndex < STOP_WAIT_COUNT; ++waitIndex) {
        if (!QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&serviceStatus),
            sizeof(serviceStatus),
            &bytesNeeded)) {
            status = GetLastError();
            logError("UnInstallDriver Failed to QueryServiceStatusEx %s LastError: 0x%x.",
                SERVICENAME, status);
            CloseServiceHandle(service);
            CloseServiceHandle(serviceManager);
            return status;
        }
        if (serviceStatus.dwCurrentState == SERVICE_STOPPED) {
            break;
        }
        Sleep(STOP_WAIT_MS);
    }
    if (serviceStatus.dwCurrentState != SERVICE_STOPPED) {
        logError("UnInstallDriver Failed to stop %s, state:%lu", SERVICENAME, serviceStatus.dwCurrentState);
        CloseServiceHandle(service);
        CloseServiceHandle(serviceManager);
        return ERROR_SERVICE_REQUEST_TIMEOUT;
    }
    if (!DeleteService(service)) {
        status = GetLastError();
        if (status != ERROR_SERVICE_MARKED_FOR_DELETE) {
            logError("UnInstallDriver Failed to DeleteService %s LastError: 0x%x.", SERVICENAME, status);
            CloseServiceHandle(service);
            CloseServiceHandle(serviceManager);
            return status;
        }
    } else {
        logInfo("UnInstallDriver DeleteService %s success.", SERVICENAME);
    }
    CloseServiceHandle(service);
    CloseServiceHandle(serviceManager);
    return ERROR_SUCCESS;
}

} // namespace

/**
 * @brief 获取当前可执行文件所在目录（实现）。
 * @return 目录 path；失败返回空 path。
 */
std::filesystem::path getExecutableDirectory() {
    char modulePath[MAX_PATH] = {};
    if (GetModuleFileNameA(GetModuleHandleA(NULL), modulePath, MAX_PATH) == 0) {
        return {};
    }
    if (!PathRemoveFileSpecA(modulePath)) {
        return {};
    }
    return std::filesystem::path(modulePath);
}

/**
 * @brief 加载 AntiRootKit 内核驱动（实现）。
 * @param driverDirectory 驱动 sys 所在目录。
 * @return 成功 true，失败 false。
 */
bool loadDriver(const std::filesystem::path& driverDirectory) {
    std::filesystem::path driverPath = driverDirectory / ARK_DRIVER_FILE;
    if (!std::filesystem::exists(driverPath)) {
        logError("%s not exist", driverPath.string().c_str());
        return false;
    }
    const DWORD status = installDriver(driverPath);
    if (status != ERROR_SUCCESS) {
        logError("InstallDriver failed,path:%s,error:0x%x", driverPath.string().c_str(), status);
        return false;
    }
    return true;
}

/**
 * @brief 停止并卸载 AntiRootKit 内核驱动（实现）。
 * @return 成功 true，失败 false。
 */
bool unloadDriver() {
    const DWORD status = uninstallDriver();
    if (status != ERROR_SUCCESS) {
        logError("UnInstallDriver fail,0x%x", status);
        return false;
    }
    return true;
}
