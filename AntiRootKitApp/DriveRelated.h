#pragma once

#include <filesystem>

/**
 * @brief 加载 AntiRootKit 内核驱动。
 *
 * 在指定目录下查找 AntiRootKitDriver.sys，注册并启动 ARK 服务。
 *
 * @param driverDirectory 驱动 sys 文件所在目录（不含文件名）。
 * @return 成功返回 true，失败返回 false。
 */
bool loadDriver(const std::filesystem::path& driverDirectory);

/**
 * @brief 停止并卸载 AntiRootKit 内核驱动。
 *
 * 向 ARK 服务发送停止请求，等待停止后删除服务。
 *
 * @return 成功返回 true，失败返回 false。
 */
bool unloadDriver();

/**
 * @brief 获取当前可执行文件所在目录。
 *
 * @return 目录路径；获取失败时返回空 path。
 */
std::filesystem::path getExecutableDirectory();
