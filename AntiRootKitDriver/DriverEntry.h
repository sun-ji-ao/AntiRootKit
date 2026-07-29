#pragma once

#include <ntifs.h>

/** @brief 驱动/服务短名称。 */
#define DRIVER_NAME L"ARK"
/** @brief 内核设备对象路径（\Device\ARK）。 */
#define NT_DEVICE_NAME L"\\Device\\" DRIVER_NAME
/** @brief DOS 设备符号链接路径（\DosDevices\ARK）。 */
#define DOS_DEVICE_NAME L"\\DosDevices\\" DRIVER_NAME

#include "../include/Common.h"

/** @brief 内核非分页池分配标签（进程条目等）。 */
#define ARK_POOL_TAG 'KRAA'
/** @brief 内核非分页池分配标签（PID 位图）。 */
#define ARK_BITMAP_TAG 'BRKA'

/** @brief 全局驱动对象指针，供卸载等路径使用。 */
extern PDRIVER_OBJECT g_pMyDriverObject;

/**
 * @brief IRP_MJ_CREATE 分发例程，打开设备句柄。
 * @param DeviceObject 设备对象。
 * @param Irp 当前 IRP。
 * @return 始终返回 STATUS_SUCCESS。
 */
NTSTATUS Create(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/**
 * @brief IRP_MJ_CLOSE 分发例程，关闭设备句柄。
 * @param DeviceObject 设备对象。
 * @param Irp 当前 IRP。
 * @return 始终返回 STATUS_SUCCESS。
 */
NTSTATUS Close(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/**
 * @brief IRP_MJ_DEVICE_CONTROL 分发例程，处理应用层 IOCTL。
 * @param DeviceObject 设备对象。
 * @param Irp 当前 IRP。
 * @return IOCTL 处理状态码。
 */
NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/**
 * @brief 驱动卸载例程，删除符号链接与设备对象。
 * @param DriverObject 驱动对象。
 */
VOID DriverUnload(PDRIVER_OBJECT DriverObject);