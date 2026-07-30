#include "DriverEntry.h"
#include "DetectHiddenProcess.h"
#include "DetectHiddenModule.h"
#include "DetectHiddenPort.h"
#include "Log.h"

/** @brief 全局驱动对象，DriverEntry 成功后赋值，卸载时清空。 */
PDRIVER_OBJECT g_pMyDriverObject = NULL;

/**
 * @brief IRP_MJ_CREATE 分发例程，打开设备句柄。
 * @param DeviceObject 设备对象（未使用）。
 * @param Irp 当前 IRP，完成后返回 STATUS_SUCCESS。
 * @return STATUS_SUCCESS。
 */
NTSTATUS Create(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/**
 * @brief IRP_MJ_CLOSE 分发例程，关闭设备句柄。
 * @param DeviceObject 设备对象（未使用）。
 * @param Irp 当前 IRP，完成后返回 STATUS_SUCCESS。
 * @return STATUS_SUCCESS。
 */
NTSTATUS Close(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/**
 * @brief 驱动卸载例程，删除符号链接与设备对象。
 * @param DriverObject 驱动对象。
 */
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    PDEVICE_OBJECT pDevObject = DriverObject->DeviceObject;
    UNICODE_STRING ntSymbolName = { 0 };
    RtlInitUnicodeString(&ntSymbolName, DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&ntSymbolName);
    if (pDevObject != NULL) {
        IoDeleteDevice(pDevObject);
    }
    g_pMyDriverObject = NULL;
    LOGI("DriverUnload success");
}

/**
 * @brief IRP_MJ_DEVICE_CONTROL 分发例程，处理应用层 IOCTL。
 *
 * 当前支持进程/模块/端口三类内核视图 IOCTL。
 *
 * @param DeviceObject 设备对象（未使用）。
 * @param Irp 当前 IRP，SystemBuffer 作为输入输出缓冲区。
 * @return IOCTL 处理状态码。
 */
NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG inputLength = 0;
    ULONG outputLength = 0;
    ULONG ioctl = 0;
    PVOID systemBuffer = NULL;
    ULONG_PTR information = 0;
    UNREFERENCED_PARAMETER(DeviceObject);
    stack = IoGetCurrentIrpStackLocation(Irp);
    inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    ioctl = stack->Parameters.DeviceIoControl.IoControlCode;
    systemBuffer = Irp->AssociatedIrp.SystemBuffer;
    Irp->IoStatus.Information = 0;
    switch (ioctl) {
    case IOCTL_ARK_QUERY_KERNEL_VIEWS: {
        ARK_KERNEL_VIEWS_RESPONSE* response = NULL;
        if (systemBuffer == NULL || outputLength < sizeof(ARK_KERNEL_VIEWS_RESPONSE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            LOGE("Output buffer too small, need:%lu got:%lu",
                 (ULONG)sizeof(ARK_KERNEL_VIEWS_RESPONSE), outputLength);
            break;
        }
        UNREFERENCED_PARAMETER(inputLength);
        response = (ARK_KERNEL_VIEWS_RESPONSE*)systemBuffer;
        status = QueryKernelProcessViews(response);
        if (NT_SUCCESS(status)) {
            information = sizeof(ARK_KERNEL_VIEWS_RESPONSE);
        }
        break;
    }
    case IOCTL_ARK_QUERY_KERNEL_MODULE_VIEWS: {
        ARK_KERNEL_MODULE_VIEWS_RESPONSE* response = NULL;
        if (systemBuffer == NULL || outputLength < sizeof(ARK_KERNEL_MODULE_VIEWS_RESPONSE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            LOGE("Module output buffer too small, need:%lu got:%lu",
                 (ULONG)sizeof(ARK_KERNEL_MODULE_VIEWS_RESPONSE), outputLength);
            break;
        }
        UNREFERENCED_PARAMETER(inputLength);
        response = (ARK_KERNEL_MODULE_VIEWS_RESPONSE*)systemBuffer;
        status = QueryKernelModuleViews(response);
        if (NT_SUCCESS(status)) {
            information = sizeof(ARK_KERNEL_MODULE_VIEWS_RESPONSE);
        }
        break;
    }
    case IOCTL_ARK_QUERY_KERNEL_PORT_VIEWS: {
        ARK_KERNEL_PORT_VIEWS_RESPONSE* response = NULL;
        if (systemBuffer == NULL || outputLength < sizeof(ARK_KERNEL_PORT_VIEWS_RESPONSE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            LOGE("Port output buffer too small, need:%lu got:%lu",
                 (ULONG)sizeof(ARK_KERNEL_PORT_VIEWS_RESPONSE), outputLength);
            break;
        }
        UNREFERENCED_PARAMETER(inputLength);
        response = (ARK_KERNEL_PORT_VIEWS_RESPONSE*)systemBuffer;
        status = QueryKernelPortViews(response);
        if (NT_SUCCESS(status)) {
            information = sizeof(ARK_KERNEL_PORT_VIEWS_RESPONSE);
        }
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        LOGE("Unknown ioctl: 0x%lx", ioctl);
        break;
    }
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/**
 * @brief 驱动入口，创建设备对象、符号链接并注册 IRP 回调。
 * @param DriverObject 系统传入的驱动对象。
 * @param RegistryPath 服务注册表路径（未使用）。
 * @return 成功返回 STATUS_SUCCESS，失败时回滚已创建资源。
 */
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    PDEVICE_OBJECT pDevObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING ntDeviceName = { 0 };
    UNICODE_STRING ntSymbolName = { 0 };
    UNREFERENCED_PARAMETER(RegistryPath);
    LOGI("DriverEntry begin");
    RtlInitUnicodeString(&ntDeviceName, NT_DEVICE_NAME);
    status = IoCreateDevice(
        DriverObject,
        0,
        &ntDeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        TRUE,
        &pDevObject);
    if (!NT_SUCCESS(status)) {
        LOGE("IoCreateDevice failed, status:0x%lx", status);
        return status;
    }
    g_pMyDriverObject = DriverObject;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = Create;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = Close;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    DriverObject->DriverUnload = DriverUnload;
    RtlInitUnicodeString(&ntSymbolName, DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&ntSymbolName);
    status = IoCreateSymbolicLink(&ntSymbolName, &ntDeviceName);
    if (!NT_SUCCESS(status)) {
        LOGE("IoCreateSymbolicLink failed, status:0x%lx", status);
        IoDeleteDevice(pDevObject);
        g_pMyDriverObject = NULL;
        return status;
    }
    LOGI("DriverEntry success, device ready");
    return status;
}