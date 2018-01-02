/**
 * Copyright (c) 2017 Assured Information Security, Inc.
 *                    Chris Patterson <pattersonc@ainfosec.com>
 *
 * For parts lifted from Windows driver samples:
 * Copyright (c) Microsoft Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 * *   Redistributions of source code must retain the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer in the documentation and/or other
 *     materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#pragma warning(push, 0)

#define INITGUID

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include <debug_interface.h>
#include <evtchn_interface.h>
#include <gnttab_interface.h>
#include <range_set_interface.h>
#include <store_interface.h>
#include <suspend_interface.h>
#include <unplug_interface.h>
#pragma warning(pop)

#include "bus.h"
#include "dbg_print.h"
#include "version.h"

#define BUS_TAG         'Xusb'

#define MAX_INSTANCE_ID_LEN 80

#pragma pack(push, 1)
typedef struct _PDO_IDENTIFICATION_DESCRIPTION
{
    WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER Header;
    ULONG DeviceId;
} PDO_IDENTIFICATION_DESCRIPTION, *PPDO_IDENTIFICATION_DESCRIPTION;

typedef struct _PDO_DEVICE_CONTEXT
{
    ULONG DeviceId;
} PDO_DEVICE_CONTEXT, *PPDO_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(PDO_DEVICE_CONTEXT, BusPdoGetContext)

typedef struct _FDO_DEVICE_CONTEXT
{
    WDFDEVICE					Device;

    //XENBUS_DEBUG_INTERFACE      DebugInterface;
    //XENBUS_SUSPEND_INTERFACE    SuspendInterface;
    //XENBUS_EVTCHN_INTERFACE     EvtchnInterface;
    XENBUS_STORE_INTERFACE      StoreInterface;
    //XENBUS_RANGE_SET_INTERFACE  RangeSetInterface;
    //XENBUS_CACHE_INTERFACE      CacheInterface;
    //XENBUS_GNTTAB_INTERFACE     GnttabInterface;
    //XENBUS_UNPLUG_INTERFACE     UnplugInterface;

    //PXENBUS_SUSPEND_CALLBACK    SuspendCallbackLate;

    HANDLE						XenstoreWatchThreadHandle;
    KEVENT                      XenstoreWatchThreadEvent;
    PXENBUS_STORE_WATCH         XenstoreWatchThreadWatch;
    BOOLEAN						XenstoreWatchThreadAlert;

    WDFSPINLOCK					XenstoreWatchLock;

} FDO_DEVICE_CONTEXT, *PFDO_DEVICE_CONTEXT;

#pragma pack(pop)

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(FDO_DEVICE_CONTEXT, BusFdoGetContext)

NTSTATUS
BusCreatePdo(
    _In_ WDFDEVICE       Device,
    _In_ PWDFDEVICE_INIT DeviceInit,
    _In_ ULONG           DeviceId
);

//EVT_WDF_DEVICE_PREPARE_HARDWARE  BusEvtDevicePrepareHardware;
//EVT_WDF_DEVICE_RELEASE_HARDWARE  BusEvtDeviceReleaseHardware;

EVT_WDF_DEVICE_D0_ENTRY BusEvtDeviceD0Entry;
EVT_WDF_DEVICE_D0_EXIT_PRE_INTERRUPTS_DISABLED BusEvtDeviceD0ExitPreInterruptsDisabled;
EVT_WDF_DEVICE_PROCESS_QUERY_INTERFACE_REQUEST EvtDeviceProcessQueryInterfaceRequest;

NTSTATUS
BusEvtDeviceProcessQueryInterfaceRequest(
    _In_    WDFDEVICE  Device,
    _In_    LPGUID     InterfaceType,
    _Inout_ PINTERFACE ExposedInterface,
    _Inout_ PVOID      ExposedInterfaceSpecificData
)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(ExposedInterface);
    UNREFERENCED_PARAMETER(ExposedInterfaceSpecificData);

    Trace("====>\n");
    TraceGuid("bus request:", InterfaceType);
    Trace("<====\n");

    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
PdoEvtDeviceProcessQueryInterfaceRequest(
    _In_    WDFDEVICE  Device,
    _In_    LPGUID     InterfaceType,
    _Inout_ PINTERFACE ExposedInterface,
    _Inout_ PVOID      ExposedInterfaceSpecificData
)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(ExposedInterface);
    UNREFERENCED_PARAMETER(ExposedInterfaceSpecificData);

    Trace("====>\n");
    TraceGuid("pdo request:", InterfaceType);
    Trace("<====\n");

    return STATUS_NOT_SUPPORTED;
}

VOID
BusEvtIoDeviceControl(
    _In_ WDFQUEUE   Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t     OutputBufferLength,
    _In_ size_t     InputBufferLength,
    _In_ ULONG      IoControlCode
)
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(IoControlCode);

    PAGED_CODE();

    Trace("====>\n");

    WdfRequestCompleteWithInformation(Request, STATUS_INVALID_PARAMETER, 0);

    Trace("<===>\n");
}

VOID
BusXenstoreWatchThread(IN WDFDEVICE Device)
{
    NTSTATUS					status;
    PFDO_DEVICE_CONTEXT			Fdo;

    Trace("====>\n");

    Fdo = BusFdoGetContext(Device);

    if (!Fdo)
    {
        Error("Failed to retrieve FDO context\n");
        return;
    }

    status = XENBUS_STORE(WatchAdd,
                          &Fdo->StoreInterface,
                          "device",
                          "vusb",
                          &Fdo->XenstoreWatchThreadEvent,
                          &Fdo->XenstoreWatchThreadWatch);

    while (!Fdo->XenstoreWatchThreadAlert)
    {
        //LARGE_INTEGER Timeout;

        Trace(".\n");

        status = KeWaitForSingleObject(&Fdo->XenstoreWatchThreadEvent,
                                       Executive,
                                       KernelMode,
                                       TRUE,
                                       NULL);

        if (status != STATUS_TIMEOUT)
        {
            Warning("Timeout on wait?\n");
        }
        else if (!NT_SUCCESS(status))
        {
            Warning("KeWaitForSingleObject failure: 0x%x", status);
        }

        WDFCHILDLIST ChildList = WdfFdoGetDefaultChildList(Device);
        if (!ChildList)
        {
            Error("Failed to retrieve default child list.\n");
            break;
        }

        BusEvtChildListScanForChildren(ChildList);

        KeClearEvent(&Fdo->XenstoreWatchThreadEvent);
    }

    (VOID)XENBUS_STORE(WatchRemove,
                       &Fdo->StoreInterface,
                       Fdo->XenstoreWatchThreadWatch);
    Fdo->XenstoreWatchThreadWatch = NULL;

    Trace("<====\n");

    PsTerminateSystemThread(status);
}

VOID
BusDestroyXenstoreWatchThread(IN WDFDEVICE Device)
{
    PFDO_DEVICE_CONTEXT			Fdo;

    Trace("====>\n");

    Fdo = BusFdoGetContext(Device);

    if (!Fdo)
    {
        Error("Failed to retrieve FDO context\n");
        return;
    }

    if (Fdo->XenstoreWatchThreadHandle != NULL)
    {
        LARGE_INTEGER Timeout;

        Timeout.QuadPart = 1000;

        // alert thread to exit
        Fdo->XenstoreWatchThreadAlert = TRUE;
        KeSetEvent(&Fdo->XenstoreWatchThreadEvent, IO_NO_INCREMENT, FALSE);

        // wait for thread to exit
        (VOID)KeWaitForSingleObject(Fdo->XenstoreWatchThreadHandle,
                                    Executive,
                                    KernelMode,
                                    FALSE,
                                    NULL);

        ObDereferenceObject(Fdo->XenstoreWatchThreadHandle);
        Fdo->XenstoreWatchThreadHandle = NULL;
    }

    Trace("<====\n");
}

NTSTATUS
BusCreateXenstoreWatchThread(IN WDFDEVICE Device)
{
    NTSTATUS					status;
    PFDO_DEVICE_CONTEXT			Fdo;
    OBJECT_ATTRIBUTES   ObjectAttributes;
    HANDLE              ThreadHandle = 0;

    Trace("====>\n");

    Fdo = BusFdoGetContext(Device);

    if (!Fdo)
    {
        Error("Failed to retrieve FDO context\n");
        return STATUS_UNSUCCESSFUL;
    }

    InitializeObjectAttributes(&ObjectAttributes, NULL,
                               OBJ_KERNEL_HANDLE, NULL, NULL);

    KeInitializeEvent(&Fdo->XenstoreWatchThreadEvent, NotificationEvent, FALSE);

    status = PsCreateSystemThread(&ThreadHandle,
                                  THREAD_ALL_ACCESS,
                                  &ObjectAttributes,
                                  NULL,
                                  NULL,
                                  BusXenstoreWatchThread,
                                  Device);

    if (!NT_SUCCESS(status))
    {
        Error("Failed to create xenstore watch thread\n");
        return STATUS_UNSUCCESSFUL;
    }

    ObReferenceObjectByHandle(ThreadHandle, THREAD_ALL_ACCESS, NULL,
                              KernelMode, (PVOID*)&Fdo->XenstoreWatchThreadHandle, NULL);

    ZwClose(ThreadHandle);

    KeSetEvent(&Fdo->XenstoreWatchThreadEvent, IO_NO_INCREMENT, FALSE);

    Trace("<====\n");

    return STATUS_SUCCESS;
}

NTSTATUS
BusPreProcessQueryInterface(
    IN WDFDEVICE Device,
    IN PIRP Irp)
{
    NTSTATUS Status = Irp->IoStatus.Status;

    Trace("===>\n");

    Trace("passing irp to WdfDeviceWdmDispatchPreprocessedIrp()\n");

    IoSkipCurrentIrpStackLocation(Irp);
    Status = WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);

    Trace("WdfDeviceWdmDispatchPreprocessedIrp returned 0x%x\n", Status);

    Trace("<====\n");
    return Status;
}

NTSTATUS
BusEvtDeviceAdd(
    IN WDFDRIVER        Driver,
    IN PWDFDEVICE_INIT  DeviceInit
)
{
    NTSTATUS                   status;
    WDF_CHILD_LIST_CONFIG      Config;
    WDF_OBJECT_ATTRIBUTES      Attributes;
    WDFDEVICE                  Device;
    WDF_IO_QUEUE_CONFIG        QueueConfig;
    WDFQUEUE                   Queue;
    PFDO_DEVICE_CONTEXT		   Fdo;
    WDF_PNPPOWER_EVENT_CALLBACKS    pnpPowerCallbacks;

    UNREFERENCED_PARAMETER(Driver);

    PAGED_CODE();

    Trace("====>\n");

    WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_BUS_EXTENDER);
    WdfDeviceInitSetExclusive(DeviceInit, TRUE);

    WDF_CHILD_LIST_CONFIG_INIT(&Config,
                               sizeof(PDO_IDENTIFICATION_DESCRIPTION),
                               BusEvtDeviceListCreatePdo
                              );

    Config.EvtChildListIdentificationDescriptionDuplicate =
        BusEvtChildListIdentificationDescriptionDuplicate;

    Config.EvtChildListIdentificationDescriptionCompare =
        BusEvtChildListIdentificationDescriptionCompare;

    Config.EvtChildListIdentificationDescriptionCleanup =
        BusEvtChildListIdentificationDescriptionCleanup;

    Config.EvtChildListScanForChildren = BusEvtChildListScanForChildren;

    WdfFdoInitSetDefaultChildListConfig(DeviceInit,
                                        &Config,
                                        WDF_NO_OBJECT_ATTRIBUTES);


    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&Attributes, FDO_DEVICE_CONTEXT);
    //Attributes.EvtCleanupCallback = BusEvtDestroyCallback;
    Attributes.ExecutionLevel = WdfExecutionLevelDispatch;

    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
    //pnpPowerCallbacks.EvtDevicePrepareHardware = BusEvtDevicePrepareHardware;
    //pnpPowerCallbacks.EvtDeviceReleaseHardware = BusEvtDeviceReleaseHardware;
    pnpPowerCallbacks.EvtDeviceD0Entry = BusEvtDeviceD0Entry;
    pnpPowerCallbacks.EvtDeviceD0ExitPreInterruptsDisabled = BusEvtDeviceD0ExitPreInterruptsDisabled;

    WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);

#ifdef DEBUG_QUERY_INTERFACE
    UCHAR MinorFunctionTable[1] = { IRP_MN_QUERY_INTERFACE };

    status = WdfDeviceInitAssignWdmIrpPreprocessCallback(
                 DeviceInit,
                 BusPreProcessQueryInterface,
                 IRP_MJ_PNP,
                 MinorFunctionTable,
                 1);

    if (!NT_SUCCESS(status))
    {
        Error("WdfDeviceInitAssignWdmIrpPreprocessCallback failed error %x\n", status);
        return status;
    }
#endif

    //
    // Create a framework device object. In response to this call, framework
    // creates a WDM deviceobject and attach to the PDO.
    //
    status = WdfDeviceCreate(&DeviceInit, &Attributes, &Device);

    if (!NT_SUCCESS(status)) {
        Error("DeviceCreate failed - status: 0x%x\n", status);
        return status;
    }

    Fdo = BusFdoGetContext(Device);

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
        &QueueConfig,
        WdfIoQueueDispatchParallel
    );

    QueueConfig.EvtIoDeviceControl = BusEvtIoDeviceControl;

    __analysis_assume(QueueConfig.EvtIoStop != 0);
    status = WdfIoQueueCreate(Device,
                              &QueueConfig,
                              WDF_NO_OBJECT_ATTRIBUTES,
                              &Queue);
    __analysis_assume(QueueConfig.EvtIoStop == 0);

    if (!NT_SUCCESS(status)) {
        Error("WdfIoQueueCreate failed: status = 0x%x\n", status);
        return status;
    }

    status = WdfFdoQueryForInterface(Device,
                                     &GUID_XENBUS_STORE_INTERFACE,
                                     &Fdo->StoreInterface.Interface,
                                     sizeof(Fdo->StoreInterface),
                                     XENBUS_STORE_INTERFACE_VERSION_MAX,
                                     NULL);

    if (!NT_SUCCESS(status))
    {
        Error("Failed to query xenbus store interface: 0x%x\n", status);
        return STATUS_SUCCESS;
    }

    Trace("Successfully queried xenbus store interface\n");

    status = XENBUS_STORE(Acquire, &Fdo->StoreInterface);

    if (!NT_SUCCESS(status))
    {
        Error("Failed to acquire xenbus store interface: 0x%x\n", status);
        return STATUS_UNSUCCESSFUL;
    }

    Trace("Successfully acquired xenbus store interface\n");

    return status;
}

VOID
BusEvtChildListScanForChildren(
    _In_ WDFCHILDLIST ChildList
)
{
    NTSTATUS		status;
    size_t			Index;
    PFDO_DEVICE_CONTEXT Fdo;
    WDFDEVICE       Device;
    PCHAR           Buffer;

    Trace("====>\n");

    Device = WdfChildListGetDevice(ChildList);

    if (!Device)
    {
        Error("Failed to retrieve Device\n");
        return;
    }

    Fdo = BusFdoGetContext(Device);

    Info("Fdo = 0x%x\n", Fdo);

    if (!Fdo)
    {
        Error("Failed to retrieve FDO context\n");
        return;
    }

    status = XENBUS_STORE(Directory,
                          &Fdo->StoreInterface,
                          NULL,
                          "device",
                          "vusb",
                          &Buffer);

    if (!NT_SUCCESS(status))
    {
        Info("Failed to perform directory in xenstore.\n");
        return;
    }

    WdfChildListBeginScan(ChildList);
    for (Index = 0;;)
    {
        PDO_IDENTIFICATION_DESCRIPTION Description;
        PCHAR           DeviceString = &Buffer[Index];
        size_t			Length;
        ULONG			DeviceId;

        if (DeviceString[0] == 0)
        {
            break;
        }

        Length = strlen(DeviceString);
        Index += Length + 1;

        Info("Parsing xenbus state for node: device/vusb/%s\n",
             DeviceString);

        if (sscanf_s(DeviceString, "%lu", &DeviceId) != 1)
        {
            Error("Failed to parse xenbus state for node: device/vusb/%s\n",
                  DeviceString);
            continue;
        }

        Info("Parsed xenbus state for node: device/vusb/%lu\n", DeviceId);

        WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER_INIT(
            &Description.Header,
            sizeof(Description)
        );

        Description.DeviceId = DeviceId;

        status = WdfChildListAddOrUpdateChildDescriptionAsPresent(
                     ChildList,
                     &Description.Header,
                     NULL);

        if (!NT_SUCCESS(status) && (status != STATUS_OBJECT_NAME_EXISTS))
        {
            Error("Failed to mark as present: device/vusb/%d\n", DeviceId);
            continue;
        }
    }

    Info("Ending list scan\n");

    WdfChildListEndScan(ChildList);

    XENBUS_STORE(Free,
                 &Fdo->StoreInterface,
                 Buffer);

    Trace("<====\n");
}

NTSTATUS
BusEvtChildListIdentificationDescriptionDuplicate(
    WDFCHILDLIST DeviceList,
    PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER SourceIdentificationDescription,
    PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER DestinationIdentificationDescription
)
{
    PPDO_IDENTIFICATION_DESCRIPTION src, dst;

    UNREFERENCED_PARAMETER(DeviceList);

    src = CONTAINING_RECORD(SourceIdentificationDescription,
                            PDO_IDENTIFICATION_DESCRIPTION,
                            Header);
    dst = CONTAINING_RECORD(DestinationIdentificationDescription,
                            PDO_IDENTIFICATION_DESCRIPTION,
                            Header);

    dst->DeviceId = src->DeviceId;
    return STATUS_SUCCESS;
}

BOOLEAN
BusEvtChildListIdentificationDescriptionCompare(
    WDFCHILDLIST DeviceList,
    PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER FirstIdentificationDescription,
    PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER SecondIdentificationDescription
)
{
    PPDO_IDENTIFICATION_DESCRIPTION lhs, rhs;

    UNREFERENCED_PARAMETER(DeviceList);

    lhs = CONTAINING_RECORD(FirstIdentificationDescription,
                            PDO_IDENTIFICATION_DESCRIPTION,
                            Header);
    rhs = CONTAINING_RECORD(SecondIdentificationDescription,
                            PDO_IDENTIFICATION_DESCRIPTION,
                            Header);

    return (lhs->DeviceId == rhs->DeviceId) ? TRUE : FALSE;
}

#pragma prefast(push)
#pragma prefast(disable:6101, "No need to assign IdentificationDescription")

VOID
BusEvtChildListIdentificationDescriptionCleanup(
    _In_ WDFCHILDLIST DeviceList,
    _Out_ PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER IdentificationDescription
)
{
    PPDO_IDENTIFICATION_DESCRIPTION pDesc;

    UNREFERENCED_PARAMETER(DeviceList);

    pDesc = CONTAINING_RECORD(IdentificationDescription,
                              PDO_IDENTIFICATION_DESCRIPTION,
                              Header);

    // nothing to free (currently)
}

#pragma prefast(pop) // disable:6101

NTSTATUS
BusEvtDeviceListCreatePdo(
    WDFCHILDLIST DeviceList,
    PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER IdentificationDescription,
    PWDFDEVICE_INIT ChildInit
)
{
    WDFDEVICE Device;
    PPDO_IDENTIFICATION_DESCRIPTION pDesc;
    NTSTATUS status;

    PAGED_CODE();

    Trace("====>\n");

    Device = WdfChildListGetDevice(DeviceList);

    pDesc = CONTAINING_RECORD(IdentificationDescription,
                              PDO_IDENTIFICATION_DESCRIPTION,
                              Header);

    status = BusCreatePdo(Device, ChildInit, pDesc->DeviceId);

    Trace("<====\n");

    return status;
}

NTSTATUS
BusEvtDeviceD0Entry(
    _In_ WDFDEVICE Device,
    IN  WDF_POWER_DEVICE_STATE PreviousState
)
{
    UNREFERENCED_PARAMETER(PreviousState);

    NTSTATUS status;

    Trace("====>\n");

    status = BusCreateXenstoreWatchThread(Device);

    if (!NT_SUCCESS(status))
    {
        Error("Failed to create xenstore watch thread.\n");
    }

    Trace("<====\n");

    return status;
}

NTSTATUS
BusEvtDeviceD0ExitPreInterruptsDisabled(
    _In_ WDFDEVICE Device,
    IN  WDF_POWER_DEVICE_STATE TargetState
)
{
    UNREFERENCED_PARAMETER(TargetState);

    Trace("====>\n");

    BusDestroyXenstoreWatchThread(Device);

    Trace("<====\n");

    return STATUS_SUCCESS;
}

#ifdef DEBUG_QUERY_INTERFACE

NTSTATUS
PdoPreProcessQueryInterface(
    IN WDFDEVICE Device,
    IN PIRP Irp)
{
    NTSTATUS Status = Irp->IoStatus.Status;

    Trace("===>\n");

    Trace("passing irp to WdfDeviceWdmDispatchPreprocessedIrp()\n");

    IoSkipCurrentIrpStackLocation(Irp);
    Status = WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);

    Trace("WdfDeviceWdmDispatchPreprocessedIrp returned 0x%x\n", Status);

    Trace("<====\n");
    return Status;
}

#endif

NTSTATUS
BusPassthroughInterface(
    IN WDFDEVICE Device,
    IN const GUID *Guid
)
{
    NTSTATUS status;
    INTERFACE Interface;
    WDF_QUERY_INTERFACE_CONFIG QueryInterfaceConfig;

    RtlZeroMemory(&Interface, sizeof(Interface));
    Interface.Size = sizeof(Interface);
    Interface.Version = 1;
    Interface.Context = Device;
    Interface.InterfaceReference = WdfDeviceInterfaceReferenceNoOp;
    Interface.InterfaceDereference = WdfDeviceInterfaceDereferenceNoOp;

    WDF_QUERY_INTERFACE_CONFIG_INIT(&QueryInterfaceConfig, NULL, Guid, NULL);

    QueryInterfaceConfig.ImportInterface = FALSE;
    QueryInterfaceConfig.SendQueryToParentStack = TRUE;

    status = WdfDeviceAddQueryInterface(Device, &QueryInterfaceConfig);
    if (!NT_SUCCESS(status)) {
        Error("Failed WdfDeviceAddQueryInterface with status = 0x%x\n", status);
    }

    TraceGuid("passed through:", Guid);
    return status;
}

NTSTATUS
BusCreatePdo(
    _In_ WDFDEVICE       Device,
    _In_ PWDFDEVICE_INIT DeviceInit,
    _In_ ULONG           DeviceId
)
{
    NTSTATUS						status;
    PPDO_DEVICE_CONTEXT				pdoData = NULL;
    WDFDEVICE						hChild = NULL;
    WDF_OBJECT_ATTRIBUTES			pdoAttributes;
    WDF_DEVICE_PNP_CAPABILITIES		pnpCaps;
    WDF_DEVICE_POWER_CAPABILITIES	powerCaps;

    DECLARE_UNICODE_STRING_SIZE(deviceName, MAX_INSTANCE_ID_LEN);
    DECLARE_UNICODE_STRING_SIZE(deviceId, MAX_INSTANCE_ID_LEN);
    DECLARE_UNICODE_STRING_SIZE(instanceId, MAX_INSTANCE_ID_LEN);

    PAGED_CODE();

    UNREFERENCED_PARAMETER(Device);

    Trace("====>\n");

    WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_BUS_EXTENDER);

    status = RtlUnicodeStringPrintf(&deviceName, L"XENVUSB\\VEN_%s0001&DEV_VUSB&REV_%08x", VENDOR_PREFIX_LSTR, 0x09000000);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = RtlUnicodeStringPrintf(&deviceId, L"XENVUSB\\VEN_%s0001&DEV_VUSB&REV_%08x", VENDOR_PREFIX_LSTR, 0x09000000);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = RtlUnicodeStringPrintf(&instanceId, L"%lu", DeviceId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfPdoInitAssignDeviceID(DeviceInit, &deviceId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfPdoInitAddHardwareID(DeviceInit, &deviceId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfPdoInitAddCompatibleID(DeviceInit, &deviceId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfPdoInitAssignInstanceID(DeviceInit, &instanceId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfPdoInitAddDeviceText(DeviceInit, &deviceId, &deviceId, 0x409);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WdfPdoInitSetDefaultLocale(DeviceInit, 0x409);

    WdfPdoInitAllowForwardingRequestToParent(DeviceInit);

#ifdef DEBUG_QUERY_INTERFACE
    UCHAR MinorFunctionTable[1] = { IRP_MN_QUERY_INTERFACE };

    status = WdfDeviceInitAssignWdmIrpPreprocessCallback(
                 DeviceInit,
                 PdoPreProcessQueryInterface,
                 IRP_MJ_PNP,
                 MinorFunctionTable,
                 1);

    if (!NT_SUCCESS(status))
    {
        Error("WdfDeviceInitAssignWdmIrpPreprocessCallback failed error %x\n", status);
        return status;
    }
#endif


    // set default attributes with specified context type
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&pdoAttributes, PDO_DEVICE_CONTEXT);

    // create pdo device (hChild)
    status = WdfDeviceCreate(&DeviceInit, &pdoAttributes, &hChild);
    if (!NT_SUCCESS(status)) {
        Error("Failed to create wdf device for device: %ws\n", deviceId.Buffer);
        return status;
    }

    // pass through interfaces
    // TODO: better method to attach to existing device stack?
    BusPassthroughInterface(hChild, &GUID_XENBUS_DEBUG_INTERFACE);
    BusPassthroughInterface(hChild, &GUID_XENBUS_EVTCHN_INTERFACE);
    BusPassthroughInterface(hChild, &GUID_XENBUS_GNTTAB_INTERFACE);
    BusPassthroughInterface(hChild, &GUID_XENBUS_RANGE_SET_INTERFACE);
    BusPassthroughInterface(hChild, &GUID_XENBUS_STORE_INTERFACE);
    BusPassthroughInterface(hChild, &GUID_XENBUS_SUSPEND_INTERFACE);
    BusPassthroughInterface(hChild, &GUID_XENBUS_UNPLUG_INTERFACE);

    // initialize pdo device context
    pdoData = BusPdoGetContext(hChild);
    pdoData->DeviceId = DeviceId;

    // initialize pnp caps
    WDF_DEVICE_PNP_CAPABILITIES_INIT(&pnpCaps);
    pnpCaps.Removable = WdfFalse;
    pnpCaps.EjectSupported = WdfFalse;
    pnpCaps.SurpriseRemovalOK = WdfFalse;
    pnpCaps.DockDevice = WdfFalse;
    pnpCaps.UniqueID = WdfTrue;
    pnpCaps.SilentInstall = WdfTrue;
    pnpCaps.HardwareDisabled = WdfFalse;
    pnpCaps.Address = DeviceId;
    pnpCaps.UINumber = DeviceId;

    WdfDeviceSetPnpCapabilities(hChild, &pnpCaps);

    // initialize power caps
    WDF_DEVICE_POWER_CAPABILITIES_INIT(&powerCaps);
    powerCaps.DeviceD1 = WdfFalse;
    powerCaps.WakeFromD1 = WdfFalse;
    powerCaps.DeviceWake = PowerDeviceUnspecified;
    powerCaps.SystemWake = PowerSystemUnspecified;
    powerCaps.DeviceState[PowerSystemWorking] = PowerDeviceD0;
    powerCaps.DeviceState[PowerSystemHibernate] = PowerDeviceD3;
    powerCaps.DeviceState[PowerSystemShutdown] = PowerDeviceD3;

    WdfDeviceSetPowerCapabilities(hChild, &powerCaps);

    Trace("Created instance device: 0x%p %ws -- %ws -- %ws (status = 0x%x)\n", hChild, deviceId.Buffer, deviceName.Buffer, instanceId.Buffer, status);

    Trace("<====\n");

    return status;
}
