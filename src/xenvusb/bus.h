/*++

Copyright (c) 2017. Assured Information Security. Chris Patterson <pattersonc@ainfosec.com>

Copyright (c) Microsoft Corporation All Rights Reserved

--*/

#pragma warning(push, 0)
#include <ntddk.h>
#include <wdf.h>
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>
#include <ntintsafe.h>
#include <initguid.h>
#pragma warning(pop)

DEFINE_GUID(GUID_BUS_XEN_VUSB_INTERFACE_STANDARD,
            0x69C657A4, 0x3402, 0x42E9, 0xBE, 0x9B, 0xF2, 0xAB, 0x2D, 0x86, 0x7A, 0x51);
// {69C657A4-3402-42E9-BE9B-F2AB2D867A51}

DEFINE_GUID(GUID_BUS_XENVUSB_INTERFACE_STANDARD,
            0x69C657A4, 0x3402, 0x42E9, 0xBE, 0x9B, 0xF2, 0xAB, 0x2D, 0x86, 0x7A, 0x52);
// {69C657A4-3402-42E9-BE9B-F2AB2D867A52}

#ifndef BUS_H
#define BUS_H

//
// Prototypes of functions
//
EVT_WDF_DRIVER_DEVICE_ADD BusEvtDeviceAdd;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL BusEvtIoDeviceControl;
EVT_WDF_CHILD_LIST_CREATE_DEVICE BusEvtDeviceListCreatePdo;
EVT_WDF_CHILD_LIST_SCAN_FOR_CHILDREN BusEvtChildListScanForChildren;
EVT_WDF_CHILD_LIST_IDENTIFICATION_DESCRIPTION_COMPARE BusEvtChildListIdentificationDescriptionCompare;
EVT_WDF_CHILD_LIST_IDENTIFICATION_DESCRIPTION_CLEANUP BusEvtChildListIdentificationDescriptionCleanup;
EVT_WDF_CHILD_LIST_IDENTIFICATION_DESCRIPTION_DUPLICATE BusEvtChildListIdentificationDescriptionDuplicate;

NTSTATUS
BusEvtDeviceAdd(
    IN WDFDRIVER        Driver,
    IN PWDFDEVICE_INIT  DeviceInit
);

//EVT_WDF_DEVICE_CONTEXT_DESTROY BusEvtDestroyCallback;

#endif

