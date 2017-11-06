// Copyright (c) 2017. Assured Information Security.Chris Patterson <pattersonc@ainfosec.com>
// Copyright (c) Citrix Systems, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//

#pragma warning(push, 0)
#include <ntddk.h>
#include <wdf.h>
#pragma warning(pop)

#include "bus.h"
#include "dbg_print.h"
#include "version.h"

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath);

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#endif

VOID
DriverUnload(
	_In_ WDFOBJECT DriverObject
)
{
	UNREFERENCED_PARAMETER(DriverObject);

	Info("Driver unload\n");
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject, 
    _In_ PUNICODE_STRING RegistryPath )
{
    WDF_DRIVER_CONFIG config;
    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES attributes;

	Trace("====>\n");

	WDF_DRIVER_CONFIG_INIT(
		&config,
		BusEvtDeviceAdd
	);

	Info("XENVUSB %d.%d.%d (%d) (%s - %s) (%02d.%02d.%04d)\n",
		MAJOR_VERSION,
		MINOR_VERSION,
		MICRO_VERSION,
		BUILD_NUMBER,
		__DATE__,
		__TIME__,
		DAY,
		MONTH,
		YEAR); 

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = DriverUnload;
	//attributes.EvtDestroyCallback = BusEvtDestroyCallback;

    WDF_DRIVER_CONFIG_INIT(&config,
		BusEvtDeviceAdd);

    status = WdfDriverCreate(DriverObject,
                             RegistryPath,
                             &attributes,
                             &config,
                             WDF_NO_HANDLE);

    if (!NT_SUCCESS(status)) 
    {
        Error("WdfDriverCreate failed %x\n", status);
    }

	Trace("<====\n");
    return status;
}
