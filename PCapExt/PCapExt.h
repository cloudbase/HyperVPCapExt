#pragma once

#include <ndis.h>

VOID InitPcapCapture();
VOID EndPcapCapture();
VOID CreatePcapCaptureFile();
VOID ClosePcapCaptureFile();
VOID WritePcapRecordWorkItem(_In_ PDEVICE_OBJECT DeviceObject, _In_opt_ PVOID Context);
VOID WindowsToEpochTime(PLARGE_INTEGER CurrentTime, PULONG EpochSeconds, PULONG MicroSeconds);
VOID DecodeNetBufferListAndQueueForPCap(PNET_BUFFER_LIST NetBufferLists);
