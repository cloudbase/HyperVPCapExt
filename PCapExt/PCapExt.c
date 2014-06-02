/*
Copyright(c) Cloudbase Solutions Srl.All Rights Reserved.
*/

#include "precomp.h"
#include "pcap.h"

HANDLE g_CaptureFileHandle;
ERESOURCE g_CaptureFileResource;

#define EPOCH_OFFSET 11644473600
#define BUFFER_SIZE 30

// TODO: must be configurable. For the time being it works only if C:\ exists and is writable
// Alternative hardcoded path: "\\SystemRoot\\PCapExt.pcap
#define PCAP_FILE L"\\DosDevices\\C:\\PCapExt.pcap"

extern NDIS_HANDLE SxDriverObject;

typedef struct PcapRecordWorkItemData_s
{
    PIO_WORKITEM pWorkItem;
    ULONG BufferLen;
    void* Buffer;
} PcapRecordWorkItemData;


VOID InitPcapCapture()
{
    ExInitializeResourceLite(&g_CaptureFileResource);
}

VOID CreatePcapCaptureFile()
{
    UNICODE_STRING     uniName;
    OBJECT_ATTRIBUTES  objAttr;
    NTSTATUS ntstatus;
    IO_STATUS_BLOCK    ioStatusBlock;
    HANDLE handle;
    pcap_hdr_t pcapHeader;

    RtlInitUnicodeString(&uniName, PCAP_FILE);
    InitializeObjectAttributes(&objAttr, &uniName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL, NULL);

    ntstatus = ZwCreateFile(&handle,
        GENERIC_WRITE | SYNCHRONIZE,
        &objAttr, &ioStatusBlock, NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_WRITE_THROUGH,
        NULL, 0);

    if (NT_SUCCESS(ntstatus)) {
        pcapHeader.magic_number = PCAP_MAGIC_NUMBER;
        pcapHeader.version_major = PCAP_VERSION_MAJOR;
        pcapHeader.version_minor = PCAP_VERSION_MINOR;
        pcapHeader.thiszone = 0;
        pcapHeader.sigfigs = 0;
        pcapHeader.snaplen = 65535;
        pcapHeader.network = 1; // Ethernet

        ntstatus = ZwWriteFile(handle, NULL, NULL, NULL, &ioStatusBlock, &pcapHeader,
                               (ULONG)sizeof(pcap_hdr_t), NULL, NULL);

        if (NT_SUCCESS(ntstatus))
            g_CaptureFileHandle = handle;
        else
            ZwClose(handle);
    }
    else
    {
        // Ignore for now
    }
}

VOID ClosePcapCaptureFile()
{
    if (g_CaptureFileHandle)
    {
        ZwClose(g_CaptureFileHandle);
        g_CaptureFileHandle = NULL;
    }
}

VOID WritePcapRecordWorkItem(_In_ PDEVICE_OBJECT DeviceObject, _In_opt_  PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    IO_STATUS_BLOCK ioStatusBlock = { 0 };
    PcapRecordWorkItemData* pPcapRecordWorkItemData = Context;

    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&g_CaptureFileResource, TRUE);

    // Ignore write errors
    if (g_CaptureFileHandle)
        ZwWriteFile(g_CaptureFileHandle, NULL, NULL, NULL, &ioStatusBlock,
                    pPcapRecordWorkItemData->Buffer,
                    pPcapRecordWorkItemData->BufferLen, NULL, NULL);

    ExReleaseResourceLite(&g_CaptureFileResource);
    KeLeaveCriticalRegion();

    IoFreeWorkItem(pPcapRecordWorkItemData->pWorkItem);
    ExFreePool(pPcapRecordWorkItemData);
}

VOID WindowsToEpochTime(PLARGE_INTEGER CurrentTime, PULONG EpochSeconds, PULONG MicroSeconds)
{
    *EpochSeconds = (ULONG)(CurrentTime->QuadPart / 10000000);
    *MicroSeconds = (ULONG)((CurrentTime->QuadPart % 10000000) / 10);
    *EpochSeconds = (ULONG)(*EpochSeconds - EPOCH_OFFSET);
}

VOID DecodeNetBufferListAndQueueForPCap(PNET_BUFFER_LIST NetBufferLists)
{
    NET_BUFFER* netBuffer = NULL;
    ULONG dataLength = 0;
    PcapRecordWorkItemData* pPcapRecordWorkItemData = NULL;
    pcaprec_hdr_t* pPcapRecHeader = NULL;
    void* data = NULL;
    void* dataStorage = NULL;
    LARGE_INTEGER currentTime = { 0 };
    ULONG epochSeconds = 0;
    ULONG microSeconds = 0;
    PIO_WORKITEM pWorkItem = NULL;

    if (g_CaptureFileHandle)
    {
        netBuffer = NET_BUFFER_LIST_FIRST_NB(NetBufferLists);

        KeQuerySystemTime(&currentTime);
        WindowsToEpochTime(&currentTime, &epochSeconds, &microSeconds);

        while (netBuffer != NULL)
        {
            dataLength = NET_BUFFER_DATA_LENGTH(netBuffer);
            if (dataLength)
            {
                pPcapRecordWorkItemData = ExAllocatePoolWithTag(NonPagedPoolNx,
                                                                sizeof(PcapRecordWorkItemData) + sizeof(pcaprec_hdr_t) + dataLength,
                                                                SxExtAllocationTag);
                NT_ASSERT(pPcapRecordWorkItemData);

                pPcapRecordWorkItemData->BufferLen = sizeof(pcaprec_hdr_t) + dataLength;
                pPcapRecordWorkItemData->Buffer = (char*)pPcapRecordWorkItemData + sizeof(PcapRecordWorkItemData);

                pPcapRecHeader = pPcapRecordWorkItemData->Buffer;
                pPcapRecHeader->ts_sec = epochSeconds;
                pPcapRecHeader->ts_usec = microSeconds;
                pPcapRecHeader->incl_len = dataLength;
                pPcapRecHeader->orig_len = dataLength;

                dataStorage = (char*)pPcapRecordWorkItemData->Buffer + sizeof(pcaprec_hdr_t);
                data = NdisGetDataBuffer(netBuffer, dataLength, dataStorage, 1, 0);
                if (data)
                {
                    if (data != dataStorage)
                        RtlCopyMemory(dataStorage, data, dataLength);

                    pWorkItem = IoAllocateWorkItem(SxDriverObject);
                    NT_ASSERT(pWorkItem);

                    pPcapRecordWorkItemData->pWorkItem = pWorkItem;
                    IoQueueWorkItem(pWorkItem, WritePcapRecordWorkItem, DelayedWorkQueue, pPcapRecordWorkItemData);
                }
                else
                {
                    ExFreePool(pPcapRecordWorkItemData);
                    pPcapRecordWorkItemData = NULL;
                }
            }

            netBuffer = NET_BUFFER_NEXT_NB(netBuffer);
        }
    }
}