#include "include/commLib.h"

int getDevMac(const PCHAR devName, char* mac) {
    LPADAPTER lpAdapter = NULL;
    PPACKET_OID_DATA  OidData = NULL;
    BOOLEAN     Status;

    if ((devName == NULL) || mac == NULL) {
        return -1;
    }
    lpAdapter = PacketOpenAdapter(devName);
    if (!(!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE)))
    {
        OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
        if (OidData != NULL) {
            OidData->Oid = OID_802_3_CURRENT_ADDRESS;
            OidData->Length = 6;
            ZeroMemory(OidData->Data, 6);
            Status = PacketRequest(lpAdapter, FALSE, OidData);
            if(Status)
            {
                sprintf(mac,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
                    (OidData->Data)[0],
                    (OidData->Data)[1],
                    (OidData->Data)[2],
                    (OidData->Data)[3],
                    (OidData->Data)[4],
                    (OidData->Data)[5]);
            }
            free(OidData);
        } else {
            printf("error allocating memory!\r\n");
            return -1;
        }
        PacketCloseAdapter(lpAdapter);
    } else {
        printf("Unable to open the adapter, Error Code : %lx\n",GetLastError());
        return -1;
    }
    return 0;
}