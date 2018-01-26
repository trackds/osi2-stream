#include "pcap.h"
#include <packet32.h>
#include <ntddndis.h>
int getDevMac(const PCHAR devName, char* mac);