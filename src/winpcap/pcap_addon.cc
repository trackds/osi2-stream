#include <nan.h>
#include "pcap.h"
#include <packet32.h>
#include <ntddndis.h>
#include "include/pcapObjFactory.h"
#include "include/commLib.h"

NAN_METHOD(PcapFindalldevsEx){
    Nan::HandleScope scope;
    v8::Local<v8::Array> arr = Nan::New<v8::Array>();
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1)
    {
        printf("find dev error \r\n");
        return;
    }

    for(d= alldevs; d != NULL; d= d->next, i++)
    {
        Nan::HandleScope scope;
        v8::Local<v8::Object> obj = Nan::New<v8::Object>();
        v8::Local<v8::Array> addrArr = Nan::New<v8::Array>();
        int j = 0;
        struct pcap_addr *addr = d->addresses;
        struct pcap_addr *naddr = addr;
        char index[10];
        char macBuf[16];

        memset(macBuf, 0, sizeof(macBuf));
        memset(index, 0, 10);
        sprintf(index,"%d",i);

        obj->Set(Nan::New("name").ToLocalChecked(), Nan::Encode(d->name,strlen(d->name),Nan::Encoding::UTF8));
        obj->Set(Nan::New("description").ToLocalChecked(), Nan::Encode(d->description,strlen(d->description),Nan::Encoding::UTF8));

        getDevMac(&d->name[8], macBuf);
        obj->Set(Nan::New("mac").ToLocalChecked(), Nan::Encode(macBuf,strlen(macBuf),Nan::Encoding::UTF8));

        for (naddr = addr, j = 0; naddr != NULL; naddr = naddr->next, j++) {
            Nan::HandleScope scope;
            v8::Local<v8::Object> addrObj = Nan::New<v8::Object>();
            char addrStr[20];
            char jindex[10];
            memset(addrStr, 0, sizeof(addrStr));
            memset(jindex, 0, sizeof(jindex));

            sprintf(jindex,"%d",j);
            
            if (naddr->addr->sa_family == 2) {
                sprintf(addrStr, "%u.%u.%u.%u",
                        (unsigned char)naddr->addr->sa_data[2],
                        (unsigned char)naddr->addr->sa_data[3],
                        (unsigned char)naddr->addr->sa_data[4],
                        (unsigned char)naddr->addr->sa_data[5]);
                addrObj->Set(Nan::New("ipaddr").ToLocalChecked(), Nan::Encode(addrStr,strlen(addrStr),Nan::Encoding::UTF8));

                memset(addrStr, 0, sizeof(addrStr));
                sprintf(addrStr, "%u.%u.%u.%u",
                        (unsigned char)naddr->netmask->sa_data[2],
                        (unsigned char)naddr->netmask->sa_data[3],
                        (unsigned char)naddr->netmask->sa_data[4],
                        (unsigned char)naddr->netmask->sa_data[5]);
                addrObj->Set(Nan::New("netmask").ToLocalChecked(), Nan::Encode(addrStr,strlen(addrStr),Nan::Encoding::UTF8));

                memset(addrStr, 0, sizeof(addrStr));
                sprintf(addrStr, "%u.%u.%u.%u",
                        (unsigned char)naddr->broadaddr->sa_data[2],
                        (unsigned char)naddr->broadaddr->sa_data[3],
                        (unsigned char)naddr->broadaddr->sa_data[4],
                        (unsigned char)naddr->broadaddr->sa_data[5]);
                addrObj->Set(Nan::New("broadaddr").ToLocalChecked(), Nan::Encode(addrStr,strlen(addrStr),Nan::Encoding::UTF8));
                addrArr->Set(Nan::New(jindex).ToLocalChecked(), addrObj);
            } else {
                j--;
            }
        }
        obj->Set(Nan::New("address").ToLocalChecked(),addrArr);
        arr->Set(Nan::New(index).ToLocalChecked(), obj);
    }
    info.GetReturnValue().Set(arr);
    pcap_freealldevs(alldevs);
}



NAN_MODULE_INIT(Init) {
    PcapObjFactory::Init(target);
    Nan::Set(target,
        Nan::New<v8::String>("findalldevs").ToLocalChecked(),
        Nan::GetFunction(Nan::New<v8::FunctionTemplate>(PcapFindalldevsEx)).ToLocalChecked()
    );
    Nan::Set(target,
        Nan::New<v8::String>("openDev").ToLocalChecked(),
        Nan::GetFunction(Nan::New<v8::FunctionTemplate>(PcapObjFactory::NewInstance)).ToLocalChecked()
    );
}

NODE_MODULE(pcap_addon, Init)
