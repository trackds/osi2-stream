#include "include/pcapObjFactory.h"

#if 0
void readPktCb(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data) {
    if (user != NULL && (pkt_data != NULL)) {
        const Nan::AsyncProgressQueueWorker<char>::ExecutionProgress* progress = (Nan::AsyncProgressQueueWorker<char>::ExecutionProgress*)user;
        if ((pkt_header != NULL) && (pkt_header->len > 0)) {
            printf("send=%p, len=%d, clen=%d\r\n", pkt_data, pkt_header->len, pkt_header->caplen);
            progress->Send((char*)pkt_data, (size_t)pkt_header->len);
            // progress->Signal();
        }
    }
}
class AsyncReadPacket : public Nan::AsyncProgressQueueWorker<char> {
public:
    AsyncReadPacket(Nan::Callback *callback, pcap_t *fp) : AsyncProgressQueueWorker<char>(callback), fp(fp) {}

    ~AsyncReadPacket(){}

    void Execute(const ExecutionProgress& progress) {
        int ret = pcap_loop(fp, 0, readPktCb, (PUCHAR)&progress);
        printf("ret=%d\r\n", ret);

    }

    void HandleProgressCallback(const char *data, size_t count) {
        Nan::HandleScope scope;
        printf("rec=%p, len=%d\r\n", data, (int)count);
        if (data == NULL) {
            return;
        }
        printf("build buffer\r\n");
        v8::Local<v8::Value> argv[] = {
            Nan::Null(), 
            Nan::NewBuffer((char*)data, (size_t)count).ToLocalChecked()
        };
        printf("build buffer done\r\n");
        printf("empty=%d\r\n", callback->IsEmpty());
        callback->Call(2, argv);
        printf("callback done\r\n");
    }
    void HandleOKCallback () {
        printf("HandleOKCallback\r\n");
    }
    void HandleErrorCallback() {
        printf("HandleErrorCallback\r\n");
    }
    void Destroy() {
        printf("Destroy\r\n");
        pcap_breakloop(fp);
    }

private:
    pcap_t *fp;
};
#else
void readPktCb(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data) {
    if (user != NULL && (pkt_data != NULL)) {
        if ((pkt_header != NULL) && (pkt_header->len > 0)) {
            Nan::Callback *callback = (Nan::Callback *)user;
            v8::Local<v8::Value> argv[] = {
                Nan::Null(), 
                Nan::NewBuffer((char*)pkt_data, (size_t)pkt_header->len).ToLocalChecked()
            };
            callback->Call(2, argv);
        }
    }
}
#endif

NAN_MODULE_INIT(PcapObjFactory::Init) {
    v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
    tpl->InstanceTemplate()->SetInternalFieldCount(1);

    Nan::SetPrototypeMethod(tpl, "getDevName", GetDevName);
    Nan::SetPrototypeMethod(tpl, "send", Send);
    Nan::SetPrototypeMethod(tpl, "read", Read);
    Nan::SetPrototypeMethod(tpl, "close", Close);
    Nan::SetPrototypeMethod(tpl, "SetFilter", SetFilter);
    Nan::SetPrototypeMethod(tpl, "GetFilter", GetFilter);
    // Nan::SetPrototypeTemplate(tpl, "test", Nan::New<v8::String>("hello").ToLocalChecked());

    constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
}

NAN_METHOD(PcapObjFactory::NewInstance){
    v8::Local<v8::Function> cons = Nan::New(constructor());
    const int argc = 1;
    v8::Local<v8::Value> argv[1] = {info[0]->IsString() ? info[0]->ToString() : Nan::New<v8::String>("321").ToLocalChecked()};
    info.GetReturnValue().Set(Nan::NewInstance(cons, argc, argv).ToLocalChecked());
}
NAN_METHOD(PcapObjFactory::SetFilter){
    PcapObjFactory* obj = PcapObjFactory::Unwrap<PcapObjFactory>(info.Holder());
    int ret = 0;
    char filterStr[256];
    bpf_u_int32 netmask = 0;
    ZeroMemory(filterStr, sizeof(filterStr));
    if (info.Length() > 0 && info[0]->IsString()) {
        if (obj->fp == NULL) {
            Nan::ThrowError("The device is not open");
            return;
        }
        pcap_freecode(&obj->filter);
        Nan::DecodeWrite(filterStr, sizeof(filterStr), info[0], Nan::Encoding::ASCII);
        netmask = info[1]->IsNumber() ? Nan::To<int>(info[1]).FromJust() : 0;

        ret = pcap_compile(obj->fp, &obj->filter, filterStr, 1, netmask);
        if (ret < 0) {
            Nan::ThrowError(pcap_geterr(obj->fp));
            return;
        }
        obj->filterRule = std::string(filterStr);
        ret = pcap_setfilter(obj->fp, &obj->filter);
        if (ret < 0) {
            pcap_freecode(&obj->filter);
            Nan::ThrowError(pcap_geterr(obj->fp));
            return;
        }
    } else {
        Nan::ThrowError("Wrong number of arguments");
    }

}
NAN_METHOD(PcapObjFactory::GetFilter){
    PcapObjFactory* obj = PcapObjFactory::Unwrap<PcapObjFactory>(info.Holder());
    info.GetReturnValue().Set(Nan::New<v8::String>(obj->filterRule).ToLocalChecked());
}

NAN_METHOD(PcapObjFactory::GetDevName) {
    PcapObjFactory* obj = PcapObjFactory::Unwrap<PcapObjFactory>(info.Holder());
    info.GetReturnValue().Set(Nan::New<v8::String>(obj->devName).ToLocalChecked());
}

NAN_METHOD(PcapObjFactory::Send) {
    pcap_t *fp = NULL;
    PcapObjFactory* obj = PcapObjFactory::Unwrap<PcapObjFactory>(info.Holder());

    fp = obj->fp;
    if (fp == NULL) {
        Nan::ThrowError("The device is not open");
        return;
    }
    
    if (info.Length() < 1) {
        Nan::ThrowError("Wrong number of arguments");
        return;
    }

    v8::Local<v8::Value> arg = info[0];
    if(!node::Buffer::HasInstance(arg)) { //判断是否是Buffer对象
        Nan::ThrowTypeError("Bad arguments");
        return;
    }
    
    size_t size = node::Buffer::Length(arg->ToObject());  //获取Buffer长度
    char *data = node::Buffer::Data(arg->ToObject());      //获取Buffer内容

    if (size > 1500) {
        Nan::ThrowError("The maximum length of Ethernet data frames cannot exceed 1500");
        return;
    }

    if (pcap_sendpacket(fp, (u_char*)data, (int)size) != 0)
    {
        Nan::ThrowError("Error sending the packet");
        return;
    }
    
}

NAN_METHOD(PcapObjFactory::Read) {
    pcap_t *fp = NULL;
    int ret = 0;
    PcapObjFactory* obj = PcapObjFactory::Unwrap<PcapObjFactory>(info.Holder());
    fp = obj->fp;
    if (NULL == fp) {
        Nan::ThrowError("The device is not open");
        return;
    }
    if(!info[0]->IsFunction()) {
        Nan::ThrowError("Must have a function to receive data");
        return;
    }
    Nan::Callback *callback = new Nan::Callback(Nan::To<v8::Function>(info[0]).ToLocalChecked());
#if 0
    AsyncQueueWorker(new AsyncReadPacket(callback, fp));
#else
    ret = pcap_loop(fp, 0, readPktCb, (PUCHAR)callback);
    if (ret == -1) {
        char errorBuf[PCAP_ERRBUF_SIZE];
        ZeroMemory(errorBuf, PCAP_ERRBUF_SIZE);
        pcap_perror(fp, errorBuf);
        Nan::ThrowError(errorBuf);
        return;
    }
#endif
}

NAN_METHOD(PcapObjFactory::Close) {
    PcapObjFactory* obj = PcapObjFactory::Unwrap<PcapObjFactory>(info.Holder());
    if (obj->fp != NULL) {
        pcap_breakloop(obj->fp);
        pcap_close(obj->fp);
        pcap_freecode(&obj->filter);
        obj->fp = NULL;
    }
}

PcapObjFactory::PcapObjFactory(const char *newdevName) {
//TODO:
    pcap_t *fp = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    this->devName = std::string(newdevName);
    ZeroMemory(errbuf, PCAP_ERRBUF_SIZE);

    /* Open the output device */
    if ( (fp= pcap_open(newdevName,            // name of the device
                        1500,                // portion of the packet to capture (only the first 100 bytes)
                        PCAP_OPENFLAG_PROMISCUOUS,  // promiscuous mode
                        1000,               // read timeout
                        NULL,               // authentication on the remote machine
                        errbuf              // error buffer
                        ) ) == NULL)
    {
        Nan::ThrowError(errbuf);
        return;
    }
    this->fp = fp;
    ZeroMemory(&filter, sizeof(filter));
}

PcapObjFactory::~PcapObjFactory() {
    if (fp != NULL) {
        pcap_breakloop(fp);
        pcap_freecode(&filter);
        pcap_close(fp);
        fp = NULL;
    }
}

NAN_METHOD(PcapObjFactory::New) {
    if (info.IsConstructCall()) {
        v8::Local<v8::String> arg;
        char devName[1024];
        memset(devName, 0, sizeof(devName));
        arg = info[0]->IsString() ? info[0]->ToString() : Nan::New<v8::String>("123").ToLocalChecked();
        Nan::DecodeWrite(devName, sizeof(devName), arg, Nan::Encoding::UTF8);
        PcapObjFactory * obj = new PcapObjFactory(devName);
        obj->Wrap(info.This());
        info.GetReturnValue().Set(info.This());
    } else {
        NewInstance(info);
    }
}

