#ifndef PCAP_OBJ_FACTORY
#define PCAP_OBJ_FACTORY
#include <nan.h>
#include "pcap.h"
// #include <packet32.h>
// #include <ntddndis.h>
class PcapObjFactory : public Nan::ObjectWrap {
public:
    static void Init(v8::Local<v8::Object> info);

    static void NewInstance(const Nan::FunctionCallbackInfo<v8::Value>& info);

private:
    explicit PcapObjFactory(const char *devName);
    ~PcapObjFactory();

    static void New(const Nan::FunctionCallbackInfo<v8::Value>& info);

    static void GetDevName(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void Send(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void Close(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void Read(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void SetFilter(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void GetFilter(const Nan::FunctionCallbackInfo<v8::Value>& info);
//   static NAN_METHOD(GetValue) {
//     MyFactoryObject* obj = ObjectWrap::Unwrap<MyFactoryObject>(info.Holder());
//     info.GetReturnValue().Set(obj->value_);
//   }
    // void readPktCb(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);

    static inline Nan::Persistent<v8::Function> & constructor() {
        static Nan::Persistent<v8::Function> my_constructor;
        return my_constructor;
    }
    
    std::string devName;
    pcap_t *fp;
    std::string filterRule;
    struct bpf_program filter;
};
#endif