#include <node_api.h>
#include <pcap/pcap.h>
#include <packet32.h>
#include <ntddndis.h>
// #include "addon.h"

typedef struct
{
  char devName[1024];
  pcap_t *fp;
  char filterRule[1024];
  struct bpf_program filter;
} PCAP_OBJ_T;

typedef struct
{
  napi_env env;
  napi_value recv;
  napi_value func;
  size_t argc;
  napi_value *argv;
  napi_value *result;
} CALLBACK_T;

static int getDevMac(const PCHAR devName, char *mac)
{
  LPADAPTER lpAdapter = NULL;
  PPACKET_OID_DATA OidData = NULL;
  BOOLEAN Status;

  if ((devName == NULL) || mac == NULL)
  {
    return -1;
  }
  lpAdapter = PacketOpenAdapter(devName);
  if (!(!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE)))
  {
    OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
    if (OidData != NULL)
    {
      OidData->Oid = OID_802_3_CURRENT_ADDRESS;
      OidData->Length = 6;
      ZeroMemory(OidData->Data, 6);
      Status = PacketRequest(lpAdapter, FALSE, OidData);
      if (Status)
      {
        sprintf(mac, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
                (OidData->Data)[0],
                (OidData->Data)[1],
                (OidData->Data)[2],
                (OidData->Data)[3],
                (OidData->Data)[4],
                (OidData->Data)[5]);
      }
      free(OidData);
    }
    else
    {
      printf("error allocating memory!\r\n");
      return -1;
    }
    PacketCloseAdapter(lpAdapter);
  }
  else
  {
    printf("Unable to open the adapter, Error Code : %lx\n", GetLastError());
    return -1;
  }
  return 0;
}

static napi_value find_alldevs_cb(napi_env env, napi_callback_info info)
{
  napi_value ret = NULL;
  napi_status status;
  pcap_if_t *alldevs;
  pcap_if_t *d;
  int i = 0;
  char errbuf[PCAP_ERRBUF_SIZE];

  status = napi_create_array(env, &ret);
  if (status != napi_ok)
  {
    printf("create ret array failed \r\n");
    return NULL;
  }

  if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1)
  {
    printf("find dev error \r\n");
    return ret;
  }

  for (d = alldevs; d != NULL; d = d->next, i++)
  {
    napi_value obj = NULL;
    napi_value name = NULL;
    napi_value mac = NULL;
    napi_value description = NULL;
    napi_value addrArr = NULL;
    int j = 0;
    struct pcap_addr *addr = d->addresses;
    struct pcap_addr *naddr = addr;
    char index[10];
    char macBuf[16];
    napi_handle_scope scope;

    status = napi_open_handle_scope(env, &scope);
    if (status != napi_ok)
    {
      break;
    }

    status = napi_create_object(env, &obj);
    if (status != napi_ok)
    {
      napi_close_handle_scope(env, scope);
      break;
    }

    status = napi_create_array(env, &addrArr);
    if (status != napi_ok)
    {
      napi_close_handle_scope(env, scope);
      break;
    }

    memset(macBuf, 0, sizeof(macBuf));
    memset(index, 0, 10);
    sprintf(index, "%d", i);

    getDevMac(&d->name[8], macBuf);
    napi_create_string_utf8(env, d->name, strlen(d->name), &name);
    napi_create_string_utf8(env, d->description, strlen(d->description), &description);
    napi_create_string_utf8(env, macBuf, strlen(macBuf), &mac);
    napi_set_named_property(env, obj, "name", name);
    napi_set_named_property(env, obj, "description", description);
    napi_set_named_property(env, obj, "mac", mac);

    for (naddr = addr, j = 0; naddr != NULL; naddr = naddr->next, j++)
    {
      napi_handle_scope scope;
      napi_value addrObj = NULL;
      napi_value ipaddr = NULL;
      napi_value netmask = NULL;
      napi_value broadaddr = NULL;
      char addrStr[20];
      char jindex[10];
      memset(addrStr, 0, sizeof(addrStr));
      memset(jindex, 0, sizeof(jindex));

      sprintf(jindex, "%d", j);
      status = napi_open_handle_scope(env, &scope);
      if (status != napi_ok)
      {
        break;
      }

      if (naddr->addr->sa_family == 2)
      {
        sprintf(addrStr, "%u.%u.%u.%u",
                (unsigned char)naddr->addr->sa_data[2],
                (unsigned char)naddr->addr->sa_data[3],
                (unsigned char)naddr->addr->sa_data[4],
                (unsigned char)naddr->addr->sa_data[5]);
        if (napi_create_string_utf8(env, addrStr, strlen(addrStr), &addrObj) == napi_ok)
        {
          napi_set_named_property(env, addrObj, "ipaddr", addrObj);
        }

        memset(addrStr, 0, sizeof(addrStr));
        sprintf(addrStr, "%u.%u.%u.%u",
                (unsigned char)naddr->netmask->sa_data[2],
                (unsigned char)naddr->netmask->sa_data[3],
                (unsigned char)naddr->netmask->sa_data[4],
                (unsigned char)naddr->netmask->sa_data[5]);
        if (napi_create_string_utf8(env, addrStr, strlen(addrStr), &netmask) == napi_ok)
        {
          napi_set_named_property(env, addrObj, "netmask", netmask);
        }

        memset(addrStr, 0, sizeof(addrStr));
        sprintf(addrStr, "%u.%u.%u.%u",
                (unsigned char)naddr->broadaddr->sa_data[2],
                (unsigned char)naddr->broadaddr->sa_data[3],
                (unsigned char)naddr->broadaddr->sa_data[4],
                (unsigned char)naddr->broadaddr->sa_data[5]);
        if (napi_create_string_utf8(env, addrStr, strlen(addrStr), &broadaddr) == napi_ok)
        {
          napi_set_named_property(env, addrObj, "broadaddr", broadaddr);
        }
        napi_set_element(env, addrArr, atoi(jindex), addrObj);
      }
      else
      {
        j--;
      }
      napi_close_handle_scope(env, scope);
    }

    napi_set_named_property(env, obj, "address", addrArr);
    napi_set_element(env, ret, atoi(index), obj);
    napi_close_handle_scope(env, scope);
  }

  pcap_freealldevs(alldevs);
  return ret;
}

static napi_value pcap_get_dev_name(napi_env env, napi_callback_info info)
{
  napi_value ret = NULL;
  PCAP_OBJ_T *pcap = NULL;
  napi_get_cb_info(env, info, NULL, NULL, NULL, &pcap);
  napi_create_string_utf8(env, (pcap != NULL) ? pcap->devName : "", NAPI_AUTO_LENGTH, &ret);
  return ret;
}

static void readPktCb(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
  if (user != NULL && (pkt_data != NULL))
  {
    if ((pkt_header != NULL) && (pkt_header->len > 0))
    {
      CALLBACK_T *callback = (CALLBACK_T *)user;
      napi_value argv[2];
      napi_get_null(callback->env, &argv[0]);
      napi_create_buffer_copy(callback->env, (size_t)pkt_header->len, (char *)pkt_data, NULL, &argv[1]);
      napi_call_function(callback->env, callback->recv, callback->func, 2, argv, callback->result);
    }
  }
}

static napi_value pcapobj_close(napi_env env, napi_callback_info info)
{
  PCAP_OBJ_T *data = NULL;
  napi_get_cb_info(env, info, NULL, NULL, NULL, &data);
  if (data != NULL)
  {
    if (data->fp != NULL)
    {
      pcap_breakloop(data->fp);
      pcap_freecode(&data->filter);
      pcap_close(data->fp);
      data->fp = NULL;
    }
    free(data);
  }

  return NULL;
}

static napi_value pcapobj_read(napi_env env, napi_callback_info info)
{
  size_t argc = 1;
  napi_value argv[1];
  PCAP_OBJ_T *pcap = NULL;
  napi_status status;
  napi_valuetype argv_type = napi_undefined;
  napi_value this_arg;
  int ret = 0;

  if (napi_get_cb_info(env, info, &argc, argv, &this_arg, &pcap) != napi_ok)
  {
    napi_throw_error(env, "Error:", "get cb info failed");
    return NULL;
  }

  if (pcap == NULL)
  {
    napi_throw_error(env, "Error:", "pcap not init");
    return NULL;
  }
  if (NULL == pcap->fp)
  {
    napi_throw_error(env, "Error:", "The device is not open");
    return NULL;
  }

  napi_typeof(env, argv[0], &argv_type);
  if (argv_type != napi_function)
  {
    napi_throw_error(env, "Error:", "Must have a function to receive data");
    return NULL;
  }
  CALLBACK_T callback = {
      env, this_arg, argv[0], 0, NULL, NULL};
#if 0
    AsyncQueueWorker(new AsyncReadPacket(callback, fp));
#else
  ret = pcap_loop(pcap->fp, 0, readPktCb, (PUCHAR)&callback);
  if (ret == -1)
  {
    char errorBuf[PCAP_ERRBUF_SIZE];
    memset(errorBuf, 0, PCAP_ERRBUF_SIZE);
    pcap_perror(pcap->fp, errorBuf);
    napi_throw_error(env, "Error:", errorBuf);
    return NULL;
  }
#endif

  return NULL;
}

static napi_value pcapobj_send(napi_env env, napi_callback_info info)
{
  size_t argc = 1;
  napi_value argv[1];
  PCAP_OBJ_T *pcap = NULL;
  napi_status status;
  bool check_type = false;

  if (napi_get_cb_info(env, info, &argc, argv, NULL, &pcap) != napi_ok)
  {
    napi_throw_error(env, "Error:", "get cb info failed");
    return NULL;
  }

  if (pcap == NULL)
  {
    napi_throw_error(env, "Error:", "pcap not init");
    return NULL;
  }

  if (pcap->fp == NULL)
  {
    napi_throw_error(env, "Error:", "The device is not open");
    return NULL;
  }

  if (argc < 1)
  {
    napi_throw_error(env, "Error:", "Wrong number of arguments");
    return NULL;
  }

  napi_is_buffer(env, argv[0], &check_type);
  if (!check_type)
  { // 判断是否是Buffer对象
    napi_throw_error(env, "Error:", "Bad arguments");
    return NULL;
  }

  size_t size = 0;   // 获取Buffer长度
  char *data = NULL; // 获取Buffer内容

  napi_get_buffer_info(env, argv[0], (void **)&data, &size);
  if (size > 1500)
  {
    napi_throw_error(env, "Error:", "The maximum length of Ethernet data frames cannot exceed 1500");
    return NULL;
  }

  if (pcap_sendpacket(pcap->fp, (u_char *)data, (int)size) != 0)
  {
    napi_throw_error(env, "Error:", "Error sending the packet");
    return NULL;
  }

  return NULL;
}

static void pcapobj_free(napi_env env, void *finalize_data, void *finalize_hint)
{
  PCAP_OBJ_T *data = finalize_data;
  if (data != NULL)
  {
    if (data->fp != NULL)
    {
      pcap_breakloop(data->fp);
      pcap_freecode(&data->filter);
      pcap_close(data->fp);
      data->fp = NULL;
    }
    free(finalize_data);
  }
}

static napi_value pcapobj_setfilter(napi_env env, napi_callback_info info)
{
  size_t argc = 2;
  napi_value argv[2];
  PCAP_OBJ_T *pcap = NULL;
  napi_status status;
  napi_valuetype argv_type = napi_undefined;
  int ret = 0;
  char filterStr[256];
  bpf_u_int32 netmask = 0;

  if (napi_get_cb_info(env, info, &argc, argv, NULL, &pcap) != napi_ok)
  {
    napi_throw_error(env, "Error:", "get cb info failed");
    return NULL;
  }

  if (pcap == NULL)
  {
    napi_throw_error(env, "Error:", "pcap not init");
    return NULL;
  }

  napi_typeof(env, argv[0], &argv_type);
  if (argc > 0 && argv_type == napi_string)
  {
    if (pcap->fp == NULL)
    {
      napi_throw_error(env, "Error:", "The device is not open");
      return NULL;
    }
    pcap_freecode(&pcap->filter);

    napi_get_value_string_utf8(env, argv[0], filterStr, sizeof(filterStr), NULL);
    napi_typeof(env, argv[1], &argv_type);
    if (argv_type == napi_number)
    {
      napi_get_value_int32(env, argv[1], &netmask);
    }
    else
    {
      netmask = 0;
    }

    ret = pcap_compile(pcap->fp, &pcap->filter, filterStr, 1, netmask);
    if (ret < 0)
    {
      napi_throw_error(env, "Error:", pcap_geterr(pcap->fp));
      return NULL;
    }

    snprintf(pcap->filterRule, sizeof(pcap->filterRule), "%s", filterStr);
    ret = pcap_setfilter(pcap->fp, &pcap->filter);
    if (ret < 0)
    {
      pcap_freecode(&pcap->filter);
      napi_throw_error(env, "Error:", pcap_geterr(pcap->fp));
      return NULL;
    }
  }
  else
  {
    napi_throw_error(env, "Error:", "Wrong number of arguments");
  }

  return NULL;
}

static napi_value pcapobj_getfilter(napi_env env, napi_callback_info info)
{
  PCAP_OBJ_T *pcap = NULL;
  napi_value ret = NULL;
  if (napi_get_cb_info(env, info, NULL, NULL, NULL, &pcap) != napi_ok)
  {
    napi_throw_error(env, "Error:", "get cb info failed");
    return NULL;
  }

  napi_create_string_utf8(env, pcap->filterRule, NAPI_AUTO_LENGTH, &ret);
  return ret;
}

static napi_value open_dev_cb(napi_env env, napi_callback_info info)
{
  size_t argc = 1;
  napi_value argv[1];
  napi_value ret = NULL;
  napi_status status;
  napi_valuetype argv_type = napi_undefined;

  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  if (status != napi_ok)
    return NULL;

  if (argc < 1)
    return NULL;

  napi_typeof(env, argv[0], &argv_type);
  if (argv_type != napi_string)
    return NULL;

  if (napi_create_object(env, &ret) == napi_ok)
  {
    napi_value getDevName = NULL;
    napi_value send = NULL;
    napi_value read = NULL;
    napi_value close = NULL;
    napi_value setfilter = NULL;
    napi_value getfilter = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    PCAP_OBJ_T *pcap_obj = (PCAP_OBJ_T *)malloc(sizeof(PCAP_OBJ_T));
    if (pcap_obj == NULL)
      return NULL;
    memset(pcap_obj, 0, sizeof(PCAP_OBJ_T));
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    napi_get_value_string_utf8(env, argv[0], pcap_obj->devName, 1024, NULL);

    if ((pcap_obj->fp = pcap_open(pcap_obj->devName,         // name of the device
                                  1500,                      // portion of the packet to capture (only the first 100 bytes)
                                  PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
                                  1000,                      // read timeout
                                  NULL,                      // authentication on the remote machine
                                  errbuf                     // error buffer
                                  )) == NULL)
    {
      free(pcap_obj);
      napi_throw_error(env, "Error", errbuf);
      return NULL;
    }

    napi_create_function(env, "getDevName", NAPI_AUTO_LENGTH, pcap_get_dev_name, pcap_obj, &getDevName);
    napi_set_named_property(env, ret, "getDevName", getDevName);
    napi_create_function(env, "send", NAPI_AUTO_LENGTH, pcapobj_send, pcap_obj, &send);
    napi_set_named_property(env, ret, "send", send);
    napi_create_function(env, "read", NAPI_AUTO_LENGTH, pcapobj_read, pcap_obj, &read);
    napi_set_named_property(env, ret, "read", read);
    napi_create_function(env, "close", NAPI_AUTO_LENGTH, pcapobj_close, pcap_obj, &close);
    napi_set_named_property(env, ret, "close", close);
    napi_create_function(env, "SetFilter", NAPI_AUTO_LENGTH, pcapobj_setfilter, pcap_obj, &setfilter);
    napi_set_named_property(env, ret, "SetFilter", setfilter);
    napi_create_function(env, "GetFilter", NAPI_AUTO_LENGTH, pcapobj_getfilter, pcap_obj, &getfilter);
    napi_set_named_property(env, ret, "GetFilter", setfilter);

    napi_add_finalizer(env, ret, pcap_obj, pcapobj_free, NULL, NULL);
  }

  return ret;
}

NAPI_MODULE_INIT(/* napi_env env, napi_value exports */)
{
  napi_value findalldevs;
  napi_value openDev;
  napi_status result;
  napi_status status;

  status = napi_create_function(env, "findalldevs", NAPI_AUTO_LENGTH, find_alldevs_cb, NULL, &findalldevs);
  if (status != napi_ok)
    return NULL;

  status = napi_create_function(env, "openDev", NAPI_AUTO_LENGTH, open_dev_cb, NULL, &openDev);
  if (status != napi_ok)
    return NULL;

  napi_set_named_property(env, exports, "findalldevs", findalldevs);
  napi_set_named_property(env, exports, "openDev", openDev);
  return exports;
}