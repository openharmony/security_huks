#ifndef HUKS_NAPI_UKEY_H
#define HUKS_NAPI_UKEY_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "huks_napi_common_item.h"

#include "hks_param.h"

namespace HuksNapiItem {
using ProviderFunc = int32_t (*)(const HksBlob *, const HksParamSet *);

class AsyncContext {
public:
    virtual ~AsyncContext() 
    {
        if(asyncWork != nullptr && env != nullptr) {
            napi_delete_async_work(env, asyncWork);
        }

        if (callback != nullptr) {
            napi_delete_reference(env, callback);
            callback = nullptr;
        }
        
        if (paramSetIn != nullptr) {
            HksFreeParamSet(&paramSetIn);
        }
        if (paramSetOut != nullptr) {
            HksFreeParamSet(&paramSetOut);
        }

    }

    napi_env env;
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;
    int32_t result = 0;

    std::function<napi_status(napi_env, napi_callback_info, AsyncContext *)> parse;
    napi_async_execute_callback execute;
    std::function<void(napi_env, AsyncContext *)> resolve;

    struct HksParamSet *paramSetIn = nullptr;
    struct HksParamSet *paramSetOut = nullptr;
};

class RegisterAndUngisterProviderContext : public AsyncContext {
public:
    ~RegisterAndUngisterProviderContext() {
        if (name != nullptr) {
            FreeHksBlob(name);
        }
    }
    struct HksBlob *name = nullptr;
};

class VerifyPinAsyncContext : public AsyncContext {
public:
    ~VerifyPinAsyncContext() {
        if (handle != nullptr) {
            FreeHksBlob(handle);
        }
    }
    struct HksBlob *handle = nullptr;
    
};

napi_value HuksNapiRegisterProvider(napi_env env, napi_callback_info info);

napi_value HuksNapiUnregisterProvider(napi_env env, napi_callback_info info);

napi_value HuksNapiVerifyPin(napi_env env, napi_callback_info info);



}  // namespace HuksNapiItem

#endif  // HUKS_NAPI_UKEY_H