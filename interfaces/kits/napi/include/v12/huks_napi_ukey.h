#ifndef HUKS_NAPI_UKEY_H
#define HUKS_NAPI_UKEY_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "hks_param.h"

namespace HuksNapiItem {
using ProviderFunc = int32_t (*)(const HksBlob *, const HksParamSet *);

struct UKeyAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t result = 0;
    struct HksBlob *name = nullptr;
    struct HksParamSet *paramSetIn = nullptr;
    struct HksParamSet *paramSetOut = nullptr;

    // napi_async_execute_callback execute;
    ProviderFunc action = nullptr;

};

struct VerifyPinAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t result = 0;
    struct HksBlob *handle = nullptr;
    struct HksParamSet *paramSetIn = nullptr;
    struct HksParamSet *paramSetOut = nullptr;

    // napi_async_execute_callback execute;
    ProviderFunc action = nullptr;

};

using UKeyAsyncContext = UKeyAsyncContextT *;

using VerifyPinAsyncContext = VerifyPinAsyncContextT *;

UKeyAsyncContext CreateUKeyAsyncContext();

VerifyPinAsyncContext CreateVerifyPinAsyncContext();

void DeleteUKeyAsyncContext(napi_env env, UKeyAsyncContext &context);

void DeleteVerifyPinAsyncContext(napi_env env, UKeyAsyncContext &context);

napi_value HuksNapiRegisterProvider(napi_env env, napi_callback_info info);

napi_value HuksNapiUnregisterProvider(napi_env env, napi_callback_info info);

napi_value HuksNapiVerifyPin(napi_env env, napi_callback_info info);



}  // namespace HuksNapiItem

#endif  // HUKS_NAPI_UKEY_H