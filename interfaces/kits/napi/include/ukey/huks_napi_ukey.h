#ifndef HUKS_NAPI_UKEY_H
#define HUKS_NAPI_UKEY_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "huks_napi_common_item.h"

#include "hks_param.h"

namespace HuksNapiItem
{

#define NAPI_TYPE_CHECK(env, valueType, expectType, code, msg) \
    if ((valueType) != (expectType))                           \
    {                                                          \
        HksNapiThrow((env), (code), (msg));                    \
        HKS_LOG_E("%s", (msg));                                \
        return nullptr;                                        \
    }

#define NAPI_CALL_RETURN_ERR(env, ret)   \
    if ((ret) != napi_ok)                \
    {                                    \
        GET_AND_THROW_LAST_ERROR((env)); \
        return ret;                      \
    }

#define NAPI_THROW_BASE(env, condition, ret, code, message)           \
    if ((condition))                                                  \
    {                                                                 \
        HKS_LOG_E(message);                                           \
        napi_throw((env), NapiCreateError((env), (code), (message))); \
        return (ret);                                                 \
    }

#define NAPI_THROW(env, condition, code, message) \
    NAPI_THROW_BASE(env, condition, nullptr, code, message)

#define NAPI_THROW_RETURN_ERR(env, condition, ret, code, message) \
    NAPI_THROW_BASE(env, condition, ret, code, message)

class AsyncContext
{
public:
    virtual ~AsyncContext()
    {
        if (asyncWork != nullptr && env != nullptr)
        {
            napi_delete_async_work(env, asyncWork);
        }

        if (callback != nullptr)
        {
            napi_delete_reference(env, callback);
            callback = nullptr;
        }

        if (paramSetIn != nullptr)
        {
            HksFreeParamSet(&paramSetIn);
        }
        if (paramSetOut != nullptr)
        {
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

class RegisterAndUngisterProviderContext : public AsyncContext
{
public:
    ~RegisterAndUngisterProviderContext()
    {
        if (name != nullptr)
        {
            FreeHksBlob(name);
        }
    }
    struct HksBlob *name = nullptr;
};

class UkeyPinContext : public AsyncContext
{
public:
    ~UkeyPinContext()
    {
        if (index != nullptr)
        {
            FreeHksBlob(index);
        }
    }
    struct HksBlob *index = nullptr;
    int32_t outStatus = 0;
    uint32_t retryCount = 0;
};

// 对外接口
napi_value HuksNapiRegisterProvider(napi_env env, napi_callback_info info);

napi_value HuksNapiUnregisterProvider(napi_env env, napi_callback_info info);

napi_value HuksNapiAuthUkeyPin(napi_env env, napi_callback_info info);

napi_value HuksNapiGetUkeyPinAuthState(napi_env env, napi_callback_info info);

// 工具函数
napi_value NapiCreateError(napi_env env, int32_t errCode, const char *errMsg);

napi_value ParseString(napi_env env, napi_value object, HksBlob *&alias);

} // namespace HuksNapiItem

#endif // HUKS_NAPI_UKEY_H