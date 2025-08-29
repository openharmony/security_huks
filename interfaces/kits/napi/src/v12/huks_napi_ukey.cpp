#include "huks_napi_ukey.h"

#include "securec.h"

#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "huks_napi_common_item.h"

namespace HuksNapiItem {

constexpr int HUKS_NAPI_TWO_ARGS = 2;

VerifyPinAsyncContext CreateVerifyPinAsyncContext()
{
    VerifyPinAsyncContext context = static_cast<VerifyPinAsyncContext>(HksMalloc(sizeof(VerifyPinAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(VerifyPinAsyncContextT), 0, sizeof(VerifyPinAsyncContextT));
    }
    return context;
}

UKeyAsyncContext CreateUKeyAsyncContext()
{
    UKeyAsyncContext context = static_cast<UKeyAsyncContext>(HksMalloc(sizeof(UKeyAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(UKeyAsyncContextT), 0, sizeof(UKeyAsyncContextT));
    }
    return context;
}

void DeleteUKeyAsyncContext(napi_env env, UKeyAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }
    DeleteCommonAsyncContext(env, context->asyncWork, context->callback, context->name, context->paramSetIn);
    if (context->paramSetOut != nullptr) {
        HksFreeParamSet(&context->paramSetOut);
    }
    HKS_FREE(context);
    context = nullptr;
}

void DeleteVerifyPinAsyncContext(napi_env env, VerifyPinAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }
    DeleteCommonAsyncContext(env, context->asyncWork, context->callback, context->handle, context->paramSetIn);
    if (context->paramSetOut != nullptr) {
        HksFreeParamSet(&context->paramSetOut);
    }
    HKS_FREE(context);
    context = nullptr;
}

napi_value ParseStringAndHksParamSet(napi_env env, napi_value *argv, size_t &index,
    HksBlob *&Name, HksParamSet *&paramSet)
{
    return ParseKeyAliasAndHksParamSet(env, argv, index, Name, paramSet);
}

static napi_value ProviderParseParams(napi_env env, napi_callback_info info, UKeyAsyncContext context)
{
    size_t argc = HUKS_NAPI_TWO_ARGS;
    napi_value argv[HUKS_NAPI_TWO_ARGS] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc < HUKS_NAPI_TWO_ARGS) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "no enough params input");
        HKS_LOG_E("no enough params");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseStringAndHksParamSet(env, argv, index, context->name, context->paramSetIn);
    if (result == nullptr) {
        HKS_LOG_E("UKey parse params failed");
        return nullptr;
    }

    index++;
    if (index < argc) {
        context->callback = GetCallback(env, argv[index]);
    }

    return GetInt32(env, 0);
}

napi_value ProviderAsyncWork(napi_env env, UKeyAsyncContext &context)
{
    napi_value promise = nullptr;
    if (context->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &promise));
    }

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "ProviderAsyncWork", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            UKeyAsyncContext napiContext = static_cast<UKeyAsyncContext>(data);
            napiContext->result = napiContext->action(napiContext->name, napiContext->paramSetIn);
        },
        [](napi_env env, napi_status status, void *data) {
            UKeyAsyncContext napiContext = static_cast<UKeyAsyncContext>(data);
            HksSuccessReturnResult resultData;
            SuccessReturnResultInit(resultData);
            HksReturnNapiResult(env, napiContext->callback, napiContext->deferred, napiContext->result, resultData);
            DeleteUKeyAsyncContext(env, napiContext);
        },
        static_cast<void *>(context),
        &context->asyncWork);

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        DeleteUKeyAsyncContext(env, context);
        HKS_LOG_E("could not queue async work");
        return nullptr;
    }

    if (context->callback == nullptr) {
        return promise;
    } else {
        return GetNull(env);
    }
}

napi_value ProviderEntry(napi_env env, napi_callback_info info, ProviderFunc action)
{
    UKeyAsyncContext context = CreateUKeyAsyncContext();
    if (context == nullptr) {
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    napi_value result = ProviderParseParams(env, info, context);
    if (result == nullptr) {
        HKS_LOG_E("could not parse params");
        DeleteUKeyAsyncContext(env, context);
        return nullptr;
    }
    context->action = action;
    result = ProviderAsyncWork(env, context);
    if (result == nullptr) {
        HKS_LOG_E("could not do async work");
        DeleteUKeyAsyncContext(env, context);
        return nullptr;
    }
    return result;
}

napi_value HuksNapiRegisterProvider(napi_env env, napi_callback_info info)
{
    return ProviderEntry(env, info, RegisterProvider);
}

napi_value HuksNapiUnregisterProvider(napi_env env, napi_callback_info info)
{
    return ProviderEntry(env, info, UnRegisterProvider);
}


static napi_value VerifyPinParseParams(napi_env env, napi_callback_info info, VerifyPinAsyncContext context)
{
    size_t argc = HUKS_NAPI_TWO_ARGS;
    napi_value argv[HUKS_NAPI_TWO_ARGS] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc < HUKS_NAPI_TWO_ARGS) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "no enough params input");
        HKS_LOG_E("no enough params");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseStringAndHksParamSet(env, argv, index, context->handle, context->paramSetIn);
    if (result == nullptr) {
        HKS_LOG_E("VerifyPin parse params failed");
        return nullptr;
    }

    index++;
    if (index < argc) {
        context->callback = GetCallback(env, argv[index]);
    }

    return GetInt32(env, 0);
}

napi_value VerifyPinAsyncWork(napi_env env, VerifyPinAsyncContext &context)
{
    napi_value promise = nullptr;
    if (context->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &promise));
    }  
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "VerifyPinAsyncWork", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            VerifyPinAsyncContext napiContext = static_cast<VerifyPinAsyncContext>(data);
            napiContext->result = VerifyPin(napiContext->handle, napiContext->paramSetIn);
        },
        [](napi_env env, napi_status status, void *data) {
            VerifyPinAsyncContext napiContext = static_cast<VerifyPinAsyncContext>(data);
            HksSuccessReturnResult resultData;
            SuccessReturnResultInit(resultData);
            HksReturnNapiResult(env, napiContext->callback, napiContext->deferred, napiContext->result, resultData);
            DeleteVerifyPinAsyncContext(env, napiContext);
        },
        static_cast<void *>(context),
        &context->asyncWork);

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        DeleteVerifyPinAsyncContext(env, context);
        HKS_LOG_E("could not queue async work");
        return nullptr;
    }
    if (context->callback == nullptr) {
        return promise;
    } else {
        return GetNull(env);
    }
}

napi_value HuksNapiVerifyPin(napi_env env, napi_callback_info info)
{
    VerifyPinAsyncContext context = CreateVerifyPinAsyncContext();
    if (context == nullptr) {
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    napi_value result = VerifyPinParseParams(env, info, context);
    if (result == nullptr) {
        HKS_LOG_E("could not parse params");
        DeleteVerifyPinAsyncContext(env, context);
        return nullptr;
    }

    result = VerifyPinAsyncWork(env, context);
    if (result == nullptr) {
        HKS_LOG_E("could not do async work");
        DeleteVerifyPinAsyncContext(env, context);
        return nullptr;
    }
    return result;
}

}  // namespace HuksNapiItem