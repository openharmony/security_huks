/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "huks_napi_get_key_item_properties.h"

#include <dlfcn.h>
#include <atomic>
#include <mutex>
#include "securec.h"

#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "huks_napi_common_item.h"
#include "hks_template.h"

namespace {
constexpr const char *COMPUTATION_PATH = HUKS_ENABLE_COMPUTATION_CONFIG;
const char PRIVACY_SEARCH_FUNC_NAME[] = "HksPrivacySearchAdapter";
std::atomic<void*> g_cczNapiHandle{nullptr};
std::mutex g_cczNapiMutex;
void *GetCczNapiHandle()
{
    if (COMPUTATION_PATH == nullptr || COMPUTATION_PATH[0] == '\0') {
        HKS_LOG_E("computation path is empty, skip dlopen");
        return nullptr;
    }
    void *handle = g_cczNapiHandle.load(std::memory_order_acquire);
    if (handle != nullptr) {
        return handle;
    }
    std::lock_guard<std::mutex> lock(g_cczNapiMutex);
    handle = g_cczNapiHandle.load(std::memory_order_relaxed);
    if (handle != nullptr) {
        return handle;
    }
    handle = dlopen(COMPUTATION_PATH, RTLD_NOW | RTLD_LOCAL);
    if (handle == nullptr) {
        HKS_LOG_E("dlopen ccz napi so failed, %" LOG_PUBLIC "s!", dlerror());
        return nullptr;
    }
    g_cczNapiHandle.store(handle, std::memory_order_release);
    return handle;
}

using GetKeyParamSetExtFunc = int32_t (*)(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSetIn, struct HksParamSet **paramSetOut);

bool IsPrivacySearchMatch(const struct HksBlob *keyAlias, const struct HksParamSet *paramSetIn)
{
    if ((keyAlias != nullptr && keyAlias->size != 0) || paramSetIn == nullptr || paramSetIn->paramsCnt == 0) {
        return false;
    }
    return paramSetIn->params[0].tag == HKS_TAG_KEY_AUTH_RESULT;
}
} // namespace

namespace HuksNapiItem {
constexpr int HUKS_NAPI_GET_KEY_PROPERTIES_MIN_ARGS = 2;
constexpr int HUKS_NAPI_GET_KEY_PROPERTIES_MAX_ARGS = 3;

constexpr int HKS_DEFAULT_OUTPARAMSET_SIZE = 2048;

GetKeyPropertiesAsyncContext CreateGetKeyPropertiesAsyncContext()
{
    GetKeyPropertiesAsyncContext context =
        static_cast<GetKeyPropertiesAsyncContext>(HksMalloc(sizeof(GetKeyPropertiesAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(GetKeyPropertiesAsyncContextT), 0, sizeof(GetKeyPropertiesAsyncContextT));
    }
    return context;
}

void DeleteGetKeyPropertiesAsyncContext(napi_env env, GetKeyPropertiesAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }
    DeleteCommonAsyncContext(env, context->asyncWork, context->callback, context->keyAlias, context->paramSetIn);
    if (context->paramSetOut != nullptr) {
        HksFreeParamSet(&context->paramSetOut);
    }
    HKS_FREE(context);
    context = nullptr;
}

static napi_value GetKeyPropertiesParseParams(
    napi_env env, napi_callback_info info, GetKeyPropertiesAsyncContext context)
{
    size_t argc = HUKS_NAPI_GET_KEY_PROPERTIES_MAX_ARGS;
    napi_value argv[HUKS_NAPI_GET_KEY_PROPERTIES_MAX_ARGS] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc < HUKS_NAPI_GET_KEY_PROPERTIES_MIN_ARGS) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "no enough params input");
        HKS_LOG_E("no enough params");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseKeyAliasAndHksParamSet(env, argv, index, context->keyAlias, context->paramSetIn);
    if (result == nullptr) {
        HKS_LOG_E("getKeyProperties parse params failed");
        return nullptr;
    }

    index++;
    if (index < argc) {
        context->callback = GetCallback(env, argv[index]);
    }

    return GetInt32(env, 0);
}

napi_value GetKeyPropertiesAsyncWork(napi_env env, GetKeyPropertiesAsyncContext &context)
{
    napi_value promise = nullptr;
    if (context->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &promise));
    }
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getKeyPropertiesAsyncWork", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            HKS_IF_NULL_LOGE_RETURN_VOID(data, "the received data is nullptr.")
            GetKeyPropertiesAsyncContext napiContext = static_cast<GetKeyPropertiesAsyncContext>(data);
            if (IsPrivacySearchMatch(napiContext->keyAlias, napiContext->paramSetIn)) {
                void *handle = GetCczNapiHandle();
                if (handle == nullptr) {
                    napiContext->result = HUKS_ERR_CODE_FEATURE_NOT_SUPPORTED;
                    return;
                }
                GetKeyParamSetExtFunc func = (GetKeyParamSetExtFunc)dlsym(handle, PRIVACY_SEARCH_FUNC_NAME);
                if (func == nullptr) {
                    HKS_LOG_E("dlsym %" LOG_PUBLIC "s failed, %" LOG_PUBLIC "s!", PRIVACY_SEARCH_FUNC_NAME, dlerror());
                    napiContext->result = HUKS_ERR_CODE_FEATURE_NOT_SUPPORTED;
                    return;
                }
                napiContext->result = func(napiContext->keyAlias, napiContext->paramSetIn, &napiContext->paramSetOut);
                return;
            }
            napiContext->paramSetOut = static_cast<struct HksParamSet *>(HksMalloc(HKS_DEFAULT_OUTPARAMSET_SIZE));
            if (napiContext->paramSetOut != nullptr) {
                napiContext->paramSetOut->paramSetSize = HKS_DEFAULT_OUTPARAMSET_SIZE;
                napiContext->paramSetOut->paramsCnt = 0;
            }
            napiContext->result = HksGetKeyParamSet(napiContext->keyAlias,
                napiContext->paramSetIn, napiContext->paramSetOut);
        },
        [](napi_env env, napi_status status, void *data) {
            HKS_IF_NULL_LOGE_RETURN_VOID(data, "the received data is nullptr.")
            GetKeyPropertiesAsyncContext napiContext = static_cast<GetKeyPropertiesAsyncContext>(data);
            HksSuccessReturnResult resultData;
            SuccessReturnResultInit(resultData);
            resultData.paramSet = napiContext->paramSetOut;
            HksReturnNapiResult(env, napiContext->callback, napiContext->deferred, napiContext->result, resultData);
            DeleteGetKeyPropertiesAsyncContext(env, napiContext);
        }, static_cast<void *>(context), &context->asyncWork);
    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        DeleteGetKeyPropertiesAsyncContext(env, context);
        HKS_LOG_E("could not queue async work");
        return nullptr;
    }
    if (context->callback == nullptr) {
        return promise;
    } else {
        return GetNull(env);
    }
}

napi_value HuksNapiGetKeyItemProperties(napi_env env, napi_callback_info info)
{
    GetKeyPropertiesAsyncContext context = CreateGetKeyPropertiesAsyncContext();
    if (context == nullptr) {
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    napi_value result = GetKeyPropertiesParseParams(env, info, context);
    if (result == nullptr) {
        HKS_LOG_E("could not parse params");
        DeleteGetKeyPropertiesAsyncContext(env, context);
        return nullptr;
    }

    result = GetKeyPropertiesAsyncWork(env, context);
    if (result == nullptr) {
        HKS_LOG_E("could not start async work");
        DeleteGetKeyPropertiesAsyncContext(env, context);
        return nullptr;
    }
    return result;
}
}  // namespace HuksNapiItem
