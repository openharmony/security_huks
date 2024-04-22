/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "huks_napi_attest_key_item_as_user.h"
#include "huks_napi_attest_key_item.h"
#include "huks_napi_common_item.h"

#include "securec.h"

#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"

namespace HuksNapiItem {
constexpr int HUKS_NAPI_ATTEST_KEY_AS_USER_ARGS_COUNT = 3;
static napi_value AttestKeyAsUserParseParams(napi_env env, napi_callback_info info, AttestKeyAsyncContext context)
{
    size_t argc = HUKS_NAPI_ATTEST_KEY_AS_USER_ARGS_COUNT;
    napi_value argv[HUKS_NAPI_ATTEST_KEY_AS_USER_ARGS_COUNT] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc != HUKS_NAPI_ATTEST_KEY_AS_USER_ARGS_COUNT) {
        HksNapiThrowInvalidParamCount(env);
        HKS_LOG_E("no enough params");
        return nullptr;
    }

    int userId = 0;
    size_t index = 0;
    napi_value result = GetUserIdValue(env, argv[index], userId);
    if (result == nullptr) {
        HksNapiThrowGetUserIdFail(env);
        HKS_LOG_E("AttestKeyAsUserParseParams could not get user id value");
        return nullptr;
    }
    index++;
    result = ParseKeyAlias(env, argv[index], context->keyAlias);
    if (result == nullptr) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get key alias");
        HKS_LOG_E("could not get alias");
        return nullptr;
    }

    index++;
    napi_value property = GetPropertyFromOptions(env, argv[index], HKS_OPTIONS_PROPERTY_PROPERTIES);
    if (property == nullptr) {
        HKS_LOG_E("attestKey get property failed");
        return nullptr;
    }
    result = ParseHksParamSetAndAddParam(env, property, context->paramSet,
        {{ .tag = HKS_TAG_ATTESTATION_BASE64, .boolParam = true },
        {.tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = userId}});
    if (result == nullptr) {
        HKS_LOG_E("could not get paramset");
        return nullptr;
    }

    return GetInt32(env, 0);
}

napi_value HuksNapiAttestKeyItemAsUser(napi_env env, napi_callback_info info, bool isAnon)
{
    AttestKeyAsyncContext context = CreateAttestKeyAsyncContext(isAnon);
    if (context == nullptr) {
        HksNapiThrowInsufficientMemory(env);
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    napi_value result = AttestKeyAsUserParseParams(env, info, context);
    if (result == nullptr) {
        HKS_LOG_E("could not parse params");
        DeleteAttestKeyAsyncContext(env, context);
        return nullptr;
    }
    result = AttestKeyAsyncWork(env, context);
    if (result == nullptr) {
        HKS_LOG_E("could not start async work");
        DeleteAttestKeyAsyncContext(env, context);
        return nullptr;
    }
    return result;
}

napi_value HuksNapiAttestKeyItemAsUser(napi_env env, napi_callback_info info)
{
    return HuksNapiAttestKeyItemAsUser(env, info, false);
}

napi_value HuksNapiAnonAttestKeyItemAsUser(napi_env env, napi_callback_info info)
{
    return HuksNapiAttestKeyItemAsUser(env, info, true);
}
}  // namespace HuksNapiItem