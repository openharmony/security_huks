/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <array>
#include <iostream>
#include <cstdint>
#include <string>
#include <vector>

#include "securec.h"
#include <ani.h>

#include "huks_ani_common.h"
#include "hks_api.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_enum.h"
#include "hks_log.h"
#include "hks_errcode_adapter.h"

using namespace HuksAni;
static const char *HUKS_GLOBAL_NAME_SPACE = "L@ohos/security/huks;";
constexpr uint32_t HKS_MAX_TOKEN_SIZE = 2048;
constexpr uint32_t OUTPURT_DATA_SIZE = 1024 * 64;

static ani_object generateKeyItemSync([[maybe_unused]] ani_env *env,
    ani_string keyAlias, ani_object options)
{
    ani_object aniReturnObject{};
    struct HksResult resultInfo{0, nullptr, nullptr};
    int32_t ret{ HKS_SUCCESS };
    CommonContext context;
    do {
        ret = HksAniParseParams<CommonContext>(env, keyAlias, options, &context);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGenerateKey HksAniParseParams failed! ret = %" LOG_PUBLIC "d", ret)

        ret = HksGenerateKey(&context.keyAlias, context.paramSetIn, context.paramSetOut);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGenerateKey failed! ret = %" LOG_PUBLIC "d", ret)
    } while (0);
    if (ret != HKS_SUCCESS) {
        resultInfo = HksConvertErrCode(ret);
        HKS_LOG_E("HksGetKeyAlias failed. ret = %" LOG_PUBLIC "d", ret);
    }
    ret = HksCreateAniResult(resultInfo, env, aniReturnObject);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksCreateAniResult failed. ret = %" LOG_PUBLIC "d", ret);
        return {};
    }
    return aniReturnObject;
}

static ani_object deleteKeyItemSync([[maybe_unused]] ani_env *env,
    ani_string keyAlias, ani_object options)
{
    ani_object aniReturnObject{};
    struct HksResult resultInfo{0, nullptr, nullptr};
    int32_t ret{ HKS_SUCCESS };
    CommonContext context;
    do {
        ret = HksAniParseParams<CommonContext>(env, keyAlias, options, &context);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksDeleteKey HksAniParseParams failed! ret = %" LOG_PUBLIC "d", ret)

        ret = HksDeleteKey(&context.keyAlias, context.paramSetIn);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksDeleteKey failed! ret = %" LOG_PUBLIC "d", ret)
    } while (0);
    if (ret != HKS_SUCCESS) {
        resultInfo = HksConvertErrCode(ret);
        HKS_LOG_E("HksDeleteKey failed. ret = %" LOG_PUBLIC "d", ret);
    }
    ret = HksCreateAniResult(resultInfo, env, aniReturnObject);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksCreateAniResult failed. ret = %" LOG_PUBLIC "d", ret);
        return {};
    }
    return aniReturnObject;
}

static ani_object importKeyItemSync([[maybe_unused]] ani_env *env,
    ani_string keyAlias, ani_object options)
{
    ani_object aniReturnObject{};
    struct HksResult resultInfo{0, nullptr, nullptr};
    int32_t ret{ HKS_SUCCESS };
    KeyContext context;
    do {
        ret = HksAniParseParams<KeyContext>(env, keyAlias, options, &context);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksImportKey HksAniParseParams failed! ret = %" LOG_PUBLIC "d", ret)

        ret = HksImportKey(&context.keyAlias, context.paramSetIn, &context.key);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksImportKey failed! ret = %" LOG_PUBLIC "d", ret)
    } while (0);
    if (ret != HKS_SUCCESS) {
        resultInfo = HksConvertErrCode(ret);
        HKS_LOG_E("HksImportKey failed. ret = %" LOG_PUBLIC "d", ret);
    }
    ret = HksCreateAniResult(resultInfo, env, aniReturnObject);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksCreateAniResult failed. ret = %" LOG_PUBLIC "d", ret);
        return {};
    }
    return aniReturnObject;
}

static ani_object importWrappedKeyItemSync([[maybe_unused]] ani_env *env,
    ani_string keyAlias, ani_string wrappingKeyAlias, ani_object options)
{
    ani_object aniReturnObject{};
    struct HksResult resultInfo{0, nullptr, nullptr};
    int32_t ret{ HKS_SUCCESS };
    ImportWrappedKeyContext context;
    do {
        ret = HksAniImportWrappedKeyParseParams(env, keyAlias, wrappingKeyAlias, options, &context);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksImportWrappedKey failed! ret = %" LOG_PUBLIC "d", ret)

        ret = HksImportWrappedKey(&context.keyAlias, &context.wrappingKeyAlias,
            context.paramSetIn, &context.key);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksImportWrappedKey failed! ret = %" LOG_PUBLIC "d", ret)
    } while (0);
    if (ret != HKS_SUCCESS) {
        resultInfo = HksConvertErrCode(ret);
        HKS_LOG_E("HksImportWrappedKey failed. ret = %" LOG_PUBLIC "d", ret);
    }
    ret = HksCreateAniResult(resultInfo, env, aniReturnObject);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksCreateAniResult failed. ret = %" LOG_PUBLIC "d", ret);
        return {};
    }
    return aniReturnObject;
}

static int32_t PrepareExportKeyContextBuffer(KeyContext &context)
{
    context.key.data = static_cast<uint8_t *>(HksMalloc(MAX_KEY_SIZE));
    if (context.key.data == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    context.key.size = MAX_KEY_SIZE;
    return HKS_SUCCESS;
}

static ani_object exportKeyItemSync([[maybe_unused]] ani_env *env,
    ani_string keyAlias, ani_object options)
{
    ani_object aniReturnObject{};
    struct HksResult resultInfo{0, nullptr, nullptr};
    int32_t ret{ HKS_SUCCESS };
    KeyContext context;
    std::vector<uint8_t> outVec;
    ani_object bufferOut = nullptr;
    do {
        ret = HksAniParseParams<CommonContext>(env, keyAlias, options, &context);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksAniParseParams failed! ret = %" LOG_PUBLIC "d", ret)

        ret = PrepareExportKeyContextBuffer(context);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "PrePareExportKeyContextBuffer failed! ret = %" LOG_PUBLIC "d", ret)

        ret = HksExportPublicKey(&context.keyAlias, context.paramSetIn, &context.key);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksExportPublicKey failed! ret = %" LOG_PUBLIC "d", ret)

        outVec.resize(context.key.size);
        outVec.reserve(context.key.size);
        if (memcpy_s(outVec.data(), context.key.size, context.key.data, context.key.size) != EOK) {
            HKS_LOG_E("export key, but copy mem to vector for creating ani object failed!");
            ret = HKS_ERROR_BUFFER_TOO_SMALL;
            break;
        }
        bool aniRet = AniUtils::CreateUint8Array(env, outVec, bufferOut);
        if (!aniRet) {
            HKS_LOG_E("export key get the keyOut ok, but creat ani object failed!");
            ret = HKS_ERROR_BUFFER_TOO_SMALL;
            break;
        }
    } while (0);
    if (ret != HKS_SUCCESS) {
        resultInfo = HksConvertErrCode(ret);
        HKS_LOG_E("HksExportPublicKey failed. ret = %" LOG_PUBLIC "d", ret);
    }
    ret = HksCreateAniResult(resultInfo, env, aniReturnObject, bufferOut);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksCreateAniResult failed. ret = %" LOG_PUBLIC "d", ret);
        return {};
    }
    return aniReturnObject;
}

static ani_object isKeyItemExistSync([[maybe_unused]] ani_env *env,
    ani_string keyAlias, ani_object options)
{
    ani_object aniReturnObject{};
    struct HksResult resultInfo{0, nullptr, nullptr};
    int32_t ret{ HKS_SUCCESS };
    CommonContext context;
    do {
        ret = HksAniParseParams<CommonContext>(env, keyAlias, options, &context);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksAniParseParams failed! ret = %" LOG_PUBLIC "d", ret)

        ret = HksKeyExist(&context.keyAlias, context.paramSetIn);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksKeyExist failed! ret = %" LOG_PUBLIC "d", ret)
    } while (0);
    resultInfo.errorCode = ret;
    if (ret != HKS_SUCCESS  && ret != HKS_ERROR_NOT_EXIST) {
        resultInfo = HksConvertErrCode(ret);
        HKS_LOG_E("HksKeyExist failed. ret = %" LOG_PUBLIC "d", ret);
    }
    ret = HksIsKeyItemExistCreateAniResult(resultInfo, env, aniReturnObject);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksIsKeyItemExistCreateAniResult failed. ret = %" LOG_PUBLIC "d", ret);
        return {};
    }
    return aniReturnObject;
}

static int32_t InitOutParams(SessionContext &context)
{
    context.handle.data = static_cast<uint8_t *>(HksMalloc(HKS_MAX_TOKEN_SIZE));
    if (context.handle.data == nullptr) {
        HKS_LOG_E("malloc handle data failed");
        return HKS_ERROR_MALLOC_FAIL;
    }
    context.handle.size = HKS_MAX_TOKEN_SIZE;

    context.token.data = static_cast<uint8_t *>(HksMalloc(HKS_MAX_TOKEN_SIZE));
    if (context.token.data == nullptr) {
        HKS_LOG_E("malloc token data failed");
        return HKS_ERROR_MALLOC_FAIL;
    }
    context.token.size = HKS_MAX_TOKEN_SIZE;
    return HKS_SUCCESS;
}

static ani_object initSessionSync([[maybe_unused]] ani_env *env,
    ani_string keyAlias, ani_object options)
{
    ani_object aniReturnObject{};
    struct HksResult resultInfo{0, nullptr, nullptr};
    int32_t ret{ HKS_SUCCESS };
    SessionContext context;
    do {
        ret = HksAniParseParams<CommonContext>(env, keyAlias, options, &context);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksAniParseParams failed! ret = %" LOG_PUBLIC "d", ret)

        ret = InitOutParams(context);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "InitOutParams failed! ret = %" LOG_PUBLIC "d", ret)

        ret = HksInit(&context.keyAlias, context.paramSetIn, &context.handle, &context.token);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksInit failed! ret = %" LOG_PUBLIC "d", ret)
    } while (0);
    if (ret != HKS_SUCCESS) {
        resultInfo = HksConvertErrCode(ret);
        HKS_LOG_E("HksInit failed. ret = %" LOG_PUBLIC "d", ret);
    }
    ret = HksInitSessionCreateAniResult(resultInfo, env, context, aniReturnObject);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksInitSessionCreateAniResult failed. ret = %" LOG_PUBLIC "d", ret);
        return {};
    }
    return aniReturnObject;
}

static ani_object updateFinishSessionSync([[maybe_unused]] ani_env *env,
    ani_long handle, ani_object options, ani_boolean isUpdate)
{
    ani_object aniReturnObject{};
    struct HksResult resultInfo{0, nullptr, nullptr};
    int32_t ret{ HKS_SUCCESS };
    std::vector<uint8_t> outVec;
    ani_object bufferOut = nullptr;
    SessionContext context;
    do {
        ret = HksAniParseParams(env, handle, options, &context);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksAniParseParams failed! ret = %" LOG_PUBLIC "d", ret)

        context.outData.size = context.inData.size + OUTPURT_DATA_SIZE;
        context.outData.data = static_cast<uint8_t *>(HksMalloc(context.outData.size));
        if (context.outData.data == nullptr) {
            HKS_LOG_E("malloc memory failed");
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }
        if (static_cast<bool>(isUpdate) == true) {
            ret = HksUpdate(&context.handle, context.paramSetIn, &context.inData, &context.outData);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "update session failed. ret = %" LOG_PUBLIC "d", ret)
        } else {
            ret = HksFinish(&context.handle, context.paramSetIn, &context.inData, &context.outData);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "finish session failed. ret = %" LOG_PUBLIC "d", ret)
        }

        outVec.resize(context.outData.size);
        if (memcpy_s(outVec.data(), context.outData.size, context.outData.data, context.outData.size) != EOK) {
            HKS_LOG_E("updat key, but copy mem to vector for creating ani object failed!");
            ret = HKS_ERROR_BUFFER_TOO_SMALL;
            break;
        }
        if (!AniUtils::CreateUint8Array(env, outVec, bufferOut)) {
            HKS_LOG_E("export key get the keyOut ok, but creat ani object failed!");
            ret = HKS_ERROR_BUFFER_TOO_SMALL;
            break;
        }
    } while (0);
    if (ret != HKS_SUCCESS) {
        resultInfo = HksConvertErrCode(ret);
        HKS_LOG_E("updateFinishSessionSync failed. ret = %" LOG_PUBLIC "d", ret);
    }
    ret = HksCreateAniResult(resultInfo, env, aniReturnObject, bufferOut);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksCreateAniResult failed. ret = %" LOG_PUBLIC "d", ret);
        return {};
    }
    return aniReturnObject;
}

static ani_object abortSessionSync([[maybe_unused]] ani_env *env,
    ani_long handle, ani_object options)
{
    ani_object aniReturnObject{};
    struct HksResult resultInfo{0, nullptr, nullptr};
    int32_t ret{ HKS_SUCCESS };
    SessionContext context;
    do {
        ret = HksAniParseParams(env, handle, options, &context);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksAniParseParams failed! ret = %" LOG_PUBLIC "d", ret)

        ret = HksAbort(&context.handle, context.paramSetIn);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "abort session failed. ret = %" LOG_PUBLIC "d", ret)
    } while (0);
    if (ret != HKS_SUCCESS) {
        resultInfo = HksConvertErrCode(ret);
        HKS_LOG_E("HksGetKeyAlias failed. ret = %" LOG_PUBLIC "d", ret);
    }
    ret = HksCreateAniResult(resultInfo, env, aniReturnObject);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksCreateAniResult failed. ret = %" LOG_PUBLIC "d", ret);
        return {};
    }
    return aniReturnObject;
}

constexpr int32_t INVALID_ANI_VERSION = 9;
constexpr int32_t ANI_CLASS_NOT_FOUND = 2;
constexpr int32_t ANI_BIND_METHOD_FAILED = 3;

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    if (vm == nullptr || result == nullptr) {
        HKS_LOG_E("vm or result is null ptr!!");
        return (ani_status)INVALID_ANI_VERSION;
    }
    ani_env *env{};
    if (vm->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        HKS_LOG_E("Unsupported ANI_VERSION_1");
        return (ani_status)INVALID_ANI_VERSION;
    }
    ani_module globalModule{};
    if (env->FindModule(HUKS_GLOBAL_NAME_SPACE, &globalModule) != ANI_OK) {
        HKS_LOG_E("Not found '%" LOG_PUBLIC "s", HUKS_GLOBAL_NAME_SPACE);
        return (ani_status)ANI_CLASS_NOT_FOUND;
    }

    std::array methods = {
        ani_native_function {"generateKeyItemSync", nullptr, reinterpret_cast<void *>(generateKeyItemSync)},
        ani_native_function {"deleteKeyItemSync", nullptr, reinterpret_cast<void *>(deleteKeyItemSync)},
        ani_native_function {"importKeyItemSync", nullptr, reinterpret_cast<void *>(importKeyItemSync)},
        ani_native_function {"importWrappedKeyItemSync", nullptr, reinterpret_cast<void *>(importWrappedKeyItemSync)},
        ani_native_function {"exportKeyItemSync", nullptr, reinterpret_cast<void *>(exportKeyItemSync)},
        ani_native_function {"isKeyItemExistSync", nullptr, reinterpret_cast<void *>(isKeyItemExistSync)},
        ani_native_function {"initSessionSync", nullptr, reinterpret_cast<void *>(initSessionSync)},
        ani_native_function {"updateFinishSessionSync", nullptr, reinterpret_cast<void *>(updateFinishSessionSync)},
        ani_native_function {"abortSessionSync", nullptr, reinterpret_cast<void *>(abortSessionSync)},
    };

    if (env->Module_BindNativeFunctions(globalModule, methods.data(), methods.size()) != ANI_OK) {
        HKS_LOG_E("Cannot bind native methods to '%" LOG_PUBLIC "s", HUKS_GLOBAL_NAME_SPACE);
        return (ani_status)ANI_BIND_METHOD_FAILED;
    };

    *result = ANI_VERSION_1;
    return ANI_OK;
}