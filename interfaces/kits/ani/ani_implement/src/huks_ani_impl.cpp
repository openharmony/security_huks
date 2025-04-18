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
#include <new>
#include <string>
#include <vector>

#include "securec.h"
#include <ani.h>
#include <ani_signature_builder.h>

#include "huks_ani_common.h"
#include "hks_api.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_enum.h"
#include "hks_log.h"
#include "hks_errcode_adapter.h"

using namespace HuksAni;
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

        ret = CheckBlob(&context.key);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "context key blob invalid!")
        outVec.resize(context.key.size);
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
    if (ret != HKS_SUCCESS) {
        resultInfo = HksConvertErrCode(ret);
        HKS_LOG_I("HksKeyExist failed. ret = %" LOG_PUBLIC "d", ret);
    }
    ret = HksCreateAniResult(resultInfo, env, aniReturnObject);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksCreateAniResult failed. ret = %" LOG_PUBLIC "d", ret);
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

static int32_t AddOutData(const HksBlob &huksData, ani_env *env, ani_object &bufferOut)
{
    std::vector<uint8_t> outVec(huksData.size);
    if (memcpy_s(outVec.data(), outVec.size(), huksData.data, huksData.size) != EOK) {
        HKS_LOG_E("updateFinishSessionSync, but copy mem to vector for creating ani object failed!");
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    if (!AniUtils::CreateUint8Array(env, outVec, bufferOut)) {
        HKS_LOG_E("updateFinishSessionSync ok, but creat ani object failed!");
        return HKS_ERROR_BAD_STATE;
    }
    return HKS_SUCCESS;
}

static ani_object updateFinishSessionSync([[maybe_unused]] ani_env *env,
    ani_long handle, ani_object options, ani_boolean isUpdate)
{
    ani_object aniReturnObject{};
    struct HksResult resultInfo{0, nullptr, nullptr};
    int32_t ret{ HKS_SUCCESS };
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
        HKS_LOG_I("context.inData.size = %" LOG_PUBLIC "u", context.inData.size);
        if (static_cast<bool>(isUpdate) == true) {
            ret = HksUpdate(&context.handle, context.paramSetIn, &context.inData, &context.outData);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "update session failed. ret = %" LOG_PUBLIC "d", ret)
        } else {
            ret = HksFinish(&context.handle, context.paramSetIn, &context.inData, &context.outData);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "finish session failed. ret = %" LOG_PUBLIC "d", ret)
        }
        HKS_LOG_I("context.outData.size = %" LOG_PUBLIC "u", context.outData.size);
        if (context.outData.size != 0 && context.outData.data != nullptr) {
            ret = AddOutData(context.outData, env, bufferOut);
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


struct CertArray {
    std::unique_ptr<std::array<uint8_t, HKS_CERT_APP_SIZE>> appCert{};
    std::unique_ptr<std::array<uint8_t, HKS_CERT_DEVICE_SIZE>> devCert{};
    std::unique_ptr<std::array<uint8_t, HKS_CERT_CA_SIZE>> caCert{};
    std::unique_ptr<std::array<uint8_t, HKS_CERT_ROOT_SIZE>> rootCert{};
    std::unique_ptr<std::array<struct HksBlob, HKS_CERT_COUNT>> blob{};
    struct HksCertChain c{};
};

static CertArray ConstructChainInput()
{
    decltype(CertArray::appCert) appCert(new (std::nothrow) std::array<uint8_t, HKS_CERT_APP_SIZE>);
    decltype(CertArray::devCert) devCert(new (std::nothrow) std::array<uint8_t, HKS_CERT_DEVICE_SIZE>);
    decltype(CertArray::caCert) caCert(new (std::nothrow) std::array<uint8_t, HKS_CERT_CA_SIZE>);
    decltype(CertArray::rootCert) rootCert(new (std::nothrow) std::array<uint8_t, HKS_CERT_ROOT_SIZE>);
    decltype(CertArray::blob) blob(new (std::nothrow) std::array<struct HksBlob, HKS_CERT_COUNT> {{
        {.size = HKS_CERT_APP_SIZE, .data = appCert->data()},
        {.size = HKS_CERT_DEVICE_SIZE, .data = devCert->data()},
        {.size = HKS_CERT_CA_SIZE, .data = caCert->data()},
        {.size = HKS_CERT_ROOT_SIZE, .data = rootCert->data()},
    }});
    if (appCert == nullptr || devCert == nullptr || caCert == nullptr || rootCert == nullptr || blob == nullptr) {
        return {};
    }
    CertArray arr{
        .appCert = std::move(appCert),
        .devCert = std::move(devCert),
        .caCert = std::move(caCert),
        .rootCert = std::move(rootCert),
        .blob = std::move(blob),
        .c = { .certs = arr.blob->data(), .certsCount = HKS_CERT_COUNT }};
    return arr;
}

static ani_object ConstructArrayString(ani_env *env, uint32_t sz, struct HksBlob *blobs)
{
    ani_class arrayCls{};
    std::string arrClassName = arkts::ani_signature::Builder::BuildClass({"escompat", "Array"}).Descriptor();
    auto status = env->FindClass(arrClassName.c_str(), &arrayCls);
    HKS_ANI_IF_NOT_SUCC_LOGE_RETURN(status, ani_object{}, "FindClass %" LOG_PUBLIC "s fail %" LOG_PUBLIC "u",
        arrClassName.c_str(), status);

    ani_method arrayCtor{};
    std::string argIntReturnVoid = arkts::ani_signature::SignatureBuilder().AddInt().BuildSignatureDescriptor();
    auto methodCtor = arkts::ani_signature::Builder::BuildConstructorName();
    status = env->Class_FindMethod(arrayCls, methodCtor.c_str(), argIntReturnVoid.c_str(), &arrayCtor);
    HKS_ANI_IF_NOT_SUCC_LOGE_RETURN(status, ani_object{}, "Class_FindMethod %" LOG_PUBLIC "s %" LOG_PUBLIC "s fail %"
        LOG_PUBLIC "u", methodCtor.c_str(), argIntReturnVoid.c_str(), status);

    ani_object arrayObj{};
    status = env->Object_New(arrayCls, arrayCtor, &arrayObj, sz);
    HKS_ANI_IF_NOT_SUCC_LOGE_RETURN(status, ani_object{}, "Object_New Array fail %" LOG_PUBLIC "u", status);

    for (uint32_t i = 0; i < sz; ++i) {
        ani_string aniCert{};
        status = env->String_NewUTF8(reinterpret_cast<char *>(blobs[i].data), blobs[i].size, &aniCert);
        HKS_ANI_IF_NOT_SUCC_LOGE_RETURN(status, ani_object{}, "String_NewUTF8 fail %" LOG_PUBLIC "u", status);

        std::string methodSig = arkts::ani_signature::SignatureBuilder().AddInt().AddClass({"std", "core", "Object"}).
            BuildSignatureDescriptor();
        status = env->Object_CallMethodByName_Void(arrayObj, "$_set", methodSig.c_str(), i, aniCert);
        HKS_ANI_IF_NOT_SUCC_LOGE_RETURN(status, ani_object{}, "Object_CallMethodByName_Void $_set fail %"
            LOG_PUBLIC "u", status);
    }

    return arrayObj;
}

static ani_object InnerAttest(ani_env *env, ani_string keyAlias, ani_object options,
    int32_t (*attestMethod)(const struct HksBlob *, const struct HksParamSet *, struct HksCertChain *))
{
    ani_object aniReturnObject{};
    struct HksResult resultInfo{0, nullptr, nullptr};
    int32_t ret{ HKS_SUCCESS };
    CommonContext context{};
    CertArray certs = ConstructChainInput();
    do {
        if (certs.c.certs == nullptr) {
            ret = HKS_ERROR_INSUFFICIENT_MEMORY;
            break;
        }

        ret = HksAniParseParams<CommonContext>(env, keyAlias, options, &context);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksAniParseParams failed! ret = %" LOG_PUBLIC "d", ret)

        ret = attestMethod(&context.keyAlias, context.paramSetIn, &certs.c);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksAttestKey or HksAnonAttestKey failed! ret = %" LOG_PUBLIC "d", ret)
    } while (false);
    if (ret != HKS_SUCCESS) {
        resultInfo = HksConvertErrCode(ret);
        HKS_LOG_E("HksInit failed. ret = %" LOG_PUBLIC "d", ret);
    }
    ret = HksCreateAniResult(resultInfo, env, aniReturnObject);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksCreateAniResult failed. ret = %" LOG_PUBLIC "d", ret);
        return {};
    }

    ani_object arrayObj = ConstructArrayString(env, certs.c.certsCount, certs.c.certs);
    if (arrayObj == nullptr) {
        HKS_LOG_E("ConstructArrayString fail");
        return {};
    }

    ani_status st = env->Object_SetFieldByName_Ref(aniReturnObject, "certChains", arrayObj);
    if (st != ANI_OK) {
        HKS_LOG_E("Object_SetFieldByName_Ref certChains %" LOG_PUBLIC "u", st);
        return {};
    }

    return aniReturnObject;
}

static ani_object attestKeyItemSync(ani_env *env,
    ani_string keyAlias, ani_object options, ani_boolean isAnonymous)
{
    if (static_cast<bool>(isAnonymous)) {
        return InnerAttest(env, keyAlias, options, HksAnonAttestKey);
    }
    return InnerAttest(env, keyAlias, options, HksAttestKey);
}

static constexpr int32_t aniInvalidVersion = 9;
static constexpr int32_t aniClassNotFound = 2;
static constexpr int32_t aniBindMethodFailed = 3;

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    if (vm == nullptr || result == nullptr) {
        HKS_LOG_E("vm or result is null ptr!!");
        return (ani_status)aniInvalidVersion;
    }
    ani_env *env{};
    if (vm->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        HKS_LOG_E("Unsupported ANI_VERSION_1");
        return (ani_status)aniInvalidVersion;
    }
    ani_module globalModule{};
    std::string globalNameSpace = arkts::ani_signature::Builder::BuildClass({
        "@ohos", "security", "huks"}).Descriptor();
    if (env->FindModule(globalNameSpace.c_str(), &globalModule) != ANI_OK) {
        HKS_LOG_E("Not found %" LOG_PUBLIC "s", globalNameSpace.c_str());
        return (ani_status)aniClassNotFound;
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
        ani_native_function {"attestKeyItemSync", nullptr, reinterpret_cast<void *>(attestKeyItemSync)},
    };

    if (env->Module_BindNativeFunctions(globalModule, methods.data(), methods.size()) != ANI_OK) {
        HKS_LOG_E("Cannot bind native methods to '%" LOG_PUBLIC "s", globalNameSpace.c_str());
        return (ani_status)aniBindMethodFailed;
    };

    *result = ANI_VERSION_1;
    return ANI_OK;
}