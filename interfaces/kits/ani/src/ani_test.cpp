#include "hks_api.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_enum.h"
#include "hks_log.h"
#include "securec.h"
#include "huks_ani_common.h"

#include <ani.h>
#include <array>
#include <iostream>
#include <string>
#include <vector>

using namespace HuksAni;
static const char *HUKS_NAME_SPACE = "LaniTest/Huks;";

static ani_int Sum([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_int a, ani_int b)
{
    return a + b;
}

static ani_object generateKeyItemSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_string keyAlias, ani_object options)
{
    ani_object aniReturnObject{};
    int32_t ret{ HKS_SUCCESS };
    CommonContext context;
    do {
        ret = HksAniParseParams<CommonContext>(env, keyAlias, options, &context);
        std::cout << "HksAniParseParams  success" << std::endl;
        
        ret = HksGenerateKey(&context.keyAlias, context.paramSetIn, context.paramSetOut);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGenerateKey failed! ret = %" LOG_PUBLIC "d", ret)
        std::cout << "HksGenerateKey  success" << std::endl;
    } while(0);
    if (ret != HKS_SUCCESS) {
        HksDeleteContext<CommonContext>(context);
        HKS_LOG_E("HksGetKeyAlias failed. ret = %" LOG_PUBLIC "d", ret);
    }
    HksDeleteContext<CommonContext>(context);
    (void)HksCreateAniResult(ret, env, aniReturnObject);
    return aniReturnObject;
}

static ani_object deleteKeyItemSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_string keyAlias, ani_object options)
{
    ani_object aniReturnObject{};
    int32_t ret{ HKS_SUCCESS };
    CommonContext context;
    do {
        ret = HksAniParseParams<CommonContext>(env, keyAlias, options, &context);
        std::cout << "HksAniParseParams  success" << std::endl;

        ret = HksDeleteKey(&context.keyAlias, context.paramSetIn);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksDeleteKey failed! ret = %" LOG_PUBLIC "d", ret)
        std::cout << "HksDeleteKey  success" << std::endl;
    } while(0);
    if (ret != HKS_SUCCESS) {
        HksDeleteContext<CommonContext>(context);
        HKS_LOG_E("HksGetKeyAlias failed. ret = %" LOG_PUBLIC "d", ret);
    }
    HksDeleteContext<CommonContext>(context);

    (void)HksCreateAniResult(ret, env, aniReturnObject);
    return aniReturnObject;
}

static ani_object importKeyItemSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_string keyAlias, ani_object options)
{
    ani_object aniReturnObject{};
    int32_t ret{ HKS_SUCCESS };
    KeyContext context;
    do {
        ret = HksAniParseParams<KeyContext>(env, keyAlias, options, &context);
        std::cout << "HksAniParseParams  success. keyIn size = " << context.key.size << std::endl;
        
        ret = HksImportKey(&context.keyAlias, context.paramSetIn, &context.key);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksImportKey failed! ret = %" LOG_PUBLIC "d", ret)
        std::cout << "HksImportKey  success" << std::endl;
    } while(0);
    if (ret != HKS_SUCCESS) {
        std::cout << "HksImportKey  ret = " << ret << std::endl;
        HksDeleteContext<KeyContext>(context);
        HKS_LOG_E("importKeyItemSync failed. ret = %" LOG_PUBLIC "d", ret);
    }
    HksDeleteContext<KeyContext>(context);
    (void)HksCreateAniResult(ret, env, aniReturnObject);
    return aniReturnObject;
}

static ani_object importWrappedKeyItemSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    ani_string keyAlias, ani_string wrappingKeyAlias, ani_object options)
{
    ani_object aniReturnObject{};
    int32_t ret{ HKS_SUCCESS };
    ImportWrappedKeyContext context;
    do {
        ret = HksAniImportWrappedKeyParseParams(env, keyAlias, wrappingKeyAlias, options, &context);
        std::cout << "HksAniImportWrappedKeyParseParams  success. keyIn size = " << context.key.size << std::endl;
        
        ret = HksImportWrappedKey(&context.keyAlias, &context.wrappingKeyAlias,
            context.paramSetIn, &context.key);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksImportWrappedKey failed! ret = %" LOG_PUBLIC "d", ret)
        std::cout << "HksImportWrappedKey  success" << std::endl;
    } while(0);
    if (ret != HKS_SUCCESS) {
        std::cout << "importWrappedKeyItemSync  ret = " << ret << std::endl;
        HksDeleteContext<ImportWrappedKeyContext>(context);
        HKS_LOG_E("HksDeleteContext failed. ret = %" LOG_PUBLIC "d", ret);
    }
    HksDeleteContext<ImportWrappedKeyContext>(context);
    (void)HksCreateAniResult(ret, env, aniReturnObject);
    return aniReturnObject;
}

static ani_object exportKeyItemSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_string keyAlias, ani_object options)
{
    ani_object aniReturnObject{};
    int32_t ret{ HKS_SUCCESS };
    KeyContext context;
    std::vector<uint8_t> outVec;
    ani_object bufferOut = nullptr;
    do {
        ret = HksAniParseParams<CommonContext>(env, keyAlias, options, &context);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksAniParseParams failed! ret = %" LOG_PUBLIC "d", ret)

        ret = HksExportPublicKey(&context.keyAlias, context.paramSetIn, &context.key);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksExportPublicKey failed! ret = %" LOG_PUBLIC "d", ret)
        
        outVec.reserve(context.key.size);
        if (memcpy_s(outVec.data(), context.key.size, context.key.data, context.key.size) != EOK) {
            HKS_LOG_E("export key, but copy mem to vector for creating ani object failed!");
            ret = HKS_ERROR_BUFFER_TOO_SMALL;
            break;
        }
        bool aniRet = AniUtils::CreateUint8Array(env, outVec, bufferOut);
        if (aniRet != true) {
            std::cerr << "CreateUint8Array failed!" <<std::endl;
            HKS_LOG_E("export key get the keyOut ok, but creat ani object failed!");
            ret = HKS_ERROR_BUFFER_TOO_SMALL;
            break;
        }
        std::cout << "HksExportPublicKey  success" << std::endl;
    } while(0);
    if (ret != HKS_SUCCESS) {
        std::cout << "HksExportPublicKey  ret = " << ret << std::endl;
        HksDeleteContext<KeyContext>(context);
        HKS_LOG_E("HksDeleteContext failed. ret = %" LOG_PUBLIC "d", ret);
    }
    (void)HksCreateAniResult(ret, env, aniReturnObject, bufferOut);
    HksDeleteContext<KeyContext>(context);
    return aniReturnObject;
}

static ani_object isKeyItemExistSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_string keyAlias, ani_object options)
{
    ani_object aniReturnObject{};
    int32_t ret{ HKS_SUCCESS };
    CommonContext context;
    do {
        ret = HksAniParseParams<CommonContext>(env, keyAlias, options, &context);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksAniParseParams failed! ret = %" LOG_PUBLIC "d", ret)
        std::cout << "HksAniParseParams  success" << std::endl;

        ret = HksKeyExist(&context.keyAlias, context.paramSetIn);
        std::cout << "HksDeleteKey  success" << std::endl;
    } while(0);
    if (ret != HKS_SUCCESS  && ret != HKS_ERROR_NOT_EXIST) {
        HksDeleteContext<CommonContext>(context);
        HKS_LOG_E("HksGetKeyAlias failed. ret = %" LOG_PUBLIC "d", ret);
    }
    HksDeleteContext<CommonContext>(context);
    (void)HksIsKeyItemExistCreateAniResult(ret, env, aniReturnObject);
    return aniReturnObject;
}

static ani_object initSessionSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    ani_string keyAlias, ani_object options)
{
    ani_object aniReturnObject{};
    int32_t ret{ HKS_SUCCESS };
    SessionContext context;
    do {
        ret = HksAniParseParams<CommonContext>(env, keyAlias, options, &context);
        std::cout << "HksAniParseParams  success" << std::endl;

        ret = HksInit(&context.keyAlias, context.paramSetIn, &context.handle, &context.token);
        std::cout << "HksInit Session success" << std::endl;
    } while(0);
    if (ret != HKS_SUCCESS) {
        HksDeleteContext<SessionContext>(context);
        HKS_LOG_E("HksGetKeyAlias failed. ret = %" LOG_PUBLIC "d", ret);
    }
    HksDeleteContext<SessionContext>(context);
    (void)HksInitSessionCreateAniResult(ret, env, context, aniReturnObject);
    return aniReturnObject;
}

static ani_object updateFinishSessionSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    ani_int handle, ani_object options, ani_boolean isUpdate)
{
    ani_object aniReturnObject{};
    int32_t ret{ HKS_SUCCESS };
    std::vector<uint8_t> outVec;
    ani_object bufferOut = nullptr;
    SessionContext context;
    do {
        ret = HksAniParseParams(env, handle, options, &context);
        std::cout << "HksAniParseParams  success" << std::endl;
        if (static_cast<bool>(isUpdate) == true) {
            ret = HksUpdate(&context.handle, context.paramSetIn, &context.inData, &context.outData);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "update session failed. ret = %" LOG_PUBLIC "d", ret)
        } else {
            ret = HksFinish(&context.handle, context.paramSetIn, &context.inData, &context.outData);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "finish session failed. ret = %" LOG_PUBLIC "d", ret)
        }

        outVec.reserve(context.outData.size);
        if (memcpy_s(outVec.data(), context.outData.size, context.outData.data, context.outData.size) != EOK) {
            HKS_LOG_E("updat key, but copy mem to vector for creating ani object failed!");
            ret = HKS_ERROR_BUFFER_TOO_SMALL;
            break;
        }
        bool aniRet = AniUtils::CreateUint8Array(env, outVec, bufferOut);
        if (aniRet != true) {
            std::cerr << "CreateUint8Array failed!" <<std::endl;
            HKS_LOG_E("export key get the keyOut ok, but creat ani object failed!");
            ret = HKS_ERROR_BUFFER_TOO_SMALL;
            break;
        }

        std::cout << "updateFinishSessionync Session success" << std::endl;
    } while(0);
    if (ret != HKS_SUCCESS) {
        HksDeleteContext<SessionContext>(context);
        HKS_LOG_E("HksGetKeyAlias failed. ret = %" LOG_PUBLIC "d", ret);
    }
    HksDeleteContext<SessionContext>(context);
    (void)HksCreateAniResult(ret, env, aniReturnObject, bufferOut);
    return aniReturnObject;
}

static ani_object abortSessionSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    ani_int handle, ani_object options)
{
    ani_object aniReturnObject{};
    int32_t ret{ HKS_SUCCESS };
    SessionContext context;
    do {
        ret = HksAniParseParams(env, handle, options, &context);
        std::cout << "HksAniParseParams  success" << std::endl;
        ret = HksAbort(&context.handle, context.paramSetIn);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "abort session failed. ret = %" LOG_PUBLIC "d", ret)

        std::cout << "HksAbort Session success" << std::endl;
    } while(0);
    if (ret != HKS_SUCCESS) {
        HksDeleteContext<SessionContext>(context);
        HKS_LOG_E("HksGetKeyAlias failed. ret = %" LOG_PUBLIC "d", ret);
    }
    HksDeleteContext<SessionContext>(context);
    (void)HksCreateAniResult(ret, env, aniReturnObject);
    return aniReturnObject;
}

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        std::cerr << "Unsupported ANI_VERSION_1" << std::endl;
        return (ani_status)9;
    }
    ani_class cls;
    if (ANI_OK != env->FindClass(HUKS_NAME_SPACE, &cls)) {
        std::cerr << "Not found '" << HUKS_NAME_SPACE << "'" << std::endl;
        return (ani_status)2;
    }

    std::array methods = {
        ani_native_function {"sum", "II:I", reinterpret_cast<void *>(Sum)},
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

    if (ANI_OK != env->Class_BindNativeMethods(cls, methods.data(), methods.size())) {
        std::cerr << "Cannot bind native methods to '" << HUKS_NAME_SPACE << "'" << std::endl;
        return (ani_status)3;
    };

    *result = ANI_VERSION_1;
    return ANI_OK;
}