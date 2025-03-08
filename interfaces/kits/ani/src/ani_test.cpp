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
    ImportKeyContext context;
    do {
        ret = HksAniParseParams<ImportKeyContext>(env, keyAlias, options, &context);
        std::cout << "HksAniParseParams  success. keyIn size = " << context.keyIn.size << std::endl;
        
        ret = HksImportKey(&context.keyAlias, context.paramSetIn, &context.keyIn);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksImportKey failed! ret = %" LOG_PUBLIC "d", ret)
        std::cout << "HksImportKey  success" << std::endl;
    } while(0);
    if (ret != HKS_SUCCESS) {
        std::cout << "HksImportKey  ret = " << ret << std::endl;
        HksDeleteContext<ImportKeyContext>(context);
        HKS_LOG_E("HksGetKeyAlias failed. ret = %" LOG_PUBLIC "d", ret);
    }
    HksDeleteContext<ImportKeyContext>(context);
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
        std::cout << "HksAniImportWrappedKeyParseParams  success. keyIn size = " << context.keyIn.size << std::endl;
        
        ret = HksImportWrappedKey(&context.keyAlias, &context.wrappingKeyAlias, context.paramSetIn, &context.keyIn);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksImportWrappedKey failed! ret = %" LOG_PUBLIC "d", ret)
        std::cout << "HksImportWrappedKey  success" << std::endl;
    } while(0);
    if (ret != HKS_SUCCESS) {
        std::cout << "HksImportKey  ret = " << ret << std::endl;
        HksDeleteContext<ImportWrappedKeyContext>(context);
        HKS_LOG_E("HksGetKeyAlias failed. ret = %" LOG_PUBLIC "d", ret);
    }
    HksDeleteContext<ImportWrappedKeyContext>(context);
    (void)HksCreateAniResult(ret, env, aniReturnObject);
    return aniReturnObject;
}

static ani_object exportKeyItemSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_string keyAlias, ani_object options)
{
    ani_object aniReturnObject{};
    int32_t ret{ HKS_SUCCESS };
    std::vector<uint8_t> outBuffer{0x44, 0x22, 0x88};
    ani_object bufferOut;
    bool aniRet = AniUtils::CreateUint8Array(env, outBuffer, bufferOut);
    if (aniRet != true) {
        std::cerr << "CreateUint8Array failed!" <<std::endl;
    }
    (void)HksCreateAniResult(ret, env, aniReturnObject, bufferOut);
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
    };

    if (ANI_OK != env->Class_BindNativeMethods(cls, methods.data(), methods.size())) {
        std::cerr << "Cannot bind native methods to '" << HUKS_NAME_SPACE << "'" << std::endl;
        return (ani_status)3;
    };

    *result = ANI_VERSION_1;
    return ANI_OK;
}