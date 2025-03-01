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

using namespace HuksAni;
static const char *HUKS_NAME_SPACE = "LaniTest/Calc;";

static ani_int Sum([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_int a, ani_int b)
{
    return a + b;
}

static ani_object generateKeyItemSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_string keyAlias)
{
    ani_object aniReturnObject{};
    std::string keyAliasStr = "";
    int32_t ret{ HKS_SUCCESS };
    HksBlob keyAliasBlob = {};
    do {
        ret = HksGetKeyAliasFromAni(env, keyAlias, keyAliasBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetKeyAlias failed! ret = %" LOG_PUBLIC "d", ret)


    } while(0);
    if (ret != HKS_SUCCESS) {
        HKS_FREE_BLOB(keyAliasBlob);
        HKS_LOG_E("HksGetKeyAlias failed. ret = %" LOG_PUBLIC "d", ret);
    }
    HKS_FREE_BLOB(keyAliasBlob);
    std::cout << "generateKeyItemSync  444  ret = " << ret << std::endl;

    (void)HksCreateAniResult(ret, "", env, aniReturnObject);
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
    };

    if (ANI_OK != env->Class_BindNativeMethods(cls, methods.data(), methods.size())) {
        std::cerr << "Cannot bind native methods to '" << HUKS_NAME_SPACE << "'" << std::endl;
        return (ani_status)3;
    };

    *result = ANI_VERSION_1;
    return ANI_OK;
}