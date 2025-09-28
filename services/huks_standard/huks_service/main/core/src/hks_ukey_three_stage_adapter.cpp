#include "hks_ukey_three_stage_adapter.h"
#include "hks_cpp_paramset.h"
#include "securec.h"
#include <string>
#include <vector>
#include "hks_template.h"

int32_t HksCheckIsUkeyOperation(const struct HksParamSet *paramSet)
{
    CppParamSet paramSetCpp(paramSet);
    auto abilityName = paramSetCpp.GetParam<HKS_TAG_KEY_CLASS>();
    if(abilityName.first == HKS_SUCCESS && abilityName.second == HKS_KEY_CLASS_EXTENSION) {
        HKS_LOG_I("HksCheckIsUkeyOperation: is ukey operation");
        return HKS_SUCCESS;
    }
    return HKS_ERROR_INVALID_ARGUMENT;
}

int32_t HksServiceOnUkeyInitSession(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *handle)
{
    return HKS_SUCCESS;
}

int32_t HksServiceOnUkeyUpdateSession(const struct HksProcessInfo *processInfo, const struct HksBlob *handle,
    const struct HksParamSet *paramSet, const struct HksBlob *inData, struct HksBlob *outData)
{
    return HKS_SUCCESS;
}

int32_t HksServiceOnUkeyFinishSession(const struct HksProcessInfo *processInfo, const struct HksBlob *handle,
    const struct HksParamSet *paramSet, const struct HksBlob *inData, struct HksBlob *outData)
{
    return HKS_SUCCESS;
}