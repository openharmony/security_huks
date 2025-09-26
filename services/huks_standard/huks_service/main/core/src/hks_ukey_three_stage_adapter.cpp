#include "hks_ukey_three_stage_adapter.h"
#include "securec.h"
#include <string>
#include <vector>

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