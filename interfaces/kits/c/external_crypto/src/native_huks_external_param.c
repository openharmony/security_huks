/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "native_huks_external_param.h"

#include "hks_param.h"
#include "hks_errcode_adapter.h"

static struct OH_Huks_Result ConvertExtParamResult(int32_t ret)
{
    struct HksResult result = HksConvertErrCode(ret);
    return *((struct OH_Huks_Result *)(&result));
}

struct OH_Huks_Result OH_Huks_InitExtParamSet(struct OH_Huks_ExternalCryptoParamSet **paramSet)
{
    int32_t result = HksInitParamSet((struct HksParamSet **) paramSet);
    return ConvertExtParamResult(result);
}

struct OH_Huks_Result OH_Huks_AddExtParams(struct OH_Huks_ExternalCryptoParamSet *paramSet,
    const struct OH_Huks_Param *params, uint32_t paramCnt)
{
    int32_t result = HksAddParams((struct HksParamSet *) paramSet,
        (const struct HksParam *) params, paramCnt);
    return ConvertExtParamResult(result);
}

struct OH_Huks_Result OH_Huks_BuildExtParamSet(struct OH_Huks_ExternalCryptoParamSet **paramSet)
{
    int32_t result = HksBuildParamSet((struct HksParamSet **) paramSet);
    return ConvertExtParamResult(result);
}

void OH_Huks_FreeExtParamSet(struct OH_Huks_ExternalCryptoParamSet **paramSet)
{
    HksFreeParamSet((struct HksParamSet **) paramSet);
}

struct OH_Huks_Result OH_Huks_CopyExtParamSet(const struct OH_Huks_ExternalCryptoParamSet *fromParamSet,
    uint32_t fromParamSetSize, struct OH_Huks_ExternalCryptoParamSet **paramSet)
{
    int32_t result = HksGetParamSet((const struct HksParamSet *) fromParamSet,
        fromParamSetSize, (struct HksParamSet **) paramSet);
    return ConvertExtParamResult(result);
}

struct OH_Huks_Result OH_Huks_GetExtParam(const struct OH_Huks_ExternalCryptoParamSet *paramSet, uint32_t tag,
    struct OH_Huks_Param **param)
{
    int32_t result = HksGetParam((const struct HksParamSet *) paramSet, tag, (struct HksParam **) param);
    return ConvertExtParamResult(result);
}

struct OH_Huks_Result OH_Huks_FreshExtParamSet(struct OH_Huks_ExternalCryptoParamSet *paramSet, bool isCopy)
{
    int32_t result = HksFreshParamSet((struct HksParamSet *) paramSet, isCopy);
    return ConvertExtParamResult(result);
}

struct OH_Huks_Result OH_Huks_IsExtParamSetTagValid(const struct OH_Huks_ExternalCryptoParamSet *paramSet)
{
    int32_t result = HksCheckParamSetTag((const struct HksParamSet *) paramSet);
    return ConvertExtParamResult(result);
}

struct OH_Huks_Result OH_Huks_IsExtParamSetValid(const struct OH_Huks_ExternalCryptoParamSet *paramSet, uint32_t size)
{
    int32_t result = HksCheckParamSet((const struct HksParamSet *) paramSet, size);
    return ConvertExtParamResult(result);
}

struct OH_Huks_Result OH_Huks_CheckExtParamMatch(const struct OH_Huks_Param *baseParam, const struct OH_Huks_Param *param)
{
    int32_t result = HksCheckParamMatch((const struct HksParam *) baseParam, (const struct HksParam *) param);
    return ConvertExtParamResult(result);
}

void OH_Huks_FreeExtCertSet(struct OH_Huks_ExtCertInfoSet *certSet)
{
    HksFreeExtCertSet((struct HksExtCertInfoSet *) certSet);
}
