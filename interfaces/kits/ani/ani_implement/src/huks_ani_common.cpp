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
#include "huks_ani_common.h"

#include <array>
#include <cerrno>
#include <cstddef>
#include <iostream>
#include <memory>
#include <ostream>
#include <cstdbool>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include <ani.h>

#include "securec.h"
#include "hks_common_check.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_enum.h"
#include "hks_log.h"
#include "hks_param.h"
#include "hks_errcode_adapter.h"

bool AniUtils::GetStirng([[maybe_unused]] ani_env *&env, const ani_string &strObject, std::string &nativeStr)
{
    ani_boolean isUndefined;
    env->Reference_IsUndefined(strObject, &isUndefined);
    if (isUndefined) {
        HKS_LOG_E("Call With Optional String NOT Pass Value ");
        return false;
    }
    ani_size strSize = 0;
    env->String_GetUTF8Size(strObject, &strSize);
    std::string buffer(strSize + 1, '\0');
    ani_size bytesWritten = 0;
    env->String_GetUTF8(strObject, buffer.data(), strSize + 1, &bytesWritten);

    if (bytesWritten <= strSize) {
        buffer[bytesWritten] = '\0';
    } else {
        HKS_LOG_E("String_GetUTF8 wrote beyond buffer size");
        buffer[bytesWritten] = '\0';
    }
    nativeStr = buffer;
    return true;
}

bool AniUtils::GetInt32Field(ani_env *&env, const ani_object &object, std::string fieldName, int32_t &value)
{
    ani_ref ref;
    if (env->Object_GetFieldByName_Ref(object, fieldName.data(), &ref) != ANI_OK) {
        HKS_LOG_E("Object_GetFieldByName_Ref int");
        return false;
    }
    ani_boolean isUndefined;
    if (env->Reference_IsUndefined(ref, &isUndefined) != ANI_OK) {
        HKS_LOG_E("Reference_IsUndefined isUndefined Failed");
        return false;
    }
    if (isUndefined) {
        return false;
    }
    if (env->Object_CallMethodByName_Int(static_cast<ani_object>(ref), "intValue", nullptr, &value) != ANI_OK) {
        HKS_LOG_E("Object_CallMethodByName_Int int Failed");
        return false;
    }
    return true;
}


bool AniUtils::GetInt32FromUnionObj(ani_env *&env, const ani_object &unionObj, int32_t &value)
{
    ani_class intClass;
    if (env->FindClass("Lstd/core/Int;", &intClass) != ANI_OK) {
        HKS_LOG_E("Not found Boolean");
        return false;
    }
    ani_boolean isInt;
    if (env->Object_InstanceOf(unionObj, intClass, &isInt) != ANI_OK) {
        HKS_LOG_E("Reference_IsUndefined isNumber Failed");
        return false;
    }
    if (!isInt) {
        HKS_LOG_E("the class is not int type! can not use CallMethodByName_Int");
        return false;
    }
    if (env->Object_CallMethodByName_Int(unionObj, "intValue", nullptr, &value) != ANI_OK) {
        HKS_LOG_E("Object_CallMethodByName_Int failed");
        return false;
    }
    return true;
}

bool AniUtils::GetUint32FromUnionObj(ani_env *&env, const ani_object &unionObj, uint32_t &value)
{
    int32_t rawValue = 0;
    bool ret = GetInt32FromUnionObj(env, unionObj, rawValue);
    if (!ret) {
        HKS_LOG_E("GetUint32FromUnionObj failed");
        return false;
    }
    value = static_cast<uint32_t>(rawValue);
    return true;
}

bool AniUtils::GetUint64FromUnionObj(ani_env *&env, const ani_object &unionObj, uint64_t &value)
{
    ani_class bigIntCls;
    const char *className = "Lescompat/BigInt;";
    if (env->FindClass(className, &bigIntCls) != ANI_OK) {
        HKS_LOG_E("Not found %" LOG_PUBLIC "s", className);
        return false;
    }
    ani_method getLongMethod;
    if (env->Class_FindMethod(bigIntCls, "getLong", ":J", &getLongMethod) != ANI_OK) {
        HKS_LOG_E("Class_GetMethod Failed %" LOG_PUBLIC "s", className);
        return false;
    }

    ani_long longNum;
    if (env->Object_CallMethod_Long(unionObj, getLongMethod, &longNum) != ANI_OK) {
        HKS_LOG_E("Object_CallMethod_Long getLongMethod Failed ");
        return false;
    }
    value = static_cast<uint64_t>(longNum);
    return true;
}

bool AniUtils::GetBooleanFromUnionObj(ani_env *&env, const ani_object &unionObj, bool &value)
{
    ani_class booleanClass;
    if (env->FindClass("Lstd/core/Boolean;", &booleanClass) != ANI_OK) {
        HKS_LOG_E("Not found Boolean");
        return false;
    }
    ani_boolean isBoolean;
    if (env->Object_InstanceOf(unionObj, booleanClass, &isBoolean) != ANI_OK) {
        HKS_LOG_E("Object_InstanceOf boolean failed!");
        return false;
    }
    if (isBoolean) {
        value = static_cast<bool>(unionObj);
        return true;
    }
    return false;
}

bool AniUtils::GetEnumRealValue(ani_env *&env, ani_enum_item &enumObj, uint32_t &realValue)
{
    ani_int enumValue;
    if (env->EnumItem_GetValue_Int(enumObj, &enumValue) != ANI_OK) {
        HKS_LOG_E("EnumItem_GetValue_Int FAILD");
        return false;
    }
    realValue = static_cast<uint32_t>(enumValue);
    return true;
}

bool AniUtils::CheckRefisDefined(ani_env *&env, const ani_ref &ref)
{
    ani_boolean isUndefined{ true };
    if (env->Reference_IsUndefined(ref, &isUndefined) != ANI_OK) {
        HKS_LOG_E("Reference_IsUndefined Failed");
        return false;
    }
    if (isUndefined) {
        HKS_LOG_E("optionField is Undefined Now");
        return false;
    }
    return true;
}

bool AniUtils::GetUint8Array(ani_env *env, ani_object array, std::vector<uint8_t> &arrayOut)
{
    ani_ref buffer;
    if (env->Object_GetFieldByName_Ref(array, "buffer", &buffer) != ANI_OK) {
        HKS_LOG_E("Failed: env->Object_GetFieldByName_Ref buffer");
        return false;
    }
    void* data = nullptr;
    size_t length = 0;
    if (env->ArrayBuffer_GetInfo(static_cast<ani_arraybuffer>(buffer), &data, &length) != ANI_OK) {
        HKS_LOG_E("Failed: env->ArrayBuffer_GetInfo");
        return false;
    }
    for (uint32_t i = 0; i < length; i++) {
        arrayOut.emplace_back(static_cast<unsigned>(static_cast<uint8_t*>(data)[i]));
    }
    return true;
}

void AniUtils::PrintUint8Array(std::vector<uint8_t> &arrayIn)
{
    std::cout << "Elements of buffer size = " << arrayIn.size() << std::endl;
    std::cout << "Elements of buffer = [";
    for (uint32_t i = 0; i < arrayIn.size(); i++) {
        std::cout << (std::to_string(arrayIn[i]) + ", ");
    }
    std::cout << "]" << std::endl;
}

bool AniUtils::CreateUint8Array(ani_env *env, std::vector<uint8_t> &arrayIn, ani_object &arrayOut)
{
    ani_class arrayClass;
    ani_status retCode = env->FindClass("Lescompat/Uint8Array;", &arrayClass);
    if (retCode != ANI_OK) {
        HKS_LOG_E("Failed: env->FindClass()");
        return false;
    }
    ani_method arrayCtor;
    retCode = env->Class_FindMethod(arrayClass, "<ctor>", "I:V", &arrayCtor);
    if (retCode != ANI_OK) {
        HKS_LOG_E("Failed: env->Class_FindMethod()");
        return false;
    }
    retCode = env->Object_New(arrayClass, arrayCtor, &arrayOut, arrayIn.size());
    if (retCode != ANI_OK) {
        HKS_LOG_E("Failed: env->Object_New(). Uint8Array");
        return false;
    }
    ani_ref buffer;
    retCode = env->Object_GetFieldByName_Ref(arrayOut, "buffer", &buffer);
    void *bufData = nullptr;
    size_t bufLength = 0;
    retCode = env->ArrayBuffer_GetInfo(static_cast<ani_arraybuffer>(buffer), &bufData, &bufLength);
    if (retCode != ANI_OK) {
        HKS_LOG_E("Failed: env->ArrayBuffer_GetInfo()");
        return false;
    }
    if (memcpy_s(bufData, bufLength, arrayIn.data(), arrayIn.size()) != EOK) {
        HKS_LOG_E("Failed: memcpy_s");
        return false;
    }
    return true;
}

bool AniUtils::CreatIntObj(ani_env *env, int32_t paramValue, ani_object &objOut)
{
    ani_class itemCls {};
    ani_method ctor {};
    if (env->FindClass("Lstd/core/Int;", &itemCls) != ANI_OK) {
        HKS_LOG_E("FindClass Failed: Not found Lstd/core/Int;");
        return false;
    }
    if (env->Class_FindMethod(itemCls, "<ctor>", nullptr, &ctor) != ANI_OK)
    {
        HKS_LOG_E("Class_FindMethod <ctor> Failed: Not found Lstd/core/Int;");
        return false;
    }
    if (env->Object_New(itemCls, ctor, &objOut, paramValue) != ANI_OK) {
        HKS_LOG_E("Create Object Failed' Int obj");
        return false;
    }
    return true;
}

namespace HuksAni {
static std::string g_huksResultClassName = "L@ohos/security/huks/HuksResultInner;";
static std::string g_ParamInnerClassName = "L@ohos/security/huks/HuksParamInner;";
static std::string g_huksParamClassName = "LHuksParam;";
static std::string g_huksNameSpace = "L@ohos/security/huks/huks;";

void FreeHksBlobAndFresh(HksBlob &blob, const bool isNeedFresh)
{
    if (blob.data != nullptr) {
        if (isNeedFresh && blob.size != 0) {
            (void)memset_s(blob.data, blob.size, 0, blob.size);
        }
        HKS_FREE(blob.data);
        blob.data = nullptr;
    }
    blob.size = 0;
}

static int32_t HksCreateAniResultCommon(const int32_t result, ani_env *&env, ani_object &resultObjOut,
    const char *errMsg = nullptr, ani_object oubBuffer = nullptr)
{
    ani_class cls;
    if (env->FindClass(g_huksResultClassName.data(), &cls) != ANI_OK) {
        HKS_LOG_E("FindClass Failed: Not found '%" LOG_PUBLIC "s", g_huksResultClassName.data());
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    ani_method ctor;
    if (env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor) != ANI_OK) {
        HKS_LOG_E("Class_FindMethod Failed: <ctor> '%" LOG_PUBLIC "s", g_huksResultClassName.data());
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (env->Object_New(cls, ctor, &resultObjOut) != ANI_OK) {
        HKS_LOG_E("Create Object Failed' '%" LOG_PUBLIC "s", g_huksResultClassName.data());
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (env->Object_SetFieldByName_Int(resultObjOut, "result", ani_int(result)) != ANI_OK) {
        HKS_LOG_E("Object_SetFieldByName_Int Failed result");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (errMsg != nullptr) {
        ani_string result_string;
        env->String_NewUTF8(errMsg, strlen(errMsg), &result_string);
        auto status = env->Object_SetFieldByName_Ref(resultObjOut, "error", result_string);
        if (status != ANI_OK) {
            HKS_LOG_E("Object_SetFieldByName_Ref Failed error");
            return HKS_ERROR_INVALID_ARGUMENT;
        }
    }

    if (oubBuffer != nullptr) {
        auto status = env->Object_SetFieldByName_Ref(resultObjOut, "outData", oubBuffer);
        if (status != ANI_OK) {
            HKS_LOG_E("Object_SetFieldByName_Ref Failed outData");
            return HKS_ERROR_INVALID_ARGUMENT;
        }
    }
    return HKS_SUCCESS;
}

int32_t HksCreateAniResult(const HksResult &resultInfo, ani_env *&env, ani_object &resultObjOut, ani_object outBuffer)
{
    int32_t ret{ HKS_SUCCESS };
    HKS_IF_NULL_LOGE_RETURN(env, HKS_ERROR_NULL_POINTER, "HksCreateAniResult, but ani env is null!")
    if (resultInfo.errorCode != HKS_SUCCESS) {
        ret = HksCreateAniResultCommon(resultInfo.errorCode, env, resultObjOut, resultInfo.errorMsg, outBuffer);
    } else {
        ret = HksCreateAniResultCommon(resultInfo.errorCode, env, resultObjOut, nullptr, outBuffer);
    }
    return ret;
}

int32_t HksIsKeyItemExistCreateAniResult(const HksResult &resultInfo, ani_env *&env, ani_object &resultObjOut)
{
    int32_t ret{ HKS_SUCCESS };
    HKS_IF_NULL_LOGE_RETURN(env, HKS_ERROR_NULL_POINTER, "HksIsKeyItemExistCreateAniResult, but ani env is null!")
    if (resultInfo.errorCode != HKS_SUCCESS && resultInfo.errorCode != HKS_ERROR_NOT_EXIST) {
        ret = HksCreateAniResultCommon(resultInfo.errorCode, env, resultObjOut, resultInfo.errorMsg, nullptr);
    } else {
        ret = HksCreateAniResultCommon(resultInfo.errorCode, env, resultObjOut, nullptr, nullptr);
    }
    return ret;
}

int32_t HksInitSessionCreateAniResult(const HksResult &resultInfo, ani_env *&env, const SessionContext &context,
    ani_object &resultObjOut)
{
    int32_t ret{ HKS_SUCCESS };
    HKS_IF_NULL_LOGE_RETURN(env, HKS_ERROR_NULL_POINTER, "HksInitSessionCreateAniResult, but ani env is null!")
    if (resultInfo.errorCode != HKS_SUCCESS) {
        ret = HksCreateAniResultCommon(resultInfo.errorCode, env, resultObjOut, resultInfo.errorMsg, nullptr);
        return ret;
    } else {
        ret = HksCreateAniResultCommon(HKS_SUCCESS, env, resultObjOut, nullptr, nullptr);
        if (context.handle.size != sizeof(uint64_t)) {
            HKS_LOG_E("handle blob is invalid. size no equal to 4 Bytes!");
            return HKS_ERROR_INVALID_ARGUMENT;
        }
        int64_t handle = static_cast<int64_t>(*reinterpret_cast<uint64_t *>(context.handle.data));
        if (context.handle.size != 0 && context.handle.data != nullptr) {
            if (env->Object_SetFieldByName_Long(resultObjOut, "handle", ani_long(handle)) != ANI_OK) {
                HKS_LOG_E("Object_SetFieldByName_Long Fail handle");
                return HKS_ERROR_INVALID_ARGUMENT;
            }
        }
        if (context.token.size != 0 && context.token.data != nullptr) {
            ani_object oubBuffer;
            std::vector<uint8_t> outVec;
            ret = CheckBlob(&context.token);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "context token blob invalid!")
            outVec.resize(context.token.size);
            if (memcpy_s(outVec.data(), context.token.size, context.token.data, context.token.size) != EOK) {
                HKS_LOG_E("init session, copy challenge to vector for creating ani object failed!");
                return HKS_ERROR_BUFFER_TOO_SMALL;
            }
            bool aniRet = AniUtils::CreateUint8Array(env, outVec, oubBuffer);
            if (!aniRet) {
                HKS_LOG_E("export key get the keyOut ok, but creat ani object failed!");
                return HKS_ERROR_BUFFER_TOO_SMALL;
            }
            if (env->Object_SetFieldByName_Ref(resultObjOut, "challenge", ani_ref(oubBuffer)) != ANI_OK) {
                HKS_LOG_E("Object_SetFieldByName_Ref Fail' challenge");
                return HKS_ERROR_INVALID_ARGUMENT;
            }
        }
    }
    return ret;
}

int32_t HksGetKeyAliasFromAni(ani_env *&env, const ani_string &strObject, HksBlob &keyAliasOut)
{
    std::string keyAliasIn = "";
    bool aniGetStringRet = AniUtils::GetStirng(env, strObject, keyAliasIn);
    HKS_IF_NOT_TRUE_LOGE_RETURN(aniGetStringRet, HKS_ERROR_INVALID_ARGUMENT, "AniUtils GetStirng failed!");
    if (keyAliasIn.empty()) {
        HKS_LOG_E("input key alias maybe null");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    int32_t ret = HKS_SUCCESS;
    keyAliasOut.size = keyAliasIn.size();
    keyAliasOut.data = static_cast<uint8_t *>(HksMalloc(keyAliasOut.size));
    if (keyAliasOut.data == nullptr) {
        HKS_LOG_E("HksMalloc for keyAlias failed!");
        return HKS_ERROR_MALLOC_FAIL;
    }
    if (memcpy_s(keyAliasOut.data, keyAliasOut.size, keyAliasIn.data(), keyAliasOut.size) != EOK) {
        HKS_LOG_E("HksGetKeyAlias failed. memcpy from keyAliasIn failed");
        HKS_FREE_BLOB(keyAliasOut);
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    HKS_LOG_I("keyAlias %" LOG_PUBLIC "s", keyAliasIn.c_str());
    return ret;
}

int32_t HksAniGetParamTag(ani_env *&env, const ani_object &object, uint32_t &value)
{
    ani_ref enumRef;
    ani_status st = env->Object_GetFieldByName_Ref(object, "tag", &enumRef);
    HKS_IF_NOT_TRUE_LOGE_RETURN(st == EOK, HKS_ERROR_INVALID_ARGUMENT, "Object_GetFieldByName_Ref tag failed %" LOG_PUBLIC "u", st);

    ani_enum_item enumItem = static_cast<ani_enum_item>(enumRef);
    bool getRealValueRet = AniUtils::GetEnumRealValue(env, enumItem, value);
    HKS_IF_NOT_TRUE_LOGE_RETURN(getRealValueRet, HKS_ERROR_INVALID_ARGUMENT, "AniUtils GetEnumRealValue failed!");
    return HKS_ERROR_INVALID_ARGUMENT;
}

static int32_t GetHuksBlobFromUnionObj(ani_env *&env, const ani_object &unionObj, HksBlob &blobOut)
{
    int32_t ret{ HKS_SUCCESS };
    std::vector<uint8_t> buffer {};
    bool aniRet = AniUtils::GetUint8Array(env, unionObj, buffer);
    if (!aniRet) {
        HKS_LOG_E("GetUint8Array fromUnionObj failed!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    blobOut.size = buffer.size();
    blobOut.data = static_cast<uint8_t *>(HksMalloc(blobOut.size));
    if (blobOut.data == nullptr) {
        HKS_LOG_E("malloc mem for huks param buffer failed!");
        return HKS_ERROR_MALLOC_FAIL;
    }
    if (memcpy_s(blobOut.data, blobOut.size, buffer.data(), blobOut.size) != EOK) {
        HKS_LOG_E("GetHuksBlobFromUnionObj memcy to blobOut failed!");
        HKS_FREE_BLOB(blobOut);
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    return ret;
}

int32_t HksAniHuksParamConvert(ani_env *&env, const ani_object &huksParamObj, HksParam &param)
{
    bool getFieldRet = HksAniGetParamTag(env, huksParamObj, param.tag);
    HKS_IF_NOT_TRUE_LOGE_RETURN(getFieldRet, HKS_ERROR_INVALID_ARGUMENT, "HksAniGetParamTag failed!");

    ani_ref valueUnionRef;
    ani_status st = env->Object_GetFieldByName_Ref(huksParamObj, "value", &valueUnionRef);
    HKS_IF_NOT_TRUE_LOGE_RETURN(st == EOK, HKS_ERROR_INVALID_ARGUMENT, "Object_GetFieldByName_Ref value failed %" LOG_PUBLIC "u", st);

    ani_object unionObj = reinterpret_cast<ani_object>(valueUnionRef);
    int32_t ret = HKS_SUCCESS;
    switch (GetTagType(static_cast<enum HksTag>(param.tag))) {
        case HKS_TAG_TYPE_BOOL:
            if (!AniUtils::GetBooleanFromUnionObj(env, unionObj, param.boolParam)) {
                ret = HKS_ERROR_INVALID_ARGUMENT;
            }
            break;
        case HKS_TAG_TYPE_UINT:
            if (!AniUtils::GetUint32FromUnionObj(env, unionObj, param.uint32Param)) {
                ret = HKS_ERROR_INVALID_ARGUMENT;
            }
            break;
        case HKS_TAG_TYPE_INT:
            if (!AniUtils::GetInt32FromUnionObj(env, unionObj, param.int32Param)) {
                ret = HKS_ERROR_INVALID_ARGUMENT;
            }
            break;
        case HKS_TAG_TYPE_ULONG:
            if (!AniUtils::GetUint64FromUnionObj(env, unionObj, param.uint64Param)) {
                ret = HKS_ERROR_INVALID_ARGUMENT;
            }
            break;
        case HKS_TAG_TYPE_BYTES:
            ret = GetHuksBlobFromUnionObj(env, unionObj, param.blob);
            HKS_IF_NOT_SUCC_LOGE(ret, "GetHuksBlobFromUnionObj failed. ret =%" LOG_PUBLIC "d", ret)
            break;
        default:
            ret = HKS_ERROR_INVALID_ARGUMENT;
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Undefin param enum type. tag value 0x%" LOG_PUBLIC "x", param.tag)
    }
    return ret;
}

static void FreeParsedParams(std::vector<HksParam> &params)
{
    for (HksParam &p : params) {
        if (GetTagType(static_cast<HksTag>(p.tag)) == HKS_TAG_TYPE_BYTES) {
            HKS_FREE_BLOB(p.blob);
        }
    }
}

int32_t HksGetParamSetFromAni(ani_env *&env, const ani_object &optionsObj, struct HksParamSet *&paramSetOut)
{
    ani_ref propertiesRef;
    ani_status st = env->Object_GetFieldByName_Ref(optionsObj, "properties", &propertiesRef);
    if (st != ANI_OK) {
        HKS_LOG_E("Object_GetFieldByName_Ref properties failed %" LOG_PUBLIC "u", st);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    bool aniRet = AniUtils::CheckRefisDefined(env, propertiesRef);
    HKS_IF_NOT_TRUE_LOGE_RETURN(aniRet, HKS_ERROR_INVALID_ARGUMENT, "AniUtils CheckRefisDefined failed!");

    ani_object propertiesArray = reinterpret_cast<ani_object>(propertiesRef);
    ani_double length;
    if (env->Object_GetPropertyByName_Double(propertiesArray, "length", &length) != ANI_OK) {
        HKS_LOG_E("Object_GetPropertyByName_Double length Failed");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    std::vector<HksParam> paramArray {};
    HksParamSet *paramSetNew = nullptr;
    int32_t ret = HKS_SUCCESS;
    do {
        for (int32_t i = 0; i < int32_t(length); i++) {
            ani_ref paramEntryRef;
            if (env->Object_CallMethodByName_Ref(propertiesArray, "$_get",
                "I:Lstd/core/Object;", &paramEntryRef, (ani_int)i) != ANI_OK) {
                HKS_LOG_E("Object_CallMethodByName_Ref get ani object Failed");
                ret = HKS_ERROR_INVALID_ARGUMENT;
                break;
            }
            ani_object huksParamObj = reinterpret_cast<ani_object>(paramEntryRef);
            HksParam tempParam;
            ret = HksAniHuksParamConvert(env, huksParamObj, tempParam);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksAniHuksParamConvert failed. ret = %" LOG_PUBLIC "d", ret)
            paramArray.emplace_back(tempParam);
        }
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get param from union failed. ret = %" LOG_PUBLIC "d", ret)

        ret = HksInitParamSet(&paramSetNew);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksInitParamSet failed. ret = %" LOG_PUBLIC "d", ret)

        ret = HksAddParams(paramSetNew, paramArray.data(), paramArray.size());
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksAddParams addParams fail. ret = %" LOG_PUBLIC "d", ret)

        ret = HksBuildParamSet(&paramSetNew);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksBuildParamSet fail. ret = %" LOG_PUBLIC "d", ret)
    } while (0);
    FreeParsedParams(paramArray);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&paramSetNew);
        return ret;
    }
    paramSetOut = paramSetNew;
    return ret;
}

int32_t HksGetBufferFromAni(ani_env *&env, const ani_object &arrayObj, HksBlob &blobBuffer)
{
    std::vector<uint8_t> keyBuffer {};
    bool getKeyRet = AniUtils::GetUint8Array(env, arrayObj, keyBuffer);
    HKS_IF_NOT_TRUE_LOGE_RETURN(getKeyRet, HKS_ERROR_INVALID_ARGUMENT, "AniUtils GetUint8Array failed!");
    blobBuffer.size = keyBuffer.size();
    blobBuffer.data = static_cast<uint8_t *>(HksMalloc(blobBuffer.size));
    HKS_IF_NULL_LOGE_RETURN(blobBuffer.data, HKS_ERROR_MALLOC_FAIL, "malloc mem for key buffer failed!")
    if (memcpy_s(blobBuffer.data, blobBuffer.size, keyBuffer.data(), blobBuffer.size) != EOK) {
        HKS_FREE_BLOB(blobBuffer);
        HKS_LOG_E("memcpy vector key buffer to blob data failed!");
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    return HKS_SUCCESS;
}

int32_t HksOptionGetInData(ani_env *&env, ani_object options, HksBlob &blobOut)
{
    ani_ref inDataRef;
    ani_status st = env->Object_GetFieldByName_Ref(options, "inData", &inDataRef);
    if (st != ANI_OK) {
        HKS_LOG_E("Object_GetFieldByName_Ref inData Fail %" LOG_PUBLIC "u", st);
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (AniUtils::CheckRefisDefined(env, inDataRef)) {
        ani_object inDataBuffer = reinterpret_cast<ani_object>(inDataRef);
        int32_t ret = HksGetBufferFromAni(env, inDataBuffer, blobOut);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_BAD_STATE, "ANIGetBuffer failed! ret = %" LOG_PUBLIC "d", ret);
    } else {
        HKS_LOG_I("AniUtils CheckRefisDefined. option.inData is undefined!");
        blobOut.size = 0;
        blobOut.data = nullptr;
    }
    return HKS_SUCCESS;
}

template<>
int32_t HksAniParseParams(ani_env *env, ani_string keyAlias, ani_object &options, KeyContext *&&contextPtr)
{
    HKS_IF_NULL_LOGE_RETURN(contextPtr, HKS_ERROR_NULL_POINTER, "ParseParams, but context is null")
    int32_t ret = HksAniParseParams<CommonContext>(env, keyAlias, options, static_cast<CommonContext *>(contextPtr));
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("import key parase common param failed");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    ret = HksOptionGetInData(env, options, contextPtr->key);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("KeyContext HksOptionGetInDatam failed");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return ret;
}

int32_t HksAniImportWrappedKeyParseParams(ani_env *env, ani_string &keyAlias, ani_string &wrappingKeyAlias,
    ani_object options, ImportWrappedKeyContext *&&contextPtr)
{
    HKS_IF_NULL_LOGE_RETURN(contextPtr, HKS_ERROR_NULL_POINTER, "ParseParams, but context is null")
    int32_t ret = HksAniParseParams<KeyContext>(env, keyAlias, options, static_cast<KeyContext *>(contextPtr));
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("import key parase common param failed");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    ret = HksGetKeyAliasFromAni(env, wrappingKeyAlias, contextPtr->wrappingKeyAlias);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksGetKeyAliasFromAni failed");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return ret;
}

int32_t HksAniParseParams(ani_env *env, ani_long &handle, ani_object &options, SessionContext *&&contextPtr)
{
    HKS_IF_NULL_LOGE_RETURN(contextPtr, HKS_ERROR_NULL_POINTER, "ParseParams, but context is null")
    int32_t ret = HksAniParseParams<CommonContext>(env, nullptr, options, static_cast<CommonContext *>(contextPtr));
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("SessionContext parase common param failed");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    ret = HksOptionGetInData(env, options, contextPtr->inData);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("SessionContext HksOptionGetInData failed");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    uint64_t huksHandle = static_cast<uint64_t>(handle);
    HKS_LOG_I("huksHandle = %" LOG_PUBLIC "llu", huksHandle);
    contextPtr->handle.size = sizeof(uint64_t);
    contextPtr->handle.data = static_cast<uint8_t *>(HksMalloc(contextPtr->handle.size));
    if (contextPtr->handle.data == nullptr) {
        HKS_FREE_BLOB(contextPtr->handle);
        HKS_LOG_E("HksMalloc mem for handle blob failed");
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(contextPtr->handle.data, contextPtr->handle.size, &huksHandle, contextPtr->handle.size);
    return ret;
}

CommonContext::~CommonContext()
{
    FreeHksBlobAndFresh(this->keyAlias);
    HksFreeParamSet(&(this->paramSetIn));
    if (this->paramSetOut != nullptr) {
        HksFreeParamSet(&(this->paramSetOut));
    }
}

KeyContext::~KeyContext()
{
    FreeHksBlobAndFresh(this->key, true);
}

ImportWrappedKeyContext::~ImportWrappedKeyContext()
{
    FreeHksBlobAndFresh(this->wrappingKeyAlias);
}

SessionContext::~SessionContext()
{
    FreeHksBlobAndFresh(this->token, true);
    FreeHksBlobAndFresh(this->handle);
    FreeHksBlobAndFresh(this->inData);
    FreeHksBlobAndFresh(this->outData, true);
}

static bool SetParamInnerValueObj(ani_env *env, const HksParam &paramIn, ani_object &outObj)
{
    ani_int etsIntValue = 0;
    switch (paramIn.tag & HKS_TAG_TYPE_MASK) {
        case HKS_TAG_TYPE_INT:
            etsIntValue = static_cast<ani_int>(paramIn.int32Param);
        case HKS_TAG_TYPE_UINT:
            etsIntValue = static_cast<ani_int>(paramIn.uint32Param);
            if (env->Object_SetFieldByName_Int(outObj, "valueInt", ani_int(etsIntValue)) != ANI_OK) {
                HKS_LOG_E("Object_SetFieldByName_Int Failed uint32Param->valueInt");
                return false;
            }
            break;
        case HKS_TAG_TYPE_ULONG:
            if (env->Object_SetFieldByName_Long(outObj, "valueLong",
                ani_long(paramIn.uint64Param)) != ANI_OK) {
                HKS_LOG_E("Object_SetFieldByName_Long Failed uint64Param->valueLong");
                return false;
            }
            break;
        case HKS_TAG_TYPE_BOOL:
            if (env->Object_SetFieldByName_Boolean(outObj, "valueBool",
                ani_boolean(paramIn.boolParam)) != ANI_OK) {
                HKS_LOG_E("Object_SetFieldByName_Boolean Failed boolParam->valueBool");
                return false;
            }
            break;
        case HKS_TAG_TYPE_BYTES:
        {
            std::vector<uint8_t> u8Vector(paramIn.blob.size);
            ani_object u8Array {};
            (void)memcpy_s(u8Vector.data(), paramIn.blob.size, paramIn.blob.data, paramIn.blob.size);
            if (!AniUtils::CreateUint8Array(env, u8Vector, u8Array)) {
                return false;
            }
            if (env->Object_SetFieldByName_Ref(outObj, "valueBuffer", u8Array) != ANI_OK) {
                HKS_LOG_E("Object_CallMethodByName_Void Failed blob->valueBuffer");
                return false;
            }
            break;
        }
        default:
            HKS_LOG_E("SetParamInnerValueObj Failed' paramIn.tag invalid");
            return false;
    }
    return true;
}

int32_t CreateHuksParamInnerArray(ani_env *env, const std::vector<HksParam> &params, ani_array_ref &arrayOut)
{
    if (env == nullptr) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    ani_class itemCls = nullptr;
    if (env->FindClass(g_ParamInnerClassName.data(), &itemCls) != ANI_OK) {
        HKS_LOG_E("FindClass Failed: Not found '%" LOG_PUBLIC "s", g_ParamInnerClassName.data());
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (env->Array_New_Ref(itemCls, params.size(), nullptr, &arrayOut) != ANI_OK) {
        HKS_LOG_E("Array_New_Ref. Fail. className = %" LOG_PUBLIC "s. size = %" LOG_PUBLIC "d",
            g_huksParamClassName.data(), params.size());
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    for (uint32_t i = 0; i < params.size(); i++) {
        ani_method ctor {};
        if (env->Class_FindMethod(itemCls, "<ctor>", nullptr, &ctor) != ANI_OK) {
            HKS_LOG_E("Class_FindMethod Failed: <ctor> '%" LOG_PUBLIC "s", g_huksParamClassName.data());
            return HKS_ERROR_INVALID_ARGUMENT;
        }
        ani_object item {};
        if (env->Object_New(itemCls, ctor, &item) != ANI_OK) {
            HKS_LOG_E("Create Object Failed' '%" LOG_PUBLIC "s", g_huksParamClassName.data());
            return HKS_ERROR_INVALID_ARGUMENT;
        }

        if (env->Object_SetFieldByName_Int(item, "tag", ani_int(params[i].tag)) != ANI_OK) {
            HKS_LOG_E("Object_CallMethodByName_Void Failed. HuksParamInner tag");
            return HKS_ERROR_INVALID_ARGUMENT;
        }
        if (!SetParamInnerValueObj(env, params[i], item)) {
            HKS_LOG_E("SetParamInnerValueObj Failed. HuksParamInner value...");
            return HKS_ERROR_INVALID_ARGUMENT;
        }
        if (env->Array_Set_Ref(arrayOut, i, ani_ref(item)) != ANI_OK) {
            return HKS_ERROR_INVALID_ARGUMENT;
        }
    }
    return HKS_SUCCESS;
}

}  // namespace
