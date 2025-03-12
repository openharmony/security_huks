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
#include "hks_common_check.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_enum.h"
#include "hks_log.h"
#include "securec.h"
#include "hks_param.h"
#include "huks_ani_common.h"
#include "hks_errcode_adapter.h"

#include <ani.h>
#include <array>
#include <cerrno>
#include <iostream>
#include <memory>
#include <ostream>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <vector>
namespace HuksAni {
static std::string HUKS_RESULT_CLASS_NAME = "L@ohos/security/huks/HuksResult;";
static std::string HUKS_OPTION_CLASS_NAME = "L@ohos/security/huks/HuksOptionsImpl;";
static std::string HUKS_PARAM_CLASS_NAME = "L@ohos/security/huks/HuksParamImpl;";
static std::string HUKS_TAG_ENUM_NAME = "LHuksTag;";
static std::string HUKS_NAME_SPACE_NAME = "L@ohos/security/huks/huks;";

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

bool AniUtils::GetStirng([[maybe_unused]] ani_env *&env, const ani_string &strObject, std::string &nativeStr)
{
    ani_boolean isUndefined;
    env->Reference_IsUndefined(strObject, &isUndefined);
    if(isUndefined)
    {
        std::cout << "Call With Optional String NOT Pass Value " << std::endl;
        return false;
    }
    ani_size strSize = 0;
    env->String_GetUTF8Size(strObject, &strSize);
    std::vector<char> buffer(strSize + 1); // +1 for null terminator
    char* utf8_buffer = buffer.data();
    ani_size bytesWritten = 0;
    env->String_GetUTF8(strObject, utf8_buffer, strSize + 1, &bytesWritten);
    
    utf8_buffer[bytesWritten] = '\0';
    nativeStr = std::string(utf8_buffer);
    return true;
}

bool AniUtils::GetInt32Field(ani_env *&env, const ani_object &object, std::string fieldName, int32_t &value)
{
    ani_ref ref;
    if (ANI_OK != env->Object_GetFieldByName_Ref(object, fieldName.data(), &ref)){
        std::cerr << "Object_GetFieldByName_Ref " << "int" << std::endl;
        return false;
    }
    ani_boolean isUndefined;
    if(ANI_OK != env->Reference_IsUndefined(ref,&isUndefined)){
        std::cerr << "Object_GetFieldByName_Ref int Failed" << std::endl;
        return false;
    }
    if(isUndefined){
        std::cout << "int is Undefined Now" << std::endl;
        return false;
    }
    if (ANI_OK != env->Object_CallMethodByName_Int(static_cast<ani_object>(ref), "intValue", nullptr, &value)) {
        std::cerr << "Object_CallMethodByName_Int int Failed" << std::endl;
        return false;
    }
    return true;
}


bool AniUtils::GetInt32FromUnionObj(ani_env *&env, const ani_object &unionObj, int32_t &value)
{
    ani_class DoubleClass;
    if (ANI_OK != env->FindClass("Lstd/core/Double;", &DoubleClass)) {
        std::cerr << "Not found '" << "Boolean" << "'" << std::endl;
        return false;
    }
    ani_boolean isNumber;
    env->Object_InstanceOf(unionObj, DoubleClass, &isNumber);
    if(!isNumber){
        std::cerr << "Not isNumber" << std::endl;
        return false;
    }
    if (ANI_OK != env->Object_CallMethodByName_Int(unionObj, "intValue", nullptr, &value)) {
        std::cerr << "Object_CallMethodByName_Int failed" << std::endl;
        return false;
    }
    return true;
}

bool AniUtils::GetUint32FromUnionObj(ani_env *&env, const ani_object &unionObj, uint32_t &value)
{
    int32_t rawValue = 0;
    bool ret = GetInt32FromUnionObj(env, unionObj, rawValue);
    HKS_IF_NOT_TRUE_LOGE_RETURN(ret, ret);
    value = static_cast<uint32_t>(rawValue);
    return true;
}

bool AniUtils::GetUint64FromUnionObj(ani_env *&env, const ani_object &unionObj, uint64_t &value)
{
    ani_class bigIntCls;
    const char * className = "Lescompat/BigInt;";
    if (ANI_OK != env->FindClass(className, &bigIntCls)) {
        std::cerr << "Not found '" << className << "'" << std::endl;
        return false;
    }
    ani_method getLongMethod;
    if (ANI_OK != env->Class_FindMethod(bigIntCls, "getLong", ":J", &getLongMethod)){
        std::cerr << "Class_GetMethod Failed '" << className << "'" << std::endl;
        return false;
    }

    ani_long longnum;
    if (ANI_OK != env->Object_CallMethod_Long(unionObj, getLongMethod, &longnum)){
        std::cerr << "Object_CallMethod_Long '" << "getLongMethod" << "'" << std::endl;
        return false;
    }
    value = static_cast<uint64_t>(longnum);
    return true;
}

bool AniUtils::GetBooleanFromUnionObj(ani_env *&env, const ani_object &unionObj, bool &value)
{
    ani_class booleanClass;
    if (ANI_OK != env->FindClass("Lstd/core/Boolean;", &booleanClass)) {
        std::cerr << "Not found '" << "Boolean" << "'" << std::endl;
    }
    ani_boolean isBoolean;
    env->Object_InstanceOf(unionObj, booleanClass, &isBoolean);
    if(isBoolean){
        value = static_cast<bool>(unionObj);
        return true;
    }
    return false;
}

bool AniUtils::GetClassPropertyGetMethod(ani_env *&env, const std::string &className, const std::string &propertyName,
    const std::string getOrSet, ani_method &methodOut)
{
    ani_class cls;
    if (ANI_OK != env->FindClass(className.data(), &cls)) {
        std::cerr << "Not found '" << className.data() << "'" << std::endl;
        return false;
    }
    std::string getMethodName = getOrSet + propertyName;
    if(ANI_OK != env->Class_FindMethod(cls, getMethodName.data(), nullptr, &methodOut)) {
        std::cerr << "Class_FindMethod Fail'" << getMethodName << "'" << std::endl;
        return false;
    }
    return true;
}

bool AniUtils::GetEnumRealValue(ani_env *&env, ani_enum_item &enumObj, uint32_t &realValue)
{
    ani_int enumValue;
    if(ANI_OK != env->EnumItem_GetValue_Int(enumObj, &enumValue)) {
        std::cerr << "EnumItem_GetValue_Int FAILD" << std::endl;
        return false;
    }
    realValue = static_cast<uint32_t>(enumValue);
    return true;
}

bool AniUtils::CheckRefisDefined(ani_env *&env, const ani_ref &ref) 
{
    ani_boolean isUndefined{ true };
    if(ANI_OK != env->Reference_IsUndefined(ref, &isUndefined)){
        std::cerr << "Reference_IsUndefined Failed" << std::endl;
        return false;
    }
    
    if(isUndefined){
        std::cout << "optionField is Undefined Now" << std::endl;
        return false;
    }
    return true;
}

bool AniUtils::GetUint8Array(ani_env *env, ani_object array, std::vector<uint8_t> &arrayOut)
{
    ani_ref buffer;
    if (auto retCode = env->Object_GetFieldByName_Ref(array, "buffer", &buffer); retCode != ANI_OK) {
        std::cout << "Failed: env->Object_GetFieldByName_Ref()" << std::endl;
        return false;
    }
    void* data;
    uint32_t length;
    if (ANI_OK != env->ArrayBuffer_GetInfo(static_cast<ani_arraybuffer>(buffer), &data, &length)) {
        std::cerr << "Failed: env->ArrayBuffer_GetInfo()" << std::endl;
        return false;
    }
    // std::cout << "Length of buffer = " << length << std::endl;
    // std::cout << "Elements of buffer = [";
    for (size_t i = 0; i < length; i++) {
        // if (i != 0) {
        //     std::cout << ", ";
        // }
        // std::cout << static_cast<unsigned>(static_cast<uint8_t*>(data)[i]);
        arrayOut.emplace_back(static_cast<unsigned>(static_cast<uint8_t*>(data)[i]));
    }
    // std::cout << "]" << std::endl;

    for (const char* propName: {"length", "byteLength", "byteOffset"}) {
        ani_int value;
        std::string fieldName = std::string{propName} + "Int";
        if (env->Object_GetFieldByName_Int(array, fieldName.c_str(), &value) != ANI_OK) {
            std::cout << "Failed: env->Object_GetFieldByName_Int(name='" << fieldName << "')" << std::endl;
            return false;;
        }
        std::cout << "array." << propName << " = " << value << std::endl;
    }
    return true;
}

void AniUtils::PrintUint8Array(std::vector<uint8_t> &arrayIn)
{
    std::cout << "Elements of buffer size = " << arrayIn.size() << std::endl;
    std::cout << "Elements of buffer = [";
    for (uint32_t i = 0; i < arrayIn.size(); i++) {
        std::cout << std::to_string(arrayIn[i]) + ", ";
    }
    std::cout << "]" << std::endl;
}

bool AniUtils::CreateUint8Array(ani_env *env, std::vector<uint8_t> &arrayIn, ani_object &arrayOut)
{
    ani_class arrayClass;
    ani_status retCode = env->FindClass("Lescompat/Uint8Array;", &arrayClass);
    if (retCode != ANI_OK) {
        std::cerr << "Failed: env->FindClass()" << std::endl;
        // todo: exception
        return false;
    }
    ani_method arrayCtor;
    retCode = env->Class_FindMethod(arrayClass, "<ctor>", "I:V", &arrayCtor);
    if (retCode != ANI_OK) {
        std::cerr << "Failed: env->Class_FindMethod()" << std::endl;
        // todo: exception
        return false;
    }
    retCode = env->Object_New(arrayClass, arrayCtor, &arrayOut, arrayIn.size());
    if (retCode != ANI_OK) {
        std::cerr << "Failed: env->Object_New()" << std::endl;
        // todo: exception
        return false;
    }
    ani_ref buffer;
    retCode = env->Object_GetFieldByName_Ref(arrayOut, "buffer", &buffer);
    void *bufData = nullptr;
    uint32_t bufLength = 0;
    retCode = env->ArrayBuffer_GetInfo(static_cast<ani_arraybuffer>(buffer), &bufData, &bufLength);
    if (retCode != ANI_OK) {
        std::cerr << "Failed: env->ArrayBuffer_GetInfo()" << std::endl;
        // todo: exception
        return false;
    }
    if (memcpy_s(bufData, bufLength, arrayIn.data(), arrayIn.size()) != EOK) {
        std::cerr << "Failed: memcpy_s" << std::endl;
        return false;
    }
    return true;
}

static int32_t HksCreateAniResultCommon(const int32_t result, ani_env *&env, ani_object &resultObjOut,
    const char *errMsg = nullptr, ani_object oubBuffer = nullptr)
{
    ani_class cls;
    if (ANI_OK != env->FindClass(HUKS_RESULT_CLASS_NAME.data(), &cls)) {
        std::cerr << "Not found '" << HUKS_RESULT_CLASS_NAME << "'" << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)){
        std::cerr << "get ctor Failed'" << HUKS_RESULT_CLASS_NAME << "'" << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (ANI_OK != env->Object_New(cls, ctor, &resultObjOut)){
        std::cerr << "Create Object Failed'" << HUKS_RESULT_CLASS_NAME << "'" << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if(ANI_OK != env->Object_CallMethodByName_Void(resultObjOut, "<set>result", nullptr, ani_int(result))) {
        std::cerr << "Object_CallMethodByName_Void Fail'" << "<set>result" << "'" << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    
    if (errMsg != nullptr) {
        ani_string result_string;
        env->String_NewUTF8(errMsg, strlen(errMsg), &result_string);
        auto status = env->Object_CallMethodByName_Void(resultObjOut, "<set>error", "Lstd/core/String;:V", result_string);
        if(ANI_OK != status) {
            std::cerr << "Class_FindMethod Fail'" << "<set>error" << "'" << std::endl;
        }
    }

    if (oubBuffer != nullptr) {
        auto status = env->Object_CallMethodByName_Void(resultObjOut, "<set>outData", nullptr, oubBuffer);
        if(ANI_OK != status) {
            std::cerr << "Object_CallMethodByName_Void Fail'" << "<set>outData" << "'" << std::endl;
        }
    }
    return HKS_SUCCESS;
}

int32_t HksCreateAniResult(const int32_t result, ani_env *&env, ani_object &resultObjOut, ani_object oubBuffer)
{
    struct HksResult errInfo {};
    int32_t ret{ HKS_SUCCESS };
    errInfo.errorCode = 0;
    if (result != HKS_SUCCESS) {
        errInfo = HksConvertErrCode(result);
        ret = HksCreateAniResultCommon(errInfo.errorCode, env, resultObjOut, errInfo.errorMsg, oubBuffer);
    } else {
        ret = HksCreateAniResultCommon(HKS_SUCCESS, env, resultObjOut, nullptr, oubBuffer);
    }
    return ret;
}

int32_t HksIsKeyItemExistCreateAniResult(const int32_t result, ani_env *&env, ani_object &resultObjOut)
{
    struct HksResult errInfo {};
    int32_t ret{ HKS_SUCCESS };
    if (result != HKS_SUCCESS && result != HKS_ERROR_NOT_EXIST) {
        errInfo = HksConvertErrCode(result);
        ret = HksCreateAniResultCommon(errInfo.errorCode, env, resultObjOut, errInfo.errorMsg, nullptr);
    } else {
        ret = HksCreateAniResultCommon(result, env, resultObjOut, nullptr, nullptr);
    }
    return ret;
}

int32_t HksInitSessionCreateAniResult(const int32_t result, ani_env *&env, const SessionContext &context, ani_object &resultObjOut)
{
    struct HksResult errInfo {};
    int32_t ret{ HKS_SUCCESS };
    if (result != HKS_SUCCESS) {
        errInfo = HksConvertErrCode(result);
        ret = HksCreateAniResultCommon(errInfo.errorCode, env, resultObjOut, errInfo.errorMsg, nullptr);
        return ret;
    } else {
        ret = HksCreateAniResultCommon(HKS_SUCCESS, env, resultObjOut, nullptr, nullptr);
        std::cerr << "HksCreateAniResultCommon success" << std::endl;
        ani_method setter;
        std::cerr << "handle size = " << context.handle.size << std::endl;
        int64_t handle = static_cast<int64_t>(*(uint64_t *)(context.handle.data));
        std::cerr << "handle data = " << handle << std::endl;
        if (context.handle.size != 0 && context.handle.data != nullptr) {
            // bool getMethodRet = AniUtils::GetClassPropertyGetMethod(env, HUKS_RESULT_CLASS_NAME, "handle",
            //     "<set>", setter);
            // std::cerr << "GetClassPropertyGetMethod success" << std::endl;
            // HKS_IF_NOT_TRUE_LOGE_RETURN(getMethodRet, HKS_ERROR_INVALID_ARGUMENT);

            // if(ANI_OK != env->Object_CallMethod_Void(resultObjOut, setter, ani_int(handle))) {
            //     std::cerr << "Object_CallMethod_Void Fail' " << "<set>handle" << std::endl;
            //     return HKS_ERROR_INVALID_ARGUMENT;
            // }
            if(ANI_OK != env->Object_CallMethodByName_Void(resultObjOut, "<set>handle", nullptr, ani_long(handle))) {
                std::cerr << "Object_CallMethod_Void Fail' " << "<set>handle" << std::endl;
                return HKS_ERROR_INVALID_ARGUMENT;
            }
            std::cerr << "set handle success" << std::endl;
        }
        if (context.token.size != 0 && context.token.data != nullptr)
        {
            ani_object oubBuffer;
            std::vector<uint8_t> outVec;
            outVec.reserve(context.token.size);
            if (memcpy_s(outVec.data(), context.token.size, context.token.data, context.token.size) != EOK) {
                HKS_LOG_E("init session, copy challenge to vector for creating ani object failed!");
                return HKS_ERROR_BUFFER_TOO_SMALL;
            }
            bool aniRet = AniUtils::CreateUint8Array(env, outVec, oubBuffer);
            if (aniRet != true) {
                std::cerr << "CreateUint8Array failed!" <<std::endl;
                HKS_LOG_E("export key get the keyOut ok, but creat ani object failed!");
                return HKS_ERROR_BUFFER_TOO_SMALL;
            }
            bool getMethodRet = AniUtils::GetClassPropertyGetMethod(env, HUKS_RESULT_CLASS_NAME, "challenge",
                "<set>", setter);
            if(ANI_OK != getMethodRet) {
                std::cerr << "Class_FindMethod Fail'" << "<set>outData" << "'" << std::endl;
            }
            HKS_IF_NOT_TRUE_LOGE_RETURN(getMethodRet, HKS_ERROR_INVALID_ARGUMENT);
            if(ANI_OK != env->Object_CallMethod_Void(resultObjOut, setter, oubBuffer)) {
                std::cerr << "Object_CallMethod_Void Fail'" << "<set>outData" << "'" << std::endl;
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
    HKS_IF_NOT_TRUE_LOGE_RETURN(aniGetStringRet, HKS_ERROR_INVALID_ARGUMENT);
    if (keyAliasIn.size() == 0) {
        HKS_LOG_E("input key alias maybe null");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    int32_t ret = HKS_SUCCESS;
    do {
        keyAliasOut.size = keyAliasIn.size();
        keyAliasOut.data = (uint8_t *)HksMalloc(keyAliasOut.size);
        if (keyAliasOut.data == nullptr) {
            HKS_LOG_E("HksMalloc for keyAlias failed!");
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }
        if (memcpy_s(keyAliasOut.data, keyAliasOut.size, keyAliasIn.data(), keyAliasOut.size) != EOK) {
            HKS_LOG_D("memcpy from keyAliasIn failed");
            ret = HKS_ERROR_BUFFER_TOO_SMALL;
        }
    } while(0);
    if (ret != HKS_SUCCESS) {
        HKS_FREE_BLOB(keyAliasOut);
        HKS_LOG_E("HksGetKeyAlias failed. ret = %" LOG_PUBLIC "d", ret);
    }
    return ret;
}

int32_t HksAniGetParamTag(ani_env *&env, const ani_object &object, uint32_t &value)
{
    ani_method tagGettter;
    bool getMethodRet = AniUtils::GetClassPropertyGetMethod(env, HUKS_PARAM_CLASS_NAME, "tag", "<get>",
        tagGettter);
    HKS_IF_NOT_TRUE_LOGE_RETURN(getMethodRet, HKS_ERROR_INVALID_ARGUMENT);

    ani_ref enumRef;
    if(ANI_OK != env->Object_CallMethod_Ref(object, tagGettter, &enumRef))
    {
        std::cerr << "Object_CallMethod_Void Fail'" << tagGettter << "'" << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    ani_enum_item enumItem = static_cast<ani_enum_item>(enumRef);
    bool getRealValueRet = AniUtils::GetEnumRealValue(env, enumItem, value);
    HKS_IF_NOT_TRUE_LOGE_RETURN(getRealValueRet, HKS_ERROR_INVALID_ARGUMENT);
    return HKS_ERROR_INVALID_ARGUMENT;
}

int32_t HksAniHuksParamConvert(ani_env *&env, const ani_object &huksParamObj, HksParam &param)
{
    ani_class cls;
    int32_t ret{ HKS_SUCCESS };
    if (ANI_OK != env->FindClass(HUKS_PARAM_CLASS_NAME.data(), &cls)) {
        std::cerr << "Not found '" << HUKS_PARAM_CLASS_NAME.data() << "'" << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    bool getFieldRet = HksAniGetParamTag(env, huksParamObj, param.tag);
    HKS_IF_NOT_TRUE_LOGE_RETURN(getFieldRet, HKS_ERROR_INVALID_ARGUMENT);
    // std::cerr << "HuksParam tag : " << param.tag << std::endl;

    ani_method valueGettter;
    bool getMethodRet = AniUtils::GetClassPropertyGetMethod(env, HUKS_PARAM_CLASS_NAME, "value", "<get>",
        valueGettter);
    HKS_IF_NOT_TRUE_LOGE_RETURN(getMethodRet, HKS_ERROR_INVALID_ARGUMENT);
    // std::cerr << "Class_FindMethod " << "<get>value" << "' success" << std::endl;

    ani_ref valueUnionRef;
    if(ANI_OK != env->Object_CallMethod_Ref(huksParamObj, valueGettter, &valueUnionRef)) {
        std::cerr << "Object_CallMethod_Ref Fail'" << " valueUnionRef'" << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    // std::cerr << "get the value object success" << std::endl;

    ani_object unionObj = reinterpret_cast<ani_object>(valueUnionRef);
    switch (GetTagType((enum HksTag)param.tag)) {
        case HKS_TAG_TYPE_BOOL:
        getFieldRet = AniUtils::GetBooleanFromUnionObj(env, unionObj, param.boolParam);
        std::cout << "bool value : " << param.boolParam << std::endl;
        break;
    case HKS_TAG_TYPE_UINT:
        getFieldRet = AniUtils::GetUint32FromUnionObj(env, unionObj, param.uint32Param);
        // std::cout << "uint value : " << param.uint32Param << std::endl;
        break;
    case HKS_TAG_TYPE_INT:
        getFieldRet = AniUtils::GetInt32FromUnionObj(env, unionObj, param.int32Param);
        std::cout << "int value : " << param.int32Param << std::endl;
        break;
    case HKS_TAG_TYPE_ULONG:
        getFieldRet = AniUtils::GetUint64FromUnionObj(env, unionObj, param.uint64Param);
        std::cout << "int value : " << param.int32Param << std::endl;
        break;
    case HKS_TAG_TYPE_BYTES: {
        std::vector<uint8_t> buffer {};
        bool aniRet = AniUtils::GetUint8Array(env, unionObj, buffer);
        if (aniRet != true) {
            ret = HKS_ERROR_INVALID_ARGUMENT;
            break;
        }
        param.blob.size = buffer.size();
        std::cout << "buffer size = " << buffer.size() << std::endl;
        param.blob.data = (uint8_t *)HksMalloc(param.blob.size);
        if(param.blob.data == nullptr) {
            ret = HKS_ERROR_MALLOC_FAIL;
            HKS_LOG_E("malloc mem for huks param buffer failed!")
            break;
        }
        (void)memcpy_s(param.blob.data, param.blob.size, buffer.data(), param.blob.size);
        break;
    }
    default:
        HKS_LOG_E("Undefin param enum type. invalid tag value 0x%" LOG_PUBLIC "x", paramOut->tag);
        getFieldRet = HKS_ERROR_INVALID_ARGUMENT;
        break;
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
    // ani_method propertiesGettter;
    // bool aniRet =  AniUtils::GetClassPropertyGetMethod(env, HUKS_OPTION_CLASS_NAME, "properties",
    //     "<get>", propertiesGettter);
    // HKS_IF_NOT_TRUE_LOGE_RETURN(aniRet, HKS_ERROR_INVALID_ARGUMENT);
    ani_ref propertiesRef;
    // if(ANI_OK != env->Object_CallMethod_Ref(optionsObj, propertiesGettter, &propertiesRef))
    // {
    //     std::cerr << "Object_CallMethod_Void Fail'" << propertiesGettter << "'" << std::endl;
    //     return HKS_ERROR_INVALID_ARGUMENT;
    // }
    if(ANI_OK != env->Object_CallMethodByName_Ref(optionsObj, "<get>properties", nullptr, &propertiesRef))
    {
        std::cerr << "Object_CallMethodByName_Ref Fail' " << "<get>properties" << "'" << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    bool aniRet = AniUtils::CheckRefisDefined(env, propertiesRef);
    HKS_IF_NOT_TRUE_LOGE_RETURN(aniRet, HKS_ERROR_INVALID_ARGUMENT);

    ani_object propertiesArray = reinterpret_cast<ani_object>(propertiesRef);
    ani_double length;
    if(ANI_OK != env->Object_GetPropertyByName_Double(propertiesArray, "length", &length)){
        std::cerr << "Object_GetPropertyByName_Double length Failed" << std::endl;    
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    std::vector<HksParam> paramArray {};
    HksParamSet *paramSetNew = nullptr;
    int32_t ret = HKS_SUCCESS;
    do {
        for (int i = 0; i < int(length); i++) {
            ani_ref paramEntryRef;
            if(ANI_OK != env->Object_CallMethodByName_Ref(propertiesArray, "$_get",
                "I:Lstd/core/Object;", &paramEntryRef, (ani_int)i)){
                std::cerr << "Object_CallMethodByName_Ref _get Failed" << std::endl;    
                return HKS_ERROR_INVALID_ARGUMENT;
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

        FreeParsedParams(paramArray);
    } while(0);
    paramSetOut = paramSetNew;
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&paramSetNew);
        FreeParsedParams(paramArray);
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return ret;
}

int32_t HksGetBufferFromAni(ani_env *&env, const ani_object &arrayObj, HksBlob &blobBuffer)
{
    std::vector<uint8_t> keyBuffer {};
    bool getKeyRet = AniUtils::GetUint8Array(env, arrayObj, keyBuffer);
    HKS_IF_NOT_TRUE_LOGE_RETURN(getKeyRet, HKS_ERROR_INVALID_ARGUMENT);
    blobBuffer.size = keyBuffer.size();
    std::cout << "keyBuffer size = " << blobBuffer.size << std::endl;
    blobBuffer.data = (uint8_t *)HksMalloc(blobBuffer.size);
    HKS_IF_NULL_LOGE_RETURN(blobBuffer.data, HKS_ERROR_MALLOC_FAIL, "malloc mem for key buffer failed!")
    if (memcpy_s(blobBuffer.data, blobBuffer.size, keyBuffer.data(), blobBuffer.size) != EOK) {
        HKS_LOG_E("memcpy vector key buffer to blob data failed!")
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    return HKS_SUCCESS;
}

int32_t HksOptionGetInData(ani_env *&env, ani_object options, HksBlob &blobOut)
{
    ani_ref inDataRef;
    if(ANI_OK != env->Object_CallMethodByName_Ref(options, "<get>inData", nullptr, &inDataRef))
    {
        std::cerr << "Object_CallMethodByName_Ref Fail' " << "<get>inData" << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    bool aniRet = AniUtils::CheckRefisDefined(env, inDataRef);
    HKS_IF_NOT_TRUE_LOGE_RETURN(aniRet, HKS_ERROR_INVALID_ARGUMENT);
    
    ani_object inDataBuffer = reinterpret_cast<ani_object>(inDataRef);
    int32_t ret = HksGetBufferFromAni(env, inDataBuffer, blobOut);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_ARGUMENT, "ANIGetBuffer failed! ret = %" LOG_PUBLIC "d", ret);
    return ret;
}

template<>
int32_t HksAniParseParams(ani_env *env, ani_string keyAlias, ani_object &options, KeyContext *&&contextPtr)
{
    HKS_IF_NULL_LOGE_RETURN(contextPtr, HKS_ERROR_NULL_POINTER, "ParseParams, but context is null")
    int32_t ret = HksAniParseParams<CommonContext>(env, keyAlias, options, static_cast<CommonContext *>(contextPtr));
    if (ret != HKS_SUCCESS) {
        std::cout << "import key parase common param failed" << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    std::cerr << "HksAniParseParams success'" << std::endl;

    ret = HksOptionGetInData(env, options, contextPtr->key);
    if (ret != HKS_SUCCESS) {
        std::cout << "KeyContext HksOptionGetInDatam failed" << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return ret;
}

template<>
void HksDeleteContext(KeyContext &context)
{
    HksDeleteContext<CommonContext>(context);
    FreeHksBlobAndFresh(context.keyAlias, true);
}

int32_t HksAniImportWrappedKeyParseParams(ani_env *env, ani_string &keyAlias, ani_string &wrappingKeyAlias,
        ani_object options, ImportWrappedKeyContext *&&contextPtr)
{
    HKS_IF_NULL_LOGE_RETURN(contextPtr, HKS_ERROR_NULL_POINTER, "ParseParams, but context is null")
    int32_t ret = HksAniParseParams<KeyContext>(env, keyAlias, options, static_cast<KeyContext *>(contextPtr));
    if (ret != HKS_SUCCESS) {
        std::cout << "import key parase common param failed" << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    std::cerr << "HksAniParseParams success'" << std::endl;
    ret = HksGetKeyAliasFromAni(env, wrappingKeyAlias, contextPtr->wrappingKeyAlias);
    if (ret != HKS_SUCCESS) {
        std::cout << "HksGetKeyAliasFromAni failed" << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return ret;
}

template<>
void HksDeleteContext(ImportWrappedKeyContext &context)
{
    HksDeleteContext<KeyContext>(context);
    FreeHksBlobAndFresh(context.wrappingKeyAlias);
}


int32_t HksAniParseParams(ani_env *env, ani_long &handle, ani_object &options, SessionContext *&&contextPtr)
{
    HKS_IF_NULL_LOGE_RETURN(contextPtr, HKS_ERROR_NULL_POINTER, "ParseParams, but context is null")
    int32_t ret = HksAniParseParams<CommonContext>(env, nullptr, options, static_cast<CommonContext *>(contextPtr));
    if (ret != HKS_SUCCESS) {
        std::cout << "SessionContext parase common param failed" << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    ret = HksOptionGetInData(env, options, contextPtr->inData);
    if (ret != HKS_SUCCESS) {
        std::cout << "SessionContext HksOptionGetInData failed" << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    uint64_t huksHandle = static_cast<uint64_t>(handle);
    contextPtr->handle.size = sizeof(uint64_t);
    contextPtr->handle.data = static_cast<uint8_t *>(HksMalloc(contextPtr->handle.size));
    (void)memcpy_s(contextPtr->handle.data, contextPtr->handle.size, &huksHandle, contextPtr->handle.size);
    return ret;
}

template<>
void HksDeleteContext(SessionContext &context)
{
    HksDeleteContext<CommonContext>(context);
    FreeHksBlobAndFresh(context.token);
    FreeHksBlobAndFresh(context.handle);
    FreeHksBlobAndFresh(context.inData);
    FreeHksBlobAndFresh(context.outData);
}
}  // namespace
