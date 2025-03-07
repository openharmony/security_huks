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
#include <stdbool.h>
#include <stdio.h>
#include <string>
#include <vector>
namespace HuksAni {
static const char *HUKS_RESULT_CLASS_NAME = "LaniTest/HuksResult;";
static std::string HUKS_OPTION_CLASS_NAME = "LaniTest/HuksOptionsImpl;";
static std::string HUKS_PARAM_CLASS_NAME = "LaniTest/HuksParamImpl;";
static std::string HUKS_TAG_NAME = "L#HuksTag;";
static std::string HUKS_NAME_SPACE_NAME = "LhuksInterface/huks;";

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
    std::cout << "Call Me With String. Get: "<< nativeStr << std::endl;
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
    ani_method &method)
{
    ani_class cls;
    if (ANI_OK != env->FindClass(className.data(), &cls)) {
        std::cerr << "Not found '" << className.data() << "'" << std::endl;
        return false;
    }
    std::string getMethodName = "<get>" + propertyName;
    if(ANI_OK != env->Class_FindMethod(cls, getMethodName.data(), nullptr, &method)){
        std::cerr << "Class_FindMethod Fail'" << getMethodName.data() << "'" << std::endl;
        return false;
    }
    return true;
}

bool AniUtils::GetEnumRealValue(ani_env *&env, ani_enum &enumObj, ani_int &enumIndex, uint32_t &realValue)
{
    ani_enum_item enumItem;
    if(ANI_OK != env->Enum_GetEnumItemByIndex(enumObj, enumIndex, &enumItem)){
        std::cerr << "Enum_GetEnumItemByIndex FAILD" << std::endl;
        return false;
    }
    ani_int tagValue;
    if(ANI_OK != env->EnumItem_GetValue_Int(enumItem, &tagValue)) {
        std::cerr << "EnumItem_GetValue_Int FAILD" << std::endl;
        return false;
    }
    std::cout << "Enum Value: " << tagValue << std::endl;
    realValue = static_cast<uint32_t>(tagValue);
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
    std::cout << "Length of buffer = " << length << std::endl;
    std::cout << "Elements of buffer = [";
    for (size_t i = 0; i < length; i++) {
        if (i != 0) {
            std::cout << ", ";
        }
        std::cout << static_cast<unsigned>(static_cast<uint8_t*>(data)[i]);
        arrayOut.emplace_back(static_cast<unsigned>(static_cast<uint8_t*>(data)[i]));
    }
    std::cout << "]" << std::endl;

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
    env->Object_GetFieldByName_Ref(arrayOut, "buffer", &buffer);
    void *bufData;
    size_t bufLength;
    retCode = env->ArrayBuffer_GetInfo(static_cast<ani_arraybuffer>(buffer), &bufData, &bufLength);
    if (retCode != ANI_OK) {
        std::cerr << "Failed: env->ArrayBuffer_GetInfo()" << std::endl;
        // todo: exception
        return false;
    }
    std::memcpy(bufData, arrayIn.data(), bufLength);
    return true;
}

int32_t HksCreateAniResult(const int32_t result, [[maybe_unused]] ani_env *&env, ani_object &resultObjOut, ani_object oubBuffer)
{
    struct HksResult errInfo {};
    errInfo.errorCode = 0;
    if (result != HKS_SUCCESS) {
        errInfo = HksConvertErrCode(result);
    }

    ani_class cls;
    if (ANI_OK != env->FindClass(HUKS_RESULT_CLASS_NAME, &cls)) {
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
    
    ani_method resultCodeSetter;
    if(ANI_OK != env->Class_FindMethod(cls, "<set>result", nullptr, &resultCodeSetter)){
        std::cerr << "Class_FindMethod Fail'" << "<set>result" << "'" << std::endl;
    }
    if(ANI_OK != env->Object_CallMethod_Void(resultObjOut, resultCodeSetter, ani_int(errInfo.errorCode)))
    {
        std::cerr << "Object_CallMethod_Void Fail'" << resultCodeSetter << "'" << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (errInfo.errorCode != HKS_SUCCESS) {
        ani_method errMsgSetter;
        if(ANI_OK != env->Class_FindMethod(cls, "<set>error", nullptr, &errMsgSetter)){
            std::cerr << "Class_FindMethod Fail'" << "<set>error" << "'" << std::endl;
        }
        ani_string result_string{};
        env->String_NewUTF8(errInfo.errorMsg, strlen(errInfo.errorMsg), &result_string);
        if(ANI_OK != env->Object_CallMethod_Void(resultObjOut, errMsgSetter, result_string)) {
            std::cerr << "Object_CallMethod_Void Fail'" << "<set>error" << "'" << std::endl;
            return HKS_ERROR_INVALID_ARGUMENT;
        }
    }

    if (oubBuffer != nullptr) {
        ani_method outBufferSetter;
        if(ANI_OK != env->Class_FindMethod(cls, "<set>outData", nullptr, &outBufferSetter)){
            std::cerr << "Class_FindMethod Fail'" << "<set>outData" << "'" << std::endl;
        }
        if(ANI_OK != env->Object_CallMethod_Void(resultObjOut, outBufferSetter, oubBuffer)) {
            std::cerr << "Object_CallMethod_Void Fail'" << "<set>outData" << "'" << std::endl;
            return HKS_ERROR_INVALID_ARGUMENT;
        }
    }
    return HKS_SUCCESS;
}

int32_t HksGetKeyAliasFromAni([[maybe_unused]] ani_env *&env, const ani_string &strObject, HksBlob &keyAliasOut)
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
    bool getMethodRet = AniUtils::GetClassPropertyGetMethod(env, HUKS_PARAM_CLASS_NAME, "tag",
        tagGettter);
    HKS_IF_NOT_TRUE_LOGE_RETURN(getMethodRet, HKS_ERROR_INVALID_ARGUMENT);

    ani_int enumIndex;
    if(ANI_OK != env->Object_CallMethod_Int(object, tagGettter, &enumIndex))
    {
        std::cerr << "Object_CallMethod_Void Fail'" << tagGettter << "'" << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    // std::cerr << "get the tag object success, this is index, not the real value" << std::endl;

    ani_namespace ns;
    if (ANI_OK != env->FindNamespace(HUKS_NAME_SPACE_NAME.data(), &ns)) {
        std::cerr << "Not FindNamespace '" << HUKS_NAME_SPACE_NAME << "'" << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    ani_enum huksTag {};
    if (ANI_OK != env->Namespace_FindEnum(ns, HUKS_TAG_NAME.data(), &huksTag)) {
        std::cerr << "Not Namespace_FindEnum '" << HUKS_TAG_NAME << "'" << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    // std::cerr << "get the tagdef from namespace success" << std::endl;

    bool getRealValueRet = AniUtils::GetEnumRealValue(env, huksTag, enumIndex, value);
    HKS_IF_NOT_TRUE_LOGE_RETURN(getRealValueRet, HKS_ERROR_INVALID_ARGUMENT);
    return HKS_ERROR_INVALID_ARGUMENT;
}


int32_t HksAniHuksParamConvert([[maybe_unused]] ani_env *&env, const ani_object &huksParamObj, HksParam &param)
{
    ani_class cls;
    if (ANI_OK != env->FindClass(HUKS_PARAM_CLASS_NAME.data(), &cls)) {
        std::cerr << "Not found '" << HUKS_PARAM_CLASS_NAME.data() << "'" << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    bool getFieldRet = HksAniGetParamTag(env, huksParamObj, param.tag);
    HKS_IF_NOT_TRUE_LOGE_RETURN(getFieldRet, HKS_ERROR_INVALID_ARGUMENT);
    // std::cerr << "HuksParam tag : " << param.tag << std::endl;

    ani_method valueGettter;
    bool getMethodRet = AniUtils::GetClassPropertyGetMethod(env, HUKS_PARAM_CLASS_NAME, "value",
        valueGettter);
    HKS_IF_NOT_TRUE_LOGE_RETURN(getMethodRet, HKS_ERROR_INVALID_ARGUMENT);
    // std::cerr << "Class_FindMethod " << "<get>value" << "' success" << std::endl;

    ani_ref valueUnionRef;
    if(ANI_OK != env->Object_CallMethod_Ref(huksParamObj, valueGettter, &valueUnionRef))
    {
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
        std::cout << "uint value : " << param.uint32Param << std::endl;
        break;
    case HKS_TAG_TYPE_INT:
        getFieldRet = AniUtils::GetInt32FromUnionObj(env, unionObj, param.int32Param);
        std::cout << "int value : " << param.int32Param << std::endl;
        break;
    case HKS_TAG_TYPE_ULONG:
        getFieldRet = AniUtils::GetUint64FromUnionObj(env, unionObj, param.uint64Param);
        std::cout << "int value : " << param.int32Param << std::endl;
        break;
    case HKS_TAG_TYPE_BYTES:
        // TODO:
        break;
    default:
        HKS_LOG_E("Undefin param enum type. invalid tag value 0x%" LOG_PUBLIC "x", paramOut->tag);
        getFieldRet = HKS_ERROR_INVALID_ARGUMENT;
        break;
    }
    return HKS_SUCCESS;
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
    ani_method propertiesGettter;
    bool aniRet =  AniUtils::GetClassPropertyGetMethod(env, HUKS_OPTION_CLASS_NAME, "properties", propertiesGettter);
    HKS_IF_NOT_TRUE_LOGE_RETURN(aniRet, HKS_ERROR_INVALID_ARGUMENT);
    ani_ref propertiesRef;
    if(ANI_OK != env->Object_CallMethod_Ref(optionsObj, propertiesGettter, &propertiesRef))
    {
        std::cerr << "Object_CallMethod_Void Fail'" << propertiesGettter << "'" << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    aniRet = AniUtils::CheckRefisDefined(env, propertiesRef);
    HKS_IF_NOT_TRUE_LOGE_RETURN(aniRet, HKS_ERROR_INVALID_ARGUMENT);

    ani_object propertiesArray = reinterpret_cast<ani_object>(propertiesRef);
    ani_double length;
    if(ANI_OK != env->Object_GetPropertyByName_Double(propertiesArray, "length", &length)){
        std::cerr << "Object_GetPropertyByName_Double length Failed" << std::endl;    
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    std::cerr << "array length = "<< length << std::endl;
    std::vector<HksParam> paramArray {};
    HksParamSet *paramSetNew = nullptr;
    int32_t ret = HKS_SUCCESS;
    do {
        for (int i = 0; i < int(length); i++) {
            ani_ref paramEntryRef;
            if(ANI_OK != env->Object_CallMethodByName_Ref(propertiesArray, "$_get", "I:Lstd/core/Object;", &paramEntryRef, (ani_int)i)){
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

template<>
int32_t HksAniParseParams(ani_env *env, ani_string keyAlias, ani_object options, ImportKeyContext *&&contextPtr)
{
    HKS_IF_NULL_LOGE_RETURN(contextPtr, HKS_ERROR_NULL_POINTER, "ParseParams, but context is null")
    int32_t ret = HksAniParseParams<CommonContext>(env, keyAlias, options, static_cast<CommonContext *>(contextPtr));
    if (ret != HKS_SUCCESS) {
        std::cout << "import key parase common param failed" << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    std::cerr << "HksAniParseParams success'" << std::endl;
    
    ani_method inDataGettter;
    bool getMethodRet =  AniUtils::GetClassPropertyGetMethod(env, HUKS_OPTION_CLASS_NAME, "inData", inDataGettter);
    HKS_IF_NOT_TRUE_LOGE_RETURN(getMethodRet, HKS_ERROR_INVALID_ARGUMENT);

    std::cerr << "HksAniParseParams success'" << std::endl;
    ani_ref inDataRef;
    if(ANI_OK != env->Object_CallMethod_Ref(options, inDataGettter, &inDataRef))
    {
        std::cerr << "Object_CallMethod_Ref Fail'" << inDataGettter << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    bool aniRet = AniUtils::CheckRefisDefined(env, inDataRef);
    HKS_IF_NOT_TRUE_LOGE_RETURN(aniRet, HKS_ERROR_INVALID_ARGUMENT);
    
    ani_object inDataBuffer = reinterpret_cast<ani_object>(inDataRef);
    aniRet = HksGetBufferFromAni(env, inDataBuffer, contextPtr->keyIn);
    HKS_IF_NOT_TRUE_LOGE_RETURN(aniRet, HKS_ERROR_INVALID_ARGUMENT);

    return HKS_SUCCESS;
}

template<>
void HksDeleteContext(ImportKeyContext &context)
{
    HksDeleteContext<CommonContext>(context);
    FreeHksBlobAndFresh(context.keyAlias, true);
}

int32_t HksAniImportWrappedKeyParseParams(ani_env *env, ani_string &keyAlias, ani_string &wrappingKeyAlias,
        ani_object options, ImportWrappedKeyContext *&&contextPtr)
{
    HKS_IF_NULL_LOGE_RETURN(contextPtr, HKS_ERROR_NULL_POINTER, "ParseParams, but context is null")
    int32_t ret = HksAniParseParams<ImportKeyContext>(env, keyAlias, options, static_cast<ImportKeyContext *>(contextPtr));
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
    HksDeleteContext<ImportKeyContext>(context);
    FreeHksBlobAndFresh(context.wrappingKeyAlias);
}

}  // namespace
