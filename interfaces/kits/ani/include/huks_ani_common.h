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

 #ifndef HKS_ANI_H
 #define HKS_ANI_H

#include "hks_mem.h"
#include "hks_type.h"
#include "hks_type_enum.h"
#include "securec.h"
#include "hks_template.h"
#include "hks_param.h"
#include "hks_log.h"

#include <ani.h>
#include <stdbool.h>
#include <string>
#include <iostream>
#include <stdio.h>
namespace HuksAni {

class CommonContext {
public:
    int32_t result = 0;
    struct HksBlob keyAlias{0, nullptr};
    struct HksParamSet *paramSetIn = nullptr;
    struct HksParamSet *paramSetOut = nullptr;
};

class KeyContext : public CommonContext {
public:
    struct HksBlob key{0, nullptr};
};

class ImportWrappedKeyContext : public KeyContext {
public:
    struct HksBlob wrappingKeyAlias{0, nullptr};
};

class SessionContext : public CommonContext {
public:
    struct HksBlob inData{0, nullptr};
    struct HksBlob outData{0, nullptr};
    struct HksBlob handle{0, nullptr};
    struct HksBlob token{0, nullptr};
};

namespace AniUtils {
    bool GetStirng([[maybe_unused]] ani_env *&env, const ani_string &strObject, std::string &nativeStr);

    bool GetInt32Field(ani_env *&env, const ani_object &object, std::string fieldName, int32_t &value);

    bool GetInt32FromUnionObj(ani_env *&env, const ani_object &unionObj, int32_t &value);

    bool GetUint32FromUnionObj(ani_env *&env, const ani_object &unionObj, uint32_t &value);

    bool GetUint64FromUnionObj(ani_env *&env, const ani_object &unionObj, uint64_t &value);

    bool GetBooleanFromUnionObj(ani_env *&env, const ani_object &unionObj, bool &value);

    bool GetClassPropertyGetMethod(ani_env *&env, const std::string &className, const std::string &propertyName,
        const std::string getOrSet, ani_method &methodOut);

    bool GetEnumRealValue(ani_env *&env, ani_enum_item &enumObj, uint32_t &realValue);

    bool GetUint8Array(ani_env *env, ani_object array, std::vector<uint8_t> &arrayOut);

    bool CheckRefisDefined(ani_env *&env, const ani_ref &ref);

    void PrintUint8Array(std::vector<uint8_t> &arrayIn);

    bool CreateUint8Array(ani_env *env, std::vector<uint8_t> &arrayIn, ani_object &arrayOut);
};

int32_t HksGetKeyAliasFromAni(ani_env *&env, const ani_string &strObject, HksBlob &keyAliasOut);

int32_t HksCreateAniResult(const int32_t result, ani_env *&env, ani_object &resultObjOut, ani_object oubBuffer = nullptr);

int32_t HksIsKeyItemExistCreateAniResult(const int32_t result, ani_env *&env, ani_object &resultObjOut);

int32_t HksInitSessionCreateAniResult(const int32_t result, ani_env *&env, const SessionContext &context, ani_object &resultObjOut);

int32_t HksGetParamSetFromAni(ani_env *&env, const ani_object &optionsObj, struct HksParamSet *&paramSetOut);

void FreeHksBlobAndFresh(HksBlob &blob, const bool isNeedFresh = false);

int32_t HksOptionGetInData(ani_env *&env, ani_object options, HksBlob &blobOut);

template<typename T>
void HksDeleteContext(T &context)
{
    FreeHksBlobAndFresh(context.keyAlias);
    HksFreeParamSet(&(context.paramSetIn));
    if (context.paramSetOut != nullptr) {
        HksFreeParamSet(&(context.paramSetOut));
    }
}

template<typename T>
int32_t HksAniParseParams(ani_env *env, ani_string keyAlias, ani_object &options, T *&&contextPtr)
{
    HKS_IF_NULL_LOGE_RETURN(contextPtr, HKS_ERROR_NULL_POINTER, "ParseParams, but context is null")
    int32_t ret{ HKS_SUCCESS };
    if (keyAlias != nullptr) {
        ret = HksGetKeyAliasFromAni(env, keyAlias, contextPtr->keyAlias);
        if (ret != HKS_SUCCESS) {
            std::cout << "HksGetKeyAliasFromAni failed" << std::endl;
            return HKS_ERROR_INVALID_ARGUMENT;
        }
    }
    ret = HksGetParamSetFromAni(env, options, contextPtr->paramSetIn);
    if (ret != HKS_SUCCESS) {
        std::cout << "HksGetParamSetFromAni failed" << std::endl;
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return ret;
}

template<>
int32_t HksAniParseParams(ani_env *env, ani_string keyAlias, ani_object &options, KeyContext *&&context);

template<>
void HksDeleteContext(KeyContext &context);


int32_t HksAniImportWrappedKeyParseParams(ani_env *env, ani_string &keyAlias, ani_string &wrappingKeyAlias,
    ani_object options, ImportWrappedKeyContext *&&contextPtr);

template<>
void HksDeleteContext(ImportWrappedKeyContext &context);

int32_t HksAniParseParams(ani_env *env, ani_long &handle, ani_object &options, SessionContext *&&contextPtr);

template<>
void HksDeleteContext(SessionContext &context);

}
#endif