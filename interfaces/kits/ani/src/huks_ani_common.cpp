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
 
 #include <ani.h>
 #include <array>
 #include <iostream>
 #include <string>
namespace HuksAni {
    static const char *HUKS_RESULT_CLASS_NAME = "LaniTest/HuksResult;";

    int32_t HksAniString2NativeStirng([[maybe_unused]] ani_env *&env, const ani_string &strObject, std::string &nativeStr)
    {
        ani_boolean isUndefined;
        env->Reference_IsUndefined(strObject, &isUndefined);
        if(isUndefined)
        {
            std::cout << "Call With Optional String NOT Pass Value " << std::endl;
            return HKS_ERROR_INVALID_ARGUMENT;
        }
        ani_size strSize = 0;
        env->String_GetUTF8Size(strObject, &strSize);
        std::vector<char> buffer(strSize + 1); // +1 for null terminator
        char* utf8_buffer = buffer.data();
        ani_size bytesWritten = 0;
        env->String_GetUTF8(strObject, utf8_buffer, strSize + 1, &bytesWritten);
        
        utf8_buffer[bytesWritten] = '\0';
        nativeStr = std::string(utf8_buffer);
        std::cout << "Call Me With Optional String Get "<< nativeStr << std::endl;
        return HKS_SUCCESS;
    }
    
    int32_t HksCreateAniResult(const int32_t result, const std::string errMsg, [[maybe_unused]] ani_env *&env, ani_object &resultObjOut)
    {
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
        if(ANI_OK != env->Object_CallMethod_Void(resultObjOut, resultCodeSetter, ani_int(result)))
        {
            std::cerr << "Object_CallMethod_Void Fail'" << resultCodeSetter << "'" << std::endl;
            return HKS_ERROR_INVALID_ARGUMENT;
        }
    
        if (errMsg.size() != 0) {
            ani_method errMsgSetter;
            if(ANI_OK != env->Class_FindMethod(cls, "<set>error", nullptr, &errMsgSetter)){
                std::cerr << "Class_FindMethod Fail'" << "<set>error" << "'" << std::endl;
            }
            ani_string result_string{};
            env->String_NewUTF8(errMsg.c_str(), errMsg.size(), &result_string);
            if(ANI_OK != env->Object_CallMethod_Void(resultObjOut, errMsgSetter, result_string)) {
                std::cerr << "Object_CallMethod_Void Fail'" << "<set>error" << "'" << std::endl;
                return HKS_ERROR_INVALID_ARGUMENT;
            }
        }
        return HKS_SUCCESS;
    }
    
    int32_t HksGetKeyAliasFromAni([[maybe_unused]] ani_env *&env, const ani_string &strObject, HksBlob &keyAliasOut)
    {
        std::string keyAliasIn = "";
        int ret = HksAniString2NativeStirng(env, strObject, keyAliasIn);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksAniString2NativeStirng failed. ret = %" LOG_PUBLIC "d", ret)
        if (keyAliasIn.size() == 0) {
            HKS_LOG_E("input key alias maybe null");
            return HKS_ERROR_INVALID_ARGUMENT;
        }
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

}
