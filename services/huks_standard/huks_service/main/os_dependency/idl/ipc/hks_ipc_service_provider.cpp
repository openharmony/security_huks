/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "hks_ipc_service_provider.h"
#include "hks_plugin_lifecycle_manager.h"

void HksIpcServiceProviderRegister(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob keyAlias = { 0, NULL }; //abilityName
    struct HksParamSet *inParamSet = NULL;
    struct HksBlob keyOut = { 0, NULL };
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;
    bool isNoneResponse = false;

    do {
        // 解析参数
        ret = HksGenerateKeyUnpack(srcData, &keyAlias, &inParamSet, &keyOut);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGenerateKeyUnpack Ipc fail")
        // keyOut.data可能为空，比如生成非对称密钥，私钥不暴露
        if (keyOut.data == NULL) {
            isNoneResponse = true;
            keyOut.data = (uint8_t *)HksMalloc(MAX_KEY_SIZE);
            if (keyOut.data == NULL) {
                HKS_LOG_E("malloc fail.");
                ret = HKS_ERROR_MALLOC_FAIL;
                break;
            }
            keyOut.size = MAX_KEY_SIZE;
        }

        // 获取调用方身份信息
        ret = HksGetProcessInfoForIPC(context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        // 权限校验
        ret = HksCheckAcrossAccountsPermission(inParamSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
        if (pluginManager == nullptr) {
            HKS_LOG_E("Failed to get plugin manager instance.");
            ret = HKS_ERROR_NULL_POINTER;
            break;
        }
        CppParamSet paramSet(inParamSet); 
        // TODO:转换时是否要进行安全检查，keyAlias可靠吗
        ret = pluginManager->RegisterProvider(processInfo, std::string(reinterpret_cast<const char*>(keyAlias.data), keyAlias.size), paramSet); 

    } while (0);
    HksSendResponse(context, ret, isNoneResponse ? NULL : &keyOut);

    HKS_FREE_BLOB(keyOut);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

void HksIpcServiceProviderUnRegister(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob keyAlias = { 0, NULL }; //abilityName
    struct HksParamSet *inParamSet = NULL;
    struct HksBlob keyOut = { 0, NULL };
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;
    bool isNoneResponse = false;

    do {
        // 解析参数
        ret = HksGenerateKeyUnpack(srcData, &keyAlias, &inParamSet, &keyOut);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGenerateKeyUnpack Ipc fail")
        // keyOut.data可能为空，比如生成非对称密钥，私钥不暴露
        if (keyOut.data == NULL) {
            isNoneResponse = true;
            keyOut.data = (uint8_t *)HksMalloc(MAX_KEY_SIZE);
            if (keyOut.data == NULL) {
                HKS_LOG_E("malloc fail.");
                ret = HKS_ERROR_MALLOC_FAIL;
                break;
            }
            keyOut.size = MAX_KEY_SIZE;
        }

        // 获取调用方身份信息
        ret = HksGetProcessInfoForIPC(context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        // 权限校验
        ret = HksCheckAcrossAccountsPermission(inParamSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
        if (pluginManager == nullptr) {
            HKS_LOG_E("Failed to get plugin manager instance.");
            ret = HKS_ERROR_NULL_POINTER;
            break;
        }
        CppParamSet paramSet(inParamSet); 
        ret = pluginManager->UnRegisterProvider(processInfo, std::string(reinterpret_cast<const char*>(keyAlias.data), keyAlias.size), paramSet); 

    } while (0);
    HksSendResponse(context, ret, isNoneResponse ? NULL : &keyOut);

    HKS_FREE_BLOB(keyOut);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

void HksIpcServiceRegistLibFunction(int32_t funCode, void *fun) {

}





