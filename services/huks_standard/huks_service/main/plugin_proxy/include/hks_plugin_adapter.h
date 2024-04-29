/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef HKS_PLUGIN_ADAPTER_H
#define HKS_PLUGIN_ADAPTER_H

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_plugin_def.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t HksInitPluginProxy(void);

int32_t HksPluginOnRemoteRequest(uint32_t code, void *data, void *reply, void *option);
int32_t HksPluginOnLocalRequest(uint32_t code, const void *data, void *reply);
void HksPluginOnReceiveEvent(const void *data);

#ifdef __cplusplus
}
#endif

#endif // HKS_PLUGIN_ADAPTER_H