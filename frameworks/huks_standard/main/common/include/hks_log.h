/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef HKS_LOG_H
#define HKS_LOG_H

#include "hks_type.h"

#ifdef L2_STANDARD
#include "hks_error_msg.h"
#endif

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#ifdef _HUKS_LOG_ENABLE_
#ifdef HKS_ENABLE_LOG_PUBLIC
#define LOG_PUBLIC "{public}"
#else
#define LOG_PUBLIC
#endif

#undef LOG_TAG
#define LOG_TAG "HUKS"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002F06 /* Security subsystem huks domain id */

#ifdef HKS_LOG_ENGINE_LOG_CORE
#include "hilog/log.h"
#define LOG_ENGINE LOG_CORE
#else
#ifdef HKS_LOG_ENGINE_HILOG_MODULE_SCY
#include "log.h"
#define LOG_ENGINE HILOG_MODULE_SCY
#endif
#endif

#ifdef L2_STANDARD
#undef LOG_PUBLIC
#define LOG_PUBLIC

enum HksLogLevel {
    HKS_LOG_LEVEL_I,
    HKS_LOG_LEVEL_E,
    HKS_LOG_LEVEL_W,
    HKS_LOG_LEVEL_D,
};

#define HKS_LOG_I(fmt, ...) \
        HksLog(HKS_LOG_LEVEL_I, " %s[%u]: " fmt, __func__, __LINE__, ##__VA_ARGS__)

#define HKS_LOG_W(fmt, ...) \
         HksLog(HKS_LOG_LEVEL_W, " %s[%u]: " fmt, __func__, __LINE__, ##__VA_ARGS__)

#define HKS_LOG_E(fmt, ...) \
        HksLog(HKS_LOG_LEVEL_E, " %s[%u]: " fmt, __func__, __LINE__, ##__VA_ARGS__)

#define HKS_LOG_D(fmt, ...) \
        HksLog(HKS_LOG_LEVEL_D, " %s[%u]: " fmt, __func__, __LINE__, ##__VA_ARGS__)

#else // L2_STANDARD

#define HKS_LOG_I(fmt, arg...) HILOG_INFO(LOG_ENGINE, "%" LOG_PUBLIC "s[%" LOG_PUBLIC "u]: " fmt "\n", \
                                                                                            __func__, __LINE__, ##arg)
#define HKS_LOG_W(fmt, arg...) HILOG_WARN(LOG_ENGINE, "%" LOG_PUBLIC "s[%" LOG_PUBLIC "u]: " fmt "\n", \
                                                                                            __func__, __LINE__, ##arg)
#define HKS_LOG_E(fmt, arg...) HILOG_ERROR(LOG_ENGINE, "%" LOG_PUBLIC "s[%" LOG_PUBLIC "u]: " fmt "\n", \
                                                                                            __func__, __LINE__, ##arg)
#define HKS_LOG_D(fmt, arg...) HILOG_DEBUG(LOG_ENGINE, "%" LOG_PUBLIC "s[%" LOG_PUBLIC "u]: " fmt "\n", \
                                                                                            __func__, __LINE__, ##arg)
#endif // L2_STANDARD

#else // _HUKS_LOG_ENABLE_
#define HKS_LOG_I(...)
#define HKS_LOG_W(...)
#define HKS_LOG_E(...)
#define HKS_LOG_D(...)
#endif //_HUKS_LOG_ENABLE_

#ifdef __cplusplus
extern "C" {
#endif

extern uint32_t g_sessionId;

#ifdef __cplusplus
}
#endif

#endif /* HKS_LOG_H */
