/*
 * Copyright (c) 2020-2023 Huawei Device Co., Ltd.
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

#ifndef HKS_RKC_V1_H
#define HKS_RKC_V1_H

#include "hks_rkc_rw.h"
#include "hks_type_inner.h"

/* the keystore file data of root key component (version 1) */
struct HksRkcKsfDataV1 {
    uint16_t version;                                   /* version */
    struct HksKsfDataRkc ksfDataRkc;                    /* fields of root key */
    struct HksKsfDataMk ksfDataMk;                      /* fields of main key */
};

#ifdef __cplusplus
extern "C" {
#endif

int32_t UpgradeV1ToV2(void);

#ifdef __cplusplus
}
#endif

#endif /* HKS_RKC_V1_H */