/*
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd.
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

#ifndef HKS_RKC_H
#define HKS_RKC_H

#include "hks_type_inner.h"

#define HKS_RKC_RMK_LEN 64                              /* the length of root main key */
#define HKS_RKC_RMK_EK_LEN 32                           /* the encryption key length of root main key */
#define HKS_RKC_RAW_KEY_LEN 64                          /* the raw key length of root key component */
#define HKS_HARDWARE_UDID_LEN 32                        /* the length of hardware UDID */
#define HKS_RKC_MK_ADD_DATA_LEN 8                       /* the additional data length of main key */
#define HKS_KSF_NAME_LEN_MAX 256                        /* the max length of rkc keystore filename */

/* the configuration of root key component */
struct HksRkcCfg {
    uint8_t state;                                      /* system state */
    uint16_t rkVersion;                                 /* the version of root key component */
    uint16_t mkVersion;                                 /* the version of main key */
    uint8_t storageType;                                /* the storage type of root key component */
    struct HksTime rkCreatedTime;                       /* the created time of root key */
    struct HksTime rkExpiredTime;                       /* the expired time of root key */
    struct HksKsfAttr ksfAttrRkc;                       /* the attribute of rkc keystore file */
    struct HksKsfAttr ksfAttrMk;                        /* the attribute of mk keystore file */
    uint32_t rmkIter;                                   /* the iterator number of times which derive Root Main Key */
    uint32_t rmkHashAlg;                                /* the hash algorithm which derive Root Main Key */
    uint8_t mkMask[HKS_RKC_MK_LEN];                     /* the mask of main key */
    uint32_t mkEncryptAlg;                              /* the encrption algorithm of main key */
    uint8_t reserve[HKS_RKC_CFG_RSV_LEN];               /* reserve data, 32 byte */
};

/* main key */
struct HksRkcMk {
    bool valid;                                         /* whether main key is valid */
    struct HksTime mkCreatedTime;                       /* the created time of main key */
    struct HksTime mkExpiredTime;                       /* the expired time of main key */
    uint8_t mkWithMask[HKS_RKC_MK_LEN];                 /* the main key with mask */
};

#ifdef __cplusplus
extern "C" {
#endif

struct HksKsfAttr *GetGlobalKsfAttrRkc();

struct HksKsfAttr *GetGlobalKsfAttrMk();

int32_t HksRkcInit(void);

void HksCfgDestroy(void);

void HksMkDestroy(void);

void HksCfgClearMem(void);

void HksMkClearMem(void);

int32_t HksRkcGetMainKey(struct HksBlob *mainKey);

#ifdef __cplusplus
}
#endif

#endif /* HKS_RKC_H */
