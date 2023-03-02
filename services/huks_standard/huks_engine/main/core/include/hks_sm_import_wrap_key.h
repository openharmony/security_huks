/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef HKS_SM_IMPORT_WRAP_KEY_H
#define HKS_SM_IMPORT_WRAP_KEY_H

#include <stdint.h>

#include "hks_keynode.h"
#include "hks_type.h"

#ifdef __cplusplus
extern "C"
{
#endif
struct HksSmWrappedKeyDataBlob {
    struct HksBlob peerPublicKey;
    struct HksBlob kekAndSignData;
    struct HksBlob kekData;
    struct HksBlob signData;
    struct HksBlob deriveKekData1;
    struct HksBlob deriveKekData2;
    struct HksBlob originKey;
    uint32_t signatureDataLength;
};

int32_t HksSmImportWrappedKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *wrappingKey, const struct HksBlob *wrappedKeyData, struct HksBlob *keyOut);
#ifdef __cplusplus
}
#endif

#endif /* HKS_SM_IMPORT_WRAP_KEY_H */