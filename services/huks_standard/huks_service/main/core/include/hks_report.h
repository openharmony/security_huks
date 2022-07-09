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

#ifndef HKS_REPORT_H
#define HKS_REPORT_H

#include <stdint.h>
#include "hisysevent_wrapper.h"

#define EXTRA_DATA_SIZE 512


#ifdef __cplusplus
extern "C" {
#endif

#define STRING_TAG_ALGORITHM "algorithm"
extern const struct HksBlob tagAlgorithm;

#define STRING_TAG_KEY_SIZE "keySize"
extern const struct HksBlob tagKeySize;

#define STRING_TAG_DIGEST "digest"
extern const struct HksBlob tagDigest;

#define STRING_TAG_BLOCK_MODE "blockMode"
extern const struct HksBlob tagBlockMode;

#define STRING_TAG_UNWRAP_ALGORITHM_SUITE "unwrapAlgorithmSuit"
extern const struct HksBlob tagUnwrapAlgorithmSuit;

#define STRING_TAG_ITERATION "iteration"
extern const struct HksBlob tagIteration;

#define STRING_TAG_PURPOSE "purpose"
extern const struct HksBlob tagPurpose;

int32_t ReportFaultEvent(const char *funcName, const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSetIn, int32_t errorCode);

#ifdef __cplusplus
}
#endif

#endif
