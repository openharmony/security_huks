/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef HKS_DCM_CALLBACK_HANDLER_H
#define HKS_DCM_CALLBACK_HANDLER_H

#ifdef __cplusplus
#include <cstdint>
#include <mutex>
#endif

typedef enum {
    DCM_SUCCESS = 0,
    DCM_ERROR_NETWORK_UNAVALIABLE = 20023,
    DCM_ERROR_SERVICE_TIME_OUT = 20024,
    DCM_ERROR_INVALID_PRIVACY_KEY = 30010
} DcmErrorCode;

struct DcmBlob {
    uint32_t size;
    uint8_t *data;
};

struct DcmCertChain {
    DcmBlob *certs;
    uint32_t certsCount;
};

typedef struct {
    DcmBlob blob;
    uint64_t requestId;
} DcmAnonymousRequest;

typedef struct {
    uint64_t requestId;
    uint32_t errCode;
    DcmBlob errInfo;
    DcmCertChain *certChain;
} DcmAnonymousResponse;

typedef struct {
    uint32_t callingUid;
    uint32_t curUTCTime;
    uint32_t tokenID;
    uint32_t remainValidatePeriod;
    uint64_t requestId;
} DcmApplyAnonymousRequest;

typedef void (*DcmCallback)(DcmAnonymousResponse *response);
typedef int32_t (*AttestFunction)(DcmAnonymousRequest *requset, DcmCallback callback);
typedef int32_t (*LocalAttestFunction)(DcmApplyAnonymousRequest *request, DcmBlob *localKeyAttest,
    DcmCallback callback);

#ifdef __cplusplus
extern "C" {
#endif

void HksDcmCallback(DcmAnonymousResponse *response);

void HksDcmOfflineCallback(DcmAnonymousResponse *response);

int32_t HksDcmCallbackHandlerSetRequestIdWithoutLock(const uint8_t *remoteObject, uint64_t requestId);

int32_t HksDcmOfflineCallbackHandlerSetRequestIdWithoutLock(const uint8_t *remoteObject, uint64_t requestId);

void HksCloseDcmFunction(void);

#ifdef __cplusplus
} // extern "C"

std::mutex &HksDcmCallbackHandlerGetMapMutex(void);

std::mutex &HksDcmOfflineCallbackHandlerGetMapMutex(void);

template<typename T>
T HksGetDcmFunction(const char* functionName);
#endif

#endif // HKS_DCM_CALLBACK_HANDLER_H