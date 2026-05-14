/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#ifndef HKS_UKEY_EXTENSION_CRYPTO_TEST_H
#define HKS_UKEY_EXTENSION_CRYPTO_TEST_H

int HksRegisterProviderTest001(void);
int HksUnregisterProviderTest001(void);
int HksQueryAbilityInfoTest001(void);
int HksExportProviderCertificatesTest001(void);
int HksExportCertificateTest001(void);
int HksImportCertificateTest001(void);
int HksAuthUkeyPinTest001(void);
int HksGetUkeyPinAuthStateTest001(void);
int HksOpenRemoteHandleTest001(void);
int HksCloseRemoteHandleTest001(void);
int HksClearUkeyPinAuthStateTest001(void);
int HksGetRemotePropertyTest001(void);
int HksGetResourceIdTest001(void);

#endif