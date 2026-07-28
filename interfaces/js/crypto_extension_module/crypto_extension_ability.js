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

class CryptoExtensionAbility {
    onOpenResource(resourceId, params){
        console.log();
    }
    
    onCloseResource(handle, params) {
        console.log();
    }

    onGetProperty(handle, params) {
        console.log();
    }

    onAuthUkeyPin(handle, params) {
        console.log();
    }

    onGerUkeyPinAuthState(handle, params) {
        console.log();
    }

    onClearUkeyPinAuthState(handle, params) {
        console.log();
    }

    onInitSession(handle, params) {
        console.log();
    }

    onUpdateSession(initHandle, params) {
        console.log();
    }

    onFinishSession(initHandle, params) {
        console.log();
    }

    onExportCertificate(resourceId, params) {
        console.log();
    }

    onEnumCertificates(params) {
        console.log();
    }
}

export default CryptoExtensionAbility;