/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { huks } from './huksInterface';

loadLibrary("huks_interfaceImpl.z")

export class Huks {    
    native sum(a: int, b: int): int;
    native generateKeyItemSync(keyAlias: string, options: huks.HuksOptions): HuksResult;
    native deleteKeyItemSync(keyAlias: string, options: huks.HuksOptions): HuksResult;
    native importKeyItemSync(keyAlias: string, options: huks.HuksOptions): HuksResult;
    native importWrappedKeyItemSync(keyAlias: string, wrappingKeyAlias: string, options: huks.HuksOptions): HuksResult;
    native exportKeyItemSync(keyAlias: string, options: huks.HuksOptions): HuksResult;
    native isKeyItemExistSync(keyAlias: string, options: huks.HuksOptions): HuksResult;
    native initSessionSync(keyAlias: string, options: huks.HuksOptions): HuksResult;
    native updateFinishSessionSync(handle: int, options: huks.HuksOptions, isUpdate: boolean): HuksResult;
    native abortSessionSync(keyAlias: string, options: huks.HuksOptions): HuksResult;
}

interface Result {
    result: int;
    error?: string | undefined;
    outData?: Uint8Array | undefined;
    handle?: int | undefined;
    challenge?: Uint8Array |undefined;
}

class HuksResult implements Result {
    result: int = 1
    error?: string | undefined = ""
    outData?: Uint8Array | undefined
    handle?: int | undefined;
    challenge?: Uint8Array |undefined;
    // constructor(result: int, error?: string | undefined) {
    //     console.log("HuksResult constructor******")
    //     this.result = result;
    //     this.error = error;
    // }
}

class HuksParamImpl implements huks.HuksParam {
    tag: huks.HuksTag
    value: boolean | number | bigint | Uint8Array = 0
    
    constructor(tag : huks.HuksTag, value : boolean | number | bigint | Uint8Array) {
        console.log("HuksParamImpl constructor******")
        this.tag = tag;
        this.value = value;
    }
}
class HuksOptionsImpl implements huks.HuksOptions {
    properties?: Array<huks.HuksParam> | undefined;
    inData?: Uint8Array | undefined;
    constructor(propertiesIn?: Array<huks.HuksParam> | undefined, inDataIn?: Uint8Array | undefined) {
        console.log("HuksOptionsImpl constructor running")
        this.properties = propertiesIn;
        this.inData = inDataIn;
        // let dh : int = huks.HuksKeyAlg.HUKS_ALG_DH;
        // console.log(`test enum is support? let dh : int = huks.HuksKeyAlg.HUKS_ALG_DH. dh = ${dh}`)
    }
}

let huksGenKeyOptions = new HuksOptionsImpl(
    new Array<huks.HuksParam>(
        new HuksParamImpl(huks.HuksTag.HUKS_TAG_ALGORITHM, 103 as number),
        // new HuksParamImpl(huks.HuksTag.HUKS_TAG_ALGORITHM, huks.HuksKeyAlg.HUKS_ALG_DH as number),
        new HuksParamImpl(huks.HuksTag.HUKS_TAG_PURPOSE, 256 as number),
        // new HuksParamImpl(huks.HuksTag.HUKS_TAG_PURPOSE, huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_AGREE as number),
        new HuksParamImpl(huks.HuksTag.HUKS_TAG_KEY_SIZE, 2048 as number),
        // new HuksParamImpl(huks.HuksTag.HUKS_TAG_KEY_SIZE, huks.HuksKeySize.HUKS_DH_KEY_SIZE_2048 as number),
    ),
    // new Array()
)

let huksImportKeyOptions = new HuksOptionsImpl(
    new Array<huks.HuksParam>(
        new HuksParamImpl(huks.HuksTag.HUKS_TAG_ALGORITHM, 20 as number),
        new HuksParamImpl(huks.HuksTag.HUKS_TAG_PURPOSE, 3 as number),
        new HuksParamImpl(huks.HuksTag.HUKS_TAG_KEY_SIZE, 256 as number),
    ),
    new Uint8Array([
        0xfb, 0x8b, 0x9f, 0x12, 0xa0, 0x83, 0x19, 0xbe, 0x6a, 0x6f, 0x63, 0x2a, 0x7c, 0x86, 0xba, 0xca,
        0x64, 0x0b, 0x88, 0x96, 0xe2, 0xfa, 0x77, 0xbc, 0x71, 0xe3, 0x0f, 0x0f, 0x9e, 0x3c, 0xe5, 0xf9
    ])
)

function main(){
    console.println("hello ani")
    let hukstest = new Huks;
    let result = hukstest.sum(1, 2)

    console.log("********new HUKSNativeModule Sync start******")
    let keyAlias = 'dh_key';
    let ret = hukstest.generateKeyItemSync(keyAlias, huksGenKeyOptions);
    console.log(`huks generateKeyItemSync endl. ${ret.result}`)
    console.log(ret.error)

    ret = hukstest.isKeyItemExistSync(keyAlias, huksGenKeyOptions);
    console.log(`huks isKeyItemExistSync endl. deletkey before, result shuold be 0: real = ${ret.result}`)
    console.log(ret.error)

    ret = hukstest.deleteKeyItemSync(keyAlias, huksGenKeyOptions);
    console.log(`huks deleteKeyItemSync endl. ${ret.result}`)
    console.log(ret.error)

    ret = hukstest.isKeyItemExistSync(keyAlias, huksGenKeyOptions);
    console.log(`huks isKeyItemExistSync endl. deletkey after, result shuold be -13: real = ${ret.result}`)
    console.log(ret.error)

    ret = hukstest.importKeyItemSync(keyAlias + "import", huksImportKeyOptions);
    console.log(`huks importKeyItemSync endl. ${ret.result}`)
    console.log(ret.error)

    ret = hukstest.exportKeyItemSync(keyAlias + "export", huksImportKeyOptions);
    console.log(`huks exportKeyItemSync endl. ${ret.result}`)
    console.log(ret.error)

    console.println("result from native")
    console.log(`test enum is support? huks.HuksKeyAlg.HUKS_ALG_DH as number = ${huks.HuksKeyAlg.HUKS_ALG_DH as number}`)
    console.println(result)
}
