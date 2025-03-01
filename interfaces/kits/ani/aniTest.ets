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
import huks from './@ohos.security.huks';

loadLibrary("huks_interfaceImpl.z")

export class Calc {

    native sum(a: int, b: int): int;

    // native generateKeyItemSync(keyAlias: string, options: huks.HuksOptions): HuksResult;
    native generateKeyItemSync(keyAlias: string): Result;
}

interface Result {
    result: int;
    error?: string | undefined;
}

class HuksResult implements Result {
    result: int = 1;
    error?: string | undefined = "";
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
    
    constructor(properties?: Array<huks.HuksParam> | undefined, inData?: Uint8Array | undefined) {
        console.log("HuksOptionsImpl constructor running")
        this.properties = properties;
        this.inData = inData;
    }
}

function main(){
    console.println("hello ani")
    let c = new Calc;
    let result = c.sum(1, 2)
    let huksOptions = new HuksOptionsImpl(
        new Array<huks.HuksParam>(
            new HuksParamImpl(huks.HuksTag.HUKS_TAG_ALGORITHM, 103 as number),
            new HuksParamImpl(huks.HuksTag.HUKS_TAG_PURPOSE, 256 as number),
            new HuksParamImpl(huks.HuksTag.HUKS_TAG_KEY_SIZE, 2048 as number),
        ),
        // new NativeBuffer(new Array())
    )
    console.log("********new HUKSNativeModule Sync start******")
    let keyAlias = 'dh_key';
    let ret = c.generateKeyItemSync(keyAlias);
    console.log(`huks generateKeyItemSync endl. ${ret.result}`)
    console.log(ret.error)
    console.println("result from native")
    console.println(result)
}
