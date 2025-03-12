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
import { huks } from './@ohos.security.huks';

class HuksParamImpl implements huks.HuksParam {
  tag: huks.HuksTag = huks.HuksTag.HUKS_TAG_AE_TAG
  value: boolean | number | bigint | Uint8Array = 0
  constructor(tag : huks.HuksTag, value : boolean | number | bigint | Uint8Array) {
      this.tag = tag;
      this.value = value;
  }
}

class HuksOptionsImpl implements huks.HuksOptions {
  properties?: Array<huks.HuksParam> | undefined;
  inData?: Uint8Array | undefined;
  constructor(propertiesIn?: Array<huks.HuksParam> | undefined, inDataIn?: Uint8Array | undefined) {
      this.properties = propertiesIn;
      this.inData = inDataIn;
  }
}


let huksGenKeyOptions = new HuksOptionsImpl(
  new Array<huks.HuksParam>(
      new HuksParamImpl(huks.HuksTag.HUKS_TAG_ALGORITHM, huks.HuksKeyAlg.HUKS_ALG_RSA as number),
      new HuksParamImpl(huks.HuksTag.HUKS_TAG_PURPOSE, huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT as number),
      new HuksParamImpl(huks.HuksTag.HUKS_TAG_KEY_SIZE, huks.HuksKeySize.HUKS_RSA_KEY_SIZE_2048 as number),
  ),
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

function GenKeyTest()
{
  console.log("******** GenKeyTest start ********")
  let huksGenKeyOptions = new HuksOptionsImpl(
    new Array<huks.HuksParam>(
        new HuksParamImpl(huks.HuksTag.HUKS_TAG_ALGORITHM, huks.HuksKeyAlg.HUKS_ALG_DH as number),
        new HuksParamImpl(huks.HuksTag.HUKS_TAG_PURPOSE, huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_AGREE as number),
        new HuksParamImpl(huks.HuksTag.HUKS_TAG_KEY_SIZE, huks.HuksKeySize.HUKS_DH_KEY_SIZE_2048 as number),
    ),
  )
  let keyAlias = 'dh_key1';
  huks.generateKeyItem(keyAlias, huksGenKeyOptions, (err : BusinessError) => {
    console.log(`generateKeyItem callback finish. result.code = ${err.code}`)
  });
  console.log('huks generateKeyItemAsyncCallback endl***')

  keyAlias = 'dh_key2';
  try {
    let retPromise = await huks.generateKeyItem(keyAlias, huksGenKeyOptions);
    console.log(`generateKeyItem Promise finish. success!`)
  } catch (err) {
    console.error(`generateKeyItem Promise finish. failed! err = ${err}`)
  }
  console.log('huks generateKeyItemAsyncPromise endl')
}

function KeyIsExistTest()
{
    console.log("******** KeyIsExistTest start ********")
    let huksGenKeyOptions = new HuksOptionsImpl(
    new Array<huks.HuksParam>(
        new HuksParamImpl(huks.HuksTag.HUKS_TAG_ALGORITHM, huks.HuksKeyAlg.HUKS_ALG_DH as number),
        new HuksParamImpl(huks.HuksTag.HUKS_TAG_PURPOSE, huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_AGREE as number),
        new HuksParamImpl(huks.HuksTag.HUKS_TAG_KEY_SIZE, huks.HuksKeySize.HUKS_DH_KEY_SIZE_2048 as number),
    ),
    )
    let keyAlias = 'dh_key1';
    huks.isKeyItemExist(keyAlias, huksGenKeyOptions, (err : BusinessError) => {
    console.log(`isKeyItemExist callback finish. result.code = ${err.code}`)
    });
    console.log('huks generateKeyItemAsyncCallback endl***')

    keyAlias = 'dh_key2';
    try {
    let retPromise = await huks.isKeyItemExist(keyAlias, huksGenKeyOptions);
     console.log(`generateKeyItem Promise finish. success!`)
    } catch (err) {
        console.error(`generateKeyItem Promise finish. failed! err = ${err}`)
    }
    console.log('huks generateKeyItemAsyncPromise endl')
}