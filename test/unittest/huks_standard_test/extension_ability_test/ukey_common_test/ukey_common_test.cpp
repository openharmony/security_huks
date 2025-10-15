#include <gtest/gtest.h>
#include <thread>
#include <chrono>

#include "hks_log.h"
#include "hks_json_wrapper.h"
#include "hks_util.h"
#include "hks_ukey_common.h"
#include "hks_cpp_paramset.h"
#include "hks_mem.h"
#include "securec.h"

using namespace testing::ext;
using namespace OHOS::Security::Huks;
namespace Unittest::UkeyComm {
class UkeyCommonTest : public testing::Test 
{
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp() override;

    void TearDown() override;
};

void UkeyCommonTest::SetUpTestCase(void) {}

void UkeyCommonTest::TearDownTestCase(void) {}

void UkeyCommonTest::SetUp() {}

void UkeyCommonTest::TearDown() {}

constexpr int32_t testNum = 30;
static void JsonWrapperBasicTest()
{
    CommJsonObject root = CommJsonObject::CreateObject();

    CommJsonObject name = CommJsonObject::CreateString("John Doe");
    CommJsonObject nameCopy = name.Clone();
    ASSERT_EQ(root.SetValue("name", std::move(nameCopy)), true);
    ASSERT_EQ(name.IsNull(), false);

    CommJsonObject tempAge = CommJsonObject::CreateNumber(testNum);
    ASSERT_EQ(root.SetValue("age", std::move(tempAge)), true);
    ASSERT_EQ(tempAge.IsNull(), true);
    ASSERT_EQ(root.SetValue("age", CommJsonObject::CreateNumber(testNum)), true);
    ASSERT_EQ(root.SetValue("isStudent", CommJsonObject::CreateBool(false)), true);

    CommJsonObject address = CommJsonObject::CreateObject();
    ASSERT_EQ(address.SetValue("street", CommJsonObject::CreateString("123 Main St")), true);
    ASSERT_EQ(address.SetValue("city", CommJsonObject::CreateString("New York")), true);
    ASSERT_EQ(root.SetValue("address", address), true);
    ASSERT_EQ(root.SetValue("address1", std::string{ "huawei.com" }), true);
    ASSERT_EQ(root["address1"].IsString(), true);
    ASSERT_EQ(root.SetValue("hight", 199.2), true);
    ASSERT_EQ(root.SetValue("hight2", 199), true);
    ASSERT_EQ(root.SetValue("hight3", -199), true);
    ASSERT_EQ(root["hight3"].IsNumber(), true);
    ASSERT_EQ(root.SetValue("boolTest", false), true);
    ASSERT_EQ(root["boolTest"].IsBool(), true);
    ASSERT_EQ(root.IsObject(), true);

    CommJsonObject hobbies = CommJsonObject::CreateArray();
    ASSERT_EQ(hobbies.IsArray(), true);
    ASSERT_EQ(hobbies.AppendElement(CommJsonObject::CreateString("reading")), true);
    ASSERT_EQ(hobbies.AppendElement(CommJsonObject::CreateString("hiking")), true);
    CommJsonObject element = CommJsonObject::CreateString("hiking2");
    ASSERT_EQ(hobbies.AppendElement(element), true);
    ASSERT_EQ(hobbies.IsArray(), true);
    hobbies.RemoveElement(1);
    ASSERT_EQ(root.SetValue("hobbies", hobbies), true);
    ASSERT_EQ(hobbies.ArraySize(), 2);

    std::string jsonStr = root.Serialize(false);
    CommJsonObject parsed = CommJsonObject::Parse(jsonStr);
    ASSERT_EQ(parsed["name"].ToString().second, "John Doe");
    EXPECT_EQ(parsed[1].ToString().second, "");
    EXPECT_EQ(parsed[1].ToBool().first, HKS_ERROR_JSON_NOT_ARRAY);
    EXPECT_EQ(parsed.SetElement(0, CommJsonObject::CreateString("John jump")), false);
    ASSERT_EQ(parsed["age"].ToNumber<uint32_t>().second, testNum);
    ASSERT_EQ(parsed["isStudent"].ToBool().second, false);
    ASSERT_EQ(parsed["address"]["city"].ToString().second, "New York");
    ASSERT_EQ(parsed["hobbies"][0].ToString().second, "reading");

    auto jsonBytes = parsed.SerializeToBytes();
    auto jsonObj = CommJsonObject::DeserializeFromBytes(jsonBytes);
    ASSERT_EQ(jsonObj["name"].ToString().second, "John Doe");
    ASSERT_EQ(jsonObj["age"].ToNumber<uint32_t>().second, testNum);
    ASSERT_EQ(jsonObj["isStudent"].ToBool().second, false);
    ASSERT_EQ(jsonObj["address"]["city"].ToString().second, "New York");
    ASSERT_EQ(jsonObj["hobbies"][0].ToString().second, "reading");
    ASSERT_EQ(jsonObj["hight"].ToDouble().second, 199.2);
    ASSERT_EQ(jsonObj["hight2"].ToNumber<int>().second, 199);
    ASSERT_EQ(jsonObj["hight3"].ToNumber<int>().second, -199);
    ASSERT_EQ(jsonObj["address1"].ToString().second, "huawei.com");
    std::vector<std::string> keyList = jsonObj.GetKeys();
    ASSERT_EQ(jsonObj.HasKey("hight2"), true);
    jsonObj.RemoveKey("hight2");
    ASSERT_EQ(jsonObj.HasKey("hight2"), false);

    CommJsonObject testGet = jsonObj.GetValue("address1");
    ASSERT_EQ(testGet.ToString().second, "huawei.com");
    testGet = jsonObj.GetValue("empty");
    ASSERT_EQ(testGet.IsNull(), true);
}


static void JsonWrapperBinarySerializationTest()
{
    CommJsonObject original = CommJsonObject::CreateObject();
    ASSERT_EQ(original.SetValue("id", CommJsonObject::CreateNumber(testNum)), true);
    ASSERT_EQ(original.SetValue("data", CommJsonObject::CreateString("Hello Binary!")), true);

    std::vector<uint8_t> bytes = original.SerializeToBytes();
    CommJsonObject restored = CommJsonObject::DeserializeFromBytes(bytes);

    ASSERT_EQ(restored["id"].ToNumber<uint32_t>().second, testNum);
    ASSERT_EQ(restored["data"].ToString().second, "Hello Binary!");
}

/* *
 * @tc.name: UkeyCommonTest.UkeyCommonTest001
 * @tc.desc: success
 * @tc.type: FUNC
 */
HWTEST_F(UkeyCommonTest, UkeyCommonTest001, TestSize.Level0)
{
    JsonWrapperBasicTest();
    JsonWrapperBinarySerializationTest();

    CommJsonObject jsonNull = CommJsonObject::CreateNull(HKS_ERROR_NULL_JSON);
    ASSERT_EQ(jsonNull.IsNull(), true);
    ASSERT_EQ(jsonNull.IsArray(), false);

    CommJsonObject emptyObj = CommJsonObject::Parse("");
    ASSERT_EQ(emptyObj.IsNull(), true);
    ASSERT_EQ(emptyObj.ToString().second, "");
    ASSERT_EQ(emptyObj.ToDouble().second, HUGE_VAL);
    ASSERT_EQ(emptyObj.ToBool().second, false);
    ASSERT_EQ(emptyObj.HasKey("test"), false);
    ASSERT_EQ(emptyObj.SetValue("test", 0), false);
    ASSERT_EQ(emptyObj.SetValue("test", jsonNull), false);
    [[maybe_unused]]std::vector<std::string> keyList = emptyObj.GetKeys();
    emptyObj.RemoveKey("test2");
    ASSERT_EQ(emptyObj.ArraySize(), INVALID_ARRAY_SIZE);

    uint8_t unit8Value = 0x25;
    std::map<std::string, Var> testMap {
        {"xiaolin", "banzhang"},
        {"xiaohong", 0},
        {"xiaochen", false},
        {"xiaozhou", INVALID_ARRAY_SIZE},
        {"xiaohu", (uint32_t) 1},
        {"xiaofang", (int64_t) 1},
        {"xiaowa", unit8Value},
        {"xiaofasf", (double) 1},
        {"xiaoju", (float) 1}
    };
    auto cJsonRet = CommJsonObject::MapToJson(testMap);
    ASSERT_EQ(cJsonRet.first, HKS_SUCCESS);
    HKS_LOG_I("Json: %" LOG_PUBLIC "s", cJsonRet.second.data());
    auto retMap = CommJsonObject::JsonToMap(cJsonRet.second);
    ASSERT_EQ(retMap.first, HKS_SUCCESS);
    ASSERT_EQ(retMap.second.size(), testMap.size());
    ASSERT_EQ(retMap.second["xiaolin"], testMap["xiaolin"]);
    ASSERT_EQ(retMap.second["xiaohong"], testMap["xiaohong"]);
    ASSERT_EQ(retMap.second["xiaochen"], testMap["xiaochen"]);
    ASSERT_EQ(retMap.second["xiaozhou"], testMap["xiaozhou"]);
    ASSERT_EQ(retMap.second["xiaohu"], testMap["xiaohu"]);
    ASSERT_EQ(retMap.second["xiaofang"], testMap["xiaofang"]);
    ASSERT_EQ(retMap.second["xiaowa"], testMap["xiaowa"]);
    ASSERT_EQ(retMap.second["xiaofasf"], testMap["xiaofasf"]);
}

/* *
 * @tc.name: UkeyCommonTest.UkeyCommonTest002
 * @tc.desc: success
 * @tc.type: FUNC
 */
HWTEST_F(UkeyCommonTest, UkeyCommonTest002, TestSize.Level0)
{
    std::vector<uint8_t> input1;
    auto [ret1, result1] = U8Vec2Base64Str(input1);
    EXPECT_EQ(ret1, HKS_SUCCESS);
    EXPECT_TRUE(result1.empty());

    std::vector<uint8_t> input2 = {0x12};
    auto [ret2, result2] = U8Vec2Base64Str(input2);
    EXPECT_EQ(ret2, HKS_SUCCESS);
    EXPECT_EQ(result2, "Eg==");
    auto [ret22, result22] = Base64Str2U8Vec(result2);
    EXPECT_EQ(ret22, HKS_SUCCESS);

    std::vector<uint8_t> input3 = {0x12, 0x34};
    auto [ret3, result3] = U8Vec2Base64Str(input3);
    EXPECT_EQ(ret3, HKS_SUCCESS);
    EXPECT_EQ(result3, "EjQ=");
    auto [ret33, result33] = Base64Str2U8Vec(result3);
    EXPECT_EQ(ret33, HKS_SUCCESS);

    std::vector<uint8_t> input4 = {0x12, 0x34, 0x76};
    auto [ret4, result4] = U8Vec2Base64Str(input4);
    EXPECT_EQ(ret4, HKS_SUCCESS);
    EXPECT_EQ(result4, "EjR2");
    auto [ret44, result44] = Base64Str2U8Vec(result4);
    EXPECT_EQ(ret44, HKS_SUCCESS);

    std::vector<uint8_t> input5 = {0x12, 0x34, 0x76, 0x78, 0x9A, 0xBC}; 
    auto [ret5, result5] = U8Vec2Base64Str(input5);
    EXPECT_EQ(ret5, HKS_SUCCESS);
    EXPECT_EQ(result5, "EjR2eJq8");
    auto [ret55, result55] = Base64Str2U8Vec(result5);
    EXPECT_EQ(ret55, HKS_SUCCESS);

    std::vector<uint8_t> input6 = {0x12, 0x34, 0x76, 0x78, 0x9A};
    auto [ret6, result6] = U8Vec2Base64Str(input6);
    EXPECT_EQ(ret6, HKS_SUCCESS);
    EXPECT_EQ(result6, "EjR2eJo=");
    auto [ret66, result66] = Base64Str2U8Vec(result6);
    EXPECT_EQ(ret66, HKS_SUCCESS);

    std::vector<uint8_t> input7 = {0xFF, 0xE0, 0x0F, 0xFF, 0x40, 0x40, 0x3F, 0x8F, 0x00};
    auto [ret7, result7] = U8Vec2Base64Str(input7);
    EXPECT_EQ(ret7, HKS_SUCCESS);
    EXPECT_EQ(result7, "/+AP/0BAP48A");
    auto [ret77, result77] = Base64Str2U8Vec(result7);
    EXPECT_EQ(ret77, HKS_SUCCESS);
}

/* *
 * @tc.name: UkeyCommonTest.UkeyCommonTest003
 * @tc.desc: success
 * @tc.type: FUNC
 */
HWTEST_F(UkeyCommonTest, UkeyCommonTest003, TestSize.Level0)
{
    std::string emptyStr;
    std::vector<uint8_t> buffer1 = {1, 2, 3};
    auto [ret1, result1] = Base64Str2U8Vec(emptyStr);
    EXPECT_EQ(ret1, HKS_SUCCESS);
    EXPECT_TRUE(result1.empty());

    std::string invalidStr = "MQ==A";
    auto [ret2, buffer2] = Base64Str2U8Vec(invalidStr);
    EXPECT_EQ(ret2, HKS_COMM_BASE64_SIZE_ERROR);
    EXPECT_TRUE(buffer2.empty());

    std::string invalidStr3 = "SGVsbG8gV29ybGQ%";
    auto [ret3, buffer3] = Base64Str2U8Vec(invalidStr3);
    EXPECT_EQ(ret3, HKS_COMM_BASE64_CHAR_INVAILD);
    EXPECT_TRUE(buffer3.empty());

    std::string invalidStr4 = "SGVsbG8gV29ybGQ=====";
    auto [ret4, buffer4] = Base64Str2U8Vec(invalidStr4);
    EXPECT_EQ(ret4, HKS_COMM_BASE64_PADDING_INVAILD);
    EXPECT_TRUE(buffer4.empty());

    std::string invalidStr5 = "SGVsbG8g=V29ybGQ====";
    auto [ret5, buffer5] = Base64Str2U8Vec(invalidStr5);
    EXPECT_EQ(ret5, HKS_COMM_BASE64_PADDING_INVAILD);
    EXPECT_TRUE(buffer5.empty());

    std::string base64 = "SGVsbG8gV29ybGQh";
    auto [ret6, buffer6] = Base64Str2U8Vec(base64);
    EXPECT_EQ(ret6, HKS_SUCCESS);
    std::vector<uint8_t> expected = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21};
    EXPECT_EQ(buffer6, expected);
}


HWTEST_F(UkeyCommonTest, UkeyCommonTest004, TestSize.Level0)
{
    std::vector<HksParam> g_genAesParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
    };
    CppParamSet paramset(g_genAesParams);
    std::vector<HksParam> newParams = {
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CCM}
    };
    EXPECT_EQ(paramset.AddParams(newParams), true);
    

    HksParam paramsUserId1000[] = { {.tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = 1000} };
    HksParamSet *paramSetSpecificUserId1000 = nullptr;
    CppParamSet paramset2(paramSetSpecificUserId1000);
    EXPECT_EQ(HksInitParamSet(&paramSetSpecificUserId1000), HKS_SUCCESS);
    EXPECT_EQ(HksAddParams(paramSetSpecificUserId1000, paramsUserId1000, std::size(paramsUserId1000)), HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramSetSpecificUserId1000), HKS_SUCCESS);
    CppParamSet paramset3(paramSetSpecificUserId1000);

    CppParamSet paramset4(paramSetSpecificUserId1000, newParams);
    CppParamSet paramset5(paramset, newParams);
    CppParamSet paramset6(paramset5);
    CppParamSet paramset7;
    paramset7 = paramset5;
    CppParamSet paramset8(std::move(paramset5));
    CppParamSet paramset9;
    paramset9 = std::move(paramset5);

    CppParamSet paramset10(paramSetSpecificUserId1000, false);
    std::string testStr = "testHuksUtil";
    HksBlob testBlob = StringToBlob(testStr);
    CppParamSet paramset11(testBlob);
}

HWTEST_F(UkeyCommonTest, UkeyCommonTest005, TestSize.Level0)
{
    {
        CommJsonObject invalidJson(nullptr, HKS_ERROR_NULL_JSON, "invalid", false);
        auto result = invalidJson.ToString();
        EXPECT_EQ(result.first, HKS_ERROR_NULL_JSON);
        EXPECT_EQ(result.second, "");

        CommJsonObject nullJson(nullptr, HKS_SUCCESS, "null", false);
        result = nullJson.ToString();
        EXPECT_EQ(result.first, HKS_ERROR_NULL_JSON);
        EXPECT_EQ(result.second, "");

        CommJsonObject numberJson = CommJsonObject::CreateNumber(123.45);
        result = numberJson.ToString();
        EXPECT_EQ(result.first, HKS_ERROR_JSON_NOT_STRING);
        EXPECT_EQ(result.second, "");
    }

    {
        CommJsonObject invalidJson(nullptr, HKS_ERROR_NULL_JSON, "invalid", false);
        auto result = invalidJson.ToDouble();
        EXPECT_EQ(result.first, HKS_ERROR_NULL_JSON);
        EXPECT_EQ(result.second, HUGE_VAL);

        CommJsonObject nullJson(nullptr, HKS_SUCCESS, "null", false);
        result = nullJson.ToDouble();
        EXPECT_EQ(result.first, HKS_ERROR_NULL_JSON);
        EXPECT_EQ(result.second, HUGE_VAL);

        CommJsonObject stringJson = CommJsonObject::CreateString("test");
        result = stringJson.ToDouble();
        EXPECT_EQ(result.first, HKS_ERROR_JSON_NOT_NUMBER);
        EXPECT_EQ(result.second, HUGE_VAL);
    }
}

HWTEST_F(UkeyCommonTest, UkeyCommonTest006, TestSize.Level0)
{
    {
        CommJsonObject invalidJson(nullptr, HKS_ERROR_NULL_JSON, "invalid", false);
        auto result = invalidJson.ToBool();
        EXPECT_EQ(result.first, HKS_ERROR_NULL_JSON);
        EXPECT_FALSE(result.second);

        CommJsonObject nullJson(nullptr, HKS_SUCCESS, "null", false);
        result = nullJson.ToBool();
        EXPECT_EQ(result.first, HKS_ERROR_NULL_JSON);
        EXPECT_FALSE(result.second);

        CommJsonObject stringJson = CommJsonObject::CreateString("test");
        result = stringJson.ToBool();
        EXPECT_EQ(result.first, HKS_ERROR_JSON_NOT_BOOL);
        EXPECT_FALSE(result.second);
    }

    {
        CommJsonObject invalidJson(nullptr, HKS_SUCCESS, "invalid", false);
        CommJsonObject value = invalidJson.GetValue("someKey");
        EXPECT_TRUE(value.IsNull());

        CommJsonObject arrayJson = CommJsonObject::CreateArray();
        value = arrayJson.GetValue("someKey");
        EXPECT_TRUE(value.IsNull());

        CommJsonObject objectJson = CommJsonObject::CreateObject();
        value = objectJson.GetValue("nonexistentKey");
        EXPECT_TRUE(value.IsNull());
    }
}

HWTEST_F(UkeyCommonTest, UkeyCommonTest007, TestSize.Level0)
{
    CommJsonObject invalidJson(nullptr, HKS_ERROR_NULL_JSON, "invalid", false);
    CommJsonObject element = invalidJson.GetElement(0);
    EXPECT_TRUE(element.IsNull());

    CommJsonObject objectJson = CommJsonObject::CreateObject();
    element = objectJson.GetElement(0);
    EXPECT_TRUE(element.IsNull());
}

HWTEST_F(UkeyCommonTest, UkeyCommonTest008, TestSize.Level0)
{
    // Test IsHksBlobEmpty
    HksBlob emptyBlob = {0, nullptr};
    EXPECT_TRUE(IsHksBlobEmpty(emptyBlob));

    HksBlob validBlob = {5, reinterpret_cast<uint8_t*>(HksMalloc(5))};
    EXPECT_FALSE(IsHksBlobEmpty(validBlob));
    HKS_FREE(validBlob.data);

    HksBlob zeroSizeBlob = {0, reinterpret_cast<uint8_t*>(HksMalloc(5))};
    EXPECT_TRUE(IsHksBlobEmpty(zeroSizeBlob));
    HKS_FREE(zeroSizeBlob.data);

    // Test IsHksExtCertInfoSetEmpty
    HksExtCertInfoSet emptyCertSet = {0, nullptr};
    EXPECT_TRUE(IsHksExtCertInfoSetEmpty(emptyCertSet));

    HksExtCertInfoSet validCertSet = {2, 
        reinterpret_cast<HksExtCertInfo*>(HksMalloc(2 * sizeof(HksExtCertInfo)))};
    EXPECT_FALSE(IsHksExtCertInfoSetEmpty(validCertSet));
    HKS_FREE(validCertSet.certs);
}

/* *
 * @tc.name: UkeyCommonTest.UkeyCommonTest009
 * @tc.desc: Test StringToBlob and BlobToString functions
 * @tc.type: FUNC
 */
HWTEST_F(UkeyCommonTest, UkeyCommonTest009, TestSize.Level0)
{
    // Test StringToBlob with empty string
    std::string emptyStr;
    HksBlob emptyBlob = StringToBlob(emptyStr);
    EXPECT_TRUE(IsHksBlobEmpty(emptyBlob));

    // Test StringToBlob with valid string
    std::string testStr = "Hello, World!";
    HksBlob testBlob = StringToBlob(testStr);
    EXPECT_FALSE(IsHksBlobEmpty(testBlob));
    EXPECT_EQ(testBlob.size, testStr.size());
    EXPECT_EQ(memcmp(testBlob.data, testStr.data(), testStr.size()), 0);

    // Test BlobToString with empty blob
    HksBlob nullBlob = {0, nullptr};
    std::string resultStr = BlobToString(nullBlob);
    EXPECT_TRUE(resultStr.empty());

    // Test BlobToString with valid blob
    resultStr = BlobToString(testBlob);
    EXPECT_EQ(resultStr, testStr);

    // Clean up
    HKS_FREE(testBlob.data);
}

/* *
 * @tc.name: UkeyCommonTest.UkeyCommonTest010
 * @tc.desc: Test StringToCertInfo and CertInfoToString functions
 * @tc.type: FUNC
 */
HWTEST_F(UkeyCommonTest, UkeyCommonTest010, TestSize.Level0)
{
    // Test StringToCertInfo with empty string
    std::string emptyJson;
    HksExtCertInfo certInfo = {0};
    int32_t ret = StringToCertInfo(emptyJson, certInfo);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    // Test StringToCertInfo with invalid JSON
    std::string invalidJson = "invalid json";
    ret = StringToCertInfo(invalidJson, certInfo);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    // Test StringToCertInfo with valid JSON containing all fields
    std::string validJson = R"({
        "purpose": 1,
        "index": "test_index",
        "cert": "test_cert_data"
    })";
    ret = StringToCertInfo(validJson, certInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(certInfo.purpose, 1);
    EXPECT_FALSE(IsHksBlobEmpty(certInfo.index));
    EXPECT_FALSE(IsHksBlobEmpty(certInfo.cert));
    
    std::string indexStr = BlobToString(certInfo.index);
    std::string certStr = BlobToString(certInfo.cert);
    EXPECT_EQ(indexStr, "test_index");
    EXPECT_EQ(certStr, "test_cert_data");

    // Test CertInfoToString
    std::string outputJson;
    ret = CertInfoToString(certInfo, outputJson);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_FALSE(outputJson.empty());

    // Verify the output can be parsed back
    HksExtCertInfo parsedCertInfo = {0};
    ret = StringToCertInfo(outputJson, parsedCertInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(parsedCertInfo.purpose, certInfo.purpose);
    
    std::string parsedIndexStr = BlobToString(parsedCertInfo.index);
    std::string parsedCertStr = BlobToString(parsedCertInfo.cert);
    EXPECT_EQ(parsedIndexStr, indexStr);
    EXPECT_EQ(parsedCertStr, certStr);

    // Clean up
    HKS_FREE(certInfo.index.data);
    HKS_FREE(certInfo.cert.data);
    HKS_FREE(parsedCertInfo.index.data);
    HKS_FREE(parsedCertInfo.cert.data);

    // Test StringToCertInfo with partial JSON (only purpose)
    std::string partialJson = R"({"purpose": 2})";
    HksExtCertInfo partialCertInfo = {0};
    ret = StringToCertInfo(partialJson, partialCertInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(partialCertInfo.purpose, 2);
    EXPECT_TRUE(IsHksBlobEmpty(partialCertInfo.index));
    EXPECT_TRUE(IsHksBlobEmpty(partialCertInfo.cert));
}

/* *
 * @tc.name: UkeyCommonTest.UkeyCommonTest011
 * @tc.desc: Test JsonArrayToCertInfoSet and CertInfoSetToJsonArray functions
 * @tc.type: FUNC
 */
HWTEST_F(UkeyCommonTest, UkeyCommonTest011, TestSize.Level0)
{
    // Test JsonArrayToCertInfoSet with empty string
    std::string emptyArray;
    HksExtCertInfoSet certSet = {0, nullptr};
    int32_t ret = JsonArrayToCertInfoSet(emptyArray, certSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    // Test JsonArrayToCertInfoSet with invalid JSON array
    std::string invalidArray = "invalid array";
    ret = JsonArrayToCertInfoSet(invalidArray, certSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    // Test JsonArrayToCertInfoSet with valid JSON array
    std::string validArray = R"([
        {
            "purpose": 1,
            "index": "index1",
            "cert": "cert1"
        },
        {
            "purpose": 2,
            "index": "index2",
            "cert": "cert2"
        }
    ])";
    ret = JsonArrayToCertInfoSet(validArray, certSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(certSet.count, 2);
    EXPECT_NE(certSet.certs, nullptr);

    // Verify the parsed data
    EXPECT_EQ(certSet.certs[0].purpose, 1);
    EXPECT_EQ(certSet.certs[1].purpose, 2);
    
    std::string index1 = BlobToString(certSet.certs[0].index);
    std::string cert1 = BlobToString(certSet.certs[0].cert);
    std::string index2 = BlobToString(certSet.certs[1].index);
    std::string cert2 = BlobToString(certSet.certs[1].cert);
    
    EXPECT_EQ(index1, "index1");
    EXPECT_EQ(cert1, "cert1");
    EXPECT_EQ(index2, "index2");
    EXPECT_EQ(cert2, "cert2");

    // Test CertInfoSetToJsonArray
    std::string outputArray;
    ret = CertInfoSetToJsonArray(certSet, outputArray);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_FALSE(outputArray.empty());

    // Verify the output can be parsed back
    HksExtCertInfoSet parsedCertSet = {0, nullptr};
    ret = JsonArrayToCertInfoSet(outputArray, parsedCertSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(parsedCertSet.count, certSet.count);

    // Clean up
    FreeCertInfoSet(certSet);
    FreeCertInfoSet(parsedCertSet);

    // Test JsonArrayToCertInfoSet with empty array
    std::string emptyJsonArray = "[]";
    HksExtCertInfoSet emptyCertSet = {0, nullptr};
    ret = JsonArrayToCertInfoSet(emptyJsonArray, emptyCertSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/* *
 * @tc.name: UkeyCommonTest.UkeyCommonTest012
 * @tc.desc: Test FreeCertInfoSet function
 * @tc.type: FUNC
 */
HWTEST_F(UkeyCommonTest, UkeyCommonTest012, TestSize.Level0)
{
    // Test FreeCertInfoSet with empty set
    HksExtCertInfoSet emptySet = {0, nullptr};
    FreeCertInfoSet(emptySet);
    EXPECT_EQ(emptySet.count, 0);
    EXPECT_EQ(emptySet.certs, nullptr);

    // Test FreeCertInfoSet with valid set
    HksExtCertInfoSet validSet = {2, 
        reinterpret_cast<HksExtCertInfo*>(HksMalloc(2 * sizeof(HksExtCertInfo)))};
    
    // Initialize the certs
    for (uint32_t i = 0; i < validSet.count; i++) {
        validSet.certs[i].purpose = i + 1;
        validSet.certs[i].index = StringToBlob("index_" + std::to_string(i));
        validSet.certs[i].cert = StringToBlob("cert_" + std::to_string(i));
    }

    FreeCertInfoSet(validSet);
    EXPECT_EQ(validSet.count, 0);
    EXPECT_EQ(validSet.certs, nullptr);
}

/* *
 * @tc.name: UkeyCommonTest.UkeyCommonTest013
 * @tc.desc: Test edge cases for certificate info conversion functions
 * @tc.type: FUNC
 */
HWTEST_F(UkeyCommonTest, UkeyCommonTest013, TestSize.Level0)
{
    // Test StringToCertInfo with JSON missing some fields
    std::string minimalJson = R"({"purpose": 3})";
    HksExtCertInfo certInfo = {0};
    int32_t ret = StringToCertInfo(minimalJson, certInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(certInfo.purpose, 3);
    EXPECT_TRUE(IsHksBlobEmpty(certInfo.index));
    EXPECT_TRUE(IsHksBlobEmpty(certInfo.cert));
    
    // Test with only index field
    std::string indexOnlyJson = R"({"index": "test_index_value"})";
    HksExtCertInfo indexOnlyCert = {0};
    ret = StringToCertInfo(indexOnlyJson, indexOnlyCert);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(indexOnlyCert.purpose, 0); // default value
    EXPECT_FALSE(IsHksBlobEmpty(indexOnlyCert.index));
    EXPECT_TRUE(IsHksBlobEmpty(indexOnlyCert.cert));
    
    std::string indexValue = BlobToString(indexOnlyCert.index);
    EXPECT_EQ(indexValue, "test_index_value");

    // Clean up
    HKS_FREE(indexOnlyCert.index.data);

    // Test CertInfoToString with minimal cert info
    HksExtCertInfo minimalCert = {0};
    minimalCert.purpose = 5;
    // index and cert are empty by default
    
    std::string minimalOutput;
    ret = CertInfoToString(minimalCert, minimalOutput);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_FALSE(minimalOutput.empty());

    // Verify the minimal output contains the purpose
    auto jsonObj = CommJsonObject::Parse(minimalOutput);
    EXPECT_FALSE(jsonObj.IsNull());
    EXPECT_TRUE(jsonObj.HasKey("purpose"));
    EXPECT_EQ(jsonObj["purpose"].ToNumber<int32_t>().second, 5);
    EXPECT_TRUE(jsonObj.HasKey("index"));
    EXPECT_TRUE(jsonObj.HasKey("cert"));
}

/* *
 * @tc.name: UkeyCommonTest.UkeyCommonTest014
 * @tc.desc: Test memory allocation failure scenarios
 * @tc.type: FUNC
 */
HWTEST_F(UkeyCommonTest, UkeyCommonTest014, TestSize.Level0)
{
    // Note: This test is mostly for documentation purposes since we can't
    // easily simulate memory allocation failures in unit tests
    
    // Test large string to blob conversion
    std::string largeString(10000, 'A'); // 10KB string
    HksBlob largeBlob = StringToBlob(largeString);
    EXPECT_FALSE(IsHksBlobEmpty(largeBlob));
    EXPECT_EQ(largeBlob.size, largeString.size());
    
    std::string convertedBack = BlobToString(largeBlob);
    EXPECT_EQ(convertedBack, largeString);
    
    HKS_FREE(largeBlob.data);

    // Test with special characters in strings
    std::string specialChars = "Line1\nLine2\tTab\x01Binary";
    HksBlob specialBlob = StringToBlob(specialChars);
    EXPECT_FALSE(IsHksBlobEmpty(specialBlob));
    
    std::string specialBack = BlobToString(specialBlob);
    EXPECT_EQ(specialBack, specialChars);
    
    HKS_FREE(specialBlob.data);
}

}