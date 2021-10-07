// UnitTests for environment variable caching.
#include "test.h"

#if defined _WIN64 || defined _WIN32

using ::testing::_;
using ::testing::Expectation;
using ::testing::Invoke;
using ::testing::AnyNumber;

#define AppDataPath L"%appdata%\\file.txt"

// InvalidArguments check for failure on invalid input.
TEST(EnvCache, InvalidArguments) {
    WCHAR ruleData[] = L"input buffer";
    WCHAR expandVariable[MAX_PATH];
    LPWSTR nullRuleData = nullptr;
    LPWSTR realRuleData = ruleData;

    EXPECT_FALSE(ExpandEnvironmentVariable(1, nullptr, expandVariable, _countof(expandVariable)));
    EXPECT_FALSE(ExpandEnvironmentVariable(1, &nullRuleData, expandVariable, _countof(expandVariable)));
    EXPECT_FALSE(ExpandEnvironmentVariable(1, &realRuleData, nullptr, _countof(expandVariable)));
    EXPECT_FALSE(ExpandEnvironmentVariable(1, &realRuleData, expandVariable, 0));
}

// NoVariable checks that a string without environment variables would work even if that case should not happen.
TEST(EnvCache, NoVariable)
{
    WCHAR ruleData[] = L"a simple string";
    LPWSTR inputRuleData = ruleData;
    WCHAR expandVariable[MAX_PATH];
    MockEnvironmentVariableCache cache;

    // Expect only a call to GetUserToken with the mockSessionId.
    EXPECT_CALL(cache, GetUserToken(mockSessionId, _))
        .Times(AnyNumber())
        .WillRepeatedly(Invoke(MockEnvironmentVariableCache::MockGetUserToken));

    ASSERT_TRUE(cache.Expand(mockSessionId, &inputRuleData, expandVariable, _countof(expandVariable)));
} 

// SessionZero tests that a session without token will successfully default to system environment variables.
TEST(EnvCache, SessionZero)
{
    WCHAR ruleData[] = L"%systemroot%";
    LPWSTR inputRuleData = ruleData;
    WCHAR expandVariable[MAX_PATH];
    MockEnvironmentVariableCache cache;

    // Simulate GetUserToken error on session zero.
    EXPECT_CALL(cache, GetUserToken(0, _))
        .Times(AnyNumber())
        .WillRepeatedly(Invoke([](ULONG sessionId, PHANDLE token){
            SetLastError(ERROR_NO_TOKEN);
            return FALSE;
        }));
    EXPECT_CALL(cache, AddValueToCache(0, _, _)).Times(1);

    // Session zero call is successful.
    ASSERT_TRUE(cache.Expand(0, &inputRuleData, expandVariable, _countof(expandVariable)));
    EXPECT_EQ(inputRuleData, expandVariable) << "On expansion, inputRuleData should be changed to point to expandVariable";
    EXPECT_STRNE(ruleData, expandVariable);
}

// Storage verifies that the cache stores the entry only when previously unknown.
TEST(EnvCache, Storage)
{
    WCHAR ruleData[] = AppDataPath;
    LPWSTR inputRuleData = ruleData;
    WCHAR expandVariable[MAX_PATH];
    MockEnvironmentVariableCache cache;

    // Expect only a call to GetUserToken with the mockSessionId.
    EXPECT_CALL(cache, GetUserToken(mockSessionId, _))
        .Times(AnyNumber())
        .WillRepeatedly(Invoke(MockEnvironmentVariableCache::MockGetUserToken));
    EXPECT_CALL(cache, AddValueToCache(mockSessionId, _, _)).Times(1);

    // First call fills the cache.
    ASSERT_TRUE(cache.Expand(mockSessionId, &inputRuleData, expandVariable, _countof(expandVariable)));
    EXPECT_EQ(inputRuleData, expandVariable) << "On expansion, inputRuleData should be changed to point to expandVariable";
    EXPECT_STRNE(ruleData, expandVariable);

    std::wstring expandVariableLower = expandVariable;
    std::transform(expandVariableLower.begin(), expandVariableLower.end(), expandVariableLower.begin(), ::towlower);
    EXPECT_STREQ(expandVariableLower.c_str(), expandVariable) << "The expanded variable should be lower case";

    // Second call will use the cache, no call to AddValueToCache.
    ZeroMemory(expandVariable, sizeof(expandVariable));
    inputRuleData = ruleData;
    ASSERT_TRUE(cache.Expand(mockSessionId, &inputRuleData, expandVariable, _countof(expandVariable)));
    EXPECT_EQ(inputRuleData, expandVariable) << "On expansion, inputRuleData should be changed to point to expandVariable";
    EXPECT_STRNE(ruleData, expandVariable);
}

// Logoff checks that a session is correctly removed for logoff.
TEST(EnvCache, Logoff)
{
    WCHAR ruleData[] = AppDataPath;
    LPWSTR inputRuleData = ruleData;
    WCHAR expandVariable[MAX_PATH];
    MockEnvironmentVariableCache cache;

    // Support two mock session ids.
    EXPECT_CALL(cache, GetUserToken(mockSessionId, _))
        .Times(AnyNumber())
        .WillRepeatedly(Invoke(MockEnvironmentVariableCache::MockGetUserToken));
    EXPECT_CALL(cache, GetUserToken(mockSecondSessionId, _))
        .Times(AnyNumber())
        .WillRepeatedly(Invoke(MockEnvironmentVariableCache::MockGetUserToken));
    
    // Values are added to the cache twice for the first mock, once only for the second as it is not cleared.
    EXPECT_CALL(cache, AddValueToCache(mockSessionId, _, _)).Times(2);
    EXPECT_CALL(cache, AddValueToCache(mockSecondSessionId, _, _)).Times(1);

    // First calls fill the cache for both sessions.
    ASSERT_TRUE(cache.Expand(mockSessionId, &inputRuleData, expandVariable, _countof(expandVariable)));
    EXPECT_EQ(inputRuleData, expandVariable) << "On expansion, inputRuleData should be changed to point to expandVariable";
    EXPECT_STRNE(ruleData, expandVariable);

    ZeroMemory(expandVariable, sizeof(expandVariable));
    inputRuleData = ruleData;
    ASSERT_TRUE(cache.Expand(mockSecondSessionId, &inputRuleData, expandVariable, _countof(expandVariable)));
    EXPECT_EQ(inputRuleData, expandVariable) << "On expansion, inputRuleData should be changed to point to expandVariable";
    EXPECT_STRNE(ruleData, expandVariable);

    cache.CleanSessionCache(mockSessionId);

    // Second call fills the cache again but only for main session.
    ZeroMemory(expandVariable, sizeof(expandVariable));
    inputRuleData = ruleData;
    ASSERT_TRUE(cache.Expand(mockSessionId, &inputRuleData, expandVariable, _countof(expandVariable)));
    EXPECT_EQ(inputRuleData, expandVariable) << "On expansion, inputRuleData should be changed to point to expandVariable";
    EXPECT_STRNE(ruleData, expandVariable);

    ZeroMemory(expandVariable, sizeof(expandVariable));
    inputRuleData = ruleData;
    ASSERT_TRUE(cache.Expand(mockSecondSessionId, &inputRuleData, expandVariable, _countof(expandVariable)));
    EXPECT_EQ(inputRuleData, expandVariable) << "On expansion, inputRuleData should be changed to point to expandVariable";
    EXPECT_STRNE(ruleData, expandVariable);
}

// ConfigChange checks that sessions are correctly cleaned on config update.
TEST(EnvCache, ConfigChange)
{
    WCHAR ruleData[] = AppDataPath;
    LPWSTR inputRuleData = ruleData;
    WCHAR expandVariable[MAX_PATH];
    MockEnvironmentVariableCache cache;

    // Support two mock session ids.
    EXPECT_CALL(cache, GetUserToken(mockSessionId, _))
        .Times(AnyNumber())
        .WillRepeatedly(Invoke(MockEnvironmentVariableCache::MockGetUserToken));
    EXPECT_CALL(cache, GetUserToken(mockSecondSessionId, _))
        .Times(AnyNumber())
        .WillRepeatedly(Invoke(MockEnvironmentVariableCache::MockGetUserToken));
    
    // Values are added to the cache twice after the clean.
    EXPECT_CALL(cache, AddValueToCache(mockSessionId, _, _)).Times(2);
    EXPECT_CALL(cache, AddValueToCache(mockSecondSessionId, _, _)).Times(2);

    // First calls fill the cache for both sessions.
    ASSERT_TRUE(cache.Expand(mockSessionId, &inputRuleData, expandVariable, _countof(expandVariable)));
    EXPECT_EQ(inputRuleData, expandVariable) << "On expansion, inputRuleData should be changed to point to expandVariable";
    EXPECT_STRNE(ruleData, expandVariable);

    ZeroMemory(expandVariable, sizeof(expandVariable));
    inputRuleData = ruleData;
    ASSERT_TRUE(cache.Expand(mockSecondSessionId, &inputRuleData, expandVariable, _countof(expandVariable)));
    EXPECT_EQ(inputRuleData, expandVariable) << "On expansion, inputRuleData should be changed to point to expandVariable";
    EXPECT_STRNE(ruleData, expandVariable);

    cache.CleanCache();

    // Second call fills the cache again but only for main session.
    ZeroMemory(expandVariable, sizeof(expandVariable));
    inputRuleData = ruleData;
    ASSERT_TRUE(cache.Expand(mockSessionId, &inputRuleData, expandVariable, _countof(expandVariable)));
    EXPECT_EQ(inputRuleData, expandVariable) << "On expansion, inputRuleData should be changed to point to expandVariable";
    EXPECT_STRNE(ruleData, expandVariable);

    ZeroMemory(expandVariable, sizeof(expandVariable));
    inputRuleData = ruleData;
    ASSERT_TRUE(cache.Expand(mockSecondSessionId, &inputRuleData, expandVariable, _countof(expandVariable)));
    EXPECT_EQ(inputRuleData, expandVariable) << "On expansion, inputRuleData should be changed to point to expandVariable";
    EXPECT_STRNE(ruleData, expandVariable);
}

#endif