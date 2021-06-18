package io.matthewnelson.test_feature_authentication_core

import io.matthewnelson.concept_authentication.data.AuthenticationStorage
import io.matthewnelson.test_concept_coroutines.CoroutineTestHelper
import kotlinx.coroutines.test.runBlockingTest
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test

class TestAuthenticationCoreStorageUnitTest: CoroutineTestHelper() {

    private val testStorage = TestAuthenticationCoreStorage()

    @Before
    fun setup() {
        setupCoroutineTestHelper()
    }

    @After
    fun tearDown() {
        tearDownCoroutineTestHelper()
    }

    @Test(expected = IllegalArgumentException::class)
    fun `test implementation throws exception as required when to overwriting the CREDENTIALS`() =
        testDispatcher.runBlockingTest {
            testStorage.putString(AuthenticationStorage.CREDENTIALS, "")
        }

    @Test
    fun `getString returns default value if nothing is stored in the map`() =
        testDispatcher.runBlockingTest {
            val defValue = "DEFAULT_VALUE"
            Assert.assertEquals(testStorage.getString("random key", defValue), defValue)
        }
}