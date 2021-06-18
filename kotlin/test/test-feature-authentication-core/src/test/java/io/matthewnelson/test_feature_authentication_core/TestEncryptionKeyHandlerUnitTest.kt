package io.matthewnelson.test_feature_authentication_core

import io.matthewnelson.concept_encryption_key.EncryptionKeyException
import io.matthewnelson.crypto_common.annotations.RawPasswordAccess
import io.matthewnelson.crypto_common.clazzes.clear
import io.matthewnelson.test_concept_coroutines.CoroutineTestHelper
import kotlinx.coroutines.test.runBlockingTest
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test

class TestEncryptionKeyHandlerUnitTest: CoroutineTestHelper() {

    private val testHandler = TestEncryptionKeyHandler()

    @Before
    fun setup() {
        setupCoroutineTestHelper()
    }

    @After
    fun tearDown() {
        tearDownCoroutineTestHelper()
    }

    @Test(expected = EncryptionKeyException::class)
    @OptIn(RawPasswordAccess::class)
    fun `validateEncryptionKey method throws exception correctly`() =
        testDispatcher.runBlockingTest {
            val key = testHandler.generateEncryptionKey()
            Assert.assertEquals(
                TestEncryptionKeyHandler.TEST_ENCRYPTION_KEY_STRING,
                key.privateKey.value.joinToString("")
            )

            key.privateKey.clear('*')
            testHandler.storeCopyOfEncryptionKey(key.privateKey.value, key.publicKey.value)
        }
}