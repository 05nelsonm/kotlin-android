package io.matthewnelson.feature_authentication_core.components

import io.matthewnelson.test_feature_authentication_core.TestAuthenticationManagerInitializer
import org.junit.Assert
import org.junit.Test

class AuthenticationManagerInitializerUnitTest {

    @Test
    fun `min user input length below 4 throws exception`() {
        try {
            TestAuthenticationManagerInitializer(3)
            Assert.fail()
        } catch (e: IllegalArgumentException) {
            Assert.assertTrue(e.message?.contains("minimumUserInputLength") == true)
        }

        // Shouldn't throw exception
        TestAuthenticationManagerInitializer(4)
    }

    @Test
    fun `max user input greater than min throws exception`() {
        try {
            TestAuthenticationManagerInitializer(8, 7)
            Assert.fail()
        } catch (e: IllegalArgumentException) {
            Assert.assertTrue(e.message?.contains("maximumUserInputLength") == true)
        }

        // Shouldn't throw an exception
        TestAuthenticationManagerInitializer(8, 8)
    }
}