package io.matthewnelson.feature_authentication_core

import io.matthewnelson.concept_authentication.coordinator.AuthenticationRequest
import io.matthewnelson.concept_authentication.coordinator.AuthenticationResponse
import io.matthewnelson.concept_authentication.data.AuthenticationStorage
import io.matthewnelson.concept_authentication_core.model.UserInput
import io.matthewnelson.feature_authentication_core.model.AuthenticateFlowResponse
import io.matthewnelson.feature_authentication_core.model.Credentials
import io.matthewnelson.feature_authentication_core.model.UserInputWriter
import io.matthewnelson.k_openssl.algos.AES256CBC_PBKDF2_HMAC_SHA256
import io.matthewnelson.crypto_common.annotations.RawPasswordAccess
import io.matthewnelson.crypto_common.annotations.UnencryptedDataAccess
import io.matthewnelson.crypto_common.clazzes.EncryptedString
import io.matthewnelson.crypto_common.clazzes.Password
import io.matthewnelson.crypto_common.clazzes.UnencryptedString
import io.matthewnelson.test_feature_authentication_core.AuthenticationCoreDefaultsTestHelper
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runBlockingTest
import org.junit.Assert
import org.junit.Test

@OptIn(RawPasswordAccess::class, UnencryptedDataAccess::class)
class AuthenticationCoreManagerUnitTest: AuthenticationCoreDefaultsTestHelper() {

    private fun getValidUserInput(
        c: Char,
        repeat: Int = testInitializer.minimumUserInputLength
    ): UserInput {
        val input = testCoreManager.getNewUserInput()
        repeat(repeat) {
            input.addCharacter(c)
        }
        return input
    }

    @Test
    fun `isAnEncryptionKeySet returns correct boolean value if encryption key is in storage`() =
        testDispatcher.runBlockingTest {
            Assert.assertFalse(testCoreManager.isAnEncryptionKeySet())
            login()
            Assert.assertTrue(testCoreManager.isAnEncryptionKeySet())
        }

    @Test
    fun `empty public key is stored as EMPTY`() =
        testDispatcher.runBlockingTest {
            Assert.assertFalse(testCoreManager.isAnEncryptionKeySet())

            // test handler generates empty public key values
            Assert.assertTrue(testHandler.generateEncryptionKey().publicKey.value.isEmpty())

            // set credentials/keys for first time
            login()

            val privateKey: Password = testCoordinator.submitAuthenticationRequest(
                AuthenticationRequest.GetEncryptionKey()
            ).first().let { response ->
                if (response is AuthenticationResponse.Success.Key) {
                    // Set EncryptionKey's public key is empty char array
                    Assert.assertTrue(response.encryptionKey.publicKey.value.isEmpty())

                    response.encryptionKey.privateKey
                } else {
                    throw AssertionError()
                }
            }

            val kOpenSSL = AES256CBC_PBKDF2_HMAC_SHA256()
            testStorage.storage[AuthenticationStorage.CREDENTIALS]?.let { credsString ->

                // credentials string has 3 concatenated string values
                credsString.split(Credentials.DELIMITER).let { splits ->
                    Assert.assertTrue(splits.size == 3)
                    val decrypted: UnencryptedString = kOpenSSL.decrypt(
                        privateKey,
                        testHandler.getTestStringEncryptHashIterations(privateKey),
                        EncryptedString(splits[1]),
                        dispatchers.default
                    )

                    // decrypted string value is actually "EMPTY"
                    Assert.assertEquals(Credentials.EMPTY, decrypted.value)
                }

                // This would throw an AuthenticationException if empty
                val publicKey: Password = Credentials.fromString(credsString)
                    .decryptPublicKey(
                        dispatchers,
                        privateKey,
                        testHandler,
                        kOpenSSL
                    )

                // decrypting the public key returns a Password containing an empty char array
                Assert.assertTrue(publicKey.value.isEmpty())

            } ?: Assert.fail("Storage was null")
        }

    @Test
    fun `min user input length not met returns error`() =
        testDispatcher.runBlockingTest {
            val input = getValidUserInput('a')
            input.dropLastCharacter()

            // Authenticate API
            val request = AuthenticationRequest.LogIn(privateKey = null)
            testCoreManager.authenticate(input, listOf(request)).first().let { flowResponse ->
                if (flowResponse !is AuthenticateFlowResponse.Error.Authenticate.InvalidPasswordEntrySize) {
                    Assert.fail()
                }
            }

            // SetPasswordFirstTime AIP
            val setPasswordResponse = AuthenticateFlowResponse
                .ConfirmInputToSetForFirstTime.instantiate(input as UserInputWriter)
            testCoreManager.setPasswordFirstTime(setPasswordResponse, input, listOf(request))
                .first().let { flowResponse ->
                    if (flowResponse !is AuthenticateFlowResponse.Error.SetPasswordFirstTime.InvalidNewPasswordEntrySize) {
                        Assert.fail()
                    }
                }

            // ResetPassword API
            val resetRequest = AuthenticationRequest.ResetPassword()
            val resetResponse = AuthenticateFlowResponse
                .PasswordConfirmedForReset.generate(input, resetRequest)!! // won't be on the list
            resetResponse.storeNewPasswordToBeSet(input)
            testCoreManager.resetPassword(resetResponse, input, listOf(resetRequest))
                .first().let { flowResponse ->
                    if (flowResponse !is AuthenticateFlowResponse.Error.ResetPassword.InvalidNewPasswordEntrySize) {
                        Assert.fail()
                    }
                }
        }
}