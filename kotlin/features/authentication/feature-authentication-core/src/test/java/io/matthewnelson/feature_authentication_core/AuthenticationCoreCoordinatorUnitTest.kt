package io.matthewnelson.feature_authentication_core

import io.matthewnelson.concept_authentication.coordinator.AuthenticationRequest
import io.matthewnelson.concept_authentication.coordinator.AuthenticationResponse
import io.matthewnelson.crypto_common.annotations.RawPasswordAccess
import io.matthewnelson.crypto_common.clazzes.Password
import io.matthewnelson.test_concept_coroutines.testObserver
import io.matthewnelson.test_feature_authentication_core.AuthenticationCoreDefaultsTestHelper
import io.matthewnelson.test_feature_authentication_core.TestEncryptionKeyHandler
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runBlockingTest
import org.junit.Assert
import org.junit.Test

@OptIn(RawPasswordAccess::class)
class AuthenticationCoreCoordinatorUnitTest: AuthenticationCoreDefaultsTestHelper() {

    ////////////////////////////////
    /// Request GetEncryptionKey ///
    ////////////////////////////////
    @Test
    fun `navigateToAuthenticationViewOnFailure equals true returns Failure instead of navigating`() =
        testDispatcher.runBlockingTest {
            val request = AuthenticationRequest.GetEncryptionKey(
                navigateToAuthenticationViewOnFailure = false
            )

            val observer = testCoordinator.submitAuthenticationRequest(request).testObserver(this)
                .delay10()
            Assert.assertEquals(1, observer.values.size)
            Assert.assertTrue(observer.values.last() is AuthenticationResponse.Failure)
            Assert.assertEquals(0, testCoordinator.navigationCalled)
            observer.finish()
        }

    @Test
    fun `getEncryptionKey request returns the key immediately if logged in`() =
        testDispatcher.runBlockingTest {
            login()
            val request = AuthenticationRequest.GetEncryptionKey(
                navigateToAuthenticationViewOnFailure = true
            )
            testCoordinator.submitAuthenticationRequest(request).first().let { response ->
                if (response is AuthenticationResponse.Success.Key) {
                    Assert.assertEquals(
                        response.encryptionKey.privateKey.value.joinToString(""),
                        TestEncryptionKeyHandler.TEST_ENCRYPTION_KEY_STRING
                    )
                } else {
                    throw AssertionError()
                }
            }
            Assert.assertEquals(0, testCoordinator.navigationCalled)
        }

    /////////////////////
    /// Request Login ///
    /////////////////////
    @Test
    fun `login returns success immediately if already logged in`() =
        testDispatcher.runBlockingTest {
            login()
            val request = AuthenticationRequest.LogIn(privateKey = null)
            testCoordinator.submitAuthenticationRequest(request).first().let { response ->
                if (response !is AuthenticationResponse.Success.Authenticated) {
                    Assert.fail()
                }
            }
            Assert.assertEquals(0, testCoordinator.navigationCalled)
        }

    @Test
    fun `logging in with encryption key that does not match what is currently set fails login`() =
        testDispatcher.runBlockingTest {
            login()
            val request = AuthenticationRequest.LogIn(
                privateKey = Password(
                    (TestEncryptionKeyHandler.TEST_ENCRYPTION_KEY_STRING + "a").toCharArray()
                )
            )
            testCoordinator.submitAuthenticationRequest(request).first().let { response ->
                if (response !is AuthenticationResponse.Failure) {
                    Assert.fail()
                }
            }
            Assert.assertEquals(0, testCoordinator.navigationCalled)
        }

    @Test
    fun `logging in with encryption key that matches what is currently set returns key`() =
        testDispatcher.runBlockingTest {
            login()
            val request = AuthenticationRequest.LogIn(
                privateKey = Password(
                    TestEncryptionKeyHandler.TEST_ENCRYPTION_KEY_STRING.toCharArray()
                )
            )

            testCoordinator.submitAuthenticationRequest(request).first().let { response ->
                if (response is AuthenticationResponse.Success.Key) {
                    Assert.assertEquals(
                        response.encryptionKey.privateKey.value.joinToString(""),
                        TestEncryptionKeyHandler.TEST_ENCRYPTION_KEY_STRING
                    )
                } else {
                    Assert.fail()
                }
            }
            Assert.assertEquals(0, testCoordinator.navigationCalled)
        }

    /////////////////////////////////////////
    /// Waits for flow subscriber to emit ///
    /////////////////////////////////////////
    @Test
    fun `submitAuthenticationRequest suspends until a subscriber to request flow is active`() =
        testDispatcher.runBlockingTest {
            val getKeyRequest = AuthenticationRequest.GetEncryptionKey(
                navigateToAuthenticationViewOnFailure = true
            )

            var getKeyResponse: AuthenticationResponse? = null
            val responseJob = this.launch {
                testCoordinator.submitAuthenticationRequest(getKeyRequest).first().let {
                    getKeyResponse = it
                }
            }
            delay(500L)
            // should be suspending, waiting for a subscriber to the
            // request flow b/c no key is set, nor are we logged in\
            // to auto-respond with the key.
            Assert.assertNull(getKeyResponse)
            Assert.assertEquals(0, testCoordinator.requestFlowSubs)
            Assert.assertEquals(0, testCoordinator.responseFlowSubs)

            val requests = mutableListOf<AuthenticationRequest>()
            val requestJob = this.launch {
                testCoordinator.requestSharedFlow.collect {
                    requests.add(it)
                }
            }
            delay(100L)
            Assert.assertFalse(requests.isEmpty())

            // both should now have subscriptions
            Assert.assertEquals(1, testCoordinator.requestFlowSubs)
            Assert.assertEquals(1, testCoordinator.responseFlowSubs)

            // Should still be null as we haven't submitted a response back
            Assert.assertNull(getKeyResponse)

            // Response is delivered after completion
            val response = AuthenticationResponse.Failure(getKeyRequest)
            testCoordinator.completeAuthentication(listOf(response))
            delay(100L)

            Assert.assertEquals(1, testCoordinator.requestFlowSubs)
            Assert.assertEquals(0, testCoordinator.responseFlowSubs)

            // we collected `first` output, so it should automatically finish
            Assert.assertFalse(responseJob.isActive)

            Assert.assertEquals(response, getKeyResponse)

            requestJob.cancel()
            delay(100L)
            Assert.assertEquals(0, testCoordinator.requestFlowSubs)
        }
}