/*
*  Copyright 2021 Matthew Nelson
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
* */
package io.matthewnelson.test_feature_authentication_core

import io.matthewnelson.concept_authentication.coordinator.AuthenticationRequest
import io.matthewnelson.concept_authentication.coordinator.AuthenticationResponse
import io.matthewnelson.concept_authentication.state.AuthenticationState
import io.matthewnelson.feature_authentication_core.components.AuthenticationManagerInitializer
import io.matthewnelson.feature_authentication_core.model.AuthenticateFlowResponse
import io.matthewnelson.test_concept_coroutines.CoroutineTestHelper
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import org.junit.Assert

abstract class AuthenticationCoreTestHelper<
        T: AuthenticationManagerInitializer,
        S: TestEncryptionKeyHandler,
        V: TestAuthenticationCoreStorage
        >: CoroutineTestHelper()
{
    protected abstract val testInitializer: T
    protected abstract val testHandler: S
    protected abstract val testStorage: V

    protected open val testCoreManager: TestAuthenticationCoreManager<S, V> by lazy {
        TestAuthenticationCoreManager(
            dispatchers as TestCoroutineDispatchers,
            testHandler,
            testStorage,
            testInitializer
        )
    }

    protected open val testCoordinator: TestAuthenticationCoreCoordinator<S, V> by lazy {
        TestAuthenticationCoreCoordinator(
            testCoreManager
        )
    }

    /**
     * Call from @Before to set up everything needed. Also sets up the coroutine test helper.
     * */
    fun setupAuthenticationCoreTestHelper() {
        setupCoroutineTestHelper()
    }

    /**
     * Call from @After to clear the coroutines
     * */
    fun tearDownAuthenticationCoreTestHelper() {
        tearDownCoroutineTestHelper()
    }

    /**
     * Logs in and sets the EncryptionKey
     * */
    protected suspend fun login(): AuthenticationResponse {
        val writer = testCoreManager.getNewUserInput()
        repeat(testInitializer.minimumUserInputLength) {
            writer.addCharacter('0')
        }

        val request = AuthenticationRequest.LogIn()

        var confirmToSetResponse: AuthenticateFlowResponse.ConfirmInputToSetForFirstTime? = null
        testCoreManager.authenticate(writer, listOf(request)).collect { flowResponse ->
            if (flowResponse is AuthenticateFlowResponse.ConfirmInputToSetForFirstTime) {
                confirmToSetResponse = flowResponse
            }
        }
        delay(500L)
        Assert.assertNotNull(confirmToSetResponse)

        var completedResponses: List<AuthenticationResponse>? = null
        testCoreManager.setPasswordFirstTime(confirmToSetResponse!!, writer, listOf(request))
            .collect { flowResponse ->
                if (flowResponse is AuthenticateFlowResponse.Success) {
                    completedResponses = flowResponse.requests
                }
            }
        delay(500L)
        Assert.assertNotNull(completedResponses)
        Assert.assertTrue(testCoreManager.authenticationStateFlow.value is AuthenticationState.NotRequired)
        Assert.assertTrue(testCoreManager.isAnEncryptionKeySet())
        return completedResponses!![0]
    }
}