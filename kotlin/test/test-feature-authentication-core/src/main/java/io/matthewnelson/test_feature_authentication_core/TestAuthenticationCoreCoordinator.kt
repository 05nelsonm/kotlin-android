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
import io.matthewnelson.feature_authentication_core.AuthenticationCoreCoordinator
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow

open class TestAuthenticationCoreCoordinator<
        S: TestEncryptionKeyHandler,
        V: TestAuthenticationCoreStorage
        >(
    testManager: TestAuthenticationCoreManager<S, V>
): AuthenticationCoreCoordinator(testManager)
{
    val requestSharedFlow: SharedFlow<AuthenticationRequest>
        get() = _authenticationRequestSharedFlow.asSharedFlow()

    val requestFlowSubs: Int
        get() = _authenticationRequestSharedFlow.subscriptionCount.value

    val responseFlowSubs: Int
        get() = _authenticationResponseSharedFlow.subscriptionCount.value

    suspend fun completeAuthentication(responses: List<AuthenticationResponse>) {
        for (response in responses) {
            _authenticationResponseSharedFlow.emit(response)
        }
    }

    var navigationCalled = 0
        private set
    override suspend fun navigateToAuthenticationView() {
        navigationCalled++
    }
}