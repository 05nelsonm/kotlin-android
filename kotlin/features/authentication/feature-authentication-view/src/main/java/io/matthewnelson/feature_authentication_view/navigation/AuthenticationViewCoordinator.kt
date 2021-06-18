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
package io.matthewnelson.feature_authentication_view.navigation

import io.matthewnelson.concept_authentication.coordinator.AuthenticationRequest
import io.matthewnelson.concept_authentication.coordinator.AuthenticationResponse
import io.matthewnelson.feature_authentication_core.AuthenticationCoreCoordinator
import io.matthewnelson.feature_authentication_core.AuthenticationCoreManager
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow

abstract class AuthenticationViewCoordinator<T>(
    private val authenticationNavigator: AuthenticationNavigator<T>,
    authenticationManager: AuthenticationCoreManager
): AuthenticationCoreCoordinator(authenticationManager) {

    @JvmSynthetic
    internal fun getAuthenticationRequestSharedFlow(): SharedFlow<AuthenticationRequest> =
        _authenticationRequestSharedFlow.asSharedFlow()

    override suspend fun navigateToAuthenticationView() {
        authenticationNavigator.toAuthenticationView()
    }

    @JvmSynthetic
    internal suspend fun completeAuthentication(responses: List<AuthenticationResponse>) {
        for (response in responses) {
            _authenticationResponseSharedFlow.emit(response)
        }
        authenticationNavigator.popBackStack()
        delay(300L)
    }
}