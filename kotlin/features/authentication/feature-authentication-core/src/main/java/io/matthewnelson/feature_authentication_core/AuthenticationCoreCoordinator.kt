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
package io.matthewnelson.feature_authentication_core

import app.cash.exhaustive.Exhaustive
import io.matthewnelson.concept_authentication.coordinator.AuthenticationCoordinator
import io.matthewnelson.concept_authentication.coordinator.AuthenticationRequest
import io.matthewnelson.concept_authentication.coordinator.AuthenticationResponse
import io.matthewnelson.concept_authentication.state.AuthenticationState
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.isActive

abstract class AuthenticationCoreCoordinator(
    protected val authenticationManager: AuthenticationCoreManager
): AuthenticationCoordinator() {

    @Suppress("RemoveExplicitTypeArguments", "PropertyName")
    protected val _authenticationResponseSharedFlow: MutableSharedFlow<AuthenticationResponse> by lazy {
        MutableSharedFlow<AuthenticationResponse>(0, 1)
    }

    @Suppress("RemoveExplicitTypeArguments", "PropertyName")
    protected val _authenticationRequestSharedFlow: MutableSharedFlow<AuthenticationRequest> by lazy {
        MutableSharedFlow<AuthenticationRequest>(0, 1)
    }

    protected abstract suspend fun navigateToAuthenticationView()

    override suspend fun isAnEncryptionKeySet(): Boolean {
        return authenticationManager.isAnEncryptionKeySet()
    }

    override suspend fun submitAuthenticationRequest(
        request: AuthenticationRequest
    ): Flow<AuthenticationResponse> {
        @Exhaustive
        when (request) {
            is AuthenticationRequest.GetEncryptionKey -> {
                when (authenticationManager.authenticationStateFlow.value) {
                    is AuthenticationState.NotRequired -> {
                        authenticationManager.getEncryptionKey()?.let { key ->
                            return flowOf(
                                AuthenticationResponse.Success.Key(request, key)
                            )
                        } ?: if (!request.navigateToAuthenticationViewOnFailure) {
                            return flowOf(
                                AuthenticationResponse.Failure(request)
                            )
                        }
                    }
                    else -> {
                        if (!request.navigateToAuthenticationViewOnFailure) {
                            return flowOf(
                                AuthenticationResponse.Failure(request)
                            )
                        }
                    }
                }
            }
            is AuthenticationRequest.LogIn -> {

                // If encryptionKey value is null, proceed with the regular checks and send
                // user to Authentication View if needed, otherwise try logging in here
                // w/o sending the user to the Authentication View.
                request.privateKey?.let { privateKey ->

                    return authenticationManager.authenticate(privateKey, request)

                } ?: when (authenticationManager.authenticationStateFlow.value) {
                    is AuthenticationState.NotRequired -> {
                        authenticationManager.getEncryptionKey()?.let {
                            return flowOf(
                                AuthenticationResponse.Success.Authenticated(request)
                            )
                        }
                    }
                    else -> {}
                }
            }
            is AuthenticationRequest.ConfirmPin,
            is AuthenticationRequest.ResetPassword -> {}
        }

        navigateToAuthenticationView()

        // TODO: Add a timeout that can be expressed in arguments
        while (
            currentCoroutineContext().isActive &&
            _authenticationRequestSharedFlow.subscriptionCount.value == 0
        ) {
            delay(50L)
        }

        _authenticationRequestSharedFlow.emit(request)

        return flow {
            _authenticationResponseSharedFlow.asSharedFlow().collect { response ->
                if (response.authenticationRequest == request) {
                    emit(response)
                }
            }
        }
    }
}
