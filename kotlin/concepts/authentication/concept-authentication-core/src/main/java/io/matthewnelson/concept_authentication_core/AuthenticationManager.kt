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
package io.matthewnelson.concept_authentication_core

import io.matthewnelson.concept_authentication.coordinator.AuthenticationRequest
import io.matthewnelson.concept_authentication.coordinator.AuthenticationResponse
import io.matthewnelson.concept_authentication.state.AuthenticationStateManager
import io.matthewnelson.concept_authentication_core.model.ConfirmUserInputToReset
import io.matthewnelson.concept_authentication_core.model.ConfirmUserInputToSetForFirstTime
import io.matthewnelson.concept_authentication_core.model.UserInput
import io.matthewnelson.concept_foreground_state.ForegroundStateManager
import io.matthewnelson.crypto_common.clazzes.Password
import kotlinx.coroutines.flow.Flow

abstract class AuthenticationManager<
        F,
        S: ConfirmUserInputToReset,
        V: ConfirmUserInputToSetForFirstTime,
        >: AuthenticationStateManager,
    ForegroundStateManager // TODO: Move to separate feature
{
    abstract fun getNewUserInput(): UserInput

    abstract suspend fun isAnEncryptionKeySet(): Boolean

    /**
     * Primarily used by the
     * [io.matthewnelson.concept_authentication.coordinator.AuthenticationCoordinator] for
     * logging in without the need to send the user to the Authentication View. This API will
     * check the [request] for if [AuthenticationRequest.LogIn.privateKey] is not null, and
     * then attempt to log in. See [AuthenticationRequest.LogIn] for more information.
     * */
    abstract fun authenticate(
        privateKey: Password,
        request: AuthenticationRequest.LogIn
    ): Flow<AuthenticationResponse>

    abstract fun authenticate(
        userInput: UserInput,
        requests: List<AuthenticationRequest>
    ): Flow<F>

    abstract fun resetPassword(
        resetPasswordResponse: S,
        userInputConfirmation: UserInput,
        requests: List<AuthenticationRequest>
    ): Flow<F>

    abstract fun setPasswordFirstTime(
        setPasswordFirstTimeResponse: V,
        userInputConfirmation: UserInput,
        requests: List<AuthenticationRequest>
    ): Flow<F>
}