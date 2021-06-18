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
package io.matthewnelson.concept_authentication.coordinator

import kotlinx.coroutines.flow.Flow

abstract class AuthenticationCoordinator {

    /**
     * Checks the persistent storage to see if a key exists. Does not decrypt the key or
     * return it.
     * */
    abstract suspend fun isAnEncryptionKeySet(): Boolean

    /**
     * Returns the corresponding response for the provided request, or
     * [AuthenticationResponse.Failure].
     *
     * Responses for [AuthenticationRequest.ConfirmPin] submission:
     *   - [AuthenticationResponse.Success.Authenticated]
     *   - [AuthenticationResponse.Failure]
     *
     * Responses for [AuthenticationRequest.GetEncryptionKey] submission:
     *   - [AuthenticationResponse.Success.Key]
     *   - [AuthenticationResponse.Failure]
     *
     * Responses for [AuthenticationRequest.LogIn] submission where
     * [AuthenticationRequest.LogIn.privateKey] is `null`:
     *   - [AuthenticationResponse.Success.Authenticated]
     *   - [AuthenticationResponse.Failure]
     *
     * Responses for [AuthenticationRequest.LogIn] submission where
     * [AuthenticationRequest.LogIn.privateKey] is **not** `null`:
     *   - [AuthenticationResponse.Success.Key]
     *   - [AuthenticationResponse.Failure]
     *
     * Responses for [AuthenticationRequest.ResetPassword] submission:
     *   - [AuthenticationResponse.Success.Authenticated]
     *   - [AuthenticationResponse.Failure]
     * */
    abstract suspend fun submitAuthenticationRequest(
        request: AuthenticationRequest
    ): Flow<AuthenticationResponse>
}
