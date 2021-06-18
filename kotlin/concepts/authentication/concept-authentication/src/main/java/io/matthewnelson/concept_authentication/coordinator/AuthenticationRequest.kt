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

import io.matthewnelson.crypto_common.clazzes.Password

abstract class ConfirmedPinListener {
    /**
     * Called from Dispatchers.Default
     * */
    abstract suspend fun doWithConfirmedPassword(password: Password)
}

sealed class AuthenticationRequest {

    abstract val priority: Int

    /**
     * Sending a [ConfirmedPinListener] along with the request will give access to the
     * user's PIN value after it has been confirmed, prior to the [AuthenticationResponse]
     * being returned.
     * */
    class ConfirmPin(
        val listener: ConfirmedPinListener? = null
    ): AuthenticationRequest() {
        override val priority: Int = 3
    }

    /**
     * If the user is logged in (The [io.matthewnelson.concept_encryption_key.EncryptionKey]
     * hasn't been cleared and state is
     * [io.matthewnelson.concept_authentication.state.AuthenticationState.NotRequired]), this
     * request will automatically return the key.
     *
     * Setting the [navigateToAuthenticationViewOnFailure] to `true` will navigate
     * to the View for the user to authenticate in the event they are not logged in. The
     * Coordinator will suspend until the request is authenticated, and return the key.
     *
     * Alternatively, setting [navigateToAuthenticationViewOnFailure] to `false` will return
     * [io.matthewnelson.concept_authentication.coordinator.AuthenticationResponse.Failure]
     * if state is requiring authentication, and then if the
     * [io.matthewnelson.concept_encryption_key.EncryptionKey] is unavailable.
     * */
    class GetEncryptionKey(
        val navigateToAuthenticationViewOnFailure: Boolean = true
    ): AuthenticationRequest() {
        override val priority: Int = 4
    }

    /**
     * Optional [privateKey] argument allows for easier implementation of custom encrypted
     * storage solution that will allow for logging the user in without sending them to the
     * Authentication View. The [privateKey] will be validated against a test string that
     * was encrypted using the originally set key. If successful, a **copy** of the key will be
     * set and [io.matthewnelson.concept_authentication.state.AuthenticationState.NotRequired] will
     * be set.
     *
     * Reminder: Passwords should never be stored clear text.
     * */
    class LogIn(val privateKey: Password? = null): AuthenticationRequest() {
        override val priority: Int = 1
    }

    class ResetPassword: AuthenticationRequest() {
        override val priority: Int = 2
    }
}
