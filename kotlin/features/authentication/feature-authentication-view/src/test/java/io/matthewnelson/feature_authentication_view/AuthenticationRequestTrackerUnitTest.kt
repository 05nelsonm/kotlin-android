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
package io.matthewnelson.feature_authentication_view

import io.matthewnelson.concept_authentication.coordinator.AuthenticationRequest
import io.matthewnelson.feature_authentication_view.components.AuthenticationRequestTracker
import org.junit.Assert
import org.junit.Test

internal class AuthenticationRequestTrackerUnitTest {

    private val tracker = AuthenticationRequestTracker()

    @Test
    fun `adding of requests sorts by request priority and returns true if highest priority changed`() {
        Assert.assertTrue(tracker.getRequestsList().isEmpty())
        Assert.assertTrue(tracker.addRequest(AuthenticationRequest.GetEncryptionKey()))
        Assert.assertTrue(tracker.addRequest(AuthenticationRequest.LogIn()))
        Assert.assertFalse(tracker.addRequest(AuthenticationRequest.GetEncryptionKey()))
        Assert.assertFalse(tracker.addRequest(AuthenticationRequest.ResetPassword()))
        Assert.assertFalse(tracker.addRequest(AuthenticationRequest.GetEncryptionKey()))
        Assert.assertTrue(tracker.addRequest(AuthenticationRequest.LogIn()))
    }
}
