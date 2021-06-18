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
package io.matthewnelson.android_feature_authentication_core.components

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.os.SystemClock
import io.matthewnelson.feature_authentication_core.AuthenticationCoreManager
import io.matthewnelson.concept_authentication.state.AuthenticationState
import io.matthewnelson.concept_foreground_state.ForegroundState
import io.matthewnelson.android_feature_authentication_core.data.AuthenticationCoreStorageAndroid
import io.matthewnelson.concept_coroutines.CoroutineDispatchers
import io.matthewnelson.concept_encryption_key.EncryptionKeyHandler
import io.matthewnelson.crypto_common.clazzes.HashIterations
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

abstract class AuthenticationCoreManagerAndroid(
    dispatchers: CoroutineDispatchers,
    encryptionKeyHashIterations: HashIterations,
    encryptionKeyHandler: EncryptionKeyHandler,
    persistentStorage: AuthenticationCoreStorageAndroid,
    authenticationManagerInitializerAndroid: AuthenticationManagerInitializerAndroid
): AuthenticationCoreManager(
    dispatchers,
    encryptionKeyHashIterations,
    encryptionKeyHandler,
    persistentStorage,
    authenticationManagerInitializerAndroid
), Application.ActivityLifecycleCallbacks {

    @Suppress("ObjectPropertyName", "RemoveExplicitTypeArguments")
    private val _foregroundStateFlow: MutableStateFlow<ForegroundState> by lazy {
        MutableStateFlow<ForegroundState>(ForegroundState.Background)
    }

    override val foregroundStateFlow: StateFlow<ForegroundState>
        get() = _foregroundStateFlow.asStateFlow()

    var backgroundLogOutTime: Long = authenticationManagerInitializerAndroid.backgroundLogOutTime
        protected set

    private fun registerCallbacks(application: Application) {
        application.registerActivityLifecycleCallbacks(this)
    }

    init {
        registerCallbacks(authenticationManagerInitializerAndroid.application)
    }

    /**
     * If the user swipes the application from the recent apps tray, [onActivityDestroyed]
     * will be called if you have a service running.
     *
     *  - true: Sets [AuthenticationState.Required.InitialLogIn] and clears the encryption key.
     *
     *  - false: Does nothing
     *
     * This is useful if you have foreground services running that persist your application's
     * state in memory even after the user swipes it out of the recent apps tray.
     * */
    protected abstract val logOutWhenApplicationIsClearedFromRecentsTray: Boolean

    var timeMovedToBackground: Long = SystemClock.uptimeMillis()
        private set
    var changingConfigurations: Boolean = false
        private set
    var activityStackCount: Int = 0
        private set

    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}

    /**
     * If the application was brought back into the foreground and the
     * [backgroundLogOutTime] has been exceeded, the user is logged out.
     * */
    override fun onActivityStarted(activity: Activity) {
        if (++activityStackCount == 1 && !changingConfigurations) {
            _foregroundStateFlow.value = ForegroundState.Foreground
            if (authenticationStateFlow.value is AuthenticationState.NotRequired &&
                backgroundLogOutTime > 0L &&
                (SystemClock.uptimeMillis() - timeMovedToBackground) > backgroundLogOutTime
            ) {
                setAuthenticationStateRequired(AuthenticationState.Required.LoggedOut)
            }
        }
        changingConfigurations = false
    }

    override fun onActivityResumed(activity: Activity) {}

    override fun onActivityPaused(activity: Activity) {}

    override fun onActivityStopped(activity: Activity) {
        changingConfigurations = activity.isChangingConfigurations
        if (--activityStackCount == 0 && !changingConfigurations) {
            _foregroundStateFlow.value = ForegroundState.Background
            timeMovedToBackground = SystemClock.uptimeMillis()
        }
    }

    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}

    /**
     * This will only be called if you have a Service running when the app is
     * cleared; Android kills the app before [onActivityDestroyed] is called
     * otherwise.
     * */
    protected open fun onApplicationClearedFromRecentsTray(activity: Activity) {}

    override fun onActivityDestroyed(activity: Activity) {
        if (
            foregroundStateFlow.value is ForegroundState.Background &&
            !activity.isChangingConfigurations
        ) {
            onApplicationClearedFromRecentsTray(activity)
            if (logOutWhenApplicationIsClearedFromRecentsTray) {
                setAuthenticationStateRequired(AuthenticationState.Required.InitialLogIn)
            }
        }
    }
}
