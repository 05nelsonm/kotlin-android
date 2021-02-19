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
package io.matthewnelson.feature_authentication_view.components

import app.cash.exhaustive.Exhaustive
import io.matthewnelson.feature_authentication_core.model.AuthenticateFlowResponse.ConfirmPinEntryToSetForFirstTime
import io.matthewnelson.feature_authentication_core.model.AuthenticateFlowResponse.ConfirmNewPinEntryToReset

internal class ConfirmPressAction {

    @Volatile
    private var action: Action = Action.Authenticate

    @JvmSynthetic
    @Synchronized
    fun getAction(): Action =
        action

    @JvmSynthetic
    @Synchronized
    fun updateAction(newAction: Action) {
        action.let { currentAction ->
            @Exhaustive
            when (currentAction) {
                is Action.Authenticate -> {}
                is Action.ResetPin -> {
                    currentAction.flowResponseResetPin.clearCurrentValidPinEntry()
                    currentAction.flowResponseResetPin.clearNewPinEntry()
                }
                is Action.SetPinFirstTime -> {
                    currentAction.flowResponseSetPinFirstTime.clearInitialPinEntry()
                }
            }
        }
        action = newAction
    }

    sealed class Action {
        object Authenticate : Action()

        class ResetPin private constructor(
            val flowResponseResetPin: ConfirmNewPinEntryToReset
        ): Action() {
            companion object {
                @JvmSynthetic
                fun instantiate(flowResponseResetPin: ConfirmNewPinEntryToReset): ResetPin =
                    ResetPin(flowResponseResetPin)
            }
        }

        class SetPinFirstTime private constructor(
            val flowResponseSetPinFirstTime: ConfirmPinEntryToSetForFirstTime
        ): Action() {
            companion object {
                @JvmSynthetic
                fun instantiate(
                    flowResponseSetPinFirstTime: ConfirmPinEntryToSetForFirstTime
                ): SetPinFirstTime =
                    SetPinFirstTime(flowResponseSetPinFirstTime)
            }
        }
    }
}
