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
package io.matthewnelson.android_feature_viewmodel

import io.matthewnelson.android_concept_views.MotionLayoutViewState
import io.matthewnelson.concept_coroutines.CoroutineDispatchers
import io.matthewnelson.concept_views.sideeffect.SideEffect

/**
 * An abstraction that defines the [BaseViewModel.viewStateContainer] as being of type
 * [MotionLayoutViewState].
 *
 * @see [MotionLayoutViewState]
 * */
abstract class MotionLayoutViewModel<
        MSC: Any,
        T,
        SE: SideEffect<T>,
        MLVS: MotionLayoutViewState<MLVS>
        >(dispatchers: CoroutineDispatchers, initialViewState: MLVS): SideEffectViewModel<
        T,
        SE,
        MLVS
        >(dispatchers, initialViewState)
{

    /**
     * Best if called from the Fragment/Activity
     *
     * Example:
     *
     *   lifecycleScope.launchWhenStarted {
     *       viewModel.viewStateContainer.collect { myMotionLayoutViewState ->
     *           if (myMotionLayoutViewState is MyMotionLayoutViewState.FinalState) {
     *               viewModel.onMotionSceneCompletion()
     *           }
     *       }
     *   }
     * */
    abstract suspend fun onMotionSceneCompletion(value: MSC)
}
