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
package io.matthewnelson.android_feature_screens.ui.motionlayout

import android.os.Bundle
import android.view.View
import androidx.annotation.LayoutRes
import androidx.constraintlayout.motion.widget.MotionLayout
import androidx.viewbinding.ViewBinding
import io.matthewnelson.android_concept_views.MotionLayoutViewState
import io.matthewnelson.concept_views.sideeffect.SideEffect
import io.matthewnelson.android_feature_screens.ui.sideeffect.SideEffectFragment
import io.matthewnelson.android_feature_viewmodel.MotionLayoutViewModel
import io.matthewnelson.android_feature_viewmodel.currentViewState

/**
 * An abstraction of [SideEffectFragment] that aids in the execution of a [MotionLayout].
 *
 * @see [MotionLayoutViewModel]
 * @see [MotionLayoutViewState]
 * */
abstract class MotionLayoutFragment<
        MSC: Any,
        T,
        SE: SideEffect<T>,
        MLVS: MotionLayoutViewState<MLVS>,
        MLVM: MotionLayoutViewModel<MSC, T, SE, MLVS>,
        VB: ViewBinding
        >(@LayoutRes layoutId: Int): SideEffectFragment<
        T,
        SE,
        MLVS,
        MLVM,
        VB
        >(layoutId), MotionLayout.TransitionListener
{
    override fun onTransitionTrigger(motionLayout: MotionLayout?, triggerId: Int, positive: Boolean, progress: Float) {}
    override fun onTransitionStarted(motionLayout: MotionLayout?, startId: Int, endId: Int) {}
    override fun onTransitionChange(motionLayout: MotionLayout?, startId: Int, endId: Int, progress: Float) {}
    override fun onTransitionCompleted(motionLayout: MotionLayout?, currentId: Int) {}

    protected open fun setTransitionListener(motionLayout: MotionLayout) {
        motionLayout.setTransitionListener(this)
    }
    protected open fun removeTransitionListener(motionLayout: MotionLayout) {
        motionLayout.removeTransitionListener(this)
    }

    /**
     * Call [MotionLayoutViewState.restoreMotionScene] for the current [viewState].
     * */
    protected abstract fun onViewCreatedRestoreMotionScene(viewState: MLVS, binding: VB)
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        currentViewState = viewModel.currentViewState
        onViewCreatedRestoreMotionScene(viewModel.currentViewState, binding)
    }

    /**
     * Ensures removal of listeners from **all** [MotionLayout]s.
     * */
    protected abstract fun getMotionLayouts(): Array<MotionLayout>
    override fun onDestroyView() {
        super.onDestroyView()
        getMotionLayouts().forEach {
            removeTransitionListener(it)
        }
    }
}
