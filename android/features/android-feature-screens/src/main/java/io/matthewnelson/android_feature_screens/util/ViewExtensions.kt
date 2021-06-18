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
package io.matthewnelson.android_feature_screens.util

import android.content.res.Resources
import android.view.View

@Suppress("NOTHING_TO_INLINE")
inline fun Int.dpToPX(): Int =
    (this * Resources.getSystem().displayMetrics.density).toInt()

@Suppress("NOTHING_TO_INLINE")
inline fun Int.pxToDp(): Int =
    (this / Resources.getSystem().displayMetrics.density).toInt()

inline val <T: View> T.visible: T
    get() {
        visibility = View.VISIBLE
        return this
    }

inline val <T: View> T.invisible: T
    get() {
        visibility = View.INVISIBLE
        return this
    }

inline val <T: View> T.gone: T
    get() {
        visibility = View.GONE
        return this
    }

@Suppress("NOTHING_TO_INLINE")
inline fun <T: View> T.invisibleIfTrue(boolean: Boolean): T =
    if (boolean) invisible else visible

@Suppress("NOTHING_TO_INLINE")
inline fun <T: View> T.invisibleIfFalse(boolean: Boolean): T =
    invisibleIfTrue(!boolean)

@Suppress("NOTHING_TO_INLINE")
inline fun <T: View> T.goneIfTrue(boolean: Boolean): T =
    if (boolean) gone else visible

@Suppress("NOTHING_TO_INLINE")
inline fun <T: View> T.goneIfFalse(boolean: Boolean): T =
    goneIfTrue(!boolean)
