package io.matthewnelson.concept_navigation_driver

import io.matthewnelson.concept_navigation_client.BaseNavigationDriver
import io.matthewnelson.concept_navigation_client.NavigationRequest
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import java.util.UUID

/**
 * This class is consumed by the driver (for Android, an activity) and injected
 * as the [BaseNavigationDriver] to feature modules.
 * */
abstract class NavigationDriver<T>(
    // For android, 3 is a good value. This really depends on if you have navigation being
    // executed automatically w/o user input (say, after animation completes). This is due
    // to configuration changes which make tracking what requests have been executed a necessity.
    protected val replayCacheSize: Int
): BaseNavigationDriver<T>() {

    init {
        require(replayCacheSize > 0)
    }

    val navigationRequestSharedFlow: SharedFlow<Pair<NavigationRequest<T>, UUID>>
        get() = _navigationRequestSharedFlow.asSharedFlow()

    private val executedNavigationRequestsLock = Object()
    private val executedNavigationRequests: Array<UUID?> =
        arrayOfNulls(replayCacheSize)

    @Suppress("MemberVisibilityCanBePrivate")
    protected fun hasBeenExecuted(request: Pair<NavigationRequest<T>, UUID>): Boolean =
        synchronized(executedNavigationRequestsLock) {
            executedNavigationRequests.contains(request.second)
        }

    /**
     * Allows for conditional checking in the implementation based off of
     * the request.
     *
     * Returning false will result in the request _not_ being executed, as well
     * as _not_ being added to [executedNavigationRequests].
     * */
    protected abstract suspend fun whenTrueExecuteRequest(request: NavigationRequest<T>): Boolean

    /**
     * Returns true if the request was executed, and false if it was not
     * */
    open suspend fun executeNavigationRequest(controller: T, request: Pair<NavigationRequest<T>, UUID>): Boolean {
        if (hasBeenExecuted(request)) {
            return false
        }

        if (!whenTrueExecuteRequest(request.first)) {
            return false
        }

        if (replayCacheSize > 0) {
            synchronized(executedNavigationRequestsLock) {
                for (i in 0 until executedNavigationRequests.lastIndex) {
                    executedNavigationRequests[i] = executedNavigationRequests[i + 1]
                }
                executedNavigationRequests[executedNavigationRequests.lastIndex] = request.second
            }
        }

        request.first.navigate(controller)
        return true
    }

    /**
     * Expose in the implementation via:
     *
     * ```
     *   val navigationRequestSharedFlow: SharedFlow
     *       get() = _navigationRequestSharedFlow.asSharedFlow()
     * ```
     * */
    @Suppress("RemoveExplicitTypeArguments", "PropertyName")
    protected val _navigationRequestSharedFlow: MutableSharedFlow<Pair<NavigationRequest<T>, UUID>> by lazy {
        MutableSharedFlow<Pair<NavigationRequest<T>, UUID>>(replayCacheSize)
    }

    /**
     * Assigns a [UUID] to the navigation request such that execution of it
     * can be tracked.
     *
     * This is needed for Android due to configuration changes which inhibits the
     * ability to use [kotlinx.coroutines.flow.SharedFlow]'s buffer overflow.
     * */
    override suspend fun submitNavigationRequest(request: NavigationRequest<T>) {
        _navigationRequestSharedFlow.emit(Pair(request, UUID.randomUUID()))
    }
}