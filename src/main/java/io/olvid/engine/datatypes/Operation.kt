/*
 *  Olvid Kotlin Engine
 *  Copyright © 2019-2026 Olvid SAS
 *
 *  This file is part of the Olvid Kotlin Engine.
 *
 *  The Olvid Kotlin Engine is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License, version 3,
 *  as published by the Free Software Foundation.
 *
 *  The Olvid Kotlin Engine is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with the Olvid Kotlin Engine.  If not, see <https://www.gnu.org/licenses/>.
 */
package io.olvid.engine.datatypes

import io.olvid.engine.Logger
import java.util.LinkedList
import java.util.concurrent.locks.ReentrantLock


abstract class Operation @JvmOverloads constructor(
    @JvmField val uid: UID? = null,
    private val onFinishCallback: OnFinishCallback? = null,
    private val onCancelCallback: OnCancelCallback? = null
) {
    fun interface OnFinishCallback {
        fun onFinishCallback(operation: Operation)
    }

    fun interface OnCancelCallback {
        fun onCancelCallback(operation: Operation)
    }

    private enum class State {
        NOT_QUEUED,
        PENDING,
        READY,
        EXECUTING,
        FINISHED,
        CANCELLED
    }

    val dependencies: MutableList<Operation>
    private var state: State
    private val lockOnState: ReentrantLock
    var timestampOfLastExecution: Long = 0
    private var cancelWasRequested = false
    var reasonForCancel: Int? = null
        private set

    init {
        state = State.NOT_QUEUED
        dependencies = LinkedList<Operation>()
        lockOnState = ReentrantLock()
    }

    override fun toString(): String {
        return "Operation of type " + this.javaClass.getName() + "(" + System.identityHashCode(this) + ")\n\tStatus: " + this.state
    }

    fun hasCancelledDependency(): Boolean {
        for (op in dependencies) {
            if (op.isCancelled) {
                return true
            }
        }
        return false
    }

    fun areAllDependenciesFinished(): Boolean {
        for (op in dependencies) {
            if (!op.isFinished) {
                return false
            }
        }
        return true
    }

    fun updateReadiness() {
        if (!this.isPending) {
            return
        }
        if (hasCancelledDependency()) {
            cancel(null)
            return
        }
        if (areAllDependenciesFinished()) {
            setReady()
        }
    }

    fun setFinished() {
        lockOnState.lock()
        if (isStateChangeAuthorized(State.FINISHED)) {
            state = State.FINISHED
            lockOnState.unlock()
            if (onFinishCallback != null) {
                onFinishCallback.onFinishCallback(this)
            }
            if (uid != null) {
                globalLock.lock()
                val uids: HashSet<UID?>? = runningOperationUIDsByClass.get(this.javaClass.getName())
                if (uids != null) {
                    uids.remove(uid)
                }
                globalLock.unlock()
            }
        } else {
            lockOnState.unlock()
        }
    }

    fun cancel(reasonForCancel: Int?) {
        lockOnState.lock()
        if ((state != State.CANCELLED) && (state != State.FINISHED) && !cancelWasRequested) {
            cancelWasRequested = true
            this.reasonForCancel = reasonForCancel
            Logger.d("Cancel with RFC " + reasonForCancel + " requested for Operation of " + javaClass)
        }
        lockOnState.unlock()
        doCancel()
    }

    abstract fun doCancel()

    fun processCancel() {
        lockOnState.lock()
        if ((state != State.CANCELLED) && (state != State.FINISHED) && cancelWasRequested) {
            state = State.CANCELLED
            lockOnState.unlock()
            if (onCancelCallback != null) {
                onCancelCallback.onCancelCallback(this)
            }
            if (uid != null) {
                globalLock.lock()
                val uids: HashSet<UID?>? = runningOperationUIDsByClass.get(this.javaClass.getName())
                if (uids != null) {
                    uids.remove(uid)
                }
                globalLock.unlock()
            }
            Logger.d("Processed cancel of Operation of " + this.javaClass.toString())
        } else {
            lockOnState.unlock()
        }
    }

    fun areConditionsFulfilled(): Boolean {
        var conditionsFulfilled = true
        globalLock.lock()
        if (uid != null) {
            val uids: HashSet<UID?>? = runningOperationUIDsByClass.get(this.javaClass.getName())
            if ((uids != null) && (uids.contains(uid))) {
                conditionsFulfilled = false
            }
        }
        globalLock.unlock()
        return conditionsFulfilled
    }

    fun execute() {
        if (uid != null) {
            globalLock.lock()
            var uids: HashSet<UID?>? = runningOperationUIDsByClass.get(this.javaClass.getName())
            if (uids == null) {
                uids = HashSet<UID?>()
                runningOperationUIDsByClass.put(this.javaClass.getName(), uids)
            }
            uids.add(uid)
            globalLock.unlock()
        }
        setExecuting()
        doExecute()
    }

    abstract fun doExecute()


    fun addDependency(operation: Operation?) {
        for (op in dependencies) {
            op.addDependency(operation)
        }
        dependencies.add(operation!!)
    }

    private fun isStateChangeAuthorized(newState: State): Boolean {
        when (state) {
            State.NOT_QUEUED -> when (newState) {
                State.NOT_QUEUED, State.PENDING, State.CANCELLED -> return true
                else -> return false
            }

            State.PENDING -> when (newState) {
                State.PENDING, State.READY, State.CANCELLED -> return true
                else -> return false
            }

            State.READY -> when (newState) {
                State.READY, State.EXECUTING, State.CANCELLED -> return true
                else -> return false
            }

            State.EXECUTING -> when (newState) {
                State.EXECUTING, State.FINISHED, State.CANCELLED -> return true
                else -> return false
            }

            State.FINISHED -> return newState == State.FINISHED
            State.CANCELLED -> return newState == State.CANCELLED
        }
        return false
    }

    fun setPending() {
        lockOnState.lock()
        if (isStateChangeAuthorized(State.PENDING)) {
            state = State.PENDING
        }
        lockOnState.unlock()
    }

    fun setReady() {
        lockOnState.lock()
        if (isStateChangeAuthorized(State.READY)) {
            state = State.READY
        }
        lockOnState.unlock()
    }

    fun setExecuting() {
        lockOnState.lock()
        if (isStateChangeAuthorized(State.EXECUTING)) {
            state = State.EXECUTING
        }
        lockOnState.unlock()
    }

    fun wasQueued(): Boolean {
        lockOnState.lock()
        val res = state != State.NOT_QUEUED
        lockOnState.unlock()
        return res
    }

    val isPending: Boolean
        get() {
            lockOnState.lock()
            val res = state == State.PENDING
            lockOnState.unlock()
            return res
        }

    val isExecuting: Boolean
        get() {
            lockOnState.lock()
            val res = state == State.EXECUTING
            lockOnState.unlock()
            return res
        }

    val isReady: Boolean
        get() {
            lockOnState.lock()
            val res = state == State.READY
            lockOnState.unlock()
            return res
        }

    val isFinished: Boolean
        get() {
            lockOnState.lock()
            val res = state == State.FINISHED
            lockOnState.unlock()
            return res
        }

    val isCancelled: Boolean
        get() {
            lockOnState.lock()
            val res = state == State.CANCELLED
            lockOnState.unlock()
            return res
        }

    fun cancelWasRequested(): Boolean {
        return cancelWasRequested
    }

    fun hasNoReasonForCancel(): Boolean {
        return reasonForCancel == null
    }

    companion object {
        val RFC_NULL: Int = -1
        private val globalLock = ReentrantLock()
        private val runningOperationUIDsByClass = HashMap<String?, HashSet<UID?>?>()
    }
}
