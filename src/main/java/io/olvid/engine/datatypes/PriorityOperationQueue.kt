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

// This class is similar to OperationQueue but adds some priority management
// Queued operations cannot have dependencies and must extend PriorityOperation

import java.util.LinkedList
import java.util.concurrent.PriorityBlockingQueue
import java.util.concurrent.locks.ReentrantLock

import io.olvid.engine.Logger

class PriorityOperationQueue {
    private val operations: PriorityBlockingQueue<PriorityOperation> = PriorityBlockingQueue()

    private val executingOperations: MutableList<PriorityOperation> = LinkedList()
    private val lockOnExecutingOperations: ReentrantLock = ReentrantLock()

    private var executing: Boolean = false
    private var numberOfThreads: Int = 0

    fun queue(op: PriorityOperation) {
        if (!op.dependencies.isEmpty()) {
            Logger.e("Cannot queue an operation with dependencies into a PriorityOperationQueue.")
            return
        }
        op.setPending()
        operations.add(op)
    }

    @JvmOverloads
    fun execute(numberOfThreads: Int, tag: String? = null) {
        if (executing) {
            Logger.e("You can only call execute once on a PriorityOperationQueue.")
            return
        }
        executing = true
        this.numberOfThreads = numberOfThreads
        for (i in 0 until numberOfThreads) {
            PriorityOperationQueueThread(i, tag).start()
        }
    }

    // NOTE: This method also returns null if there is a thread available for the new queued operation
    fun getExecutingOperationThatShouldBeCancelledWhenQueueingWithHigherPriority(): PriorityOperation? {
        var op: PriorityOperation? = null
        var maxPriority: Long = 0
        lockOnExecutingOperations.lock()
        if (executingOperations.size < numberOfThreads) {
            lockOnExecutingOperations.unlock()
            return null
        }
        for (operation in executingOperations) {
            val priority = operation.getPriority()
            if ((op == null) || (priority > maxPriority)) {
                op = operation
                maxPriority = priority
            }
        }
        lockOnExecutingOperations.unlock()
        return op
    }

    inner class PriorityOperationQueueThread(@JvmField val threadNumber: Int, tag: String?) : Thread() {
        init {
            if (tag != null) {
                name = "$tag-$threadNumber"
            }
        }

        override fun run() {
            // noinspection InfiniteLoopStatement
            while (true) {
                val op: PriorityOperation
                try {
                    op = operations.take()
                } catch (_: InterruptedException) {
                    continue
                }

                op.updateReadiness()
                op.processCancel()

                if (op.timestampOfLastExecution != 0L) {
                    val timeToWait = op.timestampOfLastExecution - System.currentTimeMillis() + OperationQueue.MILLISECONDS_TO_WAIT_BETWEEN_TWO_OPERATION_EXECUTIONS
                    if (timeToWait > 0) {
                        try {
                            sleep(timeToWait)
                        } catch (_: InterruptedException) {
                            // do nothing
                        }
                    }
                }
                op.timestampOfLastExecution = System.currentTimeMillis()

                if (op.isReady) {
                    if (op.areConditionsFulfilled()) {
                        lockOnExecutingOperations.lock()
                        executingOperations.add(op)
                        lockOnExecutingOperations.unlock()

                        try {
                            op.execute()
                        } catch (e: Exception) {
                            Logger.e("Exception in operation that could have killed a queue!")
                            Logger.x(e)
                        }

                        lockOnExecutingOperations.lock()
                        executingOperations.remove(op)
                        lockOnExecutingOperations.unlock()
                    } else {
                        operations.add(op)
                    }
                }
            }
        }
    }
}
