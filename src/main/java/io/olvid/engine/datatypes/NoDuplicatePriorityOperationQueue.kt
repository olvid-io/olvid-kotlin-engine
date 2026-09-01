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
import java.util.HashSet
import java.util.concurrent.PriorityBlockingQueue
import java.util.concurrent.locks.ReentrantLock

class NoDuplicatePriorityOperationQueue {
    private val operations: PriorityBlockingQueue<PriorityOperation> = PriorityBlockingQueue()
    private val lockOnQueuedOperationUids: ReentrantLock = ReentrantLock()
    private val queuedOperationUids: HashSet<UID> = HashSet()

    private var executing = false

    fun queue(op: PriorityOperation) {
        if (op.dependencies.isNotEmpty()) {
            Logger.e("Cannot queue an operation with dependencies into a NoDuplicatePriorityOperationQueue.")
            return
        }
        val uid = op.uid
        if (uid != null) {
            lockOnQueuedOperationUids.lock()
            if (queuedOperationUids.contains(uid)) {
                lockOnQueuedOperationUids.unlock()
                return
            }
            queuedOperationUids.add(uid)
            lockOnQueuedOperationUids.unlock()
        }
        op.setPending()
        operations.add(op)
    }

    @JvmOverloads
    fun execute(numberOfThreads: Int, tag: String? = null) {
        if (executing) {
            Logger.e("You can only call execute once on a NoDuplicatePriorityOperationQueue.")
            return
        }
        executing = true
        for (i in 0 until numberOfThreads) {
            NoDuplicatePriorityOperationQueueThread(i, tag).start()
        }
    }

    inner class NoDuplicatePriorityOperationQueueThread(private val threadNumber: Int, tag: String?) : Thread() {
        init {
            if (tag != null) {
                name = "$tag-$threadNumber"
            }
        }

        override fun run() {
            @Suppress("InfiniteLoopStatement")
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
                        } catch (_: InterruptedException) { }
                    }
                }
                op.timestampOfLastExecution = System.currentTimeMillis()

                if (op.isReady) {
                    if (op.areConditionsFulfilled()) {
                        val uid = op.uid
                        if (uid != null) {
                            lockOnQueuedOperationUids.lock()
                            queuedOperationUids.remove(uid)
                            lockOnQueuedOperationUids.unlock()
                        }
                        try {
                            op.execute()
                        } catch (e: Exception) {
                            Logger.e("Exception in operation that could have killed a queue!")
                            Logger.x(e)
                        }
                    } else {
                        operations.add(op)
                    }
                }
            }
        }
    }
}
