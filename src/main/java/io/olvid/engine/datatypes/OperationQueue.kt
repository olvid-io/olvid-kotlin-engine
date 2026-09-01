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
import java.util.Queue
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.locks.Lock
import java.util.concurrent.locks.ReentrantLock


class OperationQueue @JvmOverloads constructor(private val persistent: Boolean = false) {
    private val operations: Queue<Operation?>
    private val lockOnCount: Lock
    private var count = 0
    private val notifier: Any

    private var executing = false

    init {
        this.operations = ConcurrentLinkedQueue<Operation?>()
        this.lockOnCount = ReentrantLock()
        this.notifier = Any()
    }

    private fun addOperation(op: Operation?) {
        lockOnCount.lock()
        count++
        operations.add(op)
        lockOnCount.unlock()
        synchronized(notifier) {
            (notifier as Object).notifyAll()
        }
    }

    fun queue(op: Operation) {
        op.setPending()
        addOperation(op)
    }


    // this method waits for the queue to be empty.
    // If the queue is non-persistent, a join only returns once all threads are dead.
    // If the queue is persistent, additional operations can still be added later on.
    fun join() {
        lockOnCount.lock()
        var queueIsEmpty = count == 0
        lockOnCount.unlock()
        while (!queueIsEmpty) {
            synchronized(notifier) {
                try {
                    (notifier as Object).wait(500)
                } catch (e: InterruptedException) {
                    Logger.x(e)
                }
            }
            lockOnCount.lock()
            queueIsEmpty = count == 0
            lockOnCount.unlock()
        }
    }

    @JvmOverloads
    fun execute(numberOfThreads: Int, tag: String? = null) {
        if (persistent) {
            if (executing) {
                Logger.e("You can only call execute once on a persistent OperationQueue.")
                return
            }
            executing = true
        }
        for (i in 0..<numberOfThreads) {
            OperationQueueThread(i, tag).start()
        }
    }

    internal inner class OperationQueueThread(@JvmField val threadNumber: Int, tag: String?) : Thread() {
        init {
            if (tag != null) {
                setName(tag + "-" + threadNumber)
            }
        }

        override fun run() {
            while (true) {
                val op = operations.poll()
                if (op == null) {
                    if (persistent) {
                        synchronized(notifier) {
                            try {
                                (notifier as Object).wait(30000)
                            } catch (e: InterruptedException) {
                                Logger.x(e)
                            }
                        }
                        continue
                    } else {
                        break
                    }
                }

                op.updateReadiness()
                op.processCancel()

                if (op.timestampOfLastExecution != 0L) {
                    val timeToWait: Long =
                        op.timestampOfLastExecution - System.currentTimeMillis() + MILLISECONDS_TO_WAIT_BETWEEN_TWO_OPERATION_EXECUTIONS
                    if (timeToWait > 0) {
                        try {
                            sleep(timeToWait)
                        } catch (_: InterruptedException) {
                        }
                    }
                }
                op.timestampOfLastExecution = System.currentTimeMillis()

                if (op.isPending) {
                    addOperation(op)
                }
                if (op.isReady) {
                    if (op.areConditionsFulfilled()) {
                        try {
                            op.execute()
                        } catch (e: Exception) {
                            Logger.e("Exception in operation that could have killed a queue!")
                            Logger.x(e)
                        }
                    } else {
                        addOperation(op)
                    }
                }


                lockOnCount.lock()
                count--
                synchronized(notifier) {
                    (notifier as Object).notifyAll()
                }
                lockOnCount.unlock()
            }
        }
    }

    companion object {
        const val MILLISECONDS_TO_WAIT_BETWEEN_TWO_OPERATION_EXECUTIONS: Int = 20
    }
}
