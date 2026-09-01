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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class PriorityOperationQueueTest {

    @Test
    fun testPriorityOrderingAndCancelCandidate() {
        val opLow = GatedOperation(10)
        val opHigh = GatedOperation(100)

        val queue = PriorityOperationQueue()
        queue.queue(opLow)
        queue.queue(opHigh)
        queue.execute(1)

        // the single thread must pick the lowest-priority-value operation first
        awaitLatch(opLow.started)
        assertFalse(opHigh.started.count == 0L)
        assertEquals(opLow, queue.getExecutingOperationThatShouldBeCancelledWhenQueueingWithHigherPriority())

        // release opLow; once opHigh reports started, opLow is finished and dequeued
        opLow.release.countDown()
        awaitLatch(opHigh.started)
        assertTrue(opLow.isFinished)
        assertEquals(opHigh, queue.getExecutingOperationThatShouldBeCancelledWhenQueueingWithHigherPriority())

        // queue a lower-priority op, then cancel the executing one: the freed
        // thread must pick up the queued op
        val opNext = GatedOperation(50)
        queue.queue(opNext)
        opHigh.cancel(null)

        awaitLatch(opNext.started)
        assertTrue(opHigh.isCancelled)

        opNext.release.countDown()
        awaitFinished(opNext)

        // isFinished is set inside doExecute, slightly before the worker removes
        // the operation from the executing list — poll for the dequeue
        val deadline = System.currentTimeMillis() + 10_000
        while (queue.getExecutingOperationThatShouldBeCancelledWhenQueueingWithHigherPriority() != null &&
            System.currentTimeMillis() < deadline
        ) {
            Thread.sleep(5)
        }

        // all threads idle again: no cancel candidate
        assertNull(queue.getExecutingOperationThatShouldBeCancelledWhenQueueingWithHigherPriority())
    }

    private fun awaitLatch(latch: CountDownLatch) {
        assertTrue("timed out waiting for operation state", latch.await(10, TimeUnit.SECONDS))
    }

    private fun awaitFinished(op: Operation) {
        val deadline = System.currentTimeMillis() + 10_000
        while (!op.isFinished && System.currentTimeMillis() < deadline) {
            Thread.sleep(5)
        }
        assertTrue(op.isFinished)
    }

    // An operation whose lifecycle is driven by latches instead of wall-clock
    // sleeps: it signals when it starts executing and blocks until the test
    // releases it (or it is cancelled), so assertions never race the scheduler.
    private class GatedOperation(private val priority: Long) : PriorityOperation(null, null, null) {
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)

        override fun getPriority(): Long = priority

        override fun doCancel() {
            release.countDown()
        }

        override fun doExecute() {
            started.countDown()
            release.await(10, TimeUnit.SECONDS)
            processCancel()
            setFinished()
        }
    }
}
