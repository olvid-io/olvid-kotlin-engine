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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class ExponentialBackoffRepeatingSchedulerTest {

    private lateinit var scheduler: ExponentialBackoffRepeatingScheduler<String>
    private lateinit var executorService: java.util.concurrent.ScheduledExecutorService

    @Before
    fun setup() {
        // Use a real executor but we can override the delay
        executorService = Executors.newScheduledThreadPool(1)
        scheduler = object : ExponentialBackoffRepeatingScheduler<String>(executorService) {
            override fun computeReschedulingDelay(failedAttemptCount: Int): Long {
                // To keep tests fast
                return 1L
            }
        }
        
        // Suppress logger output to keep test logs clean, but enable it to test the branches
        Logger.setOutputter(object : Logger.LogOutputter {
            override fun d(tag: String, message: String) {}
            override fun i(tag: String, message: String) {}
            override fun w(tag: String, message: String) {}
            override fun e(tag: String, message: String) {}
            override fun x(tag: String, throwable: Throwable) {}
        })
        Logger.setOutputLogLevel(Logger.DEBUG)
    }

    @Test
    fun testSchedule() {
        val latch = CountDownLatch(1)
        scheduler.schedule("key1", Runnable { latch.countDown() })
        
        // Should execute after 1ms delay
        assertTrue(latch.await(2, TimeUnit.SECONDS))
    }

    @Test
    fun testScheduleWithTag() {
        val latch = CountDownLatch(1)
        scheduler.schedule("key1", Runnable { latch.countDown() }, "TestTag")
        
        assertTrue(latch.await(2, TimeUnit.SECONDS))
    }

    @Test
    fun testScheduleIgnoresDuplicateKey() {
        val latch1 = CountDownLatch(1)
        val latch2 = CountDownLatch(1)

        // Block the executor so we can schedule twice before execution
        val executorLatch = CountDownLatch(1)
        executorService.execute { executorLatch.await(1, TimeUnit.SECONDS) }

        scheduler.schedule("key1", Runnable { latch1.countDown() })
        scheduler.schedule("key1", Runnable { latch2.countDown() }) // should be ignored

        executorLatch.countDown()
        
        assertTrue(latch1.await(2, TimeUnit.SECONDS))
        assertEquals(1, latch2.count) // latch2 should not have been counted down
    }

    @Test
    fun testScheduleWithDelay() {
        val latch = CountDownLatch(1)
        scheduler.schedule("key1", Runnable { latch.countDown() }, "TagDelay", 10L)
        assertTrue(latch.await(2, TimeUnit.SECONDS))
    }
    
    @Test
    fun testScheduleWithDelayNullTag() {
        val latch = CountDownLatch(1)
        scheduler.schedule("key1", Runnable { latch.countDown() }, null, 10L)
        assertTrue(latch.await(2, TimeUnit.SECONDS))
    }

    @Test
    fun testSchedulePeriodically() {
        val latch = CountDownLatch(3)
        scheduler.schedulePeriodically("key1", Runnable { latch.countDown() }, "TagPeriodic", 10L)
        assertTrue(latch.await(2, TimeUnit.SECONDS))
    }
    
    @Test
    fun testSchedulePeriodicallyNullTag() {
        val latch = CountDownLatch(3)
        scheduler.schedulePeriodically("key1", Runnable { latch.countDown() }, null, 10L)
        assertTrue(latch.await(2, TimeUnit.SECONDS))
    }

    @Test
    fun testScheduleTwiceBumpsFailedCount() {
        // Covers the non-null branch of `failedAttemptCounts[key] ?: 0`:
        // the second schedule, after the first has fired, sees an existing count.
        val first = CountDownLatch(1)
        scheduler.schedule("key1", Runnable { first.countDown() })
        assertTrue(first.await(2, TimeUnit.SECONDS))

        val second = CountDownLatch(1)
        scheduler.schedule("key1", Runnable { second.countDown() }, "Retry")
        assertTrue(second.await(2, TimeUnit.SECONDS))
    }

    @Test
    fun testRetryScheduledRunnables() {
        val latch = CountDownLatch(1)
        
        // We need to schedule but prevent it from running immediately
        val executorLatch = CountDownLatch(1)
        executorService.execute { executorLatch.await(1, TimeUnit.SECONDS) }

        scheduler.schedule("key1", Runnable { latch.countDown() })
        
        // Now call retryScheduledRunnables. It clears pending and schedules them immediately
        scheduler.retryScheduledRunnables()
        
        executorLatch.countDown()
        
        // The runnable should execute
        assertTrue(latch.await(2, TimeUnit.SECONDS))
    }

    @Test
    fun testRetryScheduledRunnablesEmpty() {
        scheduler.retryScheduledRunnables() // should not crash
    }
    
    @Test
    fun testComputeReschedulingDelayDefault() {
        val realScheduler = ExponentialBackoffRepeatingScheduler<String>()
        val method = ExponentialBackoffRepeatingScheduler::class.java.getDeclaredMethod("computeReschedulingDelay", Int::class.javaPrimitiveType)
        method.isAccessible = true
        
        val delay1 = method.invoke(realScheduler, 1) as Long
        assertTrue(delay1 > 0)
        
        val delay32 = method.invoke(realScheduler, 32) as Long
        assertTrue(delay32 > 0)
        
        val delay33 = method.invoke(realScheduler, 33) as Long
        assertTrue(delay33 > 0)
    }
    
    @Test
    fun testPendingRunnableRemovedBeforeExecution() {
        // This covers the branch inside `schedule` where runnab == null
        // because it was removed. We can simulate it by retrying scheduled runnables
        // which clears the pending runnables list.
        
        val latch = CountDownLatch(1)
        val executorLatch = CountDownLatch(1)
        
        executorService.execute { executorLatch.await(1, TimeUnit.SECONDS) }
        
        // Schedules it, adds to pending list. 
        // The task block is submitted to executor
        scheduler.schedule("key1", Runnable { latch.countDown() })
        
        // Clear pending runnables
        scheduler.retryScheduledRunnables()
        
        executorLatch.countDown()
        
        // The original scheduled task will execute, lock, get pending (which is null now), 
        // and do nothing. The retry task will execute and count down the latch.
        assertTrue(latch.await(2, TimeUnit.SECONDS))
    }
}
