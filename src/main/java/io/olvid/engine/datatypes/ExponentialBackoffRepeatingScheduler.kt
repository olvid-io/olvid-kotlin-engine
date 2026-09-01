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
import java.util.Random
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

open class ExponentialBackoffRepeatingScheduler<T> @JvmOverloads constructor(
    private val scheduler: ScheduledExecutorService = Executors.newScheduledThreadPool(1)
) {
    private val failedAttemptCounts = HashMap<T, Int>()
    private val pendingRunnables = HashMap<T, Runnable>()
    private val lock = Any()
    private val random = Random()

    @JvmOverloads
    fun schedule(key: T, runnable: Runnable, tag: String? = null) {
        synchronized(lock) {
            val oldRunnable = pendingRunnables[key]
            if (oldRunnable != null) {
                return
            }
            pendingRunnables[key] = runnable

            val failedCount = (failedAttemptCounts[key] ?: 0) + 1
            failedAttemptCounts[key] = failedCount

            val delay = computeReschedulingDelay(failedCount)
            if (tag != null) {
                Logger.i("Scheduling a $tag for $key in ${delay}ms.")
            }
            scheduler.schedule({
                var runnab: Runnable?
                synchronized(lock) {
                    runnab = pendingRunnables[key]
                    if (runnab != null) {
                        pendingRunnables.remove(key)
                    }
                }
                runnab?.run()
            }, delay, TimeUnit.MILLISECONDS)
        }
    }

    // used to schedule a task with a given delay, independently of failed attempts
    fun schedule(key: T, runnable: Runnable, tag: String?, delay: Long) {
        synchronized(lock) {
            if (tag != null) {
                Logger.d("Scheduling a $tag for $key in ${delay}ms.")
            }
            scheduler.schedule(runnable, delay, TimeUnit.MILLISECONDS)
        }
    }

    // used to repeatedly schedule a task with a given period, independently of failed attempts
    fun schedulePeriodically(key: T, runnable: Runnable, tag: String?, delay: Long) {
        synchronized(lock) {
            if (tag != null) {
                Logger.d("Scheduling periodically a $tag for $key at intervals of ${delay}ms.")
            }
            scheduler.scheduleWithFixedDelay(runnable, delay, delay, TimeUnit.MILLISECONDS)
        }
    }

    fun clearFailedCount(key: T) {
        synchronized(lock) {
            failedAttemptCounts.remove(key)
        }
    }

    fun retryScheduledRunnables() {
        val runnables: List<Runnable>
        synchronized(lock) {
            runnables = ArrayList(pendingRunnables.values)
            pendingRunnables.clear()
            failedAttemptCounts.clear()
        }
        scheduler.execute {
            for (runnable in runnables) {
                runnable.run()
            }
        }
    }

    // for polling only
    protected open fun computeReschedulingDelay(failedAttemptCount: Int): Long {
        val base = Constants.BASE_RESCHEDULING_TIME shl Math.min(failedAttemptCount, 32)
        return (base * (1 + random.nextFloat())).toLong()
    }
}
