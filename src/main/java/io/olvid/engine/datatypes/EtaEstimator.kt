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

import java.util.ArrayList

class EtaEstimator(initialBytes: Long, private val totalBytes: Long) {

    companion object {
        const val MIN_SAMPLE_COUNT = 10
        const val MIN_SAMPLE_DURATION = 10000L
    }

    private var samples: MutableList<Sample> = ArrayList()
    private var offset = 0

    init {
        this.samples.add(Sample(System.currentTimeMillis(), initialBytes))
    }

    fun update(currentBytes: Long) {
        val timestamp = System.currentTimeMillis()
        synchronized(this) {
            this.samples.add(Sample(timestamp, currentBytes))
            // only ever consider the last 10 seconds of sample, but never less than 10 samples
            while (this.samples.size - offset > MIN_SAMPLE_COUNT
                && timestamp - this.samples[offset].timestamp > MIN_SAMPLE_DURATION
            ) {
                offset++
            }
            // once in a while, truncate the list
            if (offset > 1000) {
                samples = samples.subList(offset, samples.size).toMutableList()
                offset = 0
            }
        }
    }

    val speedAndEta: SpeedAndEta
        get() {
            synchronized(this) {
                val start = samples[offset]
                val end = samples[samples.size - 1]
                val elapsed = end.timestamp - start.timestamp
                val xferred = end.byteCount - start.byteCount
                if (elapsed == 0L || xferred == 0L) {
                    return SpeedAndEta(0f, 0)
                }
                val speed = 1000 * xferred.toFloat() / elapsed.toFloat()
                val eta = Math.round((totalBytes - end.byteCount) / speed)
                return SpeedAndEta(speed, eta)
            }
        }

    private class Sample(
        @JvmField val timestamp: Long,
        @JvmField val byteCount: Long
    )

    class SpeedAndEta(
        @JvmField val speedBps: Float,
        @JvmField val etaSeconds: Int
    )
}
