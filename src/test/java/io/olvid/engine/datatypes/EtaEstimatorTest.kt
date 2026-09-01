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

import org.junit.Assert.*
import org.junit.Test
import java.lang.reflect.Field

class EtaEstimatorTest {

    private fun getSamplesField(): Field {
        val field = EtaEstimator::class.java.getDeclaredField("samples")
        field.isAccessible = true
        return field
    }

    private fun getOffsetField(): Field {
        val field = EtaEstimator::class.java.getDeclaredField("offset")
        field.isAccessible = true
        return field
    }

    private fun getSampleTimestampField(sample: Any): Field {
        val field = sample.javaClass.getDeclaredField("timestamp")
        field.isAccessible = true
        return field
    }

    private fun getSampleByteCountField(sample: Any): Field {
        val field = sample.javaClass.getDeclaredField("byteCount")
        field.isAccessible = true
        return field
    }

    @Test
    fun testConstructorAndInitialState() {
        val initialBytes = 100L
        val totalBytes = 1000L
        val estimator = EtaEstimator(initialBytes, totalBytes)

        val samples = getSamplesField().get(estimator) as List<*>
        assertEquals(1, samples.size)

        val sample = samples[0]!!
        val timestamp = getSampleTimestampField(sample).get(sample) as Long
        val byteCount = getSampleByteCountField(sample).get(sample) as Long

        assertTrue(timestamp <= System.currentTimeMillis())
        assertEquals(initialBytes, byteCount)

        val offset = getOffsetField().get(estimator) as Int
        assertEquals(0, offset)
    }

    @Test
    fun testUpdateWithoutOffsetChange() {
        val estimator = EtaEstimator(0L, 1000L)
        // Add some updates quickly. They shouldn't trigger the while loop since the elapsed time
        // will be < 10,000 ms, or because count is <= 10.
        for (i in 1..5) {
            estimator.update(i * 10L)
        }

        val samples = getSamplesField().get(estimator) as List<*>
        assertEquals(6, samples.size)

        val offset = getOffsetField().get(estimator) as Int
        assertEquals(0, offset)
    }

    @Test
    fun testUpdateWithOffsetChange() {
        val estimator = EtaEstimator(0L, 1000L)
        
        // Add 10 samples (total 11 samples, which is > MIN_SAMPLE_COUNT (10)).
        for (i in 1..10) {
            estimator.update(i * 10L)
        }

        var samples = getSamplesField().get(estimator) as List<*>
        assertEquals(11, samples.size)

        // Modify the timestamps of existing samples using reflection to simulate elapsed time.
        // We want the first sample to be very old, so that timestamp - first.timestamp > MIN_SAMPLE_DURATION (10,000 ms).
        val now = System.currentTimeMillis()
        
        // Let's set sample[0] to now - 15,000 ms
        val s0 = samples[0]!!
        getSampleTimestampField(s0).set(s0, now - 15000L)

        // Set sample[1] to now - 5,000 ms
        val s1 = samples[1]!!
        getSampleTimestampField(s1).set(s1, now - 5000L)

        // Trigger an update. The new sample will have timestamp ~ now.
        // Size - offset = 11 - 0 = 11 > 10.
        // timestamp - sample[0].timestamp = now - (now - 15,000) = 15,000 > 10,000.
        // So offset should increment to 1.
        // Then, sample[1] has timestamp now - 5,000.
        // now - (now - 5,000) = 5,000 <= 10,000.
        // So offset should stop at 1.
        estimator.update(110L)

        val offset = getOffsetField().get(estimator) as Int
        assertEquals(1, offset)
    }

    @Test
    fun testUpdateWithTruncation() {
        val estimator = EtaEstimator(0L, 10000L)
        
        // Directly manipulate the estimator using reflection to simulate offset > 1000.
        val samplesField = getSamplesField()
        val offsetField = getOffsetField()

        val samplesList = samplesField.get(estimator) as ArrayList<Any>
        
        // Let's populate the samples list with 1005 mock samples
        val sampleClass = Class.forName("io.olvid.engine.datatypes.EtaEstimator\$Sample")
        val constructor = sampleClass.getDeclaredConstructor(Long::class.javaPrimitiveType, Long::class.javaPrimitiveType)
        constructor.isAccessible = true

        samplesList.clear()
        val baseTime = System.currentTimeMillis()
        for (i in 0..1005) {
            val sample = constructor.newInstance(baseTime + i * 1000L, i * 10L)
            samplesList.add(sample)
        }

        // Set offset to 1002 (> 1000)
        offsetField.set(estimator, 1002)

        // Update to trigger the offset > 1000 truncation logic
        estimator.update(10060L)

        // The list should have been truncated:
        // offset was 1002.
        // samples = samples.subList(offset, samples.size())
        // Since offset > 1000, it slices the list from 1002 to 1007 (1006 items + new updated item).
        // That leaves 5 elements.
        // And offset should be reset to 0.
        val newOffset = offsetField.get(estimator) as Int
        assertEquals(0, newOffset)

        val newSamples = samplesField.get(estimator) as List<*>
        // The size should be: 1007 - 1002 = 5 elements
        assertEquals(5, newSamples.size)
    }

    @Test
    fun testGetSpeedAndEtaZeroElapsed() {
        val estimator = EtaEstimator(0L, 1000L)
        
        // If we retrieve getSpeedAndEta immediately, start and end sample are the same,
        // so elapsed = 0.
        val speedAndEta = estimator.speedAndEta
        assertEquals(0.0f, speedAndEta.speedBps, 0.001f)
        assertEquals(0, speedAndEta.etaSeconds)
    }

    @Test
    fun testGetSpeedAndEtaZeroXferred() {
        val estimator = EtaEstimator(100L, 1000L)
        
        // Let's add another sample with elapsed time but same byte count
        val samples = getSamplesField().get(estimator) as List<*>
        val s0 = samples[0]!!
        val now = System.currentTimeMillis()
        getSampleTimestampField(s0).set(s0, now - 5000L)

        estimator.update(100L)

        val speedAndEta = estimator.speedAndEta
        assertEquals(0.0f, speedAndEta.speedBps, 0.001f)
        assertEquals(0, speedAndEta.etaSeconds)
    }

    @Test
    fun testGetSpeedAndEtaCalculations() {
        val totalBytes = 1000L
        val estimator = EtaEstimator(100L, totalBytes)
        
        val samples = getSamplesField().get(estimator) as List<*>
        val s0 = samples[0]!!
        val now = System.currentTimeMillis()
        
        // Let's say s0 was 10,000 ms ago with 100 bytes
        getSampleTimestampField(s0).set(s0, now - 10000L)

        // New update now at 500 bytes (elapsed = 10,000 ms, xferred = 400 bytes)
        estimator.update(500L)

        // speed = 1000 * 400 / 10,000 = 40.0 Bps
        // remaining = 1000 - 500 = 500 bytes
        // eta = Math.round(500 / 40.0) = Math.round(12.5) = 13
        val speedAndEta = estimator.speedAndEta
        assertEquals(40.0f, speedAndEta.speedBps, 0.001f)
        assertEquals(13, speedAndEta.etaSeconds)
    }
}
