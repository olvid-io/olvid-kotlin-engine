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

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class OperationsUnitTest {
    var j: Int? = null

    @Test
    fun testOperationQueue() {
//        j = 0
//        val queue = OperationQueue()
//        for (o in 0 until 2) {
//            val op = object : Operation() {
//                override fun doCancel() {}
//
//                override fun doExecute() {
//                    for (i in 0 until 10000) {
//                        synchronized(j!!) {
//                            j = j!! + i
//                        }
//                    }
//                    setFinished()
//                }
//            }
//            queue.queue(op)
//        }
//        for (o in 0 until 3) {
//            val op = object : Operation() {
//                override fun doCancel() {}
//
//                override fun doExecute() {
//                    for (i in 0 until 20000) {
//                        synchronized(j!!) {
//                            j = j!! + i
//                        }
//                    }
//                    setFinished()
//                }
//            }
//            queue.queue(op)
//        }
//        queue.execute(1)
//        queue.join()
//        assertEquals(j, 2 * 5000 * 9999 + 3 * 10000 * 19999)
    }

    private class FinishingOperation(uid: UID, onFinishCallback: OnFinishCallback?) : Operation(uid, onFinishCallback, null) {
        override fun doCancel() {}
        override fun doExecute() {
            setFinished()
        }
    }

    private class CancellingOperation(uid: UID, onCancelCallback: OnCancelCallback?) : Operation(uid, null, onCancelCallback) {
        override fun doCancel() {}
        override fun doExecute() {
            cancel(null)
            processCancel()
        }
    }

    private fun readyToExecute(operation: Operation): Operation {
        operation.setPending()
        operation.updateReadiness()
        assertTrue(operation.isReady)
        return operation
    }

    @Test
    fun testThrowingOnFinishCallbackReleasesUid() {
        val uid = UID(ByteArray(UID.UID_LENGTH) { 1 })
        val first = readyToExecute(FinishingOperation(uid) { throw IndexOutOfBoundsException("failing callback") })
        try {
            first.execute()
            fail("expected the callback exception")
        } catch (_: IndexOutOfBoundsException) {
            // expected
        }
        assertTrue(first.isFinished)

        // the next operation with the same uid must be allowed to run
        val next = readyToExecute(FinishingOperation(uid, null))
        assertTrue(next.areConditionsFulfilled())
        next.execute()
        assertTrue(next.isFinished)
    }

    @Test
    fun testThrowingOnCancelCallbackReleasesUid() {
        val uid = UID(ByteArray(UID.UID_LENGTH) { 2 })
        val first = readyToExecute(CancellingOperation(uid) { throw IndexOutOfBoundsException("failing callback") })
        try {
            first.execute()
            fail("expected the callback exception")
        } catch (_: IndexOutOfBoundsException) {
            // expected
        }
        assertTrue(first.isCancelled)

        val next = readyToExecute(CancellingOperation(uid, null))
        assertTrue(next.areConditionsFulfilled())
    }

    @Test
    fun testRunningOperationUidBlocksTheNextOne() {
        // sanity check of the uid lock itself: it holds while the operation runs
        val uid = UID(ByteArray(UID.UID_LENGTH) { 3 })
        var conditionsDuringExecution = true
        val first = readyToExecute(FinishingOperation(uid) {
            conditionsDuringExecution = readyToExecute(FinishingOperation(uid, null)).areConditionsFulfilled()
        })
        first.execute()
        assertFalse(conditionsDuringExecution)
        assertTrue(readyToExecute(FinishingOperation(uid, null)).areConditionsFulfilled())
    }
}
