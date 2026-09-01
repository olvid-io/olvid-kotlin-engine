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
}
