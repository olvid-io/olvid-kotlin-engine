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
import java.sql.SQLException

class CallbacksAndExceptionsTest {

    @Test
    fun testNoAcceptableChannelException() {
        val exception = NoAcceptableChannelException()
        assertNotNull(exception)
        assertTrue(exception is Exception)
    }

    @Test
    fun testNotificationListener() {
        var called = false
        var nameParam: String? = null
        var mapParam: Map<String, Any>? = null

        val listener = NotificationListener { notificationName, userInfo ->
            called = true
            nameParam = notificationName
            mapParam = userInfo
        }

        val testMap = mapOf("key" to "value")
        listener.callback("testNotification", testMap)

        assertTrue(called)
        assertEquals("testNotification", nameParam)
        assertEquals(testMap, mapParam)
    }

    @Test
    fun testGroupMembersChangedCallback() {
        var called = false
        val callback = GroupMembersChangedCallback {
            called = true
        }
        callback.callback()
        assertTrue(called)
    }

    @Test
    fun testSessionCommitListener() {
        var called = false
        val listener = SessionCommitListener {
            called = true
        }
        listener.wasCommitted()
        assertTrue(called)
    }

    @Test
    fun testObvDatabase() {
        var deleted = false
        var inserted = false
        var committed = false

        val db = object : ObvDatabase {
            override fun delete() {
                deleted = true
            }

            override fun insert() {
                inserted = true
            }

            override fun wasCommitted() {
                committed = true
            }
        }

        db.delete()
        db.insert()
        db.wasCommitted()

        assertTrue(deleted)
        assertTrue(inserted)
        assertTrue(committed)
    }
}
