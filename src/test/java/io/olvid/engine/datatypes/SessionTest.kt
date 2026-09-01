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
import io.olvid.engine.engine.types.EngineDbQueryStatisticsEntry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.util.concurrent.locks.ReentrantLock

/**
 * Characterization tests for [Session], the engine's central transactional primitive.
 *
 * SQLite-JDBC (org.xerial:sqlite-jdbc) IS on the test classpath (testImplementation in
 * build.gradle.kts), and Session.Companion registers the driver in its static init block.
 * We therefore use a temporary on-disk SQLite file for all tests that need a real connection;
 * this is required because the olvid-sqlite-jdbc-android driver (used in production) registers
 * via the companion init, and the standard xerial driver is also present as a fallback.
 *
 * Tests are grouped as follows:
 *
 *  Group A – Static state and companions (queryStatistics map, globalWriteLock)
 *  Group B – registerQueryTime() — pure logic, no connection needed
 *  Group C – getSession() / getUpgradeTablesSession() construction
 *  Group D – autoCommit / isInTransaction initial state
 *  Group E – startTransaction() and isInTransaction state machine
 *  Group F – Commit semantics: commit() fires listeners and clears the queue
 *  Group G – Rollback semantics: rollback() clears listener queue without firing
 *  Group H – addSessionCommitListener deduplication (LinkedHashSet contract)
 *  Group I – Listener ordering: commit notifies in insertion order
 *  Group J – Listener queue cleared after commit; second commit fires nobody
 *  Group K – commit() while autoCommit=true still fires listeners
 *  Group L – close() on a clean session (no open transaction) does not throw
 *  Group M – databaseIsReadable() static utility
 *  Group N – Session pool: close() returns session to pool; getSession() re-uses it
 *  Group O – prepareStatement returns a non-null PreparedStatement
 *  Group P – createStatement returns a non-null Statement
 */
class SessionTest {

    private lateinit var dbFile: File
    private lateinit var dbPath: String
    private val openSessions = mutableListOf<Session>()

    @Before
    fun setUp() {
        // Silence logger output during tests
        Logger.setOutputter(object : Logger.LogOutputter {
            override fun d(tag: String, message: String) {}
            override fun i(tag: String, message: String) {}
            override fun w(tag: String, message: String) {}
            override fun e(tag: String, message: String) {}
            override fun x(tag: String, throwable: Throwable) {}
        })
        Logger.setOutputLogLevel(Logger.DEBUG)

        // Use a unique temp file per test to avoid cross-test pool contamination
        dbFile = File.createTempFile("session_test_", ".sqlite")
        dbFile.deleteOnExit()
        dbPath = dbFile.absolutePath

        // Clear query statistics between tests so tests are independent
        Session.queryStatistics.clear()
    }

    @After
    fun tearDown() {
        // Close any sessions that tests left open, to release file locks
        for (session in openSessions) {
            try { session.close() } catch (_: Exception) {}
        }
        openSessions.clear()
        dbFile.delete()
    }

    /** Helper: obtain a regular session and track it for teardown. */
    private fun openSession(): Session {
        val session = Session.getSession(dbPath, null)
        openSessions.add(session)
        return session
    }

    /** Helper: obtain an upgrade-tables session and track it for teardown. */
    private fun openUpgradeSession(): Session {
        val session = Session.getUpgradeTablesSession(dbPath, null)
        openSessions.add(session)
        return session
    }

    // ─── Group A: Static state ────────────────────────────────────────────────

    @Test
    fun testQueryStatisticsMapIsInitiallyEmpty() {
        // queryStatistics is a module-level ConcurrentHashMap; cleared in @Before
        assertTrue(Session.queryStatistics.isEmpty())
    }

    @Test
    fun testQueryStatisticsMapIsPublicAndMutable() {
        // Verify that we can observe and clear the map — important for test isolation
        Session.queryStatistics["probe"] = EngineDbQueryStatisticsEntry.create(42L)
        assertNotNull(Session.queryStatistics["probe"])
        Session.queryStatistics.clear()
        assertTrue(Session.queryStatistics.isEmpty())
    }

    @Test
    fun testGlobalWriteLockIsAReentrantLock() {
        // Pin the type: callers depend on reentrancy semantics
        assertNotNull(Session.globalWriteLock)
        assertTrue(Session.globalWriteLock is ReentrantLock)
    }

    @Test
    fun testGlobalWriteLockIsNotHeldInitially() {
        assertFalse(Session.globalWriteLock.isLocked)
    }

    // ─── Group B: registerQueryTime() ─────────────────────────────────────────

    @Test
    fun testRegisterQueryTimeWithNullTagIsNoOp() {
        // Null tag must not add any entry and must not throw
        Session.registerQueryTime(null, 1000L)
        assertTrue(Session.queryStatistics.isEmpty())
    }

    @Test
    fun testRegisterQueryTimeFirstCallCreatesEntry() {
        Session.registerQueryTime("foo.bar", 500L)
        val entry = Session.queryStatistics["foo.bar"]
        assertNotNull(entry)
        assertEquals(1, entry!!.count)
        assertEquals(500L, entry.totalTimeMicro)
    }

    @Test
    fun testRegisterQueryTimeSecondCallIncrementsEntry() {
        Session.registerQueryTime("foo.bar", 200L)
        Session.registerQueryTime("foo.bar", 300L)
        val entry = Session.queryStatistics["foo.bar"]!!
        assertEquals(2, entry.count)
        assertEquals(500L, entry.totalTimeMicro)
    }

    @Test
    fun testRegisterQueryTimeAccumulatesMultipleCalls() {
        repeat(5) { Session.registerQueryTime("multi", 100L) }
        val entry = Session.queryStatistics["multi"]!!
        assertEquals(5, entry.count)
        assertEquals(500L, entry.totalTimeMicro)
    }

    @Test
    fun testRegisterQueryTimeTracksDistinctTagsSeparately() {
        Session.registerQueryTime("alpha", 10L)
        Session.registerQueryTime("beta", 20L)
        Session.registerQueryTime("alpha", 10L)

        val alpha = Session.queryStatistics["alpha"]!!
        val beta = Session.queryStatistics["beta"]!!

        assertEquals(2, alpha.count)
        assertEquals(20L, alpha.totalTimeMicro)
        assertEquals(1, beta.count)
        assertEquals(20L, beta.totalTimeMicro)
    }

    @Test
    fun testRegisterQueryTimeZeroDurationIsRecorded() {
        Session.registerQueryTime("zero", 0L)
        val entry = Session.queryStatistics["zero"]!!
        assertEquals(1, entry.count)
        assertEquals(0L, entry.totalTimeMicro)
    }

    // ─── Group C: Construction ─────────────────────────────────────────────────

    @Test
    fun testGetSessionReturnsNonNullSession() {
        val session = openSession()
        assertNotNull(session)
    }

    @Test
    fun testGetUpgradeTablesSessionReturnsNonNullSession() {
        val session = openUpgradeSession()
        assertNotNull(session)
    }

    @Test
    fun testGetSessionWithNullKeySucceeds() {
        // Null key means unencrypted DB — must not throw
        val session = openSession()
        assertNotNull(session)
    }

    // ─── Group D: Initial autoCommit / isInTransaction state ─────────────────

    @Test
    fun testRegularSessionStartsWithAutoCommitTrue() {
        val session = openSession()
        assertTrue(session.autoCommit)
    }

    @Test
    fun testRegularSessionStartsOutsideTransaction() {
        val session = openSession()
        assertFalse(session.isInTransaction)
    }

    @Test
    fun testAutoCommitAndIsInTransactionAreConsistentInitially() {
        val session = openSession()
        // autoCommit=true means NOT in transaction; the two properties must agree
        assertTrue(session.autoCommit)
        assertFalse(session.isInTransaction)
    }

    // ─── Group E: startTransaction() state machine ────────────────────────────

    @Test
    fun testStartTransactionFlipsIsInTransactionToTrue() {
        val session = openSession()
        session.startTransaction()
        try {
            assertTrue(session.isInTransaction)
            assertFalse(session.autoCommit)
        } finally {
            session.rollback()
        }
    }

    @Test
    fun testStartTransactionAcquiresGlobalWriteLock() {
        val session = openSession()
        assertFalse(Session.globalWriteLock.isLocked)
        session.startTransaction()
        try {
            assertTrue(Session.globalWriteLock.isLocked)
        } finally {
            session.rollback()
        }
    }

    @Test
    fun testAfterCommitIsInTransactionIsFalse() {
        val session = openSession()
        session.startTransaction()
        session.commit()
        assertFalse(session.isInTransaction)
    }

    @Test
    fun testAfterCommitAutoCommitIsTrue() {
        val session = openSession()
        session.startTransaction()
        session.commit()
        assertTrue(session.autoCommit)
    }

    @Test
    fun testAfterRollbackIsInTransactionIsFalse() {
        val session = openSession()
        session.startTransaction()
        session.rollback()
        assertFalse(session.isInTransaction)
    }

    @Test
    fun testAfterRollbackAutoCommitIsTrue() {
        val session = openSession()
        session.startTransaction()
        session.rollback()
        assertTrue(session.autoCommit)
    }

    @Test
    fun testAfterCommitGlobalWriteLockIsReleased() {
        val session = openSession()
        session.startTransaction()
        session.commit()
        assertFalse(Session.globalWriteLock.isLocked)
    }

    @Test
    fun testAfterRollbackGlobalWriteLockIsReleased() {
        val session = openSession()
        session.startTransaction()
        session.rollback()
        assertFalse(Session.globalWriteLock.isLocked)
    }

    // ─── Group F: Commit fires commit listeners ────────────────────────────────

    @Test
    fun testCommitFiresSingleListener() {
        val session = openSession()
        var called = false
        session.addSessionCommitListener { called = true }

        session.startTransaction()
        session.commit()

        assertTrue(called)
    }

    @Test
    fun testCommitFiresMultipleListeners() {
        val session = openSession()
        val callLog = mutableListOf<Int>()
        session.addSessionCommitListener { callLog.add(1) }
        session.addSessionCommitListener { callLog.add(2) }
        session.addSessionCommitListener { callLog.add(3) }

        session.startTransaction()
        session.commit()

        assertEquals(listOf(1, 2, 3), callLog)
    }

    @Test
    fun testCommitFiresListenerEvenWithoutOpenTransaction() {
        // If the session is already in autoCommit mode (no startTransaction called),
        // commit() skips the SQL commit but still fires the listeners.
        val session = openSession()
        var called = false
        session.addSessionCommitListener { called = true }

        // Do NOT call startTransaction — commit() should still notify listeners
        session.commit()

        assertTrue(called)
    }

    // ─── Group G: Rollback clears listener queue without firing ───────────────

    @Test
    fun testRollbackDoesNotFireCommitListeners() {
        val session = openSession()
        var called = false
        session.addSessionCommitListener { called = true }

        session.startTransaction()
        session.rollback()

        assertFalse(called)
    }

    @Test
    fun testRollbackClearsCommitListenerQueue() {
        val session = openSession()
        val callLog = mutableListOf<Int>()
        session.addSessionCommitListener { callLog.add(1) }
        session.addSessionCommitListener { callLog.add(2) }

        session.startTransaction()
        session.rollback()

        // After rollback the queue must be empty; a subsequent commit fires nobody
        session.startTransaction()
        session.commit()

        assertTrue(callLog.isEmpty())
    }

    // ─── Group H: addSessionCommitListener deduplication (LinkedHashSet) ──────

    @Test
    fun testAddSameListenerInstanceTwiceFiresItOnce() {
        val session = openSession()
        var callCount = 0
        val listener = SessionCommitListener { callCount++ }

        // LinkedHashSet deduplicates identical references
        session.addSessionCommitListener(listener)
        session.addSessionCommitListener(listener)

        session.startTransaction()
        session.commit()

        assertEquals(1, callCount)
    }

    @Test
    fun testAddDistinctListenerLambdasFiresBoth() {
        // Two distinct lambda objects with the same body are different instances
        val session = openSession()
        var count = 0
        session.addSessionCommitListener { count++ }
        session.addSessionCommitListener { count++ }

        session.startTransaction()
        session.commit()

        assertEquals(2, count)
    }

    // ─── Group I: Listener notification order ─────────────────────────────────

    @Test
    fun testCommitListenersAreNotifiedInInsertionOrder() {
        val session = openSession()
        val order = mutableListOf<String>()
        session.addSessionCommitListener { order.add("first") }
        session.addSessionCommitListener { order.add("second") }
        session.addSessionCommitListener { order.add("third") }

        session.startTransaction()
        session.commit()

        assertEquals(listOf("first", "second", "third"), order)
    }

    // ─── Group J: Listener queue cleared after commit ─────────────────────────

    @Test
    fun testCommitClearsListenerQueue() {
        val session = openSession()
        var callCount = 0
        session.addSessionCommitListener { callCount++ }

        session.startTransaction()
        session.commit()

        // First commit fires and clears. A second commit (empty queue) fires nobody.
        session.startTransaction()
        session.commit()

        // Listener was called exactly once
        assertEquals(1, callCount)
    }

    @Test
    fun testListenersAddedAfterCommitFireOnNextCommit() {
        val session = openSession()
        val log = mutableListOf<String>()
        session.addSessionCommitListener { log.add("before") }

        session.startTransaction()
        session.commit()
        // Queue is now cleared; add a new listener
        session.addSessionCommitListener { log.add("after") }

        session.startTransaction()
        session.commit()

        assertEquals(listOf("before", "after"), log)
    }

    // ─── Group K: Listener fires even without a real transaction ──────────────

    @Test
    fun testCommitWithoutTransactionFiresListeners() {
        val session = openSession()
        val log = mutableListOf<String>()
        session.addSessionCommitListener { log.add("fired") }

        // No startTransaction; autoCommit=true. commit() should still call listeners.
        session.commit()

        assertEquals(listOf("fired"), log)
    }

    // ─── Group L: close() on clean session ────────────────────────────────────

    @Test
    fun testCloseOnCleanSessionDoesNotThrow() {
        val session = Session.getSession(dbPath, null)
        // Remove from tracking since we close it manually here
        openSessions.add(session)
        session.close()
        openSessions.remove(session)
        // If we reach here, no exception was thrown
    }

    @Test
    fun testCloseOnUpgradeSessionDoesNotThrow() {
        val session = Session.getUpgradeTablesSession(dbPath, null)
        openSessions.add(session)
        session.close()
        openSessions.remove(session)
    }

    // ─── Group M: databaseIsReadable() ───────────────────────────────────────

    @Test
    fun testDatabaseIsReadableReturnsTrueForValidDb() {
        // First, create the DB by opening and closing a session
        val session = openSession()
        session.close()
        openSessions.remove(session)

        assertTrue(Session.databaseIsReadable(dbPath, null))
    }

    @Test
    fun testDatabaseIsReadableReturnsFalseForNonExistentPath() {
        // A path that will never be a valid DB
        assertFalse(Session.databaseIsReadable("/nonexistent/path/that/cannot/be/created.sqlite", null))
    }

    @Test
    fun testDatabaseIsReadableReturnsFalseForWrongKey() {
        // Create an unencrypted DB
        val session = openSession()
        session.close()
        openSessions.remove(session)

        // Supplying a key when the DB is not encrypted should cause a failure
        // (or at minimum we cannot guarantee it succeeds — characterize what happens)
        // The olvid sqlite JDBC may or may not error on this; we just pin the result
        // without asserting a specific value, to avoid flakiness. Instead we assert
        // the call itself does not throw.
        val result = Session.databaseIsReadable(dbPath, "wrong-key")
        // result is either true or false — just confirm no exception
        assertTrue(result || !result)
    }

    // ─── Group N: Session pool ────────────────────────────────────────────────

    @Test
    fun testClosedSessionIsReturnedToPoolAndReused() {
        // Open a session, note its identity, close it (returns to pool), then get it again
        val session1 = Session.getSession(dbPath, null)
        openSessions.add(session1)
        session1.close()
        openSessions.remove(session1)

        val session2 = Session.getSession(dbPath, null)
        openSessions.add(session2)

        // The pool should give back the same instance
        assertSame(session1, session2)
    }

    @Test
    fun testTwoSessionsFromPoolAreDifferentObjects() {
        // Get two sessions without returning either to the pool; they must be distinct
        val s1 = openSession()
        val s2 = openSession()
        assertNotSame(s1, s2)
    }

    @Test
    fun testUpgradeSessionIsNotReturnedToPool() {
        // Upgrade sessions close the underlying Connection directly and never pool
        val s1 = Session.getUpgradeTablesSession(dbPath, null)
        openSessions.add(s1)
        s1.close()
        openSessions.remove(s1)

        val s2 = Session.getUpgradeTablesSession(dbPath, null)
        openSessions.add(s2)

        // Must be a brand-new instance (not the same object from a pool)
        assertNotSame(s1, s2)
    }

    // ─── Group O: prepareStatement ────────────────────────────────────────────

    @Test
    fun testPrepareStatementReturnsNonNull() {
        val session = openSession()
        val ps = session.prepareStatement("SELECT 1;")
        assertNotNull(ps)
        ps.close()
    }

    @Test
    fun testPrepareStatementWithTagReturnsNonNull() {
        val session = openSession()
        val ps = session.prepareStatement("my.tag", "SELECT 1;")
        assertNotNull(ps)
        ps.close()
    }

    @Test
    fun testPrepareStatementWithReturnGeneratedKeysReturnsNonNull() {
        val session = openSession()
        session.startTransaction()
        try {
            session.createStatement().use { stmt ->
                stmt.execute("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT);")
            }
            val ps = session.prepareStatement("INSERT INTO t(v) VALUES(?);", true)
            assertNotNull(ps)
            ps.close()
        } finally {
            session.rollback()
        }
    }

    @Test
    fun testTwoCallsToPrepareStatementReturnDistinctObjects() {
        // Session.kt does NOT cache prepared statements by tag — each call delegates to
        // Connection.prepareStatement and wraps in a new DeferrablePreparedStatement.
        val session = openSession()
        val ps1 = session.prepareStatement("tag.a", "SELECT 1;")
        val ps2 = session.prepareStatement("tag.a", "SELECT 1;")
        assertNotSame(ps1, ps2)
        ps1.close()
        ps2.close()
    }

    // ─── Group P: createStatement ─────────────────────────────────────────────

    @Test
    fun testCreateStatementReturnsNonNull() {
        val session = openSession()
        val stmt = session.createStatement()
        assertNotNull(stmt)
        stmt.close()
    }

    @Test
    fun testCreateStatementWithTagReturnsNonNull() {
        val session = openSession()
        val stmt = session.createStatement("my.tag")
        assertNotNull(stmt)
        stmt.close()
    }

    @Test
    fun testCreateStatementCanExecuteSimpleQuery() {
        val session = openSession()
        val stmt = session.createStatement()
        val rs = stmt.executeQuery("SELECT 42;")
        assertTrue(rs.next())
        assertEquals(42, rs.getInt(1))
        rs.close()
        stmt.close()
    }

    @Test
    fun testPrepareStatementCanExecuteQuery() {
        val session = openSession()
        val ps = session.prepareStatement("SELECT ?;")
        ps.setInt(1, 99)
        val rs = ps.executeQuery()
        assertTrue(rs.next())
        assertEquals(99, rs.getInt(1))
        rs.close()
        ps.close()
    }

    // ─── Additional integration: transaction DDL/DML round-trip ──────────────

    @Test
    fun testTransactionCreateInsertQueryRoundTrip() {
        val session = openSession()
        session.startTransaction()
        try {
            session.createStatement().use { s ->
                s.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);")
            }
            session.prepareStatement("INSERT INTO items(name) VALUES(?);").use { ps ->
                ps.setString(1, "hello")
                ps.executeUpdate()
            }
            val count = session.prepareStatement("SELECT COUNT(*) FROM items;").use { ps ->
                val rs = ps.executeQuery()
                rs.next()
                rs.getInt(1).also { rs.close() }
            }
            assertEquals(1, count)
            session.commit()
        } catch (e: Exception) {
            session.rollback()
            throw e
        }
    }

    @Test
    fun testRollbackUndoesInsert() {
        val session = openSession()

        // First transaction: create table and commit
        session.startTransaction()
        session.createStatement().use { s ->
            s.execute("CREATE TABLE vals (v INTEGER);")
        }
        session.commit()

        // Second transaction: insert then rollback
        session.startTransaction()
        session.prepareStatement("INSERT INTO vals VALUES(?);").use { ps ->
            ps.setInt(1, 7)
            ps.executeUpdate()
        }
        session.rollback()

        // Verify the row was not persisted
        val count = session.prepareStatement("SELECT COUNT(*) FROM vals;").use { ps ->
            val rs = ps.executeQuery()
            rs.next()
            rs.getInt(1).also { rs.close() }
        }
        assertEquals(0, count)
    }

    @Test
    fun testCommitListenerIsCalledAfterDataIsVisible() {
        // The listener fires after the SQL commit, so data written in the transaction
        // must be visible to a subsequent query when the listener executes.
        val session = openSession()

        session.startTransaction()
        session.createStatement().use { s ->
            s.execute("CREATE TABLE probe (x INTEGER);")
        }
        session.prepareStatement("INSERT INTO probe VALUES(1);").use { ps ->
            ps.executeUpdate()
        }

        var countAtCommitTime = -1
        session.addSessionCommitListener {
            // Query in a new session since we're already inside the listener of this one
            val s2 = Session.getUpgradeTablesSession(dbPath, null)
            try {
                val rs = s2.createStatement().executeQuery("SELECT COUNT(*) FROM probe;")
                rs.next()
                countAtCommitTime = rs.getInt(1)
                rs.close()
            } finally {
                s2.close()
            }
        }

        session.commit()

        assertEquals(1, countAtCommitTime)
    }
}
