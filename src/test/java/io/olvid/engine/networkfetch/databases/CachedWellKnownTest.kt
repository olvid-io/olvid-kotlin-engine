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

package io.olvid.engine.networkfetch.databases

import io.olvid.engine.Logger
import io.olvid.engine.networkfetch.datatypes.FetchManagerSession
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Characterization tests for [CachedWellKnown] — a simple SQLite-backed entity in the
 * network-fetch module. These tests pin the observable behavior that survives without a
 * live database connection:
 *
 *   - [CachedWellKnown.create] null-guards that short-circuit before any SQL is issued.
 *   - The public 4-arg constructor stores all three fields (server, serializedWellKnown,
 *     downloadTimestamp) exactly as supplied.
 *   - The three public getters delegate to those fields with no side effects.
 *   - Default Object.equals / hashCode semantics (not overridden in the Java source).
 *   - [CachedWellKnown.wasCommitted] is a deliberate no-op and must not throw or mutate.
 *
 * Out of scope — all operations that require a live [FetchManagerSession] / Session:
 *   insert, delete, update(serializedWellKnown), get, getAll, createTable, upgradeTable.
 * The ResultSet constructor is also package-private and therefore not characterized here.
 */
class CachedWellKnownTest {

    // ─── Test data ─────────────────────────────────────────────────────────────

    private val server = "https://server.olvid.io"
    private val wellKnown = "{\"foo\":\"bar\"}"

    // ─── Setup ─────────────────────────────────────────────────────────────────

    @Before
    fun setUp() {
        Logger.setOutputter(object : Logger.LogOutputter {
            override fun d(tag: String, message: String) {}
            override fun i(tag: String, message: String) {}
            override fun w(tag: String, message: String) {}
            override fun e(tag: String, message: String) {}
            override fun x(tag: String, throwable: Throwable) {}
        })
        Logger.setOutputLogLevel(Logger.DEBUG)
    }

    // ─── Helper ────────────────────────────────────────────────────────────────

    /**
     * Constructs a [CachedWellKnown] via the public 4-arg constructor, passing null for
     * the [FetchManagerSession]. Tests in scope never exercise DB methods, so the null
     * session is safe.
     */
    private fun newInstance(
        session: FetchManagerSession? = null,
        server: String = this.server,
        serializedWellKnown: String = this.wellKnown,
        downloadTimestamp: Long = 1_700_000_000_000L,
    ): CachedWellKnown = CachedWellKnown(session, server, serializedWellKnown, downloadTimestamp)

    // ─── create() null-guards ──────────────────────────────────────────────────

    @Test
    fun testCreateReturnsNullWhenServerIsNull() {
        // The null-guard fires before any DB call, so a null session is safe here.
        assertNull(CachedWellKnown.create(null, null, wellKnown))
    }

    @Test
    fun testCreateReturnsNullWhenSerializedWellKnownIsNull() {
        assertNull(CachedWellKnown.create(null, server, null))
    }

    @Test
    fun testCreateReturnsNullWhenBothArgumentsAreNull() {
        assertNull(CachedWellKnown.create(null, null, null))
    }

    // ─── 4-arg constructor stores fields exactly ───────────────────────────────

    @Test
    fun testConstructorStoresServerByReferenceIdentity() {
        // The server string is not a compile-time literal, so the JVM will not intern it.
        // Storing by reference (not by copying) is the observable contract.
        val obj = newInstance(server = server)
        assertSame(server, obj.server)
    }

    @Test
    fun testConstructorStoresSerializedWellKnownByReferenceIdentity() {
        val obj = newInstance(serializedWellKnown = wellKnown)
        assertSame(wellKnown, obj.serializedWellKnown)
    }

    @Test
    fun testConstructorStoresDownloadTimestampExactly() {
        val ts = 1_234_567_890_123L
        val obj = newInstance(downloadTimestamp = ts)
        assertEquals(ts, obj.downloadTimestamp)
    }

    // ─── Getters delegate to stored fields ────────────────────────────────────

    @Test
    fun testGetServerReturnsConstructorValue() {
        val customServer = "https://custom.server.example.com"
        val obj = newInstance(server = customServer)
        assertEquals(customServer, obj.server)
    }

    @Test
    fun testGetSerializedWellKnownReturnsConstructorValue() {
        val customWellKnown = "{\"api_key\":\"secret\",\"relay\":\"turn.olvid.io\"}"
        val obj = newInstance(serializedWellKnown = customWellKnown)
        assertEquals(customWellKnown, obj.serializedWellKnown)
    }

    @Test
    fun testGetDownloadTimestampReturnsConstructorValue() {
        val ts = 9_999_999_999_999L
        val obj = newInstance(downloadTimestamp = ts)
        assertEquals(ts, obj.downloadTimestamp)
    }

    // ─── equals / hashCode (default Object semantics — not overridden) ─────────

    @Test
    fun testTwoInstancesWithIdenticalFieldsAreNotEqual() {
        // The Java source does NOT override equals; two distinct instances with the same
        // fields must NOT be equal. A migration to a Kotlin data class would silently
        // break this — this test pins the current reference-identity behavior.
        val obj1 = newInstance()
        val obj2 = newInstance()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(obj1.equals(obj2))
    }

    @Test
    fun testReflexiveEquality() {
        val obj = newInstance()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue(obj.equals(obj))
    }

    @Test
    fun testEqualsReturnsFalseForNullAndOtherType() {
        val obj = newInstance()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(obj.equals(null))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(obj.equals("not a CachedWellKnown"))
    }

    // ─── hashCode stability ────────────────────────────────────────────────────

    @Test
    fun testHashCodeIsStableAcrossMultipleCalls() {
        // Default Object.hashCode is stable within a JVM run; pin that per-instance.
        val obj = newInstance()
        val h1 = obj.hashCode()
        val h2 = obj.hashCode()
        assertEquals(h1, h2)
    }

    // ─── wasCommitted() is a no-op ────────────────────────────────────────────
    //
    // update(serializedWellKnown) is DB-dependent and therefore skipped in this suite.

    @Test
    fun testWasCommittedDoesNotThrowWithNullSession() {
        // wasCommitted() has no implementation body ("no hook yet"); it must complete
        // cleanly even when the FetchManagerSession is null.
        val obj = newInstance(session = null)
        obj.wasCommitted() // must not throw
    }

    @Test
    fun testWasCommittedDoesNotMutateStoredFields() {
        val ts = 4_242_424_242L
        val obj = newInstance(
            server = server,
            serializedWellKnown = wellKnown,
            downloadTimestamp = ts,
        )

        val serverBefore = obj.server
        val wellKnownBefore = obj.serializedWellKnown
        val tsBefore = obj.downloadTimestamp

        obj.wasCommitted()

        assertSame(serverBefore, obj.server)
        assertSame(wellKnownBefore, obj.serializedWellKnown)
        assertEquals(tsBefore, obj.downloadTimestamp)
    }
}
