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
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networkfetch.datatypes.FetchManagerSession
import io.olvid.engine.storage.PlainFileIo
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.lang.reflect.Field

/**
 * Characterization tests for [PendingServerQuery] — the SQLite-backed entity about to be
 * migrated to Kotlin. These tests pin observable behavior that does NOT touch a live
 * database:
 *
 *   - [PendingServerQuery.create] short-circuits to null when [serverQuery] is null (the
 *     only branch that requires no live session).
 *   - The private (FetchManagerSession, UID, Encoded, boolean) constructor stores all
 *     four fields exactly as supplied (verified via getters and reflection).
 *   - [creationTimestamp] is initialised to the wall clock at construction time — not zero,
 *     not max, and reasonably close to now.
 *   - The four public getters return the field values set at construction time.
 *   - Default Object.equals / hashCode / reference-identity semantics (not overridden).
 *   - [wasCommitted] — with [commitHookBits] = 0 (fresh instance, insert() never called),
 *     the hook is a no-op: no listener callback, no exception, no field mutation.
 *
 * Out of scope (require a live Session / DB): insert, delete, get, getAll, createTable,
 * upgradeTable, and the ResultSet constructor. The insert-then-wasCommitted notification
 * path (HOOK_BIT_INSERTED branch) is also excluded because it needs insert() to execute.
 */
class PendingServerQueryTest {

    // ─── Test data ─────────────────────────────────────────────────────────────

    private lateinit var uidA: UID
    private lateinit var uidB: UID
    private lateinit var encodedA: Encoded
    private lateinit var encodedB: Encoded

    // A minimal FetchManagerSession whose pendingServerQueryListener is null.
    // All parameters except pendingServerQueryListener are null; wasCommitted()
    // only accesses fetchManagerSession.pendingServerQueryListener so this is safe.
    private lateinit var session: FetchManagerSession

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

        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32)))

        uidA = UID(prng)
        uidB = UID(prng)

        // Two distinct, valid Encoded byte-array payloads.
        encodedA = Encoded.of(byteArrayOf(0x01, 0x02, 0x03))
        encodedB = Encoded.of(byteArrayOf(0x04, 0x05, 0x06, 0x07))

        // Null for all listeners/delegates; wasCommitted() only reads pendingServerQueryListener.
        session = FetchManagerSession(
            /* session                                   = */ Session.getSession("", null),
            /* inboxMessageListener                      = */ null,
            /* extendedPayloadListener                   = */ null,
            /* markAsListedAndDeleteOnServerListener     = */ null,
            /* inboxAttachmentListener                   = */ null,
            /* newPushNotificationConfigurationListener  = */ null,
            /* pendingServerQueryListener                = */ null,
            /* identityDelegate                          = */ null,
            /* engineBaseDirectory                       = */ null,
            /* fileIo                                    = */ PlainFileIo(),
            /* notificationPostingDelegate               = */ null,
            /* createServerSessionDelegate               = */ null,
        )
    }

    // ─── Helper: build an instance via the private constructor ─────────────────

    /**
     * Invokes the private (FetchManagerSession, UID, Encoded, boolean) constructor
     * without calling insert() — which would need a real SQL Session. This is the
     * only way to obtain an instance for pure in-memory tests.
     */
    private fun newViaReflection(
        fetchManagerSession: FetchManagerSession? = session,
        uid: UID = uidA,
        encodedQuery: Encoded = encodedA,
        webSocket: Boolean = false,
    ): PendingServerQuery {
        val ctor = PendingServerQuery::class.java.getDeclaredConstructor(
            FetchManagerSession::class.java,
            UID::class.java,
            Encoded::class.java,
            Boolean::class.javaPrimitiveType,
        )
        ctor.isAccessible = true
        return ctor.newInstance(fetchManagerSession, uid, encodedQuery, webSocket)
    }

    private fun readPrivateField(obj: PendingServerQuery, fieldName: String): Any? {
        val f: Field = PendingServerQuery::class.java.getDeclaredField(fieldName)
        f.isAccessible = true
        return f.get(obj)
    }

    // ─── create() null-guard ───────────────────────────────────────────────────

    @Test
    fun testCreateReturnsNullWhenServerQueryIsNull() {
        // Pre-DB short-circuit: when serverQuery is null the factory returns null
        // before preparing any SQL statement. The session argument is therefore
        // never dereferenced, so null is safe here.
        val result = PendingServerQuery.create(null, null, Suite.getDefaultPRNGService(0))
        assertNull(result)
    }

    // ─── Constructor: UID field ────────────────────────────────────────────────

    @Test
    fun testGetUidReturnsConstructorValue() {
        val obj = newViaReflection(uid = uidA)
        assertSame(uidA, obj.uid)
    }

    @Test
    fun testGetUidIsStoredByReferenceNotCloned() {
        // The constructor must not clone the UID; downstream code relies on the
        // same instance being reachable through the getter.
        val obj = newViaReflection(uid = uidA)
        assertTrue(obj.uid === uidA)
    }

    @Test
    fun testTwoInstancesCarryDifferentUids() {
        val objA = newViaReflection(uid = uidA)
        val objB = newViaReflection(uid = uidB)
        assertFalse(objA.uid.bytes.contentEquals(objB.uid.bytes))
    }

    // ─── Constructor: encodedQuery field ──────────────────────────────────────

    @Test
    fun testGetEncodedQueryReturnsConstructorValue() {
        val obj = newViaReflection(encodedQuery = encodedA)
        assertArrayEquals(encodedA.bytes, obj.encodedQuery.bytes)
    }

    @Test
    fun testGetEncodedQueryIsStoredByReference() {
        val obj = newViaReflection(encodedQuery = encodedA)
        assertSame(encodedA, obj.encodedQuery)
    }

    @Test
    fun testTwoInstancesCarryDifferentEncodedQueries() {
        val objA = newViaReflection(encodedQuery = encodedA)
        val objB = newViaReflection(encodedQuery = encodedB)
        assertFalse(objA.encodedQuery.bytes.contentEquals(objB.encodedQuery.bytes))
    }

    // ─── Constructor: webSocket field ─────────────────────────────────────────

    @Test
    fun testIsWebSocketFalseWhenConstructedWithFalse() {
        val obj = newViaReflection(webSocket = false)
        assertFalse(obj.isWebSocket)
    }

    @Test
    fun testIsWebSocketTrueWhenConstructedWithTrue() {
        val obj = newViaReflection(webSocket = true)
        assertTrue(obj.isWebSocket)
    }

    @Test
    fun testWebSocketFlagIsIndependentBetweenInstances() {
        val objWs = newViaReflection(webSocket = true)
        val objHttp = newViaReflection(webSocket = false)
        assertTrue(objWs.isWebSocket)
        assertFalse(objHttp.isWebSocket)
    }

    // ─── Constructor: creationTimestamp ───────────────────────────────────────

    @Test
    fun testCreationTimestampIsSetAtConstructionTime() {
        val before = System.currentTimeMillis()
        val obj = newViaReflection()
        val after = System.currentTimeMillis()
        // The constructor calls System.currentTimeMillis() internally; the stored
        // value must fall within the [before, after] window.
        assertTrue(
            "creationTimestamp (${ obj.creationTimestamp }) must be >= before ($before)",
            obj.creationTimestamp >= before,
        )
        assertTrue(
            "creationTimestamp (${ obj.creationTimestamp }) must be <= after ($after)",
            obj.creationTimestamp <= after,
        )
    }

    @Test
    fun testCreationTimestampIsNotZero() {
        // Defensive: a migration that accidentally initialises to 0L would corrupt
        // rows because the column is declared NOT NULL with semantic meaning.
        val obj = newViaReflection()
        assertTrue("creationTimestamp must not be zero", obj.creationTimestamp > 0L)
    }

    @Test
    fun testTwoInstancesConstructedSequentiallyHaveNonDecreasingTimestamps() {
        val obj1 = newViaReflection()
        val obj2 = newViaReflection()
        assertTrue(obj2.creationTimestamp >= obj1.creationTimestamp)
    }

    // ─── Private field: fetchManagerSession (via reflection) ──────────────────

    @Test
    fun testFetchManagerSessionIsStoredByConstructor() {
        val obj = newViaReflection(fetchManagerSession = session)
        assertSame(session, readPrivateField(obj, "fetchManagerSession"))
    }

    @Test
    fun testFetchManagerSessionNullIsAccepted() {
        // wasCommitted() with commitHookBits=0 never dereferences fetchManagerSession;
        // the constructor itself must therefore accept null without throwing.
        val obj = newViaReflection(fetchManagerSession = null)
        assertNull(readPrivateField(obj, "fetchManagerSession"))
    }

    // ─── equals / hashCode (default Object semantics — not overridden) ─────────

    @Test
    fun testEqualsIsReferenceIdentity() {
        // The Java source does NOT override equals; two instances built from
        // identical inputs must NOT be equal. A Kotlin migration to a data class
        // would silently break this — the test pins the current behavior.
        val obj1 = newViaReflection(uid = uidA, encodedQuery = encodedA)
        val obj2 = newViaReflection(uid = uidA, encodedQuery = encodedA)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(obj1.equals(obj2))
    }

    @Test
    fun testEqualsIsReflexive() {
        val obj = newViaReflection()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue(obj.equals(obj))
    }

    @Test
    fun testEqualsReturnsFalseForNullAndUnrelatedType() {
        val obj = newViaReflection()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(obj.equals(null))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(obj.equals("not a PendingServerQuery"))
    }

    @Test
    fun testHashCodeIsStableAcrossMultipleCalls() {
        // Default Object.hashCode is stable per-instance within a JVM run.
        val obj = newViaReflection()
        assertEquals(obj.hashCode(), obj.hashCode())
    }

    @Test
    fun testTwoDistinctInstancesAreNotSameObject() {
        val obj1 = newViaReflection()
        val obj2 = newViaReflection()
        assertNotSame(obj1, obj2)
    }

    // ─── wasCommitted() — no-op path (commitHookBits == 0) ────────────────────
    //
    // A fresh instance via reflection never goes through insert(), so commitHookBits
    // stays 0 and the HOOK_BIT_INSERTED branch is skipped. wasCommitted() must:
    //   1. complete without throwing, even with a null session;
    //   2. not mutate the observable state (uid, encodedQuery, webSocket).
    // The insert-triggered notification path (HOOK_BIT_INSERTED) is out of scope
    // because it requires insert() to execute against a real SQL session.

    @Test
    fun testWasCommittedDoesNotThrowWithNullSession() {
        // commitHookBits is 0 → listener branch is never reached → null session is safe.
        val obj = newViaReflection(fetchManagerSession = null)
        obj.wasCommitted() // must not throw
    }

    @Test
    fun testWasCommittedDoesNotThrowWithNullListener() {
        // session.pendingServerQueryListener is null; since commitHookBits == 0 the
        // null check on the listener is never reached, but confirm no exception.
        val obj = newViaReflection(fetchManagerSession = session)
        obj.wasCommitted() // must not throw
    }

    @Test
    fun testWasCommittedDoesNotMutateObservableState() {
        val obj = newViaReflection(uid = uidA, encodedQuery = encodedA, webSocket = true)
        val uidBefore = obj.uid
        val encodedBefore = obj.encodedQuery
        val wsBefore = obj.isWebSocket
        val tsBefore = obj.creationTimestamp

        obj.wasCommitted()

        assertSame(uidBefore, obj.uid)
        assertSame(encodedBefore, obj.encodedQuery)
        assertEquals(wsBefore, obj.isWebSocket)
        assertEquals(tsBefore, obj.creationTimestamp)
    }

    @Test
    fun testWasCommittedResetsCommitHookBitsToZero() {
        // Even with the initial value of 0, wasCommitted() must leave commitHookBits
        // at 0 (it always executes `commitHookBits = 0`). Verify via reflection.
        val obj = newViaReflection()
        obj.wasCommitted()
        val bits = readPrivateField(obj, "commitHookBits") as Long
        assertEquals(0L, bits)
    }

    @Test
    fun testWasCommittedIsIdempotent() {
        // Calling wasCommitted() multiple times on a fresh instance (bits=0 throughout)
        // must always complete cleanly without accumulating side effects.
        val obj = newViaReflection(fetchManagerSession = session)
        obj.wasCommitted()
        obj.wasCommitted()
        obj.wasCommitted()
        // No exception and bits remain 0.
        val bits = readPrivateField(obj, "commitHookBits") as Long
        assertEquals(0L, bits)
    }
}
