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

package io.olvid.engine.backup.databases

import io.olvid.engine.Logger
import io.olvid.engine.backup.datatypes.BackupManagerSession
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.BackupSeed
import io.olvid.engine.datatypes.Seed
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Characterization tests for [DeviceBackupSeed].
 *
 * The class is an SQLite-backed entity (extends ObvDatabase). Per the migration brief,
 * this suite intentionally avoids the database tier (CREATE/INSERT/SELECT, notification
 * firing on wasCommitted, ManagerSession plumbing) and pins down only behavior that
 * survives without a live Session:
 *
 *   - the static factory [DeviceBackupSeed.create] null-guards, which short-circuit
 *     BEFORE any SQL is issued;
 *   - the field-initialization invariants of the private (BackupManagerSession,
 *     BackupSeed, String) constructor, reachable via reflection;
 *   - the four public getters that simply expose state;
 *   - the no-op [DeviceBackupSeed.wasCommitted] hook.
 *
 * The setters [markBackupKeyInactive] and [setNextBackupTimestamp] both go through
 * `backupManagerSession.session.prepareStatement(...)` BEFORE mutating in-memory state,
 * so they cannot be characterized without a real Session and are deliberately skipped.
 *
 * Equality / hashCode / compareTo are NOT overridden by the Java source; we still pin
 * the default reference-identity semantics so a migration that accidentally promotes
 * this to a data class (or otherwise changes Object.equals) is caught.
 */
class DeviceBackupSeedTest {

    private lateinit var seedA: BackupSeed
    private lateinit var seedB: BackupSeed
    private val serverA = "https://server-a.olvid.io"
    private val serverB = "https://server-b.olvid.io"

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

        seedA = BackupSeed.generate(prng)!!
        seedB = BackupSeed.generate(prng)!!
        // sanity: distinct seed material between A and B
        assertFalse(seedA.backupSeedBytes.contentEquals(seedB.backupSeedBytes))
    }

    /**
     * Invokes the private (BackupManagerSession, BackupSeed, String) constructor
     * without going through [DeviceBackupSeed.create] (which would call insert()
     * and require a real Session). This lets us characterize the in-memory state
     * the constructor produces.
     */
    private fun newViaReflection(
        session: BackupManagerSession?,
        backupSeed: BackupSeed?,
        server: String?
    ): DeviceBackupSeed {
        val ctor = DeviceBackupSeed::class.java.getDeclaredConstructor(
            BackupManagerSession::class.java,
            BackupSeed::class.java,
            String::class.java
        )
        ctor.isAccessible = true
        return ctor.newInstance(session, backupSeed, server)
    }

    // ─── create() null-guards (pure logic, no SQL issued) ──────────────────────

    @Test
    fun testCreateReturnsNullWhenBackupSeedIsNull() {
        // Null seed must short-circuit before any DB call; the (null) session
        // is therefore never dereferenced.
        assertNull(DeviceBackupSeed.create(null, null, serverA))
    }

    @Test
    fun testCreateReturnsNullWhenServerIsNull() {
        assertNull(DeviceBackupSeed.create(null, seedA, null))
    }

    @Test
    fun testCreateReturnsNullWhenBothSeedAndServerAreNull() {
        assertNull(DeviceBackupSeed.create(null, null, null))
    }

    // ─── Constructor: stored fields ────────────────────────────────────────────

    @Test
    fun testConstructorStoresBackupSeed() {
        val obj = newViaReflection(null, seedA, serverA)
        // Reference identity: the constructor must not clone or rewrap.
        assertSame(seedA, obj.backupSeed)
    }

    @Test
    fun testConstructorStoresServer() {
        val obj = newViaReflection(null, seedA, serverA)
        assertEquals(serverA, obj.server)
    }

    @Test
    fun testConstructorPreservesSeedBytes() {
        val obj = newViaReflection(null, seedA, serverA)
        assertNotNull(obj.backupSeed)
        assertArrayEquals(seedA.backupSeedBytes, obj.backupSeed.backupSeedBytes)
    }

    // ─── Constructor: hard-coded defaults independent of input ─────────────────

    @Test
    fun testConstructorDefaultsActiveToTrue() {
        // The 3-arg constructor hard-codes active=true; there is no way to
        // create an inactive instance via constructor. A migration that adds
        // an 'active' parameter or changes the default must update callers.
        val obj = newViaReflection(null, seedA, serverA)
        assertTrue(obj.isActive)
    }

    @Test
    fun testConstructorDefaultsNextBackupTimestampToZero() {
        // Hard-coded to 0L; pins the contract that newly-created keys have no
        // scheduled backup yet.
        val obj = newViaReflection(null, seedA, serverA)
        assertEquals(0L, obj.nextBackupTimestamp)
    }

    @Test
    fun testConstructorDefaultsAreIndependentOfSeed() {
        val obj1 = newViaReflection(null, seedA, serverA)
        val obj2 = newViaReflection(null, seedB, serverB)
        assertTrue(obj1.isActive)
        assertTrue(obj2.isActive)
        assertEquals(0L, obj1.nextBackupTimestamp)
        assertEquals(0L, obj2.nextBackupTimestamp)
    }

    // ─── Server-string edge cases ──────────────────────────────────────────────

    @Test
    fun testConstructorAcceptsEmptyServer() {
        // create() guards against null but NOT empty string; characterize that.
        val obj = newViaReflection(null, seedA, "")
        assertEquals("", obj.server)
    }

    @Test
    fun testConstructorAcceptsUnicodeServer() {
        val unicode = "https://例え.olvid.io/路径?q=値"
        val obj = newViaReflection(null, seedA, unicode)
        assertEquals(unicode, obj.server)
    }

    @Test
    fun testConstructorAcceptsVeryLongServer() {
        val longServer = "https://" + "a".repeat(4096) + ".olvid.io"
        val obj = newViaReflection(null, seedA, longServer)
        assertEquals(longServer, obj.server)
        assertEquals(longServer.length, obj.server.length)
    }

    // ─── Distinct instances ────────────────────────────────────────────────────

    @Test
    fun testTwoInstancesWithSameInputsAreDistinctObjects() {
        // Constructor does not intern or cache; each call yields a fresh instance.
        val obj1 = newViaReflection(null, seedA, serverA)
        val obj2 = newViaReflection(null, seedA, serverA)
        assertNotSame(obj1, obj2)
    }

    @Test
    fun testInstancesWithDifferentSeedsCarryDifferentSeeds() {
        val objA = newViaReflection(null, seedA, serverA)
        val objB = newViaReflection(null, seedB, serverA)
        assertFalse(
            "Different seeds must surface through the getter",
            objA.backupSeed.backupSeedBytes.contentEquals(objB.backupSeed.backupSeedBytes)
        )
    }

    @Test
    fun testInstancesWithDifferentServersCarryDifferentServers() {
        val obj1 = newViaReflection(null, seedA, serverA)
        val obj2 = newViaReflection(null, seedA, serverB)
        assertNotEquals(obj1.server, obj2.server)
    }

    // ─── equals / hashCode (default Object semantics — not overridden) ─────────

    @Test
    fun testEqualsIsReferenceIdentity() {
        // The Java source does NOT override equals; two instances with identical
        // fields must NOT compare equal. A migration to a Kotlin data class would
        // break this contract — this test pins the current behavior.
        val obj1 = newViaReflection(null, seedA, serverA)
        val obj2 = newViaReflection(null, seedA, serverA)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(obj1.equals(obj2))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue(obj1.equals(obj1))
    }

    @Test
    fun testEqualsReturnsFalseForUnrelatedTypes() {
        val obj = newViaReflection(null, seedA, serverA)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(obj.equals("not a DeviceBackupSeed"))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(obj.equals(null))
    }

    @Test
    fun testHashCodeIsStableAcrossCalls() {
        // Default Object.hashCode is stable per-instance; pin that.
        val obj = newViaReflection(null, seedA, serverA)
        val h1 = obj.hashCode()
        val h2 = obj.hashCode()
        assertEquals(h1, h2)
    }

    // ─── wasCommitted() hook ───────────────────────────────────────────────────

    @Test
    fun testWasCommittedIsNoOpAndDoesNotThrow() {
        // The hook is a deliberate no-op (notifications are not fired here);
        // it must complete cleanly even with a null BackupManagerSession.
        val obj = newViaReflection(null, seedA, serverA)
        obj.wasCommitted() // must not throw
    }

    @Test
    fun testWasCommittedDoesNotMutateState() {
        val obj = newViaReflection(null, seedA, serverA)
        val seedBefore = obj.backupSeed
        val serverBefore = obj.server
        val activeBefore = obj.isActive
        val tsBefore = obj.nextBackupTimestamp

        obj.wasCommitted()

        assertSame(seedBefore, obj.backupSeed)
        assertEquals(serverBefore, obj.server)
        assertEquals(activeBefore, obj.isActive)
        assertEquals(tsBefore, obj.nextBackupTimestamp)
    }

    // ─── Multiple-instance independence ────────────────────────────────────────

    @Test
    fun testInstancesDoNotShareMutableState() {
        // Even though fields like 'active' and 'nextBackupTimestamp' are mutable
        // on the class, two freshly-constructed instances must be independent
        // (no static/shared backing).
        val obj1 = newViaReflection(null, seedA, serverA)
        val obj2 = newViaReflection(null, seedB, serverB)

        assertSame(seedA, obj1.backupSeed)
        assertSame(seedB, obj2.backupSeed)
        assertEquals(serverA, obj1.server)
        assertEquals(serverB, obj2.server)
    }
}
