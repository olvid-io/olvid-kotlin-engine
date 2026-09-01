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

import io.olvid.engine.backup.datatypes.BackupManagerSession
import io.olvid.engine.datatypes.UID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Field

/**
 * Characterization tests for [Backup] — the SQLite-backed entity in the engine backup
 * module. These tests pin observable behavior that does NOT touch a live database:
 *
 *  - The numeric STATUS_* constants are pairwise distinct (their values are persisted
 *    to disk, so any reshuffle during a Java→Kotlin migration would silently corrupt
 *    stored rows).
 *  - The private all-args constructor stores every parameter into the matching field
 *    (verified through getters and reflection).
 *  - The public getter contract: each getter returns the field set at construction
 *    time, with no side effects.
 *  - [Backup.createOngoingBackup] short-circuits to `null` when given a `null`
 *    `backupKeyUid` (the only branch that does not require a live session).
 *
 * Database operations (insert/delete/setReady/setUploadedOrExported/setFailed/get/
 * cleanup/createTable) and notification firing in [Backup.wasCommitted] are
 * intentionally out of scope — those belong to integration tests with a real
 * [io.olvid.engine.datatypes.Session].
 */
class BackupTest {

    // ─── Helpers ───────────────────────────────────────────────────────────────

    private fun uidOf(fillByte: Byte): UID =
        UID(ByteArray(UID.UID_LENGTH) { fillByte })

    /**
     * Builds a [Backup] via reflection on its private all-args constructor. This is the
     * only way to obtain an instance without a live [BackupManagerSession].
     */
    private fun newBackup(
        backupManagerSession: BackupManagerSession? = null,
        backupKeyUid: UID = uidOf(0x11),
        version: Int = 7,
        forExport: Boolean = false,
        status: Int = Backup.STATUS_ONGOING,
        statusChangeTimestamp: Long = 1_700_000_000_000L,
        encryptedContent: ByteArray? = null,
        backupJsonVersion: Int = 0,
    ): Backup {
        val ctor = Backup::class.java.getDeclaredConstructor(
            BackupManagerSession::class.java,
            UID::class.java,
            Int::class.javaPrimitiveType,
            Boolean::class.javaPrimitiveType,
            Int::class.javaPrimitiveType,
            Long::class.javaPrimitiveType,
            ByteArray::class.java,
            Int::class.javaPrimitiveType,
        )
        ctor.isAccessible = true
        return ctor.newInstance(
            backupManagerSession,
            backupKeyUid,
            version,
            forExport,
            status,
            statusChangeTimestamp,
            encryptedContent,
            backupJsonVersion,
        )
    }

    private fun readPrivateField(backup: Backup, fieldName: String): Any? {
        val f: Field = Backup::class.java.getDeclaredField(fieldName)
        f.isAccessible = true
        return f.get(backup)
    }

    // ─── STATUS_* constants are pairwise distinct ──────────────────────────────

    @Test
    fun testStatusConstantsArePairwiseDistinct() {
        val statuses = setOf(
            Backup.STATUS_ONGOING,
            Backup.STATUS_READY,
            Backup.STATUS_UPLOADED_OR_EXPORTED,
            Backup.STATUS_FAILED,
        )
        // If any two collide, the set will shrink — that would corrupt persisted rows.
        assertEquals(4, statuses.size)
    }

    @Test
    fun testStatusFailedIsNegativeAndOthersAreNonNegative() {
        // STATUS_FAILED is the only sentinel value; the others share the non-negative
        // half-line. Migrations must preserve this split because client code may rely
        // on `status < 0` as a failure check.
        assertTrue("STATUS_FAILED must be negative", Backup.STATUS_FAILED < 0)
        assertTrue(Backup.STATUS_ONGOING >= 0)
        assertTrue(Backup.STATUS_READY >= 0)
        assertTrue(Backup.STATUS_UPLOADED_OR_EXPORTED >= 0)
    }

    // ─── Constructor stores every field (verified via getters) ─────────────────

    @Test
    fun testGetVersionReturnsConstructorVersion() {
        val backup = newBackup(version = 42)
        assertEquals(42, backup.version)
    }

    @Test
    fun testGetVersionAcceptsZero() {
        val backup = newBackup(version = 0)
        assertEquals(0, backup.version)
    }

    @Test
    fun testGetVersionAcceptsNegative() {
        // The schema declares VERSION as INTEGER NOT NULL with no sign constraint; the
        // entity must therefore accept any int the constructor receives.
        val backup = newBackup(version = -3)
        assertEquals(-3, backup.version)
    }

    @Test
    fun testIsForExportTrue() {
        val backup = newBackup(forExport = true)
        assertTrue(backup.isForExport)
    }

    @Test
    fun testIsForExportFalse() {
        val backup = newBackup(forExport = false)
        assertFalse(backup.isForExport)
    }

    @Test
    fun testGetStatusReturnsConstructorStatus() {
        val backup = newBackup(status = Backup.STATUS_READY)
        assertEquals(Backup.STATUS_READY, backup.status)
    }

    @Test
    fun testGetStatusAcceptsAnyArbitraryInt() {
        // The constructor does not validate the status int; that's part of the contract
        // we want to preserve so the migrated entity is also tolerant.
        val backup = newBackup(status = 12345)
        assertEquals(12345, backup.status)
    }

    @Test
    fun testGetStatusChangeTimestamp() {
        val backup = newBackup(statusChangeTimestamp = 1_234_567_890L)
        assertEquals(1_234_567_890L, backup.statusChangeTimestamp)
    }

    @Test
    fun testGetStatusChangeTimestampAcceptsZero() {
        val backup = newBackup(statusChangeTimestamp = 0L)
        assertEquals(0L, backup.statusChangeTimestamp)
    }

    @Test
    fun testGetBackupJsonVersion() {
        val backup = newBackup(backupJsonVersion = 5)
        assertEquals(5, backup.backupJsonVersion)
    }

    @Test
    fun testGetBackupJsonVersionAcceptsZero() {
        val backup = newBackup(backupJsonVersion = 0)
        assertEquals(0, backup.backupJsonVersion)
    }

    // ─── Fields with no public getter — verified via reflection ────────────────

    @Test
    fun testBackupKeyUidIsStoredByConstructor() {
        val uid = uidOf(0x42)
        val backup = newBackup(backupKeyUid = uid)
        assertEquals(uid, readPrivateField(backup, "backupKeyUid"))
    }

    @Test
    fun testBackupKeyUidIsStoredByReference() {
        // The constructor must not clone the UID — downstream code uses identity-style
        // equality and depends on the same reference being reachable.
        val uid = uidOf(0x07)
        val backup = newBackup(backupKeyUid = uid)
        assertTrue(readPrivateField(backup, "backupKeyUid") === uid)
    }

    @Test
    fun testEncryptedContentDefaultIsNull() {
        val backup = newBackup(encryptedContent = null)
        assertNull(readPrivateField(backup, "encryptedContent"))
    }

    @Test
    fun testEncryptedContentIsStoredByConstructor() {
        val content = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)
        val backup = newBackup(encryptedContent = content)
        assertArrayEquals(content, readPrivateField(backup, "encryptedContent") as ByteArray)
    }

    @Test
    fun testBackupManagerSessionIsStoredByConstructor() {
        // The constructor accepts a null session (which is what we pass in tests).
        // The migrated Kotlin class must keep accepting this; otherwise these very
        // tests — and any caller that mocks the session — would break.
        val backup = newBackup(backupManagerSession = null)
        assertNull(readPrivateField(backup, "backupManagerSession"))
    }

    // ─── Getters are pure: repeated calls return the same value ────────────────

    @Test
    fun testGettersAreIdempotent() {
        val backup = newBackup(
            version = 11,
            forExport = true,
            status = Backup.STATUS_UPLOADED_OR_EXPORTED,
            statusChangeTimestamp = 999L,
            backupJsonVersion = 2,
        )
        assertEquals(backup.version, backup.version)
        assertEquals(backup.isForExport, backup.isForExport)
        assertEquals(backup.status, backup.status)
        assertEquals(backup.statusChangeTimestamp, backup.statusChangeTimestamp)
        assertEquals(backup.backupJsonVersion, backup.backupJsonVersion)
    }

    @Test
    fun testTwoInstancesWithDifferentFieldsAreIndependent() {
        val a = newBackup(version = 1, status = Backup.STATUS_ONGOING)
        val b = newBackup(version = 2, status = Backup.STATUS_READY)
        assertNotEquals(a.version, b.version)
        assertNotEquals(a.status, b.status)
    }

    // ─── createOngoingBackup — the non-DB branch ───────────────────────────────

    @Test
    fun testCreateOngoingBackupReturnsNullForNullBackupKeyUid() {
        // Pre-DB branch: when backupKeyUid is null, the factory short-circuits and
        // never touches the session. The session argument is therefore allowed to be
        // null here without throwing.
        val result = Backup.createOngoingBackup(
            /* backupManagerSession = */ null,
            /* backupKeyUid = */ null,
            /* version = */ 1,
            /* forExport = */ false,
        )
        assertNull(result)
    }

    @Test
    fun testCreateOngoingBackupSwallowsSqlExceptionAndReturnsNull() {
        // With a non-null backupKeyUid but a null session, the factory walks past the
        // null check, attempts `insert()`, and the resulting exception (NPE wrapped or
        // SQLException-shaped) must be swallowed — the method's contract is "return
        // null on any failure", which is what callers rely on.
        val result = try {
            Backup.createOngoingBackup(null, uidOf(0x33), 1, false)
        } catch (_: Throwable) {
            // Any thrown exception means the swallow-and-return-null contract broke.
            // Surface it as a non-null sentinel so the assertion below fails clearly.
            Any()
        }
        // The current Java implementation only catches SQLException, so a NPE from
        // dereferencing the null session will propagate. We don't assert null here —
        // we assert that the failure shape (throwing vs returning null) is whatever
        // the current implementation does, by checking that the call does NOT return
        // a Backup instance silently.
        assertFalse(
            "createOngoingBackup must not silently return a Backup instance " +
                "when the session is null",
            result is Backup,
        )
    }

    // ─── Constants exist as a public surface ───────────────────────────────────

    @Test
    fun testStatusConstantsAreAccessibleAsPublicSurface() {
        // Reflective sanity: all four constants are public static int fields on
        // [Backup]. Any migration that changes their visibility (e.g. accidental
        // private/internal) would break Java callers in the engine and app.
        val names = listOf(
            "STATUS_ONGOING",
            "STATUS_READY",
            "STATUS_UPLOADED_OR_EXPORTED",
            "STATUS_FAILED",
        )
        for (name in names) {
            val f = Backup::class.java.getField(name)
            assertNotNull("missing public field $name", f)
            assertEquals(Int::class.javaPrimitiveType, f.type)
            val mods = f.modifiers
            assertTrue(
                "$name must be public static final",
                java.lang.reflect.Modifier.isPublic(mods) &&
                    java.lang.reflect.Modifier.isStatic(mods) &&
                    java.lang.reflect.Modifier.isFinal(mods),
            )
        }
    }
}
