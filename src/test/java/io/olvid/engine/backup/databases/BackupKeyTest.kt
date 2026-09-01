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
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.symmetric.MACHmacSha256Key
import io.olvid.engine.datatypes.key.symmetric.MACKey
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Characterization tests for [BackupKey] before its Java->Kotlin migration.
 *
 * BackupKey is an SQLite-backed entity ([ObvDatabase]) whose pure surface is small:
 * the private all-fields constructor is used reflectively to construct instances
 * without a live database session. SQL-tier behavior (insert/delete/update/get) is
 * intentionally out of scope (covered by integration tests, not characterization).
 */
class BackupKeyTest {

    private lateinit var uid: UID
    private lateinit var encryptionPublicKey: EncryptionPublicKey
    private lateinit var macKey: MACKey

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

        uid = UID(prng)
        encryptionPublicKey = EncryptionEciesCurve25519KeyPair.generate(prng).publicKey as EncryptionPublicKey
        macKey = MACHmacSha256Key.of(ByteArray(MACHmacSha256Key.KEY_BYTE_LENGTH) { it.toByte() })
    }

    // ---------------------------------------------------------------------
    // Reflection helpers — the all-fields constructor is private, so we
    // must reach in to build instances without going through the DB layer.
    // ---------------------------------------------------------------------

    @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
    private fun newBackupKey(
        session: BackupManagerSession? = null,
        uid: UID? = this.uid,
        encryptionPublicKey: EncryptionPublicKey? = this.encryptionPublicKey,
        macKey: MACKey? = this.macKey,
        keyGenerationTimestamp: Long = 0L,
        lastSuccessfulKeyVerificationTimestamp: Long = 0L,
        lastKeyVerificationPromptTimestamp: Long = 0L,
        successfulVerificationCount: Int = 0,
        uploadedBackupVersion: Int? = null,
        exportedBackupVersion: Int? = null,
        latestBackupVersion: Int? = null,
    ): BackupKey {
        val ctor = BackupKey::class.java.getDeclaredConstructor(
            BackupManagerSession::class.java,
            UID::class.java,
            EncryptionPublicKey::class.java,
            MACKey::class.java,
            java.lang.Long.TYPE,
            java.lang.Long.TYPE,
            java.lang.Long.TYPE,
            java.lang.Integer.TYPE,
            java.lang.Integer::class.java,
            java.lang.Integer::class.java,
            java.lang.Integer::class.java,
        )
        ctor.isAccessible = true
        return ctor.newInstance(
            session,
            uid,
            encryptionPublicKey,
            macKey,
            keyGenerationTimestamp,
            lastSuccessfulKeyVerificationTimestamp,
            lastKeyVerificationPromptTimestamp,
            successfulVerificationCount,
            uploadedBackupVersion,
            exportedBackupVersion,
            latestBackupVersion,
        )
    }

    // ---------------------------------------------------------------------
    // Type contract
    // ---------------------------------------------------------------------

    @Test
    fun testImplementsObvDatabase() {
        // Verify via java reflection so the assertion holds even after the
        // Kotlin migration (Kotlin's smart-cast lint would warn if we used `is`).
        assertTrue(
            "BackupKey must implement ObvDatabase",
            ObvDatabase::class.java.isAssignableFrom(BackupKey::class.java),
        )
    }

    @Test
    fun testWasCommittedIsANoOp() {
        val key = newBackupKey()
        // wasCommitted is invoked from outside the DB session; the contract is
        // that it does not throw and has no observable side-effect on getters.
        key.wasCommitted()
        assertEquals(uid, key.uid)
        assertEquals(0, key.successfulVerificationCount)
    }

    // ---------------------------------------------------------------------
    // Field-to-getter mapping (each getter must surface its dedicated field)
    // ---------------------------------------------------------------------

    @Test
    fun testGetUidReturnsConstructorValue() {
        val key = newBackupKey(uid = uid)
        assertSame(uid, key.uid)
    }

    @Test
    fun testGetEncryptionPublicKeyReturnsConstructorValue() {
        val key = newBackupKey(encryptionPublicKey = encryptionPublicKey)
        assertSame(encryptionPublicKey, key.encryptionPublicKey)
    }

    @Test
    fun testGetMacKeyReturnsConstructorValue() {
        val key = newBackupKey(macKey = macKey)
        assertSame(macKey, key.macKey)
    }

    @Test
    fun testGetKeyGenerationTimestampReturnsConstructorValue() {
        val key = newBackupKey(keyGenerationTimestamp = 1_234_567_890L)
        assertEquals(1_234_567_890L, key.keyGenerationTimestamp)
    }

    @Test
    fun testGetLastSuccessfulKeyVerificationTimestampReturnsConstructorValue() {
        val key = newBackupKey(lastSuccessfulKeyVerificationTimestamp = 42L)
        assertEquals(42L, key.lastSuccessfulKeyVerificationTimestamp)
    }

    @Test
    fun testGetSuccessfulVerificationCountReturnsConstructorValue() {
        val key = newBackupKey(successfulVerificationCount = 7)
        assertEquals(7, key.successfulVerificationCount)
    }

    @Test
    fun testGetUploadedBackupVersionReturnsConstructorValue() {
        val key = newBackupKey(uploadedBackupVersion = 12)
        assertEquals(Integer.valueOf(12), key.uploadedBackupVersion)
    }

    @Test
    fun testGetUploadedBackupVersionNullableIsNull() {
        val key = newBackupKey(uploadedBackupVersion = null)
        assertNull(key.uploadedBackupVersion)
    }

    @Test
    fun testGetExportedBackupVersionReturnsConstructorValue() {
        val key = newBackupKey(exportedBackupVersion = 3)
        assertEquals(Integer.valueOf(3), key.exportedBackupVersion)
    }

    @Test
    fun testGetExportedBackupVersionNullableIsNull() {
        val key = newBackupKey(exportedBackupVersion = null)
        assertNull(key.exportedBackupVersion)
    }

    @Test
    fun testGetLatestBackupVersionReturnsConstructorValue() {
        val key = newBackupKey(latestBackupVersion = 99)
        assertEquals(Integer.valueOf(99), key.latestBackupVersion)
    }

    @Test
    fun testGetLatestBackupVersionNullableIsNull() {
        val key = newBackupKey(latestBackupVersion = null)
        assertNull(key.latestBackupVersion)
    }

    @Test
    fun testFieldsAreIndependent() {
        // Pin down that getters do not cross-talk: changing one field must not
        // alter what another returns.
        val key = newBackupKey(
            keyGenerationTimestamp = 100L,
            lastSuccessfulKeyVerificationTimestamp = 200L,
            successfulVerificationCount = 5,
            uploadedBackupVersion = 1,
            exportedBackupVersion = 2,
            latestBackupVersion = 3,
        )
        assertEquals(100L, key.keyGenerationTimestamp)
        assertEquals(200L, key.lastSuccessfulKeyVerificationTimestamp)
        assertEquals(5, key.successfulVerificationCount)
        assertEquals(Integer.valueOf(1), key.uploadedBackupVersion)
        assertEquals(Integer.valueOf(2), key.exportedBackupVersion)
        assertEquals(Integer.valueOf(3), key.latestBackupVersion)
    }

    @Test
    fun testGetUidPreservesByteContent() {
        val key = newBackupKey(uid = uid)
        assertArrayEquals(uid.bytes, key.uid.bytes)
    }

    // ---------------------------------------------------------------------
    // create() — null-guard branch (the only branch reachable without a DB)
    // ---------------------------------------------------------------------

    @Test
    fun testCreateReturnsNullWhenUidIsNull() {
        val result = BackupKey.create(null, null, encryptionPublicKey, macKey)
        assertNull(result)
    }

    @Test
    fun testCreateReturnsNullWhenEncryptionPublicKeyIsNull() {
        val result = BackupKey.create(null, uid, null, macKey)
        assertNull(result)
    }

    @Test
    fun testCreateReturnsNullWhenMacKeyIsNull() {
        val result = BackupKey.create(null, uid, encryptionPublicKey, null)
        assertNull(result)
    }

    @Test
    fun testCreateReturnsNullWhenAllParamsNull() {
        val result = BackupKey.create(null, null, null, null)
        assertNull(result)
    }

    // ---------------------------------------------------------------------
    // getUploadedBackup() / getExportedBackup() — null-version short-circuit
    //
    // When the corresponding version field is null, these methods return null
    // WITHOUT touching the backupManagerSession (this is the documented
    // behavior we need to preserve through the migration).
    // ---------------------------------------------------------------------

    @Test
    fun testGetUploadedBackupReturnsNullWhenUploadedVersionIsNull() {
        // session is null but the null-version branch is taken first, so this
        // must not throw a NullPointerException.
        val key = newBackupKey(uploadedBackupVersion = null)
        assertNull(key.uploadedBackup)
    }

    @Test
    fun testGetExportedBackupReturnsNullWhenExportedVersionIsNull() {
        val key = newBackupKey(exportedBackupVersion = null)
        assertNull(key.exportedBackup)
    }

    // ---------------------------------------------------------------------
    // Two distinct constructions yield distinct objects (sanity for reflection
    // helper itself, and confirmation that BackupKey has no identity-via-uid
    // equals override — equality is reference equality only).
    // ---------------------------------------------------------------------

    @Test
    fun testNoCustomEqualsTwoKeysWithSameDataAreNotEqual() {
        val a = newBackupKey(uid = uid)
        val b = newBackupKey(uid = uid)
        // Different instances; BackupKey does NOT override equals, so reference
        // semantics apply. Pinning this so the migration doesn't accidentally
        // introduce a data-class-style equals.
        assertNotSame(a, b)
        assertNotEquals(
            "BackupKey should not override equals — two instances built from the same fields must not be equal",
            a,
            b,
        )
    }

    @Test
    fun testNoCustomHashCodeTwoKeysWithSameDataMayDifferInHash() {
        // Since equals is not overridden, hashCode falls back to identity-hash.
        // The contract we pin: NOT a data-class-style hash based on fields.
        val a = newBackupKey(uid = uid)
        val b = newBackupKey(uid = uid)
        // Two object identities almost certainly produce different identity-hash
        // values; if they happened to collide, the test would be flaky. We
        // assert the structural contract by verifying System.identityHashCode
        // matches Object.hashCode (i.e. no override).
        assertEquals(System.identityHashCode(a), a.hashCode())
        assertEquals(System.identityHashCode(b), b.hashCode())
    }

    // ---------------------------------------------------------------------
    // Constructor sanity — non-null after construction
    // ---------------------------------------------------------------------

    @Test
    fun testConstructorProducesNonNullInstance() {
        val key = newBackupKey()
        assertNotNull(key)
    }

    @Test
    fun testTimestampZeroIsPreservedDistinctlyFromOtherValues() {
        // Pin that timestamp fields preserve 0 (the create() default for
        // unverified keys) rather than being normalised to some other value.
        val key = newBackupKey(
            keyGenerationTimestamp = 0L,
            lastSuccessfulKeyVerificationTimestamp = 0L,
        )
        assertEquals(0L, key.keyGenerationTimestamp)
        assertEquals(0L, key.lastSuccessfulKeyVerificationTimestamp)
    }

    @Test
    fun testCreateInitialStateContract() {
        // create() initialises with: keyGenerationTimestamp = now,
        // lastSuccessfulKeyVerificationTimestamp = 0L,
        // lastKeyVerificationPromptTimestamp = 0L,
        // successfulVerificationCount = 0,
        // uploadedBackupVersion = null,
        // exportedBackupVersion = null,
        // latestBackupVersion = null.
        //
        // We can't invoke create() without a DB session, so we reproduce the
        // same field values via the reflective constructor and verify the
        // getters expose them — pinning the "freshly created BackupKey" shape
        // that downstream code relies on.
        val nowBefore = System.currentTimeMillis()
        val key = newBackupKey(
            keyGenerationTimestamp = nowBefore,
            lastSuccessfulKeyVerificationTimestamp = 0L,
            lastKeyVerificationPromptTimestamp = 0L,
            successfulVerificationCount = 0,
            uploadedBackupVersion = null,
            exportedBackupVersion = null,
            latestBackupVersion = null,
        )
        assertEquals(nowBefore, key.keyGenerationTimestamp)
        assertEquals(0L, key.lastSuccessfulKeyVerificationTimestamp)
        assertEquals(0, key.successfulVerificationCount)
        assertNull(key.uploadedBackupVersion)
        assertNull(key.exportedBackupVersion)
        assertNull(key.latestBackupVersion)
    }
}
