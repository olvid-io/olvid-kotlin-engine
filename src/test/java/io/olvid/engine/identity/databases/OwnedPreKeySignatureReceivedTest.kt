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
package io.olvid.engine.identity.databases

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.KeyId
import io.olvid.engine.datatypes.Session
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import io.olvid.engine.storage.PlainFileIo
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File

/**
 * Tests of the [OwnedPreKeySignatureReceived] table, used to prevent the replay of messages received through a pre-key
 * channel, on a real (temporary) SQLite database.
 *
 * The parent `owned_pre_key` table is created with [OwnedPreKey.createTable], and a minimal `owned_identity` table
 * (only the column referenced by the `owned_pre_key` foreign key) is created so that foreign keys can be enforced.
 */
class OwnedPreKeySignatureReceivedTest {

    private lateinit var dbFile: File
    private lateinit var session: Session
    private lateinit var identityManagerSession: IdentityManagerSession

    private val ownedIdentityBytes = ByteArray(40) { 1 }
    private val keyId1 = KeyId(ByteArray(KeyId.KEYID_LENGTH) { 2 })
    private val keyId2 = KeyId(ByteArray(KeyId.KEYID_LENGTH) { 3 })
    private val signature1 = ByteArray(80) { 4 }
    private val signature2 = ByteArray(80) { 5 }

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

        dbFile = File.createTempFile("owned_pre_key_signature_received_test_", ".sqlite")
        dbFile.deleteOnExit()
        session = Session.getSession(dbFile.absolutePath, null)
        identityManagerSession = IdentityManagerSession(session, null, null, null, PlainFileIo(), null, null)

        session.createStatement().use { statement ->
            statement.execute(
                "CREATE TABLE " + OwnedIdentity.TABLE_NAME + " (" + OwnedIdentity.OWNED_IDENTITY + " BLOB PRIMARY KEY);"
            )
        }
        OwnedPreKey.createTable(session)
        OwnedPreKeySignatureReceived.createTable(session)

        insertOwnedIdentity(ownedIdentityBytes)
        insertOwnedPreKey(keyId1, ownedIdentityBytes)
        insertOwnedPreKey(keyId2, ownedIdentityBytes)
    }

    @After
    fun tearDown() {
        try { session.close() } catch (_: Exception) {}
        dbFile.delete()
    }

    private fun insertOwnedIdentity(identityBytes: ByteArray) {
        session.prepareStatement(
            "test.insertOwnedIdentity",
            "INSERT INTO " + OwnedIdentity.TABLE_NAME + " VALUES (?);"
        ).use { statement ->
            statement.setBytes(1, identityBytes)
            statement.executeUpdate()
        }
    }

    private fun insertOwnedPreKey(keyId: KeyId, ownedIdentityBytes: ByteArray) {
        session.prepareStatement(
            "test.insertOwnedPreKey",
            "INSERT INTO " + OwnedPreKey.TABLE_NAME + " VALUES (?,?,?,?,?);"
        ).use { statement ->
            statement.setBytes(1, keyId.bytes)
            statement.setBytes(2, ownedIdentityBytes)
            statement.setLong(3, 0L)
            statement.setBytes(4, ByteArray(1))
            statement.setBytes(5, ByteArray(1))
            statement.executeUpdate()
        }
    }

    private fun deleteOwnedPreKey(keyId: KeyId) {
        session.prepareStatement(
            "test.deleteOwnedPreKey",
            "DELETE FROM " + OwnedPreKey.TABLE_NAME + " WHERE " + OwnedPreKey.KEY_ID + " = ?;"
        ).use { statement ->
            statement.setBytes(1, keyId.bytes)
            statement.executeUpdate()
        }
    }

    private fun deleteOwnedIdentity(identityBytes: ByteArray) {
        session.prepareStatement(
            "test.deleteOwnedIdentity",
            "DELETE FROM " + OwnedIdentity.TABLE_NAME + " WHERE " + OwnedIdentity.OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, identityBytes)
            statement.executeUpdate()
        }
    }

    @Test
    fun testExistsIsFalseBeforeCreateAndTrueAfter() {
        assertFalse(OwnedPreKeySignatureReceived.exists(identityManagerSession, keyId1, signature1))
        assertNotNull(OwnedPreKeySignatureReceived.create(identityManagerSession, keyId1, signature1))
        assertTrue(OwnedPreKeySignatureReceived.exists(identityManagerSession, keyId1, signature1))
    }

    @Test
    fun testExistsMatchesBothKeyIdAndSignature() {
        assertNotNull(OwnedPreKeySignatureReceived.create(identityManagerSession, keyId1, signature1))
        assertFalse(OwnedPreKeySignatureReceived.exists(identityManagerSession, keyId1, signature2))
        assertFalse(OwnedPreKeySignatureReceived.exists(identityManagerSession, keyId2, signature1))
    }

    @Test
    fun testExistsWithNullInputsIsFalse() {
        assertFalse(OwnedPreKeySignatureReceived.exists(identityManagerSession, null, signature1))
        assertFalse(OwnedPreKeySignatureReceived.exists(identityManagerSession, keyId1, null))
    }

    @Test
    fun testCreatingTheSameSignatureTwiceFails() {
        assertNotNull(OwnedPreKeySignatureReceived.create(identityManagerSession, keyId1, signature1))
        assertNull(OwnedPreKeySignatureReceived.create(identityManagerSession, keyId1, signature1))
    }

    @Test
    fun testCreatingForAnUnknownPreKeyFails() {
        val unknownKeyId = KeyId(ByteArray(KeyId.KEYID_LENGTH) { 9 })
        assertNull(OwnedPreKeySignatureReceived.create(identityManagerSession, unknownKeyId, signature1))
    }

    @Test
    fun testDeletingThePreKeyDeletesItsSignatures() {
        assertNotNull(OwnedPreKeySignatureReceived.create(identityManagerSession, keyId1, signature1))
        assertNotNull(OwnedPreKeySignatureReceived.create(identityManagerSession, keyId2, signature2))

        deleteOwnedPreKey(keyId1)

        assertFalse(OwnedPreKeySignatureReceived.exists(identityManagerSession, keyId1, signature1))
        assertTrue(OwnedPreKeySignatureReceived.exists(identityManagerSession, keyId2, signature2))
    }

    @Test
    fun testDeletingTheOwnedIdentityDeletesTheSignatures() {
        assertNotNull(OwnedPreKeySignatureReceived.create(identityManagerSession, keyId1, signature1))
        assertNotNull(OwnedPreKeySignatureReceived.create(identityManagerSession, keyId2, signature2))

        deleteOwnedIdentity(ownedIdentityBytes)

        assertFalse(OwnedPreKeySignatureReceived.exists(identityManagerSession, keyId1, signature1))
        assertFalse(OwnedPreKeySignatureReceived.exists(identityManagerSession, keyId2, signature2))
    }

    @Test
    fun testUpgradeTableCreatesAWorkingTable() {
        session.createStatement().use { statement ->
            statement.execute("DROP TABLE " + OwnedPreKeySignatureReceived.TABLE_NAME + ";")
        }
        OwnedPreKeySignatureReceived.upgradeTable(session, 52, 53)

        assertNotNull(OwnedPreKeySignatureReceived.create(identityManagerSession, keyId1, signature1))
        assertTrue(OwnedPreKeySignatureReceived.exists(identityManagerSession, keyId1, signature1))
        deleteOwnedPreKey(keyId1)
        assertFalse(OwnedPreKeySignatureReceived.exists(identityManagerSession, keyId1, signature1))
    }
}
