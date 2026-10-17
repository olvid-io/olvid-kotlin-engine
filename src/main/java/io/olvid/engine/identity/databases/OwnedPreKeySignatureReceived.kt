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
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import java.sql.SQLException

// Stores the signatures of all messages received through a pre-key channel, to prevent the replay of these messages.
// Entries are cascade-deleted when the corresponding OwnedPreKey is deleted.
class OwnedPreKeySignatureReceived : ObvDatabase {
    internal val identityManagerSession: IdentityManagerSession

    internal val keyId: KeyId
    internal val signature: ByteArray

    internal constructor(
        identityManagerSession: IdentityManagerSession,
        keyId: KeyId,
        signature: ByteArray
    ) {
        this.identityManagerSession = identityManagerSession
        this.keyId = keyId
        this.signature = signature
    }


    @Throws(SQLException::class)
    override fun insert() {
        identityManagerSession.session.prepareStatement(
            "OwnedPreKeySignatureReceived.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?);"
        ).use { statement ->
            statement.setBytes(1, keyId.bytes)
            statement.setBytes(2, signature)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        identityManagerSession.session.prepareStatement(
            "OwnedPreKeySignatureReceived.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + KEY_ID + " = ? AND " + SIGNATURE + " = ?;"
        ).use { statement ->
            statement.setBytes(1, keyId.bytes)
            statement.setBytes(2, signature)
            statement.executeUpdate()
        }
    }

    override fun wasCommitted() {
        // No hooks here
    }

    companion object {
        const val TABLE_NAME: String = "owned_pre_key_signature_received"

        const val KEY_ID: String = "key_id"
        const val SIGNATURE: String = "signature"


        // region constructors
        fun create(
            identityManagerSession: IdentityManagerSession,
            keyId: KeyId?,
            signature: ByteArray?
        ): OwnedPreKeySignatureReceived? {
            if (keyId == null || signature == null) {
                return null
            }
            try {
                val ownedPreKeySignatureReceived =
                    OwnedPreKeySignatureReceived(identityManagerSession, keyId, signature)
                ownedPreKeySignatureReceived.insert()
                return ownedPreKeySignatureReceived
            } catch (e: SQLException) {
                Logger.x(e)
                return null
            }
        }

        // endregion
        // region database
        @Throws(SQLException::class)
        fun createTable(session: Session) {
            session.createStatement().use { statement ->
                statement.execute(
                    "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                            KEY_ID + " BLOB NOT NULL, " +
                            SIGNATURE + " BLOB NOT NULL, " +
                            "CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY (" + KEY_ID + ", " + SIGNATURE + "), " +
                            "FOREIGN KEY (" + KEY_ID + ") REFERENCES " + OwnedPreKey.TABLE_NAME + " (" + OwnedPreKey.KEY_ID + ") ON DELETE CASCADE);"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 53 && newVersion >= 53) {
                Logger.d("CREATING `owned_pre_key_signature_received` TABLE AS PART OF VERSION 53")
                session.createStatement().use { statement ->
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS owned_pre_key_signature_received (" +
                                " key_id BLOB NOT NULL, " +
                                " signature BLOB NOT NULL, " +
                                " CONSTRAINT PK_owned_pre_key_signature_received PRIMARY KEY (key_id, signature), " +
                                " FOREIGN KEY (key_id) REFERENCES owned_pre_key(key_id) ON DELETE CASCADE);"
                    )
                }
                oldVersion = 53
            }
        }

        // endregion
        @Throws(SQLException::class)
        fun exists(
            identityManagerSession: IdentityManagerSession,
            keyId: KeyId?,
            signature: ByteArray?
        ): Boolean {
            if (keyId == null || signature == null) {
                return false
            }
            identityManagerSession.session.prepareStatement(
                "OwnedPreKeySignatureReceived.exists",
                "SELECT 1 FROM " + TABLE_NAME + " WHERE " + KEY_ID + " = ? AND " + SIGNATURE + " = ?;"
            ).use { statement ->
                statement.setBytes(1, keyId.bytes)
                statement.setBytes(2, signature)
                statement.executeQuery().use { res ->
                    return res.next()
                }
            }
        }
    }
}
