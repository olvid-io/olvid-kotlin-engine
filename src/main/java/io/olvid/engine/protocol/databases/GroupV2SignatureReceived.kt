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
package io.olvid.engine.protocol.databases

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import java.sql.SQLException

class GroupV2SignatureReceived : ObvDatabase {
    internal val protocolManagerSession: ProtocolManagerSession

    internal val ownedIdentity: Identity
    internal val signature: ByteArray

    internal constructor(
        protocolManagerSession: ProtocolManagerSession,
        ownedIdentity: Identity,
        signature: ByteArray
    ) {
        this.protocolManagerSession = protocolManagerSession
        this.ownedIdentity = ownedIdentity
        this.signature = signature
    }


//    internal constructor(protocolManagerSession: ProtocolManagerSession, res: ResultSet) {
//        this.protocolManagerSession = protocolManagerSession
//
//        try {
//            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
//        } catch (_: DecodingException) {
//            throw SQLException()
//        }
//        this.signature = res.getBytes(SIGNATURE)
//    }


    @Throws(SQLException::class)
    override fun insert() {
        protocolManagerSession.session.prepareStatement(
            "GroupV2SignatureReceived.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?);"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity.getBytes())
            statement.setBytes(2, signature)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        protocolManagerSession.session.prepareStatement(
            "GroupV2SignatureReceived.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ? AND " + SIGNATURE + " = ?;"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity.getBytes())
            statement.setBytes(2, signature)
            statement.executeUpdate()
        }
    }

    override fun wasCommitted() {
        // No hooks here
    }

    companion object {
        const val TABLE_NAME: String = "group_v2_signature_received"

        const val OWNED_IDENTITY: String = "owned_identity"
        const val SIGNATURE: String = "signature"


        // region constructors
        fun create(
            protocolManagerSession: ProtocolManagerSession,
            ownedIdentity: Identity?,
            signature: ByteArray?
        ): GroupV2SignatureReceived? {
            if (ownedIdentity == null || signature == null) {
                return null
            }
            try {
                val groupV2SignatureReceived =
                    GroupV2SignatureReceived(protocolManagerSession, ownedIdentity, signature)
                groupV2SignatureReceived.insert()
                return groupV2SignatureReceived
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
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            SIGNATURE + " BLOB NOT NULL, " +
                            "CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY (" + OWNED_IDENTITY + ", " + SIGNATURE + "));"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 32 && newVersion >= 32) {
                Logger.d("CREATING `group_v2_signature_received` TABLE AS PART OF VERSION 32")
                session.createStatement().use { statement ->
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS group_v2_signature_received (" +
                                " owned_identity BLOB NOT NULL, " +
                                " signature BLOB NOT NULL, " +
                                "CONSTRAINT PK_group_v2_signature_received PRIMARY KEY (owned_identity, signature));"
                    )
                }
                oldVersion = 32
            }
        }

        // endregion
        @Throws(SQLException::class)
        fun exists(
            protocolManagerSession: ProtocolManagerSession,
            ownedIdentity: Identity?,
            commitment: ByteArray?
        ): Boolean {
            if (ownedIdentity == null || commitment == null) {
                return false
            }
            protocolManagerSession.session.prepareStatement(
                "GroupV2SignatureReceived.exists",
                "SELECT 1 FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ? AND " + SIGNATURE + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setBytes(2, commitment)
                statement.executeQuery().use { res ->
                    return res.next()
                }
            }
        }

        @Throws(SQLException::class)
        fun deleteAllForOwnedIdentity(
            protocolManagerSession: ProtocolManagerSession,
            ownedIdentity: Identity
        ) {
            protocolManagerSession.session.prepareStatement(
                "GroupV2SignatureReceived.deleteAllForOwnedIdentity",
                "DELETE FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeUpdate()
            }
        }
    }
}
