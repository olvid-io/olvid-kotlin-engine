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
import io.olvid.engine.datatypes.UID
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolState
import java.sql.ResultSet
import java.sql.SQLException
import java.sql.Types

class ProtocolInstance : ObvDatabase {
    @JvmField val protocolManagerSession: ProtocolManagerSession

    // To improve: add an expiration timestamp, updated each time a new state is written
    //  --> this timestamp should depend on the protocol type (infinite for group management)
    @JvmField val uid: UID
    @JvmField val ownedIdentity: Identity
    @JvmField val protocolId: Int
    var currentStateId: Int
        private set
    var encodedCurrentState: Encoded? = null
        private set


    @Throws(SQLException::class)
    fun updateCurrentState(
        newState: ConcreteProtocolState,
        protocolInstanceNeedsToBeInserted: Boolean
    ) {
        this.currentStateId = newState.id
        this.encodedCurrentState = newState.encode()
        if (protocolInstanceNeedsToBeInserted) {
            insert()
        } else {
            protocolManagerSession.session.prepareStatement(
                "ProtocolInstance.updateCurrentState",
                "UPDATE " + TABLE_NAME + " SET " +
                        CURRENT_STATE_ID + " = ?, " +
                        ENCODED_CURRENT_STATE + " = ? " +
                        " WHERE " + UID_ + " = ? AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setInt(1, this.currentStateId)
                if (this.encodedCurrentState != null) {
                    statement.setBytes(2, this.encodedCurrentState!!.bytes)
                } else {
                    statement.setNull(2, Types.BLOB)
                }
                statement.setBytes(3, uid.bytes)
                statement.setBytes(4, ownedIdentity.getBytes())
                statement.executeUpdate()
            }
        }
    }


    internal constructor(
        protocolManagerSession: ProtocolManagerSession,
        protocolInstanceUid: UID,
        ownedIdentity: Identity,
        protocolId: Int,
        currentStateId: Int,
        encodedCurrentState: Encoded?
    ) {
        this.protocolManagerSession = protocolManagerSession

        this.uid = protocolInstanceUid
        this.ownedIdentity = ownedIdentity
        this.protocolId = protocolId
        this.currentStateId = currentStateId
        this.encodedCurrentState = encodedCurrentState
    }

    internal constructor(protocolManagerSession: ProtocolManagerSession, res: ResultSet) {
        this.protocolManagerSession = protocolManagerSession

        this.uid = UID(res.getBytes(UID_))
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
        } catch (_: DecodingException) {
            throw SQLException()
        }
        this.protocolId = res.getInt(PROTOCOL_ID)
        this.currentStateId = res.getInt(CURRENT_STATE_ID)
        val bytes: ByteArray? = res.getBytes(ENCODED_CURRENT_STATE)
        if (bytes == null) {
            this.encodedCurrentState = null
        } else {
            this.encodedCurrentState = Encoded(bytes)
        }
    }


    @Throws(SQLException::class)
    override fun insert() {
        protocolManagerSession.session.prepareStatement(
            "ProtocolInstance.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?);"
        ).use { statement ->
            statement.setBytes(1, uid.bytes)
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.setInt(3, protocolId)
            statement.setInt(4, currentStateId)
            if (encodedCurrentState != null) {
                statement.setBytes(5, encodedCurrentState!!.bytes)
            } else {
                statement.setNull(5, Types.BLOB)
            }
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        protocolManagerSession.session.prepareStatement(
            "ProtocolInstance.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + UID_ + " = ? AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, uid.bytes)
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.executeUpdate()
        }
    }


    override fun wasCommitted() {
        // No hooks here
    }

    companion object {
        const val TABLE_NAME: String = "protocol_instance"

        const val UID_: String = "uid"
        const val OWNED_IDENTITY: String = "owned_identity"
        const val PROTOCOL_ID: String = "protocol_id"
        const val CURRENT_STATE_ID: String = "current_state_id"
        const val ENCODED_CURRENT_STATE: String = "encoded_current_state"

        fun createNotInDb(
            protocolManagerSession: ProtocolManagerSession,
            protocolInstanceUid: UID?,
            ownedIdentity: Identity?,
            protocolId: Int,
            protocolState: ConcreteProtocolState?
        ): ProtocolInstance? {
            if ((protocolInstanceUid == null) || (ownedIdentity == null) || (protocolState == null)) {
                return null
            }
            return ProtocolInstance(
                protocolManagerSession,
                protocolInstanceUid,
                ownedIdentity,
                protocolId,
                protocolState.id,
                protocolState.encode()
            )
        }

        @Throws(SQLException::class)
        fun createTable(session: Session) {
            session.createStatement().use { statement ->
                statement.execute(
                    "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                            UID_ + " BLOB NOT NULL, " +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            PROTOCOL_ID + " INT NOT NULL, " +
                            CURRENT_STATE_ID + " INT NOT NULL, " +
                            ENCODED_CURRENT_STATE + " BLOB, " +
                            "CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + UID_ + ", " + OWNED_IDENTITY + "));"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 11 && newVersion >= 11) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING protocol_instance DATABASE FROM VERSION " + oldVersion + " TO 11")
                    statement.execute("DELETE FROM protocol_instance WHERE protocol_id = 5;")
                }
                oldVersion = 11
            }
            if (oldVersion < 33 && newVersion >= 33) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING protocol_instance DATABASE FROM VERSION " + oldVersion + " TO 33")
                    statement.execute("DELETE FROM protocol_instance WHERE protocol_id = 1;")
                }
                oldVersion = 33
            }
        }

        fun get(
            protocolManagerSession: ProtocolManagerSession,
            protocolInstanceUid: UID?,
            ownedIdentity: Identity?
        ): ProtocolInstance? {
            if ((protocolInstanceUid == null) || (ownedIdentity == null)) {
                return null
            }
            try {
                protocolManagerSession.session.prepareStatement(
                    "ProtocolInstance.get",
                    "SELECT * FROM " + TABLE_NAME + " WHERE " + UID_ + " = ? AND " + OWNED_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, protocolInstanceUid.bytes)
                    statement.setBytes(2, ownedIdentity.getBytes())
                    statement.executeQuery().use { res ->
                        if (res.next()) {
                            return ProtocolInstance(protocolManagerSession, res)
                        } else {
                            return null
                        }
                    }
                }
            } catch (_: SQLException) {
                return null
            }
        }

        //    public static List<ProtocolInstance> getAllForProtocolId(ProtocolManagerSession protocolManagerSession, int protocolId) {
        //        try (PreparedStatement statement = protocolManagerSession!!.session.prepareStatement("ProtocolInstance.getAllForProtocolId",
        //        "SELECT * FROM " + TABLE_NAME + " WHERE " + PROTOCOL_ID + " = ?;")) {
        //            statement.setInt(1, protocolId);
        //            try (ResultSet res = statement.executeQuery()) {
        //                List<ProtocolInstance> list = new ArrayList<>();
        //                while (res.next()) {
        //                    list.add(new ProtocolInstance(protocolManagerSession, res));
        //                }
        //                return list;
        //            }
        //        } catch (SQLException e) {
        //            return Collections.emptyList();
        //        }
        //    }
        //
        //    public static List<ProtocolInstance> getAllForOwnedIdentityProtocolId(ProtocolManagerSession protocolManagerSession, Identity ownedIdentity, int protocolId) {
        //        try (PreparedStatement statement = protocolManagerSession!!.session.prepareStatement("ProtocolInstance.getAllForOwnedIdentityProtocolId",
        //        "SELECT * FROM " + TABLE_NAME +
        //                " WHERE " + PROTOCOL_ID + " = ? " +
        //                " AND " + OWNED_IDENTITY + " = ?;")) {
        //            statement.setInt(1, protocolId);
        //            statement.setBytes(2, ownedIdentity!!.getBytes());
        //            try (ResultSet res = statement.executeQuery()) {
        //                List<ProtocolInstance> list = new ArrayList<>();
        //                while (res.next()) {
        //                    list.add(new ProtocolInstance(protocolManagerSession, res));
        //                }
        //                return list;
        //            }
        //        } catch (SQLException e) {
        //            return Collections.emptyList();
        //        }
        //    }
        @Throws(SQLException::class)
        fun deleteAllForOwnedIdentity(
            protocolManagerSession: ProtocolManagerSession,
            ownedIdentity: Identity,
            excludedProtocolInstanceUid: UID?
        ) {
            if (excludedProtocolInstanceUid == null) {
                protocolManagerSession.session.prepareStatement(
                    "ProtocolInstance.deleteAllForOwnedIdentity",
                    "DELETE FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, ownedIdentity.getBytes())
                    statement.executeUpdate()
                }
            } else {
                protocolManagerSession.session.prepareStatement(
                    "ProtocolInstance.deleteAllForOwnedIdentity",
                    "DELETE FROM " + TABLE_NAME +
                            " WHERE " + OWNED_IDENTITY + " = ?" +
                            " AND " + UID_ + " != ?;"
                ).use { statement ->
                    statement.setBytes(1, ownedIdentity.getBytes())
                    statement.setBytes(2, excludedProtocolInstanceUid.bytes)
                    statement.executeUpdate()
                }
            }
        }

        @Throws(SQLException::class)
        fun deleteAllTransfer(protocolManagerSession: ProtocolManagerSession) {
            protocolManagerSession.session.prepareStatement(
                "ProtocolInstance.deleteAllTransfer",
                "DELETE FROM " + TABLE_NAME + " WHERE " + PROTOCOL_ID + " = ?;"
            ).use { statement ->
                statement.setInt(1, ConcreteProtocol.OWNED_IDENTITY_TRANSFER_PROTOCOL_ID)
                statement.executeUpdate()
            }
        }
    }
}
