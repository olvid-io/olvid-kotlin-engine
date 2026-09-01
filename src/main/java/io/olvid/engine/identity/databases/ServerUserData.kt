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
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.UserData
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import java.sql.ResultSet
import java.sql.SQLException

class ServerUserData : ObvDatabase {
    private val identityManagerSession: IdentityManagerSession

    private var ownedIdentity: Identity? = null
    private var label: UID? = null
    private var nextRefreshTimestamp: Long = 0
    private var bytesGroupOwnerAndUidOrIdentifier: ByteArray? = null // null for owned identity user data
    private var userDataType: Int = 0
    val userData: UserData?
        get() {
            var type: UserData.Type?
            when (userDataType) {
                TYPE_GROUP_V2 -> return UserData(
                    ownedIdentity,
                    label,
                    nextRefreshTimestamp,
                    UserData.Type.GROUP_V2,
                    bytesGroupOwnerAndUidOrIdentifier
                )

                TYPE_GROUP -> return UserData(
                    ownedIdentity,
                    label,
                    nextRefreshTimestamp,
                    UserData.Type.GROUP,
                    bytesGroupOwnerAndUidOrIdentifier
                )

                TYPE_OWNED_IDENTITY -> return UserData(
                    ownedIdentity,
                    label,
                    nextRefreshTimestamp,
                    UserData.Type.OWNED_IDENTITY,
                    null
                )
            }
            return null
        }

    private constructor(
        identityManagerSession: IdentityManagerSession,
        ownedIdentity: Identity,
        label: UID,
        nextRefreshTimestamp: Long,
        bytesGroupOwnerAndUidOrIdentifier: ByteArray?,
        userDataType: Int
    ) {
        this.identityManagerSession = identityManagerSession
        this.ownedIdentity = ownedIdentity
        this.label = label
        this.nextRefreshTimestamp = nextRefreshTimestamp
        this.bytesGroupOwnerAndUidOrIdentifier = bytesGroupOwnerAndUidOrIdentifier
        this.userDataType = userDataType
    }

    private constructor(identityManagerSession: IdentityManagerSession, res: ResultSet) {
        this.identityManagerSession = identityManagerSession
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
            this.label = UID(res.getBytes(LABEL))
            this.nextRefreshTimestamp = res.getLong(NEXT_REFRESH_TIMESTAMP)
            this.bytesGroupOwnerAndUidOrIdentifier = res.getBytes(
                BYTES_GROUP_OWNER_AND_UID_OR_IDENTIFIER
            )
            this.userDataType = res.getInt(USER_DATA_TYPE)
        } catch (_: DecodingException) {
            throw SQLException()
        }
    }


    @Throws(SQLException::class)
    override fun insert() {
        identityManagerSession.session.prepareStatement(
            "ServerUserData.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?);"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity!!.getBytes())
            statement.setBytes(2, label!!.bytes)
            statement.setLong(3, nextRefreshTimestamp)
            statement.setBytes(4, bytesGroupOwnerAndUidOrIdentifier)
            statement.setInt(5, userDataType)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        identityManagerSession.session.prepareStatement(
            "ServerUserData.delete",
            "DELETE FROM " + TABLE_NAME +
                    " WHERE " + OWNED_IDENTITY + " = ? " +
                    " AND " + LABEL + " = ?;"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity!!.getBytes())
            statement.setBytes(2, label!!.bytes)
            statement.executeUpdate()
        }
    }

    // endregion
    // region setters
    fun updateNextRefreshTimestamp() {
        try {
            identityManagerSession.session.prepareStatement(
                "ServerUserData.updateNextRefreshTimestamp",
                "UPDATE " + TABLE_NAME +
                        " SET " + NEXT_REFRESH_TIMESTAMP + " = ? " +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + LABEL + " = ?;"
            ).use { statement ->
                val timestamp = System.currentTimeMillis() + Constants.USER_DATA_REFRESH_INTERVAL
                statement.setLong(1, timestamp)
                statement.setBytes(2, ownedIdentity!!.getBytes())
                statement.setBytes(3, label!!.bytes)
                statement.executeUpdate()
                this.nextRefreshTimestamp = timestamp
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    // endregion
    // region hooks
    override fun wasCommitted() {
        // no hooks
    } // endregion

    companion object {
        const val TABLE_NAME: String = "server_user_data"

        const val OWNED_IDENTITY: String = "owned_identity"
        const val LABEL: String = "label"
        const val NEXT_REFRESH_TIMESTAMP: String = "next_refresh_timestamp"
        const val BYTES_GROUP_OWNER_AND_UID_OR_IDENTIFIER: String =
            "bytes_group_owner_and_uid_or_identifier"
        const val USER_DATA_TYPE: String = "user_data_type"

        const val TYPE_OWNED_IDENTITY: Int = 1
        const val TYPE_GROUP: Int = 2
        const val TYPE_GROUP_V2: Int = 3


        // region constructors
        fun createForOwnedIdentityDetails(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            label: UID?
        ): ServerUserData? {
            if (ownedIdentity == null || label == null) {
                return null
            }
            try {
                val nextRefreshTimestamp =
                    System.currentTimeMillis() + Constants.USER_DATA_REFRESH_INTERVAL
                val serverUserData = ServerUserData(
                    identityManagerSession,
                    ownedIdentity,
                    label,
                    nextRefreshTimestamp,
                    null,
                    TYPE_OWNED_IDENTITY
                )
                serverUserData.insert()
                return serverUserData
            } catch (_: SQLException) {
                return null
            }
        }

        fun createForOwnedGroupDetails(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            label: UID?,
            bytesGroupOwnerAndUid: ByteArray?
        ): ServerUserData? {
            if (ownedIdentity == null || label == null || bytesGroupOwnerAndUid == null) {
                return null
            }
            try {
                val nextRefreshTimestamp =
                    System.currentTimeMillis() + Constants.USER_DATA_REFRESH_INTERVAL
                val serverUserData = ServerUserData(
                    identityManagerSession,
                    ownedIdentity,
                    label,
                    nextRefreshTimestamp,
                    bytesGroupOwnerAndUid,
                    TYPE_GROUP
                )
                serverUserData.insert()
                return serverUserData
            } catch (_: SQLException) {
                return null
            }
        }

        fun createForGroupV2(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            label: UID?,
            bytesGroupIdentifier: ByteArray?
        ): ServerUserData? {
            if (ownedIdentity == null || label == null || bytesGroupIdentifier == null) {
                return null
            }
            try {
                val nextRefreshTimestamp =
                    System.currentTimeMillis() + Constants.USER_DATA_REFRESH_INTERVAL
                val serverUserData = ServerUserData(
                    identityManagerSession,
                    ownedIdentity,
                    label,
                    nextRefreshTimestamp,
                    bytesGroupIdentifier,
                    TYPE_GROUP_V2
                )
                serverUserData.insert()
                return serverUserData
            } catch (_: SQLException) {
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
                            LABEL + " BLOB NOT NULL, " +
                            NEXT_REFRESH_TIMESTAMP + " INT NOT NULL, " +
                            BYTES_GROUP_OWNER_AND_UID_OR_IDENTIFIER + " BLOB, " +
                            USER_DATA_TYPE + " INT NOT NULL, " +
                            "CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + OWNED_IDENTITY + ", " + LABEL + "));"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 21 && newVersion >= 21) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING server_user_data DATABASE FROM VERSION " + oldVersion + " TO 21")
                    statement.execute("ALTER TABLE server_user_data RENAME TO old_server_user_data")
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS server_user_data (" +
                                " owned_identity BLOB NOT NULL, " +
                                " label BLOB NOT NULL, " +
                                " next_refresh_timestamp INT NOT NULL, " +
                                " group_details_owner_and_uid BLOB, " +
                                "CONSTRAINT PK_server_user_data PRIMARY KEY(owned_identity, label));"
                    )
                    statement.execute("INSERT INTO server_user_data (owned_identity, label, next_refresh_timestamp, group_details_owner_and_uid) SELECT owned_identity, label, next_refresh_timestamp, group_details_owner_and_uid FROM old_server_user_data")
                    statement.execute("DROP TABLE old_server_user_data")
                }
                oldVersion = 21
            }
            if (oldVersion < 32 && newVersion >= 32) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING server_user_data DATABASE FROM VERSION " + oldVersion + " TO 32")
                    statement.execute("ALTER TABLE server_user_data RENAME TO old_server_user_data")
                    statement.execute(
                        "CREATE TABLE server_user_data (" +
                                " owned_identity BLOB NOT NULL, " +
                                " label BLOB NOT NULL, " +
                                " next_refresh_timestamp INT NOT NULL, " +
                                " bytes_group_owner_and_uid_or_identifier BLOB, " +
                                " user_data_type INT NOT NULL, " +
                                "CONSTRAINT PK_server_user_data PRIMARY KEY(owned_identity, label));"
                    )
                    statement.execute("INSERT INTO server_user_data (owned_identity, label, next_refresh_timestamp, bytes_group_owner_and_uid_or_identifier, user_data_type) SELECT owned_identity, label, next_refresh_timestamp, group_details_owner_and_uid, CASE WHEN group_details_owner_and_uid IS NULL THEN 1 ELSE 2 END FROM old_server_user_data")
                    statement.execute("DROP TABLE old_server_user_data")
                }
                oldVersion = 32
            }
        }

        // endregion
        // region getters
        @Throws(SQLException::class)
        fun get(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            label: UID
        ): ServerUserData? {
            identityManagerSession.session.prepareStatement(
                "ServerUserData.get",
                "SELECT * FROM " + TABLE_NAME + " WHERE " +
                        OWNED_IDENTITY + " = ? AND " +
                        LABEL + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setBytes(2, label.bytes)
                statement.executeQuery().use { res ->
                    if (res.next()) {
                        return ServerUserData(identityManagerSession, res)
                    } else {
                        return null
                    }
                }
            }
        }

        @Throws(SQLException::class)
        fun deleteAllForOwnedIdentity(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity
        ) {
            identityManagerSession.session.prepareStatement(
                "ServerUserData.deleteAllForOwnedIdentity",
                "DELETE FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeUpdate()
            }
        }

        @Throws(SQLException::class)
        fun getAll(identityManagerSession: IdentityManagerSession): Array<ServerUserData?> {
            identityManagerSession.session.prepareStatement(
                "ServerUserData.getAll",
                "SELECT * FROM " + TABLE_NAME + ";"
            ).use { statement ->
                statement.executeQuery().use { res ->
                    val list: MutableList<ServerUserData?> = ArrayList<ServerUserData?>()
                    while (res.next()) {
                        list.add(ServerUserData(identityManagerSession, res))
                    }
                    return list.toTypedArray<ServerUserData?>()
                }
            }
        }
    }
}
