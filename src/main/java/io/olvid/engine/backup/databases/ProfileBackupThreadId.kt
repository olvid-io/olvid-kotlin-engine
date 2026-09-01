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
import io.olvid.engine.crypto.PRNG
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.encoder.DecodingException
import java.sql.ResultSet
import java.sql.SQLException

class ProfileBackupThreadId : ObvDatabase {
    private val backupManagerSession: BackupManagerSession

    @JvmField val ownedIdentity: Identity // primary key
    @JvmField val threadId: UID // the profile backup threadId on the server
    var nextBackupTimestamp: Long
        private set

    private constructor(
        backupManagerSession: BackupManagerSession,
        ownedIdentity: Identity,
        threadId: UID
    ) {
        this.backupManagerSession = backupManagerSession
        this.ownedIdentity = ownedIdentity
        this.threadId = threadId
        this.nextBackupTimestamp = 0
    }


    private constructor(backupManagerSession: BackupManagerSession, res: ResultSet) {
        this.backupManagerSession = backupManagerSession
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
        } catch (_: DecodingException) {
            throw SQLException()
        }
        this.threadId = UID(res.getBytes(THREAD_ID))
        this.nextBackupTimestamp = res.getLong(NEXT_BACKUP_TIMESTAMP)
    }

    @Throws(SQLException::class)
    override fun insert() {
        backupManagerSession.session.prepareStatement(
            "ProfileBackupThreadId.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?);"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity.getBytes())
            statement.setBytes(2, threadId.bytes)
            statement.setLong(3, nextBackupTimestamp)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        backupManagerSession.session.prepareStatement(
            "ProfileBackupThreadId.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity.getBytes())
            statement.executeUpdate()
        }
    }

    // endregion
    // region setters
    @Throws(SQLException::class)
    fun updateNextBackupTimestamp(nextBackupTimestamp: Long) {
        backupManagerSession.session.prepareStatement(
            "ProfileBackupThreadId.setNextBackupTimestamp",
            "UPDATE " + TABLE_NAME +
                    " SET " + NEXT_BACKUP_TIMESTAMP + " = ? " +
                    " WHERE " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setLong(1, nextBackupTimestamp)
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.executeUpdate()
            this.nextBackupTimestamp = nextBackupTimestamp
        }
    }

    // endregion
    // region hooks
    override fun wasCommitted() {
    } // endregion

    companion object {
        const val TABLE_NAME: String = "profile_backup_thread_id"

        const val OWNED_IDENTITY: String = "owned_identity"
        const val THREAD_ID: String = "thread_id"
        const val NEXT_BACKUP_TIMESTAMP: String = "next_backup_timestamp"

        // region constructors
        fun create(
            backupManagerSession: BackupManagerSession,
            ownedIdentity: Identity?,
            prng: PRNG?
        ): ProfileBackupThreadId? {
            if (ownedIdentity == null || prng == null) {
                return null
            }
            try {
                val threadId = UID(prng)
                val profileBackupThreadId =
                    ProfileBackupThreadId(backupManagerSession, ownedIdentity, threadId)
                profileBackupThreadId.insert()
                return profileBackupThreadId
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
                            OWNED_IDENTITY + " BLOB PRIMARY KEY, " +
                            THREAD_ID + " BLOB NOT NULL, " +
                            NEXT_BACKUP_TIMESTAMP + " BIGINT NOT NULL " +
                            ");"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 44 && newVersion >= 44) {
                Logger.d("CREATING `device_backup_seed` DATABASE FOR VERSION 44")
                session.createStatement().use { statement ->
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS profile_backup_thread_id (" +
                                " owned_identity BLOB PRIMARY KEY, " +
                                " thread_id BLOB NOT NULL, " +
                                " next_backup_timestamp BIGINT NOT NULL " +
                                ");"
                    )
                }
                oldVersion = 44
            }
        }

        // endregion
        // region getters
        @Throws(SQLException::class)
        fun get(
            backupManagerSession: BackupManagerSession,
            ownedIdentity: Identity
        ): ProfileBackupThreadId? {
            backupManagerSession.session.prepareStatement(
                "ProfileBackupThreadId.get",
                "SELECT * FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { preparedStatement ->
                preparedStatement.setBytes(1, ownedIdentity.getBytes())
                val res = preparedStatement.executeQuery()
                return if (res.next()) {
                    ProfileBackupThreadId(backupManagerSession, res)
                } else {
                    null
                }
            }
        }

        @Throws(SQLException::class)
        fun getAll(backupManagerSession: BackupManagerSession): MutableList<ProfileBackupThreadId> {
            backupManagerSession.session.prepareStatement(
                "ProfileBackupThreadId.getAll",
                "SELECT * FROM " + TABLE_NAME + ";"
            ).use { preparedStatement ->
                val res = preparedStatement.executeQuery()
                val list: MutableList<ProfileBackupThreadId> = ArrayList()
                while (res.next()) {
                    list.add(ProfileBackupThreadId(backupManagerSession, res))
                }
                return list
            }
        }
    }
}
