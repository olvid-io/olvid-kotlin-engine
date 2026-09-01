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
import io.olvid.engine.datatypes.BackupSeed
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import java.sql.ResultSet
import java.sql.SQLException

class DeviceBackupSeed : ObvDatabase {
    private val backupManagerSession: BackupManagerSession

    @JvmField val backupSeed: BackupSeed // primary key
    @JvmField val server: String // the server on which the device backup should be uploaded
    var isActive: Boolean // there can be at most one active key at a time. Inactive keys are being cleaned from server and deleted
        private set
    var nextBackupTimestamp: Long
        private set

    private constructor(
        backupManagerSession: BackupManagerSession,
        backupSeed: BackupSeed,
        server: String
    ) {
        this.backupManagerSession = backupManagerSession
        this.backupSeed = backupSeed
        this.server = server
        this.isActive = true
        this.nextBackupTimestamp = 0
    }


    private constructor(backupManagerSession: BackupManagerSession, res: ResultSet) {
        this.backupManagerSession = backupManagerSession
        this.backupSeed = BackupSeed(res.getBytes(BACKUP_SEED))
        this.server = res.getString(SERVER)
        this.isActive = res.getBoolean(ACTIVE)
        this.nextBackupTimestamp = res.getLong(NEXT_BACKUP_TIMESTAMP)
    }

    @Throws(SQLException::class)
    override fun insert() {
        backupManagerSession.session.prepareStatement(
            "DeviceBackupSeed.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?);"
        ).use { statement ->
            statement.setBytes(1, backupSeed.backupSeedBytes)
            statement.setString(2, server)
            statement.setBoolean(3, this.isActive)
            statement.setLong(4, nextBackupTimestamp)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        backupManagerSession.session.prepareStatement(
            "DeviceBackupSeed.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + BACKUP_SEED + " = ?;"
        ).use { statement ->
            statement.setBytes(1, backupSeed.backupSeedBytes)
            statement.executeUpdate()
        }
    }

    // endregion
    // region setters
    @Throws(SQLException::class)
    fun markBackupKeyInactive() {
        backupManagerSession.session.prepareStatement(
            "DeviceBackupSeed.markBackupKeyInactive",
            "UPDATE " + TABLE_NAME +
                    " SET " + ACTIVE + " = ? " +
                    " WHERE " + BACKUP_SEED + " = ?;"
        ).use { statement ->
            statement.setBoolean(1, false)
            statement.setBytes(2, backupSeed.backupSeedBytes)
            statement.executeUpdate()
            this.isActive = false
        }
    }

    @Throws(SQLException::class)
    fun updateNextBackupTimestamp(nextBackupTimestamp: Long) {
        if (!this.isActive) {
            return
        }
        backupManagerSession.session.prepareStatement(
            "DeviceBackupSeed.setNextBackupTimestamp",
            "UPDATE " + TABLE_NAME +
                    " SET " + NEXT_BACKUP_TIMESTAMP + " = ? " +
                    " WHERE " + BACKUP_SEED + " = ?;"
        ).use { statement ->
            statement.setLong(1, nextBackupTimestamp)
            statement.setBytes(2, backupSeed.backupSeedBytes)
            statement.executeUpdate()
            this.nextBackupTimestamp = nextBackupTimestamp
        }
    }

    // endregion
    // region hooks
    override fun wasCommitted() {
    } // endregion

    companion object {
        const val TABLE_NAME: String = "device_backup_seed"

        const val BACKUP_SEED: String = "backup_seed"
        const val SERVER: String = "server"
        const val ACTIVE: String = "active"
        const val NEXT_BACKUP_TIMESTAMP: String = "next_backup_timestamp"

        // region constructors
        fun create(
            backupManagerSession: BackupManagerSession?,
            backupSeed: BackupSeed?,
            server: String?
        ): DeviceBackupSeed? {
            if (backupManagerSession == null || backupSeed == null || server == null) {
                return null
            }
            try {
                val backupKey = DeviceBackupSeed(backupManagerSession, backupSeed, server)
                backupKey.insert()
                return backupKey
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
                            BACKUP_SEED + " BLOB PRIMARY KEY, " +
                            SERVER + " TEXT NOT NULL, " +
                            ACTIVE + " BIY NOT NULL, " +
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
                        "CREATE TABLE IF NOT EXISTS device_backup_seed (" +
                                " backup_seed BLOB PRIMARY KEY, " +
                                " server TEXT NOT NULL, " +
                                " active BIT NOT NULL," +
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
            backupSeed: BackupSeed
        ): DeviceBackupSeed? {
            backupManagerSession.session.prepareStatement(
                "DeviceBackupSeed.get",
                "SELECT * FROM " + TABLE_NAME + " WHERE " + BACKUP_SEED + " = ?;"
            ).use { preparedStatement ->
                preparedStatement.setBytes(1, backupSeed.backupSeedBytes)
                val res = preparedStatement.executeQuery()
                return if (res.next()) {
                    DeviceBackupSeed(backupManagerSession, res)
                } else {
                    null
                }
            }
        }

        @Throws(SQLException::class)
        fun getActive(backupManagerSession: BackupManagerSession): DeviceBackupSeed? {
            backupManagerSession.session.prepareStatement(
                "DeviceBackupSeed.getActive",
                "SELECT * FROM " + TABLE_NAME + " WHERE " + ACTIVE + " = ?;"
            ).use { preparedStatement ->
                preparedStatement.setBoolean(1, true)
                val res = preparedStatement.executeQuery()
                return if (res.next()) {
                    DeviceBackupSeed(backupManagerSession, res)
                } else {
                    null
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllInactive(backupManagerSession: BackupManagerSession): Array<DeviceBackupSeed?> {
            backupManagerSession.session.prepareStatement(
                "DeviceBackupSeed.getAllInactive",
                "SELECT * FROM " + TABLE_NAME + " WHERE " + ACTIVE + " = ?;"
            ).use { preparedStatement ->
                preparedStatement.setBoolean(1, false)
                val res = preparedStatement.executeQuery()
                val list: MutableList<DeviceBackupSeed?> = ArrayList()
                while (res.next()) {
                    list.add(DeviceBackupSeed(backupManagerSession, res))
                }
                return list.toTypedArray<DeviceBackupSeed?>()
            }
        }
    }
}
