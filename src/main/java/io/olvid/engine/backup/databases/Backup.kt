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
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import java.sql.ResultSet
import java.sql.SQLException

class Backup : ObvDatabase {
    private val backupManagerSession: BackupManagerSession

    private val backupKeyUid: UID
    @JvmField val version: Int
    @JvmField val isForExport: Boolean
    var status: Int
        private set
    var statusChangeTimestamp: Long
        private set
    private var encryptedContent: ByteArray?
    @JvmField val backupJsonVersion: Int

    private constructor(
        backupManagerSession: BackupManagerSession,
        backupKeyUid: UID,
        version: Int,
        forExport: Boolean,
        status: Int,
        statusChangeTimestamp: Long,
        encryptedContent: ByteArray?,
        backupJsonVersion: Int
    ) {
        this.backupManagerSession = backupManagerSession
        this.backupKeyUid = backupKeyUid
        this.version = version
        this.isForExport = forExport
        this.status = status
        this.statusChangeTimestamp = statusChangeTimestamp
        this.encryptedContent = encryptedContent
        this.backupJsonVersion = backupJsonVersion
    }

    private constructor(backupManagerSession: BackupManagerSession, res: ResultSet) {
        this.backupManagerSession = backupManagerSession
        this.backupKeyUid = UID(res.getBytes(BACKUP_KEY_UID))
        this.version = res.getInt(VERSION)
        this.isForExport = res.getBoolean(FOR_EXPORT)
        this.status = res.getInt(STATUS)
        this.statusChangeTimestamp = res.getLong(STATUS_CHANGE_TIMESTAMP)
        this.encryptedContent = res.getBytes(ENCRYPTED_CONTENT)
        this.backupJsonVersion = res.getInt(BACKUP_JSON_VERSION)
    }

    @Throws(SQLException::class)
    override fun insert() {
        backupManagerSession.session.prepareStatement(
            "Backup.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?, ?,?);"
        ).use { statement ->
            statement.setBytes(1, backupKeyUid.bytes)
            statement.setInt(2, version)
            statement.setBoolean(3, this.isForExport)
            statement.setInt(4, status)
            statement.setLong(5, statusChangeTimestamp)
            statement.setBytes(6, encryptedContent)
            statement.setInt(7, backupJsonVersion)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        backupManagerSession.session.prepareStatement(
            "Backup.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + BACKUP_KEY_UID + " = ? AND " + VERSION + " = ?;"
        ).use { statement ->
            statement.setBytes(1, backupKeyUid.bytes)
            statement.setInt(2, version)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    fun setReady(encryptedContent: ByteArray?) {
        backupManagerSession.session.prepareStatement(
            "Backup.setReady",
            "UPDATE " + TABLE_NAME +
                    " SET " + STATUS + " = ?, " +
                    ENCRYPTED_CONTENT + " = ?, " +
                    STATUS_CHANGE_TIMESTAMP + " = ? " +
                    " WHERE " + BACKUP_KEY_UID + " = ? AND " +
                    VERSION + " = ?;"
        ).use { statement ->
            val timestamp = System.currentTimeMillis()
            statement.setInt(1, STATUS_READY)
            statement.setBytes(2, encryptedContent)
            statement.setLong(3, timestamp)
            statement.setBytes(4, backupKeyUid.bytes)
            statement.setInt(5, version)
            statement.executeUpdate()
            this.status = STATUS_READY
            this.encryptedContent = encryptedContent
            this.statusChangeTimestamp = timestamp
        }
    }

    @Throws(SQLException::class)
    fun setUploadedOrExported() {
        backupManagerSession.session.prepareStatement(
            "Backup.setUploadedOrExported",
            "UPDATE " + TABLE_NAME +
                    " SET " + STATUS + " = ?, " +
                    STATUS_CHANGE_TIMESTAMP + " = ? " +
                    " WHERE " + BACKUP_KEY_UID + " = ? AND " +
                    VERSION + " = ? AND " +
                    FOR_EXPORT + " = 0;"
        ).use { statement ->
            val timestamp = System.currentTimeMillis()
            statement.setInt(1, STATUS_UPLOADED_OR_EXPORTED)
            statement.setLong(2, timestamp)
            statement.setBytes(3, backupKeyUid.bytes)
            statement.setInt(4, version)
            statement.executeUpdate()
            this.status = STATUS_UPLOADED_OR_EXPORTED
            this.statusChangeTimestamp = timestamp
        }
    }

    @Throws(SQLException::class)
    fun setFailed() {
        backupManagerSession.session.prepareStatement(
            "Backup.setFailed",
            "UPDATE " + TABLE_NAME +
                    " SET " + STATUS + " = ?, " +
                    STATUS_CHANGE_TIMESTAMP + " = ? " +
                    " WHERE " + BACKUP_KEY_UID + " = ? AND " +
                    VERSION + " = ? AND " +
                    FOR_EXPORT + " = 0;"
        ).use { statement ->
            val timestamp = System.currentTimeMillis()
            statement.setInt(1, STATUS_FAILED)
            statement.setLong(2, timestamp)
            statement.setBytes(3, backupKeyUid.bytes)
            statement.setInt(4, version)
            statement.executeUpdate()
            this.status = STATUS_FAILED
            this.statusChangeTimestamp = timestamp
        }
    }

    // endregion
    override fun wasCommitted() {
    }

    companion object {
        const val TABLE_NAME: String = "backup"

        const val BACKUP_KEY_UID: String = "backup_key_uid"
        const val VERSION: String = "version"
        const val FOR_EXPORT: String = "for_export"
        const val STATUS: String = "status"
        const val STATUS_CHANGE_TIMESTAMP: String = "status_change_timestamp"
        const val ENCRYPTED_CONTENT: String = "encrypted_content"
        const val BACKUP_JSON_VERSION: String = "backup_json_version"

        const val STATUS_ONGOING: Int = 0
        const val STATUS_READY: Int = 1
        const val STATUS_UPLOADED_OR_EXPORTED: Int = 2
        const val STATUS_FAILED: Int = -1

        @Throws(SQLException::class)
        fun cleanup(
            backupManagerSession: BackupManagerSession,
            backupKeyUid: UID,
            uploadedBackupVersion: Int?,
            exportedBackupVersion: Int?,
            latestBackupVersion: Int?
        ) {
            backupManagerSession.session.prepareStatement(
                "Backup.cleanup",
                "DELETE FROM " + TABLE_NAME +
                        " WHERE " + BACKUP_KEY_UID + " = ? " +
                        " AND " + VERSION + " NOT IN (?,?,?);"
            ).use { statement ->
                statement.setBytes(1, backupKeyUid.bytes)
                statement.setInt(
                    2,
                    if (uploadedBackupVersion != null) uploadedBackupVersion else -1
                )
                statement.setInt(
                    3,
                    if (exportedBackupVersion != null) exportedBackupVersion else -1
                )
                statement.setInt(4, if (latestBackupVersion != null) latestBackupVersion else -1)
                statement.executeUpdate()
            }
        }


        // region constructors
        fun createOngoingBackup(
            backupManagerSession: BackupManagerSession?,
            backupKeyUid: UID?,
            version: Int,
            forExport: Boolean
        ): Backup? {
            if (backupManagerSession == null || backupKeyUid == null) {
                return null
            }
            try {
                val backup = Backup(
                    backupManagerSession,
                    backupKeyUid,
                    version,
                    forExport,
                    STATUS_ONGOING,
                    System.currentTimeMillis(),
                    null,
                    Constants.CURRENT_BACKUP_JSON_VERSION
                )
                backup.insert()
                return backup
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
                            BACKUP_KEY_UID + " BLOB NOT NULL, " +
                            VERSION + " INTEGER NOT NULL, " +
                            FOR_EXPORT + " BIT NOT NULL, " +
                            STATUS + " INTEGER NOT NULL, " +
                            STATUS_CHANGE_TIMESTAMP + " INTEGER NOT NULL, " +
                            ENCRYPTED_CONTENT + " BLOB, " +
                            BACKUP_JSON_VERSION + " INTEGER NOT NULL, " +
                            "CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + BACKUP_KEY_UID + ", " + VERSION + "));"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
        }

        @Throws(SQLException::class)
        fun deleteAll(backupManagerSession: BackupManagerSession) {
            backupManagerSession.session.prepareStatement(
                "Backup.deleteAll",
                " DELETE FROM " + TABLE_NAME + ";"
            ).use { statement ->
                statement.executeUpdate()
            }
        }


        fun get(
            backupManagerSession: BackupManagerSession,
            backupKeyUid: UID,
            version: Int
        ): Backup? {
            try {
                backupManagerSession.session.prepareStatement(
                    "Backup.get",
                    "SELECT * FROM " + TABLE_NAME + " WHERE " + BACKUP_KEY_UID + " = ? AND " + VERSION + " = ?;"
                ).use { preparedStatement ->
                    preparedStatement.setBytes(1, backupKeyUid.bytes)
                    preparedStatement.setInt(2, version)
                    val res = preparedStatement.executeQuery()
                    if (res.next()) {
                        return Backup(backupManagerSession, res)
                    } else {
                        return null
                    }
                }
            } catch (_: SQLException) {
                return null
            }
        }
    }
}
