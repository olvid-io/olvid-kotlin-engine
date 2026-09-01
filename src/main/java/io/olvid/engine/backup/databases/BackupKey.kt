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
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.symmetric.MACKey
import io.olvid.engine.encoder.Encoded
import java.sql.ResultSet
import java.sql.SQLException
import java.sql.Types

class BackupKey : ObvDatabase {
    private val backupManagerSession: BackupManagerSession

    @JvmField val uid: UID // can also be used as a unique identifier to locate the backup file in the cloud
    var encryptionPublicKey: EncryptionPublicKey
        private set
    var macKey: MACKey
        private set
    @JvmField val keyGenerationTimestamp: Long
    var lastSuccessfulKeyVerificationTimestamp: Long
        private set
    private var lastKeyVerificationPromptTimestamp: Long
    var successfulVerificationCount: Int
        private set
    var uploadedBackupVersion: Int?
        private set
    var exportedBackupVersion: Int?
        private set
    var latestBackupVersion: Int?
        private set

    private constructor(
        backupManagerSession: BackupManagerSession,
        uid: UID,
        encryptionPublicKey: EncryptionPublicKey,
        macKey: MACKey,
        keyGenerationTimestamp: Long,
        lastSuccessfulKeyVerificationTimestamp: Long,
        lastKeyVerificationPromptTimestamp: Long,
        successfulVerificationCount: Int,
        uploadedBackupVersion: Int?,
        exportedBackupVersion: Int?,
        latestBackupVersion: Int?
    ) {
        this.backupManagerSession = backupManagerSession
        this.uid = uid
        this.encryptionPublicKey = encryptionPublicKey
        this.macKey = macKey
        this.keyGenerationTimestamp = keyGenerationTimestamp
        this.lastSuccessfulKeyVerificationTimestamp = lastSuccessfulKeyVerificationTimestamp
        this.lastKeyVerificationPromptTimestamp = lastKeyVerificationPromptTimestamp
        this.successfulVerificationCount = successfulVerificationCount
        this.uploadedBackupVersion = uploadedBackupVersion
        this.exportedBackupVersion = exportedBackupVersion
        this.latestBackupVersion = latestBackupVersion
    }

    private constructor(backupManagerSession: BackupManagerSession, res: ResultSet) {
        this.backupManagerSession = backupManagerSession
        this.uid = UID(res.getBytes(UID_))
        try {
            this.encryptionPublicKey = Encoded(res.getBytes(ENCRYPTION_PUBLIC_KEY)).decodePublicKey() as EncryptionPublicKey
            this.macKey = Encoded(res.getBytes(MAC_KEY)).decodeSymmetricKey() as MACKey
        } catch (e: Exception) {
            Logger.e("Unable to parse encryption public key or MAC key in BackupKey database!!!")
            throw e
        }
        this.keyGenerationTimestamp = res.getLong(KEY_GENERATION_TIMESTAMP)
        this.lastSuccessfulKeyVerificationTimestamp = res.getLong(
            LAST_SUCCESSFUL_KEY_VERIFICATION_TIMESTAMP
        )
        this.lastKeyVerificationPromptTimestamp =
            res.getLong(LAST_KEY_VERIFICATION_PROMPT_TIMESTAMP)
        this.successfulVerificationCount = res.getInt(SUCCESSFUL_VERIFICATION_COUNT)
        this.uploadedBackupVersion = res.getInt(UPLOADED_BACKUP_VERSION)
        if (res.wasNull()) {
            this.uploadedBackupVersion = null
        }
        this.exportedBackupVersion = res.getInt(EXPORTED_BACKUP_VERSION)
        if (res.wasNull()) {
            this.exportedBackupVersion = null
        }
        this.latestBackupVersion = res.getInt(LATEST_BACKUP_VERSION)
        if (res.wasNull()) {
            this.latestBackupVersion = null
        }
    }

    @Throws(SQLException::class)
    override fun insert() {
        backupManagerSession.session.prepareStatement(
            "BackupKey.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?, ?,?,?,?,?);"
        ).use { statement ->
            statement.setBytes(1, uid.bytes)
            statement.setBytes(2, Encoded.of(encryptionPublicKey).bytes)
            statement.setBytes(3, Encoded.of(macKey).bytes)
            statement.setLong(4, keyGenerationTimestamp)
            statement.setLong(5, lastSuccessfulKeyVerificationTimestamp)
            statement.setLong(6, lastKeyVerificationPromptTimestamp)
            statement.setInt(7, successfulVerificationCount)
            if (uploadedBackupVersion == null) {
                statement.setNull(8, Types.INTEGER)
            } else {
                statement.setInt(8, uploadedBackupVersion!!)
            }
            if (exportedBackupVersion == null) {
                statement.setNull(9, Types.INTEGER)
            } else {
                statement.setInt(9, exportedBackupVersion!!)
            }
            if (latestBackupVersion == null) {
                statement.setNull(10, Types.INTEGER)
            } else {
                statement.setInt(10, latestBackupVersion!!)
            }
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        backupManagerSession.session.prepareStatement(
            "BackupKey.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + UID_ + " = ?;"
        ).use { statement ->
            statement.setBytes(1, uid.bytes)
            statement.executeUpdate()
        }
    }

    // endregion
    // region setters
    @Throws(SQLException::class)
    fun addSuccessfulVerification() {
        backupManagerSession.session.prepareStatement(
            "BackupKey.addSuccessfulVerification",
            "UPDATE " + TABLE_NAME +
                    " SET " + SUCCESSFUL_VERIFICATION_COUNT + " = ?, " +
                    LAST_SUCCESSFUL_KEY_VERIFICATION_TIMESTAMP + " = ? " +
                    " WHERE " + UID_ + " = ?;"
        ).use { statement ->
            val timestamp = System.currentTimeMillis()
            statement.setInt(1, successfulVerificationCount + 1)
            statement.setLong(2, timestamp)
            statement.setBytes(3, uid.bytes)
            statement.executeUpdate()
            this.successfulVerificationCount++
            this.lastSuccessfulKeyVerificationTimestamp = timestamp
        }
    }


    @Throws(SQLException::class)
    fun setLastKeyVerificationPromptTimestamp() {
        backupManagerSession.session.prepareStatement(
            "BackupKey.setLastKeyVerificationPromptTimestamp",
            "UPDATE " + TABLE_NAME +
                    " SET " + LAST_KEY_VERIFICATION_PROMPT_TIMESTAMP + " = ? " +
                    " WHERE " + UID_ + " = ?;"
        ).use { statement ->
            val timestamp = System.currentTimeMillis()
            statement.setLong(1, timestamp)
            statement.setBytes(2, uid.bytes)
            statement.executeUpdate()
            this.lastKeyVerificationPromptTimestamp = timestamp
        }
    }

    @Throws(SQLException::class)
    fun setLatestBackupVersion(version: Int) {
        backupManagerSession.session.prepareStatement(
            "BackupKey.setLatestBackupVersion",
            "UPDATE " + TABLE_NAME +
                    " SET " + LATEST_BACKUP_VERSION + " = ? " +
                    " WHERE " + UID_ + " = ?;"
        ).use { statement ->
            statement.setInt(1, version)
            statement.setBytes(2, uid.bytes)
            statement.executeUpdate()
            this.latestBackupVersion = version
        }
    }

    @Throws(SQLException::class)
    fun setExportedBackupVersion(version: Int) {
        backupManagerSession.session.prepareStatement(
            "BackupKey.setExportedBackupVersion",
            "UPDATE " + TABLE_NAME +
                    " SET " + EXPORTED_BACKUP_VERSION + " = ? " +
                    " WHERE " + UID_ + " = ?;"
        ).use { statement ->
            statement.setInt(1, version)
            statement.setBytes(2, uid.bytes)
            statement.executeUpdate()
            this.exportedBackupVersion = version
        }
    }

    @Throws(SQLException::class)
    fun setUploadedBackupVersion(version: Int) {
        backupManagerSession.session.prepareStatement(
            "BackupKey.setUploadedBackupVersion",
            "UPDATE " + TABLE_NAME +
                    " SET " + UPLOADED_BACKUP_VERSION + " = ? " +
                    " WHERE " + UID_ + " = ?;"
        ).use { statement ->
            statement.setInt(1, version)
            statement.setBytes(2, uid.bytes)
            statement.executeUpdate()
            this.uploadedBackupVersion = version
        }
    }

    val uploadedBackup: Backup?
        get() {
            val v = uploadedBackupVersion ?: return null
            return Backup.get(backupManagerSession, uid, v)
        }

    val exportedBackup: Backup?
        get() {
            val v = exportedBackupVersion ?: return null
            return Backup.get(backupManagerSession, uid, v)
        }

    // endregion
    override fun wasCommitted() {
    }

    companion object {
        const val TABLE_NAME: String = "backup_key"

        const val UID_: String = "uid"
        const val ENCRYPTION_PUBLIC_KEY: String = "encryption_public_key"
        const val MAC_KEY: String = "mac_key"
        const val KEY_GENERATION_TIMESTAMP: String = "key_generation_timestamp"
        const val LAST_SUCCESSFUL_KEY_VERIFICATION_TIMESTAMP: String =
            "last_successful_key_verification_timestamp"
        const val LAST_KEY_VERIFICATION_PROMPT_TIMESTAMP: String =
            "last_key_verification_prompt_timestamp"
        const val SUCCESSFUL_VERIFICATION_COUNT: String = "successful_verification_count"
        const val UPLOADED_BACKUP_VERSION: String = "uploaded_backup_version"
        const val EXPORTED_BACKUP_VERSION: String = "exported_backup_version"
        const val LATEST_BACKUP_VERSION: String = "latest_backup_version"


        // region constructors
        fun create(
            backupManagerSession: BackupManagerSession?,
            uid: UID?,
            encryptionPublicKey: EncryptionPublicKey?,
            macKey: MACKey?
        ): BackupKey? {
            if (backupManagerSession == null || uid == null || encryptionPublicKey == null || macKey == null) {
                return null
            }
            try {
                val backupKey = BackupKey(
                    backupManagerSession,
                    uid,
                    encryptionPublicKey,
                    macKey,
                    System.currentTimeMillis(),
                    0L,
                    0L,
                    0,
                    null,
                    null,
                    null
                )
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
                            UID_ + " BLOB PRIMARY KEY, " +
                            ENCRYPTION_PUBLIC_KEY + " BLOB NOT NULL, " +
                            MAC_KEY + " BLOB NOT NULL, " +
                            KEY_GENERATION_TIMESTAMP + " INTEGER NOT NULL, " +
                            LAST_SUCCESSFUL_KEY_VERIFICATION_TIMESTAMP + " INTEGER NOT NULL, " +
                            LAST_KEY_VERIFICATION_PROMPT_TIMESTAMP + " INTEGER NOT NULL, " +
                            SUCCESSFUL_VERIFICATION_COUNT + " INTEGER NOT NULL, " +
                            UPLOADED_BACKUP_VERSION + " INTEGER, " +
                            EXPORTED_BACKUP_VERSION + " INTEGER, " +
                            LATEST_BACKUP_VERSION + " INTEGER, " +
                            "FOREIGN KEY (" + UID_ + "," + UPLOADED_BACKUP_VERSION + ") REFERENCES " + Backup.TABLE_NAME + " (" + Backup.BACKUP_KEY_UID + "," + Backup.VERSION + "), " +
                            "FOREIGN KEY (" + UID_ + "," + EXPORTED_BACKUP_VERSION + ") REFERENCES " + Backup.TABLE_NAME + " (" + Backup.BACKUP_KEY_UID + "," + Backup.VERSION + "), " +
                            "FOREIGN KEY (" + UID_ + "," + LATEST_BACKUP_VERSION + ") REFERENCES " + Backup.TABLE_NAME + " (" + Backup.BACKUP_KEY_UID + "," + Backup.VERSION + "));"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 36 && newVersion >= 36) {
                Logger.d("MIGRATING `backup_key` DATABASE FROM VERSION " + oldVersion + " TO 36")
                session.createStatement().use { statement ->
                    statement.execute(
                        "CREATE TABLE backup_key_new (" +
                                " uid BLOB PRIMARY KEY, " +
                                " encryption_public_key BLOB NOT NULL, " +
                                " mac_key BLOB NOT NULL, " +
                                " key_generation_timestamp INTEGER NOT NULL, " +
                                " last_successful_key_verification_timestamp INTEGER NOT NULL, " +
                                " last_key_verification_prompt_timestamp INTEGER NOT NULL, " +
                                " successful_verification_count INTEGER NOT NULL, " +
                                " uploaded_backup_version INTEGER, " +
                                " exported_backup_version INTEGER, " +
                                " latest_backup_version INTEGER, " +
                                "FOREIGN KEY (uid, uploaded_backup_version) REFERENCES backup (backup_key_uid, version), " +
                                "FOREIGN KEY (uid, exported_backup_version) REFERENCES backup (backup_key_uid, version), " +
                                "FOREIGN KEY (uid, latest_backup_version) REFERENCES backup (backup_key_uid, version));"
                    )
                    val res = statement.executeQuery("SELECT * FROM backup_key WHERE uid IS NULL")
                    if (res.next()) {
                        // we have a null primary key --> copy it partially to new table
                        session.prepareStatement("INSERT INTO backup_key_new VALUES (?,?,?,?,?, ?,?,?,?,?)")
                            .use { ps ->
                                ps.setBytes(
                                    1,
                                    UID(Suite.getDefaultPRNGService(Suite.LATEST_VERSION)).bytes
                                )
                                ps.setBytes(2, res.getBytes("encryption_public_key"))
                                ps.setBytes(3, res.getBytes("mac_key"))
                                ps.setLong(4, res.getLong("key_generation_timestamp"))
                                ps.setLong(
                                    5,
                                    res.getLong("last_successful_key_verification_timestamp")
                                )
                                ps.setLong(6, res.getLong("last_key_verification_prompt_timestamp"))
                                ps.setInt(7, res.getInt("successful_verification_count"))
                                ps.setNull(8, Types.INTEGER)
                                ps.setNull(9, Types.INTEGER)
                                ps.setNull(10, Types.INTEGER)
                                ps.executeUpdate()
                            }
                        // delete all existing backups (the backup_key_uid no longer exists)
                        statement.execute("DELETE FROM backup")
                    } else {
                        // no null primary key, simply copy the content of the old table to the new one
                        statement.execute("INSERT into backup_key_new (uid, encryption_public_key, mac_key, key_generation_timestamp, last_successful_key_verification_timestamp, last_key_verification_prompt_timestamp, successful_verification_count, uploaded_backup_version, exported_backup_version, latest_backup_version) SELECT uid, encryption_public_key, mac_key, key_generation_timestamp, last_successful_key_verification_timestamp, last_key_verification_prompt_timestamp, successful_verification_count, uploaded_backup_version, exported_backup_version, latest_backup_version FROM backup_key")
                    }
                    statement.execute("DROP TABLE backup_key")
                    statement.execute("ALTER TABLE backup_key_new RENAME TO backup_key")
                }
                oldVersion = 36
            }
        }

        // delete all BackupKey and all Backup
        @Throws(SQLException::class)
        fun deleteAll(backupManagerSession: BackupManagerSession) {
            backupManagerSession.session.prepareStatement(
                "BackupKey.deleteAll",
                "DELETE FROM " + TABLE_NAME + ";"
            ).use { statement ->
                statement.executeUpdate()
            }
            Backup.deleteAll(backupManagerSession)
        }

        // endregion
        // region getters
        fun get(backupManagerSession: BackupManagerSession, backupKeyUid: UID): BackupKey? {
            try {
                backupManagerSession.session.prepareStatement(
                    "BackupKey.get",
                    "SELECT * FROM " + TABLE_NAME + " WHERE " + UID_ + " = ?;"
                ).use { preparedStatement ->
                    preparedStatement.setBytes(1, backupKeyUid.bytes)
                    val res = preparedStatement.executeQuery()
                    return if (res.next()) {
                        BackupKey(backupManagerSession, res)
                    } else {
                        null
                    }
                }
            } catch (_: Exception) {
                return null
            }
        }

        fun getAll(backupManagerSession: BackupManagerSession): Array<BackupKey> {
            try {
                backupManagerSession.session.prepareStatement(
                    "BackupKey.getAll",
                    "SELECT * FROM " + TABLE_NAME + ";"
                ).use { preparedStatement ->
                    val res = preparedStatement.executeQuery()
                    val list: MutableList<BackupKey> = ArrayList()
                    while (res.next()) {
                        list.add(BackupKey(backupManagerSession, res))
                    }
                    return list.toTypedArray<BackupKey>()
                }
            } catch (_: Exception) {
                return emptyArray()
            }
        }
    }
}
