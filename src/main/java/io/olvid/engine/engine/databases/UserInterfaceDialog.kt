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
package io.olvid.engine.engine.databases

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.datatypes.EngineSession
import io.olvid.engine.engine.types.ObvDialog
import java.sql.ResultSet
import java.sql.SQLException
import java.util.UUID

class UserInterfaceDialog : ObvDatabase {
    private val engineSession: EngineSession

    private val uuid: UUID
    private var encodedDialog: Encoded
    private var creationTimestamp: Long
    fun getUuid(): UUID {
        return uuid
    }

    fun getCreationTimestamp(): Long {
        return creationTimestamp
    }

    fun resend() {
        try {
            sendNotification()
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    fun update(encodedDialog: Encoded) {
        try {
            engineSession.session.prepareStatement(
                "UserInterfaceDialog.update",
                "UPDATE " + TABLE_NAME + " SET " +
                        ENCODED_DIALOG + " = ?, " +
                        CREATION_TIMESTAMP + " = ? " +
                        " WHERE " + UUID_ + " = ?;"
            ).use { statement ->
                val timestamp = System.currentTimeMillis()
                statement.setBytes(1, encodedDialog.bytes)
                statement.setLong(2, timestamp)
                statement.setString(3, Logger.getUuidString(uuid))
                statement.executeUpdate()
                this.encodedDialog = encodedDialog
                this.creationTimestamp = timestamp
                this.commitHookBits = this.commitHookBits or HOOK_BIT_SHOULD_SEND_NOTIFICATION
                engineSession.session.addSessionCommitListener(this)
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }


    private constructor(engineSession: EngineSession, uuid: UUID, encodedDialog: Encoded) {
        this.engineSession = engineSession

        this.uuid = uuid
        this.encodedDialog = encodedDialog
        this.creationTimestamp = System.currentTimeMillis()
    }

    private constructor(engineSession: EngineSession, res: ResultSet) {
        this.engineSession = engineSession

        this.uuid = UUID.fromString(res.getString(UUID_))
        this.encodedDialog = Encoded(res.getBytes(ENCODED_DIALOG))
        this.creationTimestamp = res.getLong(CREATION_TIMESTAMP)
    }


    @Throws(SQLException::class)
    override fun insert() {
        engineSession.session.prepareStatement(
            "UserInterfaceDialog.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?);"
        ).use { statement ->
            statement.setString(1, Logger.getUuidString(uuid))
            statement.setBytes(2, encodedDialog.bytes)
            statement.setLong(3, creationTimestamp)
            statement.executeUpdate()
            this.commitHookBits = this.commitHookBits or HOOK_BIT_SHOULD_SEND_NOTIFICATION
            engineSession.session.addSessionCommitListener(this)
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        engineSession.session.prepareStatement(
            "UserInterfaceDialog.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + UUID_ + " = ?;"
        ).use { statement ->
            statement.setString(1, Logger.getUuidString(uuid))
            statement.executeUpdate()
            this.commitHookBits = this.commitHookBits or HOOK_BIT_DELETED
            engineSession.session.addSessionCommitListener(this)
        }
    }


    @Throws(Exception::class)
    fun sendNotification() {
        engineSession.userInterfaceDialogListener!!.sendUserInterfaceDialogNotification(
            uuid,
            getObvDialog(),
            creationTimestamp
        )
    }

    @Throws(Exception::class)
    fun getObvDialog(): ObvDialog {
        // stamp the dialog version with the (strictly incrementing) creationTimestamp, so that a
        // response can later be matched against the dialog it was actually answering
        val decoded = ObvDialog.of(encodedDialog, engineSession.jsonObjectMapper)
        return ObvDialog(
            decoded.uuid,
            decoded.encodedElements,
            decoded.bytesOwnedIdentity,
            decoded.category,
            creationTimestamp
        )
    }


    private var commitHookBits: Long = 0
    override fun wasCommitted() {
        if ((commitHookBits and HOOK_BIT_SHOULD_SEND_NOTIFICATION) != 0L) {
            if (engineSession.userInterfaceDialogListener != null) {
                try {
                    sendNotification()
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }
        }
        if ((commitHookBits and HOOK_BIT_DELETED) != 0L) {
            if (engineSession.userInterfaceDialogListener != null) {
                try {
                    engineSession.userInterfaceDialogListener.sendUserInterfaceDialogDeletionNotification(
                        uuid
                    )
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }
        }
        commitHookBits = 0
    }

    companion object {
        const val TABLE_NAME: String = "user_interface_dialog"

        const val UUID_: String = "uuid"
        const val ENCODED_DIALOG: String = "encoded_dialog"
        const val CREATION_TIMESTAMP: String = "creation_timestamp"

        fun createOrReplace(
            engineSession: EngineSession,
            dialog: ObvDialog?
        ): UserInterfaceDialog? {
            if (dialog == null) {
                return null
            }
            try {
                val previousUserInterfaceDialog: UserInterfaceDialog? =
                    get(engineSession, dialog.getUuid())
                if (previousUserInterfaceDialog != null) {
                    previousUserInterfaceDialog.update(dialog.encode(engineSession.jsonObjectMapper!!))
                    return previousUserInterfaceDialog
                } else {
                    val userInterfaceDialog = UserInterfaceDialog(
                        engineSession,
                        dialog.getUuid(),
                        dialog.encode(engineSession.jsonObjectMapper!!)
                    )
                    userInterfaceDialog.insert()
                    return userInterfaceDialog
                }
            } catch (e: SQLException) {
                Logger.x(e)
                return null
            }
        }

        @Throws(SQLException::class)
        fun createTable(session: Session) {
            session.createStatement().use { statement ->
                statement.execute(
                    "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                            UUID_ + " VARCHAR PRIMARY KEY, " +
                            ENCODED_DIALOG + " BLOB NOT NULL, " +
                            CREATION_TIMESTAMP + " BIGINT NOT NULL);"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 8 && newVersion >= 8) {
                session.createStatement().use { statement ->
                    statement.execute("DELETE FROM user_interface_dialog")
                }
                oldVersion = 8
            }
            if (oldVersion < 11 && newVersion >= 11) {
                session.createStatement().use { statement ->
                    statement.execute("DELETE FROM user_interface_dialog")
                }
                oldVersion = 11
            }
            if (oldVersion < 28 && newVersion >= 28) {
                Logger.d("MIGRATING `user_interface_dialog` TABLE FROM VERSION " + oldVersion + " TO 28")
                session.createStatement().use { statement ->
                    val dialogUuids: MutableList<String?> = ArrayList()
                    statement.executeQuery("SELECT * FROM user_interface_dialog").use { res ->
                        while (res.next()) {
                            val encodedDialog = Encoded(res.getBytes("encoded_dialog"))
                            try {
                                val encodedCategory = encodedDialog.decodeList()[3]
                                val id = encodedCategory.decodeList()[0].decodeLong().toInt()
                                if (id == 9 || id == 10 || id == 11 || id == 12) {
                                    dialogUuids.add(res.getString("uuid"))
                                }
                            } catch (_: Exception) { }
                        }
                    }
                    for (uuid in dialogUuids) {
                        statement.execute("DELETE FROM user_interface_dialog WHERE uuid = '" + uuid + "'")
                    }
                }
                oldVersion = 28
            }
        }

        fun get(engineSession: EngineSession, uuid: UUID?): UserInterfaceDialog? {
            if (uuid == null) {
                return null
            }
            try {
                engineSession.session.prepareStatement(
                    "UserInterfaceDialog.get",
                    "SELECT * FROM " + TABLE_NAME + " WHERE " + UUID_ + " = ?;"
                ).use { statement ->
                    statement.setString(1, Logger.getUuidString(uuid))
                    statement.executeQuery().use { res ->
                        return if (res.next()) {
                            UserInterfaceDialog(engineSession, res)
                        } else {
                            null
                        }
                    }
                }
            } catch (_: SQLException) {
                return null
            }
        }

        fun getAll(engineSession: EngineSession): Array<UserInterfaceDialog> {
            try {
                engineSession.session.prepareStatement(
                    "UserInterfaceDialog.getAll",
                    "SELECT * FROM " + TABLE_NAME + ";"
                ).use { statement ->
                    statement.executeQuery().use { res ->
                        val list: MutableList<UserInterfaceDialog> =
                            ArrayList()
                        while (res.next()) {
                            list.add(UserInterfaceDialog(engineSession, res))
                        }
                        return list.toTypedArray<UserInterfaceDialog>()
                    }
                }
            } catch (e: SQLException) {
                Logger.x(e)
                return emptyArray()
            }
        }


        private const val HOOK_BIT_SHOULD_SEND_NOTIFICATION: Long = 0x1
        private const val HOOK_BIT_DELETED: Long = 0x2
    }
}
