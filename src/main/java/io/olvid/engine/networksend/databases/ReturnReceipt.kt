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
package io.olvid.engine.networksend.databases

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networksend.datatypes.SendManagerSession
import java.sql.ResultSet
import java.sql.SQLException
import java.sql.Types

class ReturnReceipt : ObvDatabase {
    private val sendManagerSession: SendManagerSession?


    var id: Long = 0 // Autoincrement primary key
        private set
    private var ownedIdentity: Identity? = null
    private var contactIdentity: Identity? = null
    var contactDeviceUids: Array<UID?>? = null
        private set
    @JvmField val status: Int
    @JvmField val nonce: ByteArray?
    var key: AuthEncKey? = null
        private set
    var attachmentNumber: Int?
        private set
    val creationTimestamp: Long

    fun getOwnedIdentity(): Identity {
        return ownedIdentity!!
    }

    fun getContactIdentity(): Identity {
        return contactIdentity!!
    }

    constructor(
        sendManagerSession: SendManagerSession?,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        contactDeviceUids: Array<UID?>?,
        status: Int,
        nonce: ByteArray?,
        key: AuthEncKey?,
        attachmentNumber: Int?
    ) {
        this.sendManagerSession = sendManagerSession
        this.ownedIdentity = ownedIdentity
        this.contactIdentity = contactIdentity
        this.contactDeviceUids = contactDeviceUids
        this.status = status
        this.nonce = nonce
        this.key = key
        this.attachmentNumber = attachmentNumber
        this.creationTimestamp = System.currentTimeMillis()
    }

    private constructor(sendManagerSession: SendManagerSession, res: ResultSet) {
        this.sendManagerSession = sendManagerSession
        this.id = res.getLong(ID)
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
            this.contactIdentity = Identity.of(res.getBytes(CONTACT_IDENTITY))
            this.key = Encoded(res.getBytes(KEY)).decodeSymmetricKey() as AuthEncKey?
            this.contactDeviceUids = Encoded(res.getBytes(CONTACT_DEVICE_UIDS)).decodeUidArray()
        } catch (e: DecodingException) {
            Logger.x(e)
        } catch (e: ClassCastException) {
            Logger.x(e)
        }
        this.status = res.getInt(STATUS)
        this.nonce = res.getBytes(NONCE)
        this.attachmentNumber = res.getInt(ATTACHMENT_NUMBER)
        if (res.wasNull()) {
            this.attachmentNumber = null
        }
        this.creationTimestamp = res.getLong(CREATION_TIMESTAMP)
    }


    @Throws(SQLException::class)
    override fun insert() {
        sendManagerSession!!.session.prepareStatement(
            "ReturnReceipt.insert",
            "INSERT INTO " + TABLE_NAME +
                    "(" + OWNED_IDENTITY + ", " +
                    CONTACT_IDENTITY + ", " +
                    CONTACT_DEVICE_UIDS + ", " +
                    STATUS + ", " +
                    NONCE + ", " +
                    KEY + ", " +
                    ATTACHMENT_NUMBER + ", " +
                    CREATION_TIMESTAMP + ") VALUES (?,?,?,?,?, ?,?,?);",
            true
        ).use { statement ->
            statement.setBytes(1, ownedIdentity!!.getBytes())
            statement.setBytes(2, contactIdentity!!.getBytes())
            statement.setBytes(3, Encoded.of(contactDeviceUids!!).bytes)
            statement.setInt(4, status)
            statement.setBytes(5, nonce)
            statement.setBytes(6, Encoded.of(key!!).bytes)
            if (attachmentNumber != null) {
                statement.setInt(7, attachmentNumber!!)
            } else {
                statement.setNull(7, Types.INTEGER)
            }
            statement.setLong(8, creationTimestamp)
            statement.executeUpdate()
            statement.getGeneratedKeys().use { res ->
                if (res.next()) {
                    id = res.getLong(1)
                    this.commitHookBits = this.commitHookBits or HOOK_BIT_INSERT
                    sendManagerSession.session.addSessionCommitListener(this)
                }
            }
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        sendManagerSession!!.session.prepareStatement(
            "ReturnReceipt.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + ID + " = ?;"
        ).use { statement ->
            statement.setLong(1, id)
            statement.executeUpdate()
        }
    }

    // region hooks
    fun interface NewReturnReceiptListener {
        fun newReturnReceipt(server: String?, ownedIdentity: Identity?, returnReceiptId: Long)
    }

    private var commitHookBits: Long = 0
    override fun wasCommitted() {
        if ((commitHookBits and HOOK_BIT_INSERT) != 0L) {
            if (sendManagerSession?.newReturnReceiptListener != null) {
                sendManagerSession.newReturnReceiptListener.newReturnReceipt(
                    contactIdentity!!.server,
                    ownedIdentity,
                    id
                )
            }
        }
    } // endregion

    companion object {
        const val TABLE_NAME: String = "return_receipt"

        const val ID: String = "id"
        const val OWNED_IDENTITY: String = "owned_identity"
        const val CONTACT_IDENTITY: String = "contact_identity"
        const val CONTACT_DEVICE_UIDS: String = "contact_device_uids"
        const val STATUS: String = "status"
        const val NONCE: String = "nonce"
        const val KEY: String = "key"
        const val ATTACHMENT_NUMBER: String = "attachment_number"
        const val CREATION_TIMESTAMP: String = "creation_timestamp"


        fun create(
            sendManagerSession: SendManagerSession?,
            ownedIdentity: Identity?,
            contactIdentity: Identity?,
            contactDeviceUids: Array<UID?>?,
            status: Int,
            nonce: ByteArray?,
            key: AuthEncKey?,
            attachmentNumber: Int?
        ): ReturnReceipt? {
            if ((ownedIdentity == null) || (contactIdentity == null) || (nonce == null) || (key == null)) {
                return null
            }
            try {
                val returnReceipt = ReturnReceipt(
                    sendManagerSession,
                    ownedIdentity,
                    contactIdentity,
                    contactDeviceUids,
                    status,
                    nonce,
                    key,
                    attachmentNumber
                )
                returnReceipt.insert()
                return returnReceipt
            } catch (e: SQLException) {
                Logger.x(e)
                return null
            }
        }

        @Throws(SQLException::class)
        fun get(sendManagerSession: SendManagerSession, returnReceiptId: Long): ReturnReceipt? {
            sendManagerSession.session.prepareStatement(
                "ReturnReceipt.get",
                "SELECT * FROM " + TABLE_NAME + " WHERE " + ID + " = ?;"
            ).use { statement ->
                statement.setLong(1, returnReceiptId)
                statement.executeQuery().use { res ->
                    if (res.next()) {
                        return ReturnReceipt(sendManagerSession, res)
                    } else {
                        return null
                    }
                }
            }
        }


        @Throws(SQLException::class)
        fun getMany(
            sendManagerSession: SendManagerSession,
            ids: Array<Long?>?
        ): Array<ReturnReceipt?>? {
            if (ids == null) {
                return null
            }

            // build a ?,? string
            var count = ids.size
            val sb = StringBuilder(count * 2)
            while (count-- > 1) {
                sb.append("?,")
            }
            sb.append("?")

            sendManagerSession.session.prepareStatement(
                "ReturnReceipt.getMany",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + ID + " IN (" + sb + ");"
            ).use { statement ->
                for (i in ids.indices) {
                    statement.setLong(i + 1, ids[i]!!)
                }
                statement.executeQuery().use { res ->
                    val list: MutableList<ReturnReceipt?> = ArrayList<ReturnReceipt?>()
                    while (res.next()) {
                        list.add(ReturnReceipt(sendManagerSession, res))
                    }
                    return list.toTypedArray<ReturnReceipt?>()
                }
            }
        }


        @Throws(SQLException::class)
        fun getAll(sendManagerSession: SendManagerSession): Array<ReturnReceipt?> {
            sendManagerSession.session.prepareStatement(
                "ReturnReceipt.getAll",
                "SELECT * FROM " + TABLE_NAME + ";"
            ).use { statement ->
                statement.executeQuery().use { res ->
                    val list: MutableList<ReturnReceipt?> = ArrayList<ReturnReceipt?>()
                    while (res.next()) {
                        list.add(ReturnReceipt(sendManagerSession, res))
                    }
                    return list.toTypedArray<ReturnReceipt?>()
                }
            }
        }

        @Throws(SQLException::class)
        fun deleteAllForOwnedIdentity(
            sendManagerSession: SendManagerSession,
            ownedIdentity: Identity
        ) {
            sendManagerSession.session.prepareStatement(
                "ReturnReceipt.deleteAllForOwnedIdentity",
                "DELETE FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeUpdate()
            }
        }


        @Throws(SQLException::class)
        fun createTable(session: Session) {
            session.createStatement().use { statement ->
                statement.execute(
                    "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                            ID + " INTEGER PRIMARY KEY, " +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            CONTACT_IDENTITY + " BLOB NOT NULL, " +
                            CONTACT_DEVICE_UIDS + " BLOB NOT NULL, " +
                            STATUS + " INTEGER NOT NULL, " +
                            NONCE + " BLOB NOT NULL, " +
                            KEY + " BLOB NOT NULL, " +
                            ATTACHMENT_NUMBER + " INTEGER, " +
                            CREATION_TIMESTAMP + " BIGINT NOT NULL);"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 26 && newVersion >= 26) {
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE return_receipt ADD COLUMN attachment_number INTEGER DEFAULT NULL")
                }
                oldVersion = 26
            }
            if (oldVersion < 51 && newVersion >= 51) {
                Logger.d("MIGRATING `return_receipt` DATABASE FROM VERSION $oldVersion TO 51")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE return_receipt ADD COLUMN creation_timestamp BIGINT NOT NULL DEFAULT 0")
                }
                // set the creation timestamp of pre-existing return receipts to now, so they expire 60 days from the migration
                session.prepareStatement("UPDATE return_receipt SET creation_timestamp = ?").use { preparedStatement ->
                    preparedStatement.setLong(1, System.currentTimeMillis())
                    preparedStatement.executeUpdate()
                }
                oldVersion = 51
            }
        }

        private const val HOOK_BIT_INSERT: Long = 0x1
    }
}
