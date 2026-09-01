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
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.containers.IdentityWithSerializedDetails
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import java.sql.ResultSet
import java.sql.SQLException

class PendingGroupMember : ObvDatabase {
    private val identityManagerSession: IdentityManagerSession

    @JvmField val groupOwnerAndUid: ByteArray?
    private var ownedIdentity: Identity? = null
    private var contactIdentity: Identity? = null
    @JvmField val contactSerializedDetails: String
    @JvmField var declined: Boolean

    fun getOwnedIdentity(): Identity {
        return ownedIdentity!!
    }

    fun getContactIdentity(): Identity {
        return contactIdentity!!
    }

    fun isDeclined(): Boolean {
        return declined
    }

    constructor(
        identityManagerSession: IdentityManagerSession,
        groupOwnerAndUid: ByteArray,
        ownedIdentity: Identity,
        contactIdentity: Identity,
        contactSerializedDetails: String
    ) {
        this.identityManagerSession = identityManagerSession
        this.groupOwnerAndUid = groupOwnerAndUid
        this.ownedIdentity = ownedIdentity
        this.contactIdentity = contactIdentity
        this.contactSerializedDetails = contactSerializedDetails
        this.declined = false
    }

    private constructor(identityManagerSession: IdentityManagerSession, res: ResultSet) {
        this.identityManagerSession = identityManagerSession
        this.groupOwnerAndUid = res.getBytes(GROUP_OWNER_AND_UID)
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
            this.contactIdentity = Identity.of(res.getBytes(CONTACT_IDENTITY))
        } catch (_: DecodingException) {
            throw SQLException()
        }
        this.contactSerializedDetails = res.getString(CONTACT_SERIALIZED_DETAILS)
        this.declined = res.getBoolean(DECLINED)
    }

    @Throws(SQLException::class)
    override fun insert() {
        identityManagerSession.session.prepareStatement(
            "PendingGroupMember.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?);"
        ).use { statement ->
            statement.setBytes(1, groupOwnerAndUid)
            statement.setBytes(2, ownedIdentity!!.getBytes())
            statement.setBytes(3, contactIdentity!!.getBytes())
            statement.setString(4, contactSerializedDetails)
            statement.setBoolean(5, declined)
            statement.executeUpdate()
            commitHookBits = commitHookBits or HOOK_BIT_INSERTED
            identityManagerSession.session.addSessionCommitListener(this)
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        identityManagerSession.session.prepareStatement(
            "PendingGroupMember.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + GROUP_OWNER_AND_UID + " = ? AND " + OWNED_IDENTITY + " = ? AND " + CONTACT_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, groupOwnerAndUid)
            statement.setBytes(2, ownedIdentity!!.getBytes())
            statement.setBytes(3, contactIdentity!!.getBytes())
            statement.executeUpdate()
            commitHookBits = commitHookBits or HOOK_BIT_DELETED
            identityManagerSession.session.addSessionCommitListener(this)
        }
    }


    // endregion
    // region setters
    @Throws(SQLException::class)
    fun setDeclined(declined: Boolean) {
        identityManagerSession.session.prepareStatement(
            "PendingGroupMember.setDeclined",
            "UPDATE " + TABLE_NAME +
                    " SET " + DECLINED + " = ? " +
                    " WHERE " + GROUP_OWNER_AND_UID + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ? " +
                    " AND " + CONTACT_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBoolean(1, declined)
            statement.setBytes(2, this.groupOwnerAndUid)
            statement.setBytes(3, this.ownedIdentity!!.getBytes())
            statement.setBytes(4, this.contactIdentity!!.getBytes())
            statement.executeUpdate()
            this.declined = declined
        }
        commitHookBits = commitHookBits or HOOK_BIT_DECLINED_TOGGLED
        identityManagerSession.session.addSessionCommitListener(this)
    }


    // endregion
    // region hooks
    private var commitHookBits: Long = 0
    override fun wasCommitted() {
        if ((commitHookBits and HOOK_BIT_INSERTED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_ADDED_GROUP_UID_KEY,
                groupOwnerAndUid!!
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_ADDED_OWNED_IDENTITY_KEY,
                ownedIdentity!!
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_ADDED_CONTACT_IDENTITY_KEY,
                contactIdentity!!
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_ADDED_CONTACT_SERIALIZED_DETAILS_KEY,
                contactSerializedDetails
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_ADDED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_DELETED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_REMOVED_GROUP_UID_KEY,
                groupOwnerAndUid!!
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_REMOVED_OWNED_IDENTITY_KEY,
                ownedIdentity!!
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_REMOVED_CONTACT_IDENTITY_KEY,
                contactIdentity!!
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_REMOVED_CONTACT_SERIALIZED_DETAILS_KEY,
                contactSerializedDetails
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_REMOVED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_DECLINED_TOGGLED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_DECLINED_TOGGLED_GROUP_UID_KEY,
                groupOwnerAndUid!!
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_DECLINED_TOGGLED_OWNED_IDENTITY_KEY,
                ownedIdentity!!
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_DECLINED_TOGGLED_CONTACT_IDENTITY_KEY,
                contactIdentity!!
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_DECLINED_TOGGLED_DECLINED_KEY,
                declined
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_DECLINED_TOGGLED,
                userInfo
            )
        }
        commitHookBits = 0
    }

    private fun backup(): Pojo_0 {
        val pojo = Pojo_0()
        pojo.contact_identity = contactIdentity!!.getBytes()
        pojo.serialized_details = contactSerializedDetails
        pojo.declined = declined
        return pojo
    }

    class Pojo_0 {
        @JvmField var contact_identity: ByteArray? = null
        @JvmField var serialized_details: String? = null
        @JvmField var declined: Boolean = false
    } // endregion

    companion object {
        const val TABLE_NAME: String = "pending_group_member"

        const val GROUP_OWNER_AND_UID: String = "group_owner_and_uid"
        const val OWNED_IDENTITY: String = "owned_identity"
        const val CONTACT_IDENTITY: String = "contact_identity"
        const val CONTACT_SERIALIZED_DETAILS: String = "contact_display_name"
        const val DECLINED: String = "declined"

        // region constructors
        fun create(
            identityManagerSession: IdentityManagerSession,
            groupOwnerAndUid: ByteArray?,
            ownedIdentity: Identity?,
            contactIdentity: Identity?,
            contactSerializedDetails: String?
        ): PendingGroupMember? {
            if ((groupOwnerAndUid == null) || (ownedIdentity == null) || (contactIdentity == null) || (contactSerializedDetails == null)) {
                return null
            }
            try {
                val pendingGroupMember = PendingGroupMember(
                    identityManagerSession,
                    groupOwnerAndUid,
                    ownedIdentity,
                    contactIdentity,
                    contactSerializedDetails
                )
                pendingGroupMember.insert()
                return pendingGroupMember
            } catch (_: SQLException) {
                return null
            }
        }

        // endregion
        @Throws(SQLException::class)
        fun createTable(session: Session) {
            session.createStatement().use { statement ->
                statement.execute(
                    "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                            GROUP_OWNER_AND_UID + " BLOB NOT NULL, " +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            CONTACT_IDENTITY + " BLOB NOT NULL, " +
                            CONTACT_SERIALIZED_DETAILS + " TEXT NOT NULL, " +
                            DECLINED + " BIT NOT NULL, " +
                            "CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + GROUP_OWNER_AND_UID + ", " + OWNED_IDENTITY + ", " + CONTACT_IDENTITY + "), " +
                            "FOREIGN KEY (" + GROUP_OWNER_AND_UID + "," + OWNED_IDENTITY + ") REFERENCES " + ContactGroup.TABLE_NAME + "(" + ContactGroup.GROUP_OWNER_AND_UID + "," + ContactGroup.OWNED_IDENTITY + ") ON DELETE CASCADE);"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 11 && newVersion >= 11) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING pending_group_member DATABASE FROM VERSION " + oldVersion + " TO 11")
                    statement.execute("DROP TABLE pending_group_member")
                    statement.execute(
                        "CREATE TABLE pending_group_member (" +
                                "group_owner_and_uid BLOB NOT NULL, " +
                                "owned_identity BLOB NOT NULL, " +
                                "contact_identity BLOB NOT NULL, " +
                                "contact_display_name TEXT NOT NULL, " +
                                "declined BIT NOT NULL, " +
                                "CONSTRAINT PK_pending_group_member PRIMARY KEY(group_owner_and_uid, owned_identity, contact_identity), " +
                                "FOREIGN KEY (group_owner_and_uid,owned_identity) REFERENCES contact_group(group_owner_and_uid,owned_identity) ON DELETE CASCADE);"
                    )
                }
                oldVersion = 11
            }
            if (oldVersion < 12 && newVersion >= 12) {
                session.createStatement().use { statement ->
                    statement.execute(
                        "DELETE FROM pending_group_member AS p " +
                                " WHERE NOT EXISTS (" +
                                " SELECT 1 FROM contact_group " +
                                " WHERE group_owner_and_uid = p.group_owner_and_uid" +
                                " AND owned_identity = p.owned_identity" +
                                " )"
                    )
                }
                oldVersion = 12
            }
        }

        // endregion
        // region getters
        fun getPendingMembersInGroup(
            identityManagerSession: IdentityManagerSession,
            groupOwnerAndUid: ByteArray?,
            ownedIdentity: Identity?
        ): Array<IdentityWithSerializedDetails> {
            if ((groupOwnerAndUid == null) || (ownedIdentity == null)) {
                return emptyArray()
            }
            try {
                identityManagerSession.session.prepareStatement(
                    "PendingGroupMember.getPendingMembersInGroup",
                    "SELECT * FROM " + TABLE_NAME + " WHERE " + GROUP_OWNER_AND_UID + " = ? AND " + OWNED_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, groupOwnerAndUid)
                    statement.setBytes(2, ownedIdentity.getBytes())
                    statement.executeQuery().use { res ->
                        val list: MutableList<IdentityWithSerializedDetails> = ArrayList()
                        while (res.next()) {
                            val pendingGroupMember = PendingGroupMember(identityManagerSession, res)
                            list.add(
                                IdentityWithSerializedDetails(
                                    pendingGroupMember.contactIdentity!!,
                                    pendingGroupMember.contactSerializedDetails
                                )
                            )
                        }
                        return list.toTypedArray<IdentityWithSerializedDetails>()
                    }
                }
            } catch (_: SQLException) {
                return emptyArray()
            }
        }

        fun getDeclinedPendingMembersInGroup(
            identityManagerSession: IdentityManagerSession,
            groupOwnerAndUid: ByteArray?,
            ownedIdentity: Identity?
        ): Array<Identity> {
            if ((groupOwnerAndUid == null) || (ownedIdentity == null)) {
                return emptyArray()
            }
            try {
                identityManagerSession.session.prepareStatement(
                    "PendingGroupMember.getDeclinedPendingMembersInGroup",
                    "SELECT * FROM " + TABLE_NAME + " WHERE " + GROUP_OWNER_AND_UID + " = ? AND " + OWNED_IDENTITY + " = ? AND " + DECLINED + " = 1;"
                ).use { statement ->
                    statement.setBytes(1, groupOwnerAndUid)
                    statement.setBytes(2, ownedIdentity.getBytes())
                    statement.executeQuery().use { res ->
                        val list: MutableList<Identity> = ArrayList()
                        while (res.next()) {
                            val pendingGroupMember = PendingGroupMember(identityManagerSession, res)
                            list.add(pendingGroupMember.contactIdentity!!)
                        }
                        return list.toTypedArray<Identity>()
                    }
                }
            } catch (_: SQLException) {
                return emptyArray()
            }
        }

        @Throws(SQLException::class)
        fun get(
            identityManagerSession: IdentityManagerSession,
            groupUid: ByteArray?,
            ownedIdentity: Identity?,
            contactIdentity: Identity?
        ): PendingGroupMember? {
            if ((groupUid == null) || (ownedIdentity == null) || (contactIdentity == null)) {
                return null
            }
            identityManagerSession.session.prepareStatement(
                "PendingGroupMember.get",
                "SELECT * FROM " + TABLE_NAME + " WHERE " + GROUP_OWNER_AND_UID + " = ? AND " + OWNED_IDENTITY + " = ? AND " + CONTACT_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, groupUid)
                statement.setBytes(2, ownedIdentity.getBytes())
                statement.setBytes(3, contactIdentity.getBytes())
                statement.executeQuery().use { res ->
                    if (res.next()) {
                        return PendingGroupMember(identityManagerSession, res)
                    } else {
                        return null
                    }
                }
            }
        }

        fun getAllInGroup(
            identityManagerSession: IdentityManagerSession,
            groupOwnerAndUid: ByteArray?,
            ownedIdentity: Identity?
        ): Array<PendingGroupMember?> {
            if ((groupOwnerAndUid == null) || (ownedIdentity == null)) {
                return arrayOfNulls<PendingGroupMember>(0)
            }
            try {
                identityManagerSession.session.prepareStatement(
                    "PendingGroupMember.getAllInGroup",
                    "SELECT * FROM " + TABLE_NAME + " WHERE " + GROUP_OWNER_AND_UID + " = ? AND " + OWNED_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, groupOwnerAndUid)
                    statement.setBytes(2, ownedIdentity.getBytes())
                    statement.executeQuery().use { res ->
                        val list: MutableList<PendingGroupMember?> =
                            ArrayList<PendingGroupMember?>()
                        while (res.next()) {
                            val pendingGroupMember = PendingGroupMember(identityManagerSession, res)
                            list.add(pendingGroupMember)
                        }
                        return list.toTypedArray<PendingGroupMember?>()
                    }
                }
            } catch (_: SQLException) {
                return arrayOfNulls<PendingGroupMember>(0)
            }
        }

        fun getGroupOwnerAndUidOfGroupsWhereContactIsPending(
            identityManagerSession: IdentityManagerSession,
            contactIdentity: Identity?,
            ownedIdentity: Identity?,
            excludeDeclined: Boolean
        ): Array<ByteArray> {
            if ((ownedIdentity == null) || (contactIdentity == null)) {
                return emptyArray()
            }
            try {
                identityManagerSession.session.prepareStatement(
                    "PendingGroupMember.getGroupOwnerAndUidOfGroupsWhereContactIsPending",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + CONTACT_IDENTITY + " = ? " +
                            " AND " + OWNED_IDENTITY + " = ? " +
                            (if (excludeDeclined) (" AND " + DECLINED + " = 0 ") else "") +
                            " AND " + GROUP_OWNER_AND_UID +
                            " IN (SELECT " + ContactGroup.GROUP_OWNER_AND_UID + " FROM " + ContactGroup.TABLE_NAME + " WHERE " + ContactGroup.OWNED_IDENTITY + " = ? AND " + ContactGroup.GROUP_OWNER + " IS NULL);"
                ).use { statement ->
                    statement.setBytes(1, contactIdentity.getBytes())
                    statement.setBytes(2, ownedIdentity.getBytes())
                    statement.setBytes(3, ownedIdentity.getBytes())
                    statement.executeQuery().use { res ->
                        val list: MutableList<ByteArray> = ArrayList()
                        while (res.next()) {
                            val pendingGroupMember = PendingGroupMember(identityManagerSession, res)
                            list.add(pendingGroupMember.groupOwnerAndUid!!)
                        }
                        return list.toTypedArray<ByteArray>()
                    }
                }
            } catch (_: SQLException) {
                return emptyArray()
            }
        }


        private const val HOOK_BIT_INSERTED: Long = 0x1
        private const val HOOK_BIT_DELETED: Long = 0x2
        private const val HOOK_BIT_DECLINED_TOGGLED: Long = 0x4

        // endregion
        // region backup
        fun backupAll(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            groupOwnerAndUid: ByteArray?
        ): Array<Pojo_0?> {
            val pendingGroupMembers: Array<PendingGroupMember?> =
                getAllInGroup(identityManagerSession, groupOwnerAndUid, ownedIdentity)
            val pojos = arrayOfNulls<Pojo_0>(pendingGroupMembers.size)
            for (i in pendingGroupMembers.indices) {
                pojos[i] = pendingGroupMembers[i]!!.backup()
            }
            return pojos
        }

        @Throws(SQLException::class)
        fun restoreAll(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            groupOwnerAndUid: ByteArray,
            pojos: Array<Pojo_0>?
        ) {
            if (pojos == null) {
                return
            }
            for (pojo in pojos) {
                restore(identityManagerSession, ownedIdentity, groupOwnerAndUid, pojo)
            }
        }

        @Throws(SQLException::class)
        fun restore(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            groupOwnerAndUid: ByteArray,
            pojo: Pojo_0
        ) {
            try {
                val pendingGroupMember = PendingGroupMember(
                    identityManagerSession,
                    groupOwnerAndUid,
                    ownedIdentity,
                    Identity.of(pojo.contact_identity!!),
                    pojo.serialized_details!!
                )
                pendingGroupMember.declined = pojo.declined
                pendingGroupMember.insert()
            } catch (e: DecodingException) {
                Logger.x(e)
            }
        }
    }
}
