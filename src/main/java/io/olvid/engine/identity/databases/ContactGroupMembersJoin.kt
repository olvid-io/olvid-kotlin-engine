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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import java.sql.ResultSet
import java.sql.SQLException

class ContactGroupMembersJoin : ObvDatabase {
    private val identityManagerSession: IdentityManagerSession

    private val groupOwnerAndUid: ByteArray
    private var ownedIdentity: Identity
    private var contactIdentity: Identity

    private constructor(
        identityManagerSession: IdentityManagerSession,
        groupOwnerAndUid: ByteArray,
        ownedIdentity: Identity,
        contactIdentity: Identity
    ) {
        this.identityManagerSession = identityManagerSession
        this.groupOwnerAndUid = groupOwnerAndUid
        this.ownedIdentity = ownedIdentity
        this.contactIdentity = contactIdentity
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
    }


    @Throws(SQLException::class)
    override fun insert() {
        identityManagerSession.session.prepareStatement(
            "ContactGroupMembersJoin.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?);"
        ).use { statement ->
            statement.setBytes(1, groupOwnerAndUid)
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.setBytes(3, contactIdentity.getBytes())
            statement.executeUpdate()
            commitHookBits = commitHookBits or HOOK_BIT_INSERTED
            identityManagerSession.session.addSessionCommitListener(this)
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        identityManagerSession.session.prepareStatement(
            "ContactGroupMembersJoin.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + GROUP_OWNER_AND_UID + " = ? AND " + OWNED_IDENTITY + " = ? AND " + CONTACT_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, groupOwnerAndUid)
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.setBytes(3, contactIdentity.getBytes())
            statement.executeUpdate()
            commitHookBits = commitHookBits or HOOK_BIT_DELETED
            identityManagerSession.session.addSessionCommitListener(this)
        }
    }


    // endregion
    // region hooks
    private var commitHookBits: Long = 0
    override fun wasCommitted() {
        if ((commitHookBits and HOOK_BIT_INSERTED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo[IdentityNotifications.NOTIFICATION_GROUP_MEMBER_ADDED_GROUP_OWNER_AND_UID_KEY] =
                groupOwnerAndUid
            userInfo[IdentityNotifications.NOTIFICATION_GROUP_MEMBER_ADDED_OWNED_IDENTITY_KEY] =
                ownedIdentity
            userInfo[IdentityNotifications.NOTIFICATION_GROUP_MEMBER_ADDED_CONTACT_IDENTITY_KEY] =
                contactIdentity
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_GROUP_MEMBER_ADDED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_DELETED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo[IdentityNotifications.NOTIFICATION_GROUP_MEMBER_REMOVED_GROUP_UID_KEY] =
                groupOwnerAndUid
            userInfo[IdentityNotifications.NOTIFICATION_GROUP_MEMBER_REMOVED_OWNED_IDENTITY_KEY] =
                ownedIdentity
            userInfo[IdentityNotifications.NOTIFICATION_GROUP_MEMBER_REMOVED_CONTACT_IDENTITY_KEY] =
                contactIdentity
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_GROUP_MEMBER_REMOVED,
                userInfo
            )
        }
        commitHookBits = 0
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class Pojo_0 {
        @JvmField var contact_identity: ByteArray? = null
    } // endregion

    companion object {
        const val TABLE_NAME: String = "contact_group_members_join"

        const val GROUP_OWNER_AND_UID: String = "group_owner_and_uid"
        const val OWNED_IDENTITY: String = "owned_identity"
        const val CONTACT_IDENTITY: String = "contact_identity"

        // region constructors
        fun create(
            identityManagerSession: IdentityManagerSession,
            groupOwnerAndUid: ByteArray?,
            ownedIdentity: Identity?,
            contactIdentity: Identity?
        ): ContactGroupMembersJoin? {
            if ((groupOwnerAndUid == null) || (ownedIdentity == null) || (contactIdentity == null)) {
                return null
            }
            try {
                val contactGroupMembersJoin = ContactGroupMembersJoin(
                    identityManagerSession,
                    groupOwnerAndUid,
                    ownedIdentity,
                    contactIdentity
                )
                contactGroupMembersJoin.insert()
                return contactGroupMembersJoin
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
                            GROUP_OWNER_AND_UID + " BLOB NOT NULL, " +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            CONTACT_IDENTITY + " BLOB NOT NULL, " +
                            " CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + GROUP_OWNER_AND_UID + ", " + OWNED_IDENTITY + ", " + CONTACT_IDENTITY + "), " +
                            " FOREIGN KEY (" + GROUP_OWNER_AND_UID + "," + OWNED_IDENTITY + ") REFERENCES " + ContactGroup.TABLE_NAME + "(" + ContactGroup.GROUP_OWNER_AND_UID + "," + ContactGroup.OWNED_IDENTITY + ") ON DELETE CASCADE, " +
                            " FOREIGN KEY (" + CONTACT_IDENTITY + "," + OWNED_IDENTITY + ") REFERENCES " + ContactIdentity.TABLE_NAME + "(" + ContactIdentity.CONTACT_IDENTITY + "," + ContactIdentity.OWNED_IDENTITY + ") ON DELETE CASCADE);"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 11 && newVersion >= 11) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING contact_group_members_join DATABASE FROM VERSION " + oldVersion + " TO 11")
                    statement.execute("ALTER TABLE contact_group_members_join RENAME TO old_contact_group_members_join")
                    statement.execute(
                        "CREATE TABLE contact_group_members_join (" +
                                " group_owner_and_uid BLOB NOT NULL, " +
                                " owned_identity BLOB NOT NULL, " +
                                " contact_identity BLOB NOT NULL, " +
                                " CONSTRAINT PK_contact_group_members_join PRIMARY KEY(group_owner_and_uid, owned_identity, contact_identity), " +
                                " FOREIGN KEY (group_owner_and_uid,owned_identity) REFERENCES contact_group(group_owner_and_uid,owned_identity) ON DELETE CASCADE, " +
                                " FOREIGN KEY (contact_identity,owned_identity) REFERENCES contact_identity(identity,owned_identity) ON DELETE CASCADE);"
                    )
                    statement.executeQuery("SELECT * FROM old_contact_group_members_join")
                        .use { res ->
                            while (res.next()) {
                                session.prepareStatement("INSERT INTO contact_group_members_join VALUES (?,?,?)")
                                    .use { preparedStatement ->
                                        preparedStatement.setBytes(1, res.getBytes(1))
                                        preparedStatement.setBytes(2, res.getBytes(2))
                                        preparedStatement.setBytes(3, res.getBytes(3))
                                        preparedStatement.executeUpdate()
                                    }
                            }
                        }
                    statement.execute("DROP TABLE old_contact_group_members_join")
                }
                oldVersion = 11
            }
            if (oldVersion < 12 && newVersion >= 12) {
                session.createStatement().use { statement ->
                    statement.execute(
                        "DELETE FROM contact_group_members_join AS p " +
                                " WHERE NOT EXISTS (" +
                                " SELECT 1 FROM contact_group " +
                                " WHERE group_owner_and_uid = p.group_owner_and_uid" +
                                " AND owned_identity = p.owned_identity" +
                                " )"
                    )
                    statement.execute(
                        "DELETE FROM contact_group_members_join AS p " +
                                " WHERE NOT EXISTS (" +
                                " SELECT 1 FROM contact_identity " +
                                " WHERE identity = p.contact_identity" +
                                " AND owned_identity = p.owned_identity" +
                                " )"
                    )
                }
                oldVersion = 12
            }
        }

        // endregion
        // region getters
        @Throws(SQLException::class)
        fun get(
            identityManagerSession: IdentityManagerSession,
            groupOwnerAndUid: ByteArray?,
            ownedIdentity: Identity,
            contactIdentity: Identity
        ): ContactGroupMembersJoin? {
            identityManagerSession.session.prepareStatement(
                "ContactGroupMembersJoin.get",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + GROUP_OWNER_AND_UID + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ? " +
                        " AND " + CONTACT_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, groupOwnerAndUid)
                statement.setBytes(2, ownedIdentity.getBytes())
                statement.setBytes(3, contactIdentity.getBytes())
                statement.executeQuery().use { res ->
                    return if (res.next()) {
                        ContactGroupMembersJoin(identityManagerSession, res)
                    } else {
                        null
                    }
                }
            }
        }


        fun getContactIdentitiesInGroup(
            identityManagerSession: IdentityManagerSession,
            groupOwnerAndUid: ByteArray?,
            ownedIdentity: Identity
        ): Array<Identity> {
            try {
                identityManagerSession.session.prepareStatement(
                    "ContactGroupMembersJoin.getContactIdentitiesInGroup",
                    "SELECT contact." + ContactIdentity.CONTACT_IDENTITY + " FROM " + TABLE_NAME + " AS joiin " +
                            " INNER JOIN " + ContactIdentity.TABLE_NAME + " AS contact " +
                            " ON contact." + ContactIdentity.CONTACT_IDENTITY + " = joiin." + CONTACT_IDENTITY +
                            " AND contact." + ContactIdentity.OWNED_IDENTITY + " = joiin." + OWNED_IDENTITY +
                            " WHERE joiin." + GROUP_OWNER_AND_UID + " = ? AND joiin." + OWNED_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, groupOwnerAndUid)
                    statement.setBytes(2, ownedIdentity.getBytes())
                    statement.executeQuery().use { res ->
                        val list: MutableList<Identity> = ArrayList()
                        while (res.next()) {
                            try {
                                list.add(Identity.of(res.getBytes(1)))
                            } catch (e: DecodingException) {
                                Logger.x(e)
                            }
                        }
                        return list.toTypedArray<Identity>()
                    }
                }
            } catch (e: SQLException) {
                Logger.x(e)
                return emptyArray()
            }
        }

        @Throws(SQLException::class)
        fun getGroupOwnerAndUidsOfGroupsContainingContact(
            identityManagerSession: IdentityManagerSession,
            contactIdentity: Identity,
            ownedIdentity: Identity
        ): Array<ByteArray> {
            identityManagerSession.session.prepareStatement(
                "ContactGroupMembersJoin.getGroupOwnerAndUidsOfGroupsContainingContact",
                "SELECT * FROM " + TABLE_NAME + " WHERE " + CONTACT_IDENTITY + " = ? AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, contactIdentity.getBytes())
                statement.setBytes(2, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    val list: MutableList<ByteArray> = ArrayList()
                    while (res.next()) {
                        val contactGroupMembersJoin =
                            ContactGroupMembersJoin(identityManagerSession, res)
                        list.add(contactGroupMembersJoin.groupOwnerAndUid)
                    }
                    return list.toTypedArray<ByteArray>()
                }
            }
        }


        private const val HOOK_BIT_INSERTED: Long = 0x1
        private const val HOOK_BIT_DELETED: Long = 0x2

        // endregion
        // region backup
        fun backupAll(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            groupOwnerAndUid: ByteArray?
        ): Array<Pojo_0?> {
            val contactIdentities: Array<Identity> =
                getContactIdentitiesInGroup(identityManagerSession, groupOwnerAndUid, ownedIdentity)
            val pojos = arrayOfNulls<Pojo_0>(contactIdentities.size)
            for (i in contactIdentities.indices) {
                pojos[i] = Pojo_0()
                pojos[i]!!.contact_identity = contactIdentities[i].getBytes()
            }
            return pojos
        }

        fun restoreAll(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            groupOwnerAndUid: ByteArray?,
            pojos: Array<Pojo_0>?
        ) {
            if (pojos == null) {
                return
            }
            try {
                for (pojo in pojos) {
                    create(
                        identityManagerSession,
                        groupOwnerAndUid,
                        ownedIdentity,
                        Identity.of(pojo.contact_identity!!)
                    )
                }
            } catch (e: DecodingException) {
                Logger.x(e)
            }
        }
    }
}
