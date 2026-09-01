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
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.containers.GroupV2.Permission.Companion.deserializePermissions
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.engine.types.JsonIdentityDetails
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import java.nio.charset.StandardCharsets
import java.sql.ResultSet
import java.sql.SQLException
import java.util.Arrays
import net.iharder.Base64

class ContactGroupV2PendingMember : ObvDatabase {
    private val identityManagerSession: IdentityManagerSession

    private val groupUid: UID
    private val serverUrl: String?
    private val category: Int
    private val ownedIdentity: Identity
    @JvmField val contactIdentity: Identity
    private val serializedContactDetails: String
    @JvmField val serializedPermissions: ByteArray // permission strings separated by 0x00 bytes --> allows storing future permissions
    private val groupInvitationNonce: ByteArray?

    fun getSerializedContactDetails(): String {
        return serializedContactDetails
    }

    fun getGroupInvitationNonce(): ByteArray? {
        return groupInvitationNonce
    }


    private constructor(
        identityManagerSession: IdentityManagerSession,
        groupUid: UID,
        serverUrl: String?,
        category: Int,
        ownedIdentity: Identity,
        contactIdentity: Identity,
        serializedContactDetails: String,
        serializedPermissions: ByteArray,
        groupInvitationNonce: ByteArray?
    ) {
        this.identityManagerSession = identityManagerSession
        this.groupUid = groupUid
        this.serverUrl = serverUrl
        this.category = category
        this.ownedIdentity = ownedIdentity
        this.contactIdentity = contactIdentity
        this.serializedContactDetails = serializedContactDetails
        this.serializedPermissions = serializedPermissions
        this.groupInvitationNonce = groupInvitationNonce
    }

    constructor(identityManagerSession: IdentityManagerSession, res: ResultSet) {
        this.identityManagerSession = identityManagerSession
        this.groupUid = UID(res.getBytes(GROUP_UID))
        this.serverUrl = res.getString(SERVER_URL)
        this.category = res.getInt(CATEGORY)
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
        } catch (_: DecodingException) {
            throw SQLException()
        }
        try {
            this.contactIdentity = Identity.of(res.getBytes(CONTACT_IDENTITY))
        } catch (_: DecodingException) {
            throw SQLException()
        }
        this.serializedContactDetails = res.getString(SERIALIZED_CONTACT_DETAILS)
        this.serializedPermissions = res.getBytes(SERIALIZED_PERMISSIONS)
        this.groupInvitationNonce = res.getBytes(GROUP_INVITATION_NONCE)
    }


    @Throws(Exception::class)
    fun setPermissions(permissionStrings: MutableList<String>) {
        val serializedPermissions = GroupV2.Permission.serializePermissionStrings(permissionStrings)
        if (serializedPermissions == null) {
            throw Exception("Unable to serialize permissions")
        }

        identityManagerSession.session.prepareStatement(
            "ContactGroupV2PendingMember.setPermissions",
            "UPDATE " + TABLE_NAME +
                    " SET " + SERIALIZED_PERMISSIONS + " = ? " +
                    " WHERE " + GROUP_UID + " = ? " +
                    " AND " + SERVER_URL + " = ? " +
                    " AND " + CATEGORY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?" +
                    " AND " + CONTACT_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, serializedPermissions)
            statement.setBytes(2, groupUid.bytes)
            statement.setString(3, serverUrl)
            statement.setInt(4, category)
            statement.setBytes(5, ownedIdentity.getBytes())
            statement.setBytes(6, contactIdentity.getBytes())
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    fun setGroupInvitationNonce(groupInvitationNonce: ByteArray?) {
        identityManagerSession.session.prepareStatement(
            "ContactGroupV2PendingMember.setGroupInvitationNonce",
            "UPDATE " + TABLE_NAME +
                    " SET " + GROUP_INVITATION_NONCE + " = ? " +
                    " WHERE " + GROUP_UID + " = ? " +
                    " AND " + SERVER_URL + " = ? " +
                    " AND " + CATEGORY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?" +
                    " AND " + CONTACT_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, groupInvitationNonce)
            statement.setBytes(2, groupUid.bytes)
            statement.setString(3, serverUrl)
            statement.setInt(4, category)
            statement.setBytes(5, ownedIdentity.getBytes())
            statement.setBytes(6, contactIdentity.getBytes())
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    fun setSerializedContactDetails(serializedContactDetails: String?) {
        identityManagerSession.session.prepareStatement(
            "ContactGroupV2PendingMember.setSerializedContactDetails",
            "UPDATE " + TABLE_NAME +
                    " SET " + SERIALIZED_CONTACT_DETAILS + " = ? " +
                    " WHERE " + GROUP_UID + " = ? " +
                    " AND " + SERVER_URL + " = ? " +
                    " AND " + CATEGORY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?" +
                    " AND " + CONTACT_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setString(1, serializedContactDetails)
            statement.setBytes(2, groupUid.bytes)
            statement.setString(3, serverUrl)
            statement.setInt(4, category)
            statement.setBytes(5, ownedIdentity.getBytes())
            statement.setBytes(6, contactIdentity.getBytes())
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun insert() {
        identityManagerSession.session.prepareStatement(
            "ContactGroupV2PendingMember.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?, ?,?,?);"
        ).use { statement ->
            statement.setBytes(1, groupUid.bytes)
            statement.setString(2, serverUrl)
            statement.setInt(3, category)
            statement.setBytes(4, ownedIdentity.getBytes())
            statement.setBytes(5, contactIdentity.getBytes())

            statement.setString(6, serializedContactDetails)
            statement.setBytes(7, serializedPermissions)
            statement.setBytes(8, groupInvitationNonce)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        identityManagerSession.session.prepareStatement(
            "ContactGroupV2PendingMember.delete",
            " DELETE FROM " + TABLE_NAME +
                    " WHERE " + GROUP_UID + " = ? " +
                    " AND " + SERVER_URL + " = ? " +
                    " AND " + CATEGORY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ? " +
                    " AND " + CONTACT_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, groupUid.bytes)
            statement.setString(2, serverUrl)
            statement.setInt(3, category)
            statement.setBytes(4, ownedIdentity.getBytes())
            statement.setBytes(5, contactIdentity.getBytes())
            statement.executeUpdate()
        }
    }

    // endregion
    override fun wasCommitted() {
    }


    fun backup(): Pojo_0 {
        val pojo = Pojo_0()
        pojo.contact_identity = contactIdentity.getBytes()
        pojo.serialized_details = serializedContactDetails
        pojo.permissions = deserializePermissions(serializedPermissions).toTypedArray<String?>()
        pojo.invitation_nonce = groupInvitationNonce
        return pojo
    }


    @JsonIgnoreProperties(ignoreUnknown = true)
    class Pojo_0 {
        @JvmField var contact_identity: ByteArray? = null
        @JvmField var serialized_details: String? = null
        @JvmField var permissions: Array<String?> = emptyArray()
        @JvmField var invitation_nonce: ByteArray? = null
    } // endregion

    companion object {
        const val TABLE_NAME: String = "contact_group_v2_pending_member"

        const val GROUP_UID: String = "group_uid"
        const val SERVER_URL: String = "server_url"
        const val CATEGORY: String = "category"
        const val OWNED_IDENTITY: String = "owned_identity"
        const val CONTACT_IDENTITY: String = "contact_identity"
        const val SERIALIZED_CONTACT_DETAILS: String = "serialized_contact_details"
        const val SERIALIZED_PERMISSIONS: String = "serialized_permissions"
        const val GROUP_INVITATION_NONCE: String = "group_invitation_nonce"

        // region constructor
        fun create(
            identityManagerSession: IdentityManagerSession?,
            ownedIdentity: Identity?,
            groupIdentifier: GroupV2.Identifier?,
            contactIdentity: Identity?,
            serializedContactDetails: String?,
            permissionStrings: MutableCollection<String>?,
            groupInvitationNonce: ByteArray?
        ): ContactGroupV2PendingMember? {
            if ((identityManagerSession == null) || (ownedIdentity == null) || (groupIdentifier == null) || (contactIdentity == null) || (permissionStrings == null) || (serializedContactDetails == null) || (groupInvitationNonce == null)) {
                return null
            }

            try {
                val serializedPermissions =
                    GroupV2.Permission.serializePermissionStrings(permissionStrings)

                val contactGroupPendingMember = ContactGroupV2PendingMember(
                    identityManagerSession,
                    groupIdentifier.groupUid,
                    groupIdentifier.serverUrl,
                    groupIdentifier.category,
                    ownedIdentity,
                    contactIdentity,
                    serializedContactDetails,
                    serializedPermissions!!,
                    groupInvitationNonce
                )
                contactGroupPendingMember.insert()
                return contactGroupPendingMember
            } catch (e: Exception) {
                Logger.x(e)
                return null
            }
        }


        // endregion
        // region Get and Set
        @Throws(SQLException::class)
        fun get(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            groupIdentifier: GroupV2.Identifier?,
            contactIdentity: Identity?
        ): ContactGroupV2PendingMember? {
            if ((ownedIdentity == null) || (groupIdentifier == null) || (contactIdentity == null)) {
                return null
            }
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2PendingMember.get",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + GROUP_UID + " = ? " +
                        " AND " + SERVER_URL + " = ? " +
                        " AND " + CATEGORY + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ?" +
                        " AND " + CONTACT_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, groupIdentifier.groupUid.bytes)
                statement.setString(2, groupIdentifier.serverUrl)
                statement.setInt(3, groupIdentifier.category)
                statement.setBytes(4, ownedIdentity.getBytes())
                statement.setBytes(5, contactIdentity.getBytes())
                statement.executeQuery().use { res ->
                    if (res.next()) {
                        return ContactGroupV2PendingMember(identityManagerSession, res)
                    } else {
                        return null
                    }
                }
            }
        }

        @Throws(SQLException::class)
        fun getAll(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            groupIdentifier: GroupV2.Identifier?
        ): MutableList<ContactGroupV2PendingMember?>? {
            if ((ownedIdentity == null) || (groupIdentifier == null)) {
                return null
            }
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2PendingMember.getAll",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + GROUP_UID + " = ? " +
                        " AND " + SERVER_URL + " = ? " +
                        " AND " + CATEGORY + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, groupIdentifier.groupUid.bytes)
                statement.setString(2, groupIdentifier.serverUrl)
                statement.setInt(3, groupIdentifier.category)
                statement.setBytes(4, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    val list: MutableList<ContactGroupV2PendingMember?> =
                        ArrayList<ContactGroupV2PendingMember?>()
                    while (res.next()) {
                        list.add(ContactGroupV2PendingMember(identityManagerSession, res))
                    }
                    return list
                }
            }
        }

        @Throws(SQLException::class)
        fun getKeycloakGroupV2IdentifiersWhereContactIsPending(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            contactIdentity: Identity?
        ): MutableList<GroupV2.Identifier?>? {
            if ((ownedIdentity == null) || (contactIdentity == null)) {
                return null
            }
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2PendingMember.getKeycloakGroupV2IdentifiersWhereContactIsPending",
                "SELECT " + GROUP_UID + " as uid, " + SERVER_URL + " as url FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + CONTACT_IDENTITY + " = ?" +
                        " AND " + CATEGORY + " = " + GroupV2.Identifier.CATEGORY_KEYCLOAK + ";"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setBytes(2, contactIdentity.getBytes())
                statement.executeQuery().use { res ->
                    val list: MutableList<GroupV2.Identifier?> = ArrayList<GroupV2.Identifier?>()
                    while (res.next()) {
                        try {
                            list.add(
                                GroupV2.Identifier(
                                    UID(res.getBytes("uid")),
                                    res.getString("url"),
                                    GroupV2.Identifier.CATEGORY_KEYCLOAK
                                )
                            )
                        } catch (e: Exception) {
                            Logger.x(e)
                        }
                    }
                    return list
                }
            }
        }


        // endregion
        // region database
        @Throws(SQLException::class)
        fun createTable(session: Session) {
            session.createStatement().use { statement ->
                statement.execute(
                    "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                            GROUP_UID + " BLOB NOT NULL, " +
                            SERVER_URL + " TEXT NOT NULL, " +
                            CATEGORY + " INT NOT NULL, " +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            CONTACT_IDENTITY + " BLOB NOT NULL, " +
                            SERIALIZED_CONTACT_DETAILS + " TEXT NOT NULL, " +
                            SERIALIZED_PERMISSIONS + " BLOB NOT NULL, " +
                            GROUP_INVITATION_NONCE + " BLOB NOT NULL, " +
                            " CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + GROUP_UID + ", " + SERVER_URL + ", " + CATEGORY + ", " + OWNED_IDENTITY + ", " + CONTACT_IDENTITY + "), " +
                            " FOREIGN KEY (" + GROUP_UID + ", " + SERVER_URL + ", " + CATEGORY + ", " + OWNED_IDENTITY + ") REFERENCES " + ContactGroupV2.TABLE_NAME + "(" + ContactGroupV2.GROUP_UID + ", " + ContactGroupV2.SERVER_URL + ", " + ContactGroupV2.CATEGORY + ", " + ContactGroupV2.OWNED_IDENTITY + ") ON DELETE CASCADE );"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 32 && newVersion >= 32) {
                session.createStatement().use { statement ->
                    Logger.d("CREATING contact_group_v2_member DATABASE FOR VERSION 32")
                    statement.execute(
                        "CREATE TABLE contact_group_v2_pending_member (" +
                                "group_uid BLOB NOT NULL, " +
                                "server_url TEXT NOT NULL, " +
                                "category INT NOT NULL, " +
                                "owned_identity BLOB NOT NULL, " +
                                "contact_identity BLOB NOT NULL, " +
                                "serialized_contact_details TEXT NOT NULL, " +
                                "serialized_permissions BLOB NOT NULL, " +
                                "group_invitation_nonce BLOB NOT NULL, " +
                                " CONSTRAINT PK_contact_group_v2_pending_member PRIMARY KEY(group_uid, server_url, category, owned_identity, contact_identity), " +
                                " FOREIGN KEY (group_uid, server_url, category, owned_identity) REFERENCES contact_group_v2 (group_uid, server_url, category, owned_identity) ON DELETE CASCADE );"
                    )
                }
                oldVersion = 32
            }
        }


        // region backup
        @Throws(SQLException::class)
        fun backupAll(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            groupIdentifier: GroupV2.Identifier?
        ): Array<Pojo_0?> {
            val members: MutableList<ContactGroupV2PendingMember?> =
                getAll(identityManagerSession, ownedIdentity, groupIdentifier) ?: mutableListOf()
            val pojos = arrayOfNulls<Pojo_0>(members.size)
            for (i in pojos.indices) {
                pojos[i] = members.get(i)!!.backup()
            }
            return pojos
        }

        fun restoreAll(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            groupIdentifier: GroupV2.Identifier?,
            pojos: Array<Pojo_0>?
        ) {
            if (pojos == null) {
                return
            }
            for (pojo in pojos) {
                try {
                    var sanitizedSerializedDetails: String? = null
                    try {
                        // check whether the input is base64 or plain JSON (there was a bug on iOS where the details were base64 encoded)
                        identityManagerSession.jsonObjectMapper!!.readValue<JsonIdentityDetails?>(
                            pojo.serialized_details,
                            JsonIdentityDetails::class.java
                        )
                        sanitizedSerializedDetails = pojo.serialized_details
                    } catch (_: Exception) {
                        try {
                            val serializedDetailsString = String(
                                Base64.decode(pojo.serialized_details),
                                StandardCharsets.UTF_8
                            )
                            identityManagerSession.jsonObjectMapper!!.readValue<JsonIdentityDetails?>(
                                serializedDetailsString,
                                JsonIdentityDetails::class.java
                            )
                            sanitizedSerializedDetails = serializedDetailsString
                        } catch (_: Exception) {
                            Logger.i("Could not determine serialized details of GroupV2 pending member.")
                        }
                    }

                    if (sanitizedSerializedDetails != null) {
                        create(
                            identityManagerSession,
                            ownedIdentity,
                            groupIdentifier,
                            Identity.of(pojo.contact_identity!!),
                            sanitizedSerializedDetails,
                            pojo.permissions.filterNotNull().toMutableList(),
                            pojo.invitation_nonce
                        )
                    }
                } catch (e: DecodingException) {
                    Logger.x(e)
                }
            }
        }
    }
}
