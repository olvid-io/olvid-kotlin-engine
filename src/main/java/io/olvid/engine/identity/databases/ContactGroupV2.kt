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
import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.SessionCommitListener
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.containers.GroupV2.AdministratorsChain
import io.olvid.engine.datatypes.containers.GroupV2.BlobKeys
import io.olvid.engine.datatypes.containers.GroupV2.IdentifierAndAdminStatus
import io.olvid.engine.datatypes.containers.GroupV2.IdentifierVersionAndKeys
import io.olvid.engine.datatypes.containers.GroupV2.IdentityAndPermissions
import io.olvid.engine.datatypes.containers.GroupV2.IdentityAndPermissionsAndDetails
import io.olvid.engine.datatypes.containers.GroupV2.Permission.Companion.deserializeKnownPermissions
import io.olvid.engine.datatypes.containers.GroupV2.Permission.Companion.deserializePermissions
import io.olvid.engine.datatypes.containers.GroupV2.Permission.Companion.serializePermissionStrings
import io.olvid.engine.datatypes.containers.GroupV2.ServerBlob
import io.olvid.engine.datatypes.containers.GroupV2.ServerPhotoInfo
import io.olvid.engine.datatypes.containers.KeycloakGroupV2UpdateOutput
import io.olvid.engine.datatypes.containers.TrustOrigin.Companion.createKeycloakTrustOrigin
import io.olvid.engine.datatypes.containers.TrustOrigin.Companion.createServerGroupV2TrustOrigin
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPrivateKey
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.JsonKeycloakUserDetails
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import io.olvid.engine.identity.datatypes.KeycloakGroupBlob
import io.olvid.engine.identity.datatypes.KeycloakGroupMemberAndPermissions
import io.olvid.engine.protocol.datatypes.ProtocolStarterDelegate
import io.olvid.engine.storage.EngineFile
import java.io.File
import java.sql.ResultSet
import java.sql.SQLException
import java.sql.Types
import java.util.Arrays
import java.util.Random
import org.jose4j.jwt.consumer.JwtConsumerBuilder

class ContactGroupV2 : ObvDatabase {
    private val identityManagerSession: IdentityManagerSession

    private val groupUid: UID
    private val serverUrl: String
    private val category: Int
    @JvmField val ownedIdentity: Identity
    private var serializedOwnPermissions: ByteArray? // permission strings separated by 0x00 bytes --> allows storing future permissions
    var version: Int // always 0 for a keycloak group
        private set
    @JvmField var trustedDetailsVersion: Int // always 0 for a keycloak group
    var verifiedAdministratorsChain: ByteArray? // null for a keycloak group
        private set
    var blobMainSeed: Seed? =
        null // used to decrypt the blob on the server, null for a keycloak group
        private set
    var blobVersionSeed: Seed? =
        null // used to decrypt the blob on the server, null for a keycloak group
        private set
    var groupAdminServerAuthenticationPrivateKey: ServerAuthenticationPrivateKey? =
        null // non-null for admins --> required to upload the blob
        private set
    var ownGroupInvitationNonce: ByteArray
        private set
    private var frozen: Boolean // set to true after a backup restore until the blob keys have been verified online
    var lastModificationTimestamp: Long
        private set
    var pushTopic: String? // non-null only for keyclaok groups
        private set
    var serializedSharedSettings: String? // non-null only for keyclaok groups
        private set
    var serializedJsonGroupType: String?
        private set
    private var alreadyTrustedDetailsVersion: Int? // non-null only if some details were trusted on another device while the version to be trusted was not yet available on this device

    val groupIdentifier: GroupV2.Identifier
        get() = GroupV2.Identifier(
            groupUid,
            serverUrl,
            category
        )

    fun isFrozen(): Boolean {
        return frozen
    }

    fun getTrustedDetailsVersion(): Int {
        return trustedDetailsVersion
    }

    val ownPermissionStrings: MutableList<String?>
        get() = GroupV2.Permission.deserializePermissions(serializedOwnPermissions!!)

    fun getAlreadyTrustedDetailsVersion(): Int? {
        return alreadyTrustedDetailsVersion
    }

    private var inviterIdentity: Identity? = null
    private var deletedBy: Identity? = null

    fun setDeletedBy(deletedBy: Identity?) {
        this.deletedBy = deletedBy
    }

    constructor(
        identityManagerSession: IdentityManagerSession,
        groupUid: UID,
        serverUrl: String,
        category: Int,
        ownedIdentity: Identity,
        serializedOwnPermission: ByteArray?,
        version: Int,
        verifiedAdministratorsChain: ByteArray?,
        blobKeys: BlobKeys?,
        ownGroupInvitationNonce: ByteArray,
        frozen: Boolean,
        lastModificationTimestamp: Long,
        pushTopic: String?,
        serializedSharedSettings: String?,
        serializedJsonGroupType: String?
    ) {
        this.identityManagerSession = identityManagerSession
        this.groupUid = groupUid
        this.serverUrl = serverUrl
        this.category = category
        this.ownedIdentity = ownedIdentity
        this.serializedOwnPermissions = serializedOwnPermission
        this.version = version
        this.trustedDetailsVersion = version
        this.verifiedAdministratorsChain = verifiedAdministratorsChain
        if (blobKeys == null) {
            this.blobMainSeed = null
            this.blobVersionSeed = null
            this.groupAdminServerAuthenticationPrivateKey = null
        } else {
            this.blobMainSeed = blobKeys.blobMainSeed
            this.blobVersionSeed = blobKeys.blobVersionSeed
            this.groupAdminServerAuthenticationPrivateKey =
                blobKeys.groupAdminServerAuthenticationPrivateKey
        }
        this.ownGroupInvitationNonce = ownGroupInvitationNonce
        this.frozen = frozen
        this.lastModificationTimestamp = lastModificationTimestamp
        this.pushTopic = pushTopic
        this.serializedSharedSettings = serializedSharedSettings
        this.serializedJsonGroupType = serializedJsonGroupType
        this.alreadyTrustedDetailsVersion = null
    }

    private constructor(identityManagerSession: IdentityManagerSession, res: ResultSet) {
        this.identityManagerSession = identityManagerSession
        this.groupUid = UID(res.getBytes(GROUP_UID))
        this.serverUrl = res.getString(SERVER_URL)
        this.category = res.getInt(CATEGORY)
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
        } catch (_: DecodingException) {
            throw SQLException()
        }
        this.serializedOwnPermissions = res.getBytes(SERIALIZED_OWN_PERMISSIONS)
        this.version = res.getInt(VERSION)
        this.trustedDetailsVersion = res.getInt(TRUSTED_DETAILS_VERSION)
        this.verifiedAdministratorsChain = res.getBytes(VERIFIED_ADMINISTRATORS_CHAIN)
        var bytes: ByteArray? = res.getBytes(BLOB_MAIN_SEED)
        this.blobMainSeed = if (bytes == null) null else Seed(bytes)
        bytes = res.getBytes(BLOB_VERSION_SEED)
        this.blobVersionSeed = if (bytes == null) null else Seed(bytes)
        bytes = res.getBytes(GROUP_ADMIN_SERVER_AUTHENTICATION_PRIVATE_KEY)
        if (bytes == null) {
            this.groupAdminServerAuthenticationPrivateKey = null
        } else {
            try {
                this.groupAdminServerAuthenticationPrivateKey =
                    Encoded(bytes).decodePrivateKey() as ServerAuthenticationPrivateKey?
            } catch (_: DecodingException) {
                throw SQLException()
            }
        }
        this.ownGroupInvitationNonce = res.getBytes(OWN_GROUP_INVITATION_NONCE)
        this.frozen = res.getBoolean(FROZEN)
        this.lastModificationTimestamp = res.getLong(LAST_MODIFICATION_TIMESTAMP)
        this.pushTopic = res.getString(PUSH_TOPIC)
        this.serializedSharedSettings = res.getString(SERIALIZED_SHARED_SETTINGS)
        this.serializedJsonGroupType = res.getString(SERIALIZED_JSON_GROUP_TYPE)
        this.alreadyTrustedDetailsVersion = res.getInt(ALREADY_TRUSTED_DETAILS_VERSION)
        if (res.wasNull()) {
            this.alreadyTrustedDetailsVersion = null
        }
    }


    @Throws(Exception::class)
    fun setDownloadedPhotoUrl(
        ownedIdentity: Identity?,
        serverPhotoInfo: ServerPhotoInfo?,
        photo: ByteArray
    ) {
        val detailsList: MutableList<ContactGroupV2Details?>? =
            ContactGroupV2Details.getByGroupIdentifierAndServerPhotoInfo(
                identityManagerSession, ownedIdentity,
                this.groupIdentifier, serverPhotoInfo
            )

        if (detailsList == null || detailsList.isEmpty()) {
            return
        }

        // find a non-existing fileName
        val fileName =
            Constants.IDENTITY_PHOTOS_DIRECTORY + File.separator + Logger.toHexString(groupUid.bytes)
        var randFileName: String? = null
        val random = Random()
        var dstPhotoFile: EngineFile? = null
        do {
            randFileName = fileName + "_" + random.nextInt(65536)
            dstPhotoFile = identityManagerSession.fileIo.file(identityManagerSession.engineBaseDirectory, randFileName)
        } while (dstPhotoFile.exists())

        dstPhotoFile.openOutput().use { os ->
            os.write(photo, 0, photo.size)
        }
        for (details in detailsList) {
            // update the details
            details?.setPhotoUrl(randFileName)
        }

        // notify that the group photo (trusted or published) changed
        commitHookBits = commitHookBits or HOOK_BIT_PHOTO_UPDATED
        identityManagerSession.session.addSessionCommitListener(this)
    }

    @Throws(SQLException::class)
    fun setFrozen(frozen: Boolean) {
        if (this.frozen == frozen) {
            return
        }
        identityManagerSession.session.prepareStatement(
            "ContactGroupV2.setFrozen",
            "UPDATE " + TABLE_NAME +
                    " SET " + FROZEN + " = ? " +
                    " WHERE " + GROUP_UID + " = ? " +
                    " AND " + SERVER_URL + " = ? " +
                    " AND " + CATEGORY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBoolean(1, frozen)
            statement.setBytes(2, groupUid.bytes)
            statement.setString(3, serverUrl)
            statement.setInt(4, category)
            statement.setBytes(5, ownedIdentity.getBytes())
            statement.executeUpdate()
            this.frozen = frozen
            commitHookBits = commitHookBits or HOOK_BIT_FROZEN_CHANGED
            identityManagerSession.session.addSessionCommitListener(this)
        }
    }

    @Throws(SQLException::class)
    fun setTrustedDetailsVersion(trustedDetailsVersion: Int) {
        identityManagerSession.session.prepareStatement(
            "ContactGroupV2.setTrustedDetailsVersion",
            "UPDATE " + TABLE_NAME +
                    " SET " + TRUSTED_DETAILS_VERSION + " = ? " +
                    " WHERE " + GROUP_UID + " = ? " +
                    " AND " + SERVER_URL + " = ? " +
                    " AND " + CATEGORY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setInt(1, trustedDetailsVersion)
            statement.setBytes(2, groupUid.bytes)
            statement.setString(3, serverUrl)
            statement.setInt(4, category)
            statement.setBytes(5, ownedIdentity.getBytes())
            statement.executeUpdate()
            this.trustedDetailsVersion = trustedDetailsVersion
            this.updatedByMe = true
            this.updatedBy = null
            commitHookBits = commitHookBits or HOOK_BIT_UPDATED
            identityManagerSession.session.addSessionCommitListener(this)
        }
    }

    @Throws(SQLException::class)
    fun setAlreadyTrustedDetailsVersion(alreadyTrustedDetailsVersion: Int?) {
        identityManagerSession.session.prepareStatement(
            "ContactGroupV2.setAlreadyTrustedDetailsVersion",
            "UPDATE " + TABLE_NAME +
                    " SET " + ALREADY_TRUSTED_DETAILS_VERSION + " = ? " +
                    " WHERE " + GROUP_UID + " = ? " +
                    " AND " + SERVER_URL + " = ? " +
                    " AND " + CATEGORY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            if (alreadyTrustedDetailsVersion == null) {
                statement.setNull(1, Types.INTEGER)
            } else {
                statement.setInt(1, alreadyTrustedDetailsVersion)
            }
            statement.setBytes(2, groupUid.bytes)
            statement.setString(3, serverUrl)
            statement.setInt(4, category)
            statement.setBytes(5, ownedIdentity.getBytes())
            statement.executeUpdate()
            this.alreadyTrustedDetailsVersion = alreadyTrustedDetailsVersion
        }
    }


    @Throws(SQLException::class)
    fun updateWithNewBlob(
        serverBlob: ServerBlob,
        blobKeys: BlobKeys,
        updatedByMe: Boolean,
        updatedBy: Identity?,
        leavers: MutableList<Identity?>?,
        groupUpdateTimestamp: Long?
    ): MutableList<Identity?>? {
        if (!identityManagerSession.session.isInTransaction) {
            throw SQLException("Calling ContactGroupV2.updateGroupV2WithNewBlob outside a transaction!")
        }
        // check the blob is validated
        if (!serverBlob.administratorsChain.integrityWasChecked) {
            return null
        }

        // if the blob is outdated, ignore it
        if (version > serverBlob.version) {
            return ArrayList<Identity?>()
        }

        // build a hashmap of group members for easier access
        val groupMembersMap = HashMap<Identity?, IdentityAndPermissionsAndDetails>()
        for (identityAndPermissionsAndDetails in serverBlob.groupMemberIdentityAndPermissionsAndDetailsList) {
            groupMembersMap.put(
                identityAndPermissionsAndDetails.identity,
                identityAndPermissionsAndDetails
            )
        }


        /**////////////////////////////////// */
        // update the local ContactGroupV2 fields

        // check I am indeed in the group (and remove myself from the map)
        val ownIdentityAndPermissionsAndDetails = groupMembersMap.remove(ownedIdentity)
        if (ownIdentityAndPermissionsAndDetails == null) {
            return null
        }

        // check the previous chain is a prefix of the new chain
        try {
            if (!serverBlob.administratorsChain.isPrefixedBy(
                    AdministratorsChain.of(
                        Encoded(
                            verifiedAdministratorsChain!!
                        )
                    )
                )
            ) {
                return null
            }
        } catch (e: DecodingException) {
            Logger.x(e)
            return null
        }

        // update group fields
        serializedOwnPermissions =
            serializePermissionStrings(ownIdentityAndPermissionsAndDetails.permissionStrings)
        ownGroupInvitationNonce = ownIdentityAndPermissionsAndDetails.groupInvitationNonce
        verifiedAdministratorsChain = serverBlob.administratorsChain.encode().bytes
        blobMainSeed = blobKeys.blobMainSeed
        blobVersionSeed = blobKeys.blobVersionSeed
        groupAdminServerAuthenticationPrivateKey = blobKeys.groupAdminServerAuthenticationPrivateKey
        lastModificationTimestamp =
            if (groupUpdateTimestamp == null) System.currentTimeMillis() else groupUpdateTimestamp
        serializedJsonGroupType = serverBlob.serializedGroupType

        if (serverBlob.version - version == 1) {
            this.updatedBy = updatedBy
            this.updatedGroupLeavers = leavers
        }

        // create the new group details
        val groupIdentifier =
            this.groupIdentifier
        val publishedDetails: ContactGroupV2Details = ContactGroupV2Details.get(
            identityManagerSession,
            ownedIdentity,
            groupIdentifier,
            version
        ) ?: return null
        if (serverBlob.version != version) {
            val newDetails: ContactGroupV2Details? = ContactGroupV2Details.create(
                identityManagerSession,
                ownedIdentity,
                groupIdentifier,
                serverBlob.version,
                serverBlob.serializedGroupDetails,
                serverBlob.serverPhotoInfo
            )
            if (newDetails == null) {
                return null
            }
            if (serverBlob.serverPhotoInfo != null && serverBlob.serverPhotoInfo.equals(
                    publishedDetails.serverPhotoInfo
                )
                && publishedDetails.getPhotoUrl() != null
            ) {
                // photo is the same, copy the photoUrl
                newDetails.setPhotoUrl(publishedDetails.getPhotoUrl())
            } else {
                if (publishedDetails.photoServerIdentity == ownedIdentity) {
                    // serverPhotoInfo changed and I was the previous upload, notify the user data can be deleted
                    labelToDelete = publishedDetails.photoServerLabel
                    commitHookBits = commitHookBits or HOOK_BIT_SERVER_USER_DATA_CAN_BE_DELETED
                }
                if (newDetails.photoServerIdentity == ownedIdentity) {
                    // new photo is owned by me --> create the ServerUserData to maintain it
                    ServerUserData.createForGroupV2(
                        identityManagerSession,
                        ownedIdentity,
                        newDetails.photoServerLabel,
                        this.groupIdentifier.bytes
                    )
                }
            }
            version = newDetails.version

            // check if this new version was already trusted on another device
            if (alreadyTrustedDetailsVersion != null) {
                if (version == alreadyTrustedDetailsVersion) {
                    // we can immediately trust the new version
                    trustedDetailsVersion = alreadyTrustedDetailsVersion!!
                    alreadyTrustedDetailsVersion = null
                } else if (version > alreadyTrustedDetailsVersion!!) {
                    // a new update was published since our already trusted version --> discard it
                    alreadyTrustedDetailsVersion = null
                }
            }
        }

        // update the group in DB
        update()
        this.updatedByMe = updatedByMe
        commitHookBits = commitHookBits or HOOK_BIT_UPDATED
        identityManagerSession.session.addSessionCommitListener(this)

        // we do not check if we can auto-trust the new details --> this is the App's job
        // cleanup any obsolete details (after the update)
        ContactGroupV2Details.cleanup(
            identityManagerSession,
            ownedIdentity,
            groupIdentifier,
            version,
            trustedDetailsVersion
        )

        /**/////////////////////// */
        // Now, update the members and pending members
        val membersWithNewInvitationNonce: MutableList<Identity?> = ArrayList<Identity?>()

        try {
            for (contactGroupV2Member in ContactGroupV2Member.getAll(
                identityManagerSession,
                ownedIdentity,
                groupIdentifier
            ) ?: emptyList()) {
                contactGroupV2Member ?: continue
                val newPermissionsAndDetails =
                    groupMembersMap.get(contactGroupV2Member.contactIdentity)
                if (newPermissionsAndDetails == null) {
                    // user was removed from the group
                    contactGroupV2Member.delete()
                } else if (!contactGroupV2Member.getGroupInvitationNonce()
                        .contentEquals(newPermissionsAndDetails.groupInvitationNonce)
                ) {
                    // nonce changed --> member must be moved to pending members
                    //  - delete the member
                    //  - do not remove from groupMembersMap so that it is added to pending members a few lines below
                    contactGroupV2Member.delete()
                } else {
                    // remove the member from the map
                    groupMembersMap.remove(contactGroupV2Member.contactIdentity)
                    // check if permissions are equal
                    if (HashSet<String?>(deserializePermissions(contactGroupV2Member.serializedPermissions)) != HashSet<String?>(
                            newPermissionsAndDetails.permissionStrings
                        )
                    ) {
                        contactGroupV2Member.setPermissions(newPermissionsAndDetails.permissionStrings)
                    }
                }
            }

            for (contactGroupV2PendingMember in ContactGroupV2PendingMember.getAll(
                identityManagerSession,
                ownedIdentity,
                groupIdentifier
            ) ?: emptyList()) {
                contactGroupV2PendingMember ?: continue
                val newPermissionsAndDetails =
                    groupMembersMap.remove(contactGroupV2PendingMember.contactIdentity)
                if (newPermissionsAndDetails == null) {
                    // pending member was removed from the group
                    contactGroupV2PendingMember.delete()
                } else {
                    // check if permissions are equal
                    if (HashSet<String?>(deserializePermissions(contactGroupV2PendingMember.serializedPermissions)) != HashSet<String?>(
                            newPermissionsAndDetails.permissionStrings
                        )
                    ) {
                        contactGroupV2PendingMember.setPermissions(newPermissionsAndDetails.permissionStrings)
                    }

                    // check the invitation nonce
                    if (!contactGroupV2PendingMember.getGroupInvitationNonce()
                            .contentEquals(newPermissionsAndDetails.groupInvitationNonce)
                    ) {
                        contactGroupV2PendingMember.setGroupInvitationNonce(newPermissionsAndDetails.groupInvitationNonce)
                        membersWithNewInvitationNonce.add(contactGroupV2PendingMember.contactIdentity)
                    }

                    // check the serialized details
                    if (contactGroupV2PendingMember.getSerializedContactDetails() != newPermissionsAndDetails.serializedIdentityDetails) {
                        contactGroupV2PendingMember.setSerializedContactDetails(
                            newPermissionsAndDetails.serializedIdentityDetails
                        )
                    }
                }
            }

            // add all remaining members to ContactGroupV2PendingMember db
            for (pendingGroupMember in groupMembersMap.values) {
                membersWithNewInvitationNonce.add(pendingGroupMember.identity)
                val pendingMember: ContactGroupV2PendingMember =
                    ContactGroupV2PendingMember.create(
                        identityManagerSession,
                        ownedIdentity,
                        groupIdentifier,
                        pendingGroupMember.identity,
                        pendingGroupMember.serializedIdentityDetails,
                        pendingGroupMember.permissionStrings,
                        pendingGroupMember.groupInvitationNonce
                    ) ?: throw Exception("Unable to create new ContactGroupV2PendingMember")
            }
        } catch (e: Exception) {
            Logger.x(e)
            Logger.w("Error while updating group members from new serverBlob")
            return null
        }

        return membersWithNewInvitationNonce
    }

    @Throws(Exception::class)
    fun movePendingMemberToMembers(groupMemberIdentity: Identity?) {
        if (!identityManagerSession.session.isInTransaction) {
            throw Exception("Called ContactGroupV2.movePendingMemberToMembers outside a transaction")
        }

        val pendingMember: ContactGroupV2PendingMember? = ContactGroupV2PendingMember.get(
            identityManagerSession, ownedIdentity,
            this.groupIdentifier, groupMemberIdentity
        )
        if (pendingMember == null) {
            return
        }

        var member: ContactGroupV2Member? = ContactGroupV2Member.get(
            identityManagerSession, ownedIdentity,
            this.groupIdentifier, groupMemberIdentity
        )
        if (member == null) { // this should always be the case
            // add a contact if we don't have one, or add a trust origin
            if (category != GroupV2.Identifier.CATEGORY_KEYCLOAK) {
                if (identityManagerSession.identityDelegate?.isIdentityAContactOfOwnedIdentity(
                        identityManagerSession.session,
                        ownedIdentity,
                        groupMemberIdentity
                    ) != true
                ) {
                    identityManagerSession.identityDelegate?.addContactIdentity(
                        identityManagerSession.session,
                        groupMemberIdentity,
                        pendingMember.getSerializedContactDetails(),
                        ownedIdentity,
                        createServerGroupV2TrustOrigin(
                            System.currentTimeMillis(),
                            this.groupIdentifier
                        ),
                        false
                    )
                } else {
                    identityManagerSession.identityDelegate.addTrustOriginToContact(
                        identityManagerSession.session,
                        groupMemberIdentity,
                        ownedIdentity,
                        createServerGroupV2TrustOrigin(
                            System.currentTimeMillis(),
                            this.groupIdentifier
                        ),
                        false
                    )
                }
            } else {
                // for keycloak groups, don't add a trust origin for each group, only have one keycloak origin
                if (identityManagerSession.identityDelegate?.isIdentityAContactOfOwnedIdentity(
                        identityManagerSession.session,
                        ownedIdentity,
                        groupMemberIdentity
                    ) != true
                ) {
                    identityManagerSession.identityDelegate?.addContactIdentity(
                        identityManagerSession.session,
                        groupMemberIdentity,
                        pendingMember.getSerializedContactDetails(),
                        ownedIdentity,
                        createKeycloakTrustOrigin(
                            System.currentTimeMillis(), serverUrl
                        ),
                        false
                    )
                }
            }

            // for Keycloak groups, before moving a pending member to actual member, check their details are actually keycloak certified
            // (still, we do add the contact before this so that they have a chance to present new updated and validly signed details)
            if (category != GroupV2.Identifier.CATEGORY_KEYCLOAK || identityManagerSession.identityDelegate?.isContactIdentityCertifiedByOwnKeycloak(
                    identityManagerSession.session,
                    ownedIdentity,
                    groupMemberIdentity
                ) == true
            ) {
                // crate the ContactGroupV2Member
                member = ContactGroupV2Member.create(
                    identityManagerSession,
                    ownedIdentity,
                    this.groupIdentifier,
                    groupMemberIdentity,
                    deserializePermissions(pendingMember.serializedPermissions).filterNotNull().toMutableList(),
                    pendingMember.getGroupInvitationNonce()
                )
                if (member == null) {
                    throw Exception("In ContactGroupV2.movePendingMemberToMembers, failed to create ContactGroupV2Member")
                }
                // delete the pending member
                pendingMember.delete()
            }
        } else {
            // only delete the pending member
            pendingMember.delete()
        }

        this.updatedByMe = false
        this.updatedBy = null
        commitHookBits = commitHookBits or HOOK_BIT_UPDATED
        identityManagerSession.session.addSessionCommitListener(this)
    }


    @Throws(Exception::class)
    fun updateWithNewKeycloakBlob(
        keycloakGroupBlob: KeycloakGroupBlob,
        jsonObjectMapper: ObjectMapper
    ): KeycloakGroupV2UpdateOutput? {
        val groupIdentifier =
            this.groupIdentifier

        // build a hashmap of group members for easier access
        val groupMembersMap = HashMap<Identity?, KeycloakGroupMemberAndPermissions?>()
        for (groupMemberAndPermissions in keycloakGroupBlob.groupMembersAndPermissions ?: emptySet()) {
            groupMemberAndPermissions ?: continue
            val memberIdentity = Identity.of(groupMemberAndPermissions.identity!!)
            groupMembersMap.put(memberIdentity, groupMemberAndPermissions)
        }

        // get my own updated information
        val ownKeycloakGroupMemberAndPermissions = groupMembersMap.remove(ownedIdentity)
        if (ownKeycloakGroupMemberAndPermissions == null) {
            return null
        }


        // update the ContactGroupV2
        this.ownGroupInvitationNonce = ownKeycloakGroupMemberAndPermissions.groupInvitationNonce!!
        this.serializedOwnPermissions =
            serializePermissionStrings(ownKeycloakGroupMemberAndPermissions.permissions?.filterNotNull()?.toMutableList() ?: mutableListOf())
        this.lastModificationTimestamp = keycloakGroupBlob.timestamp
        if (this.pushTopic != keycloakGroupBlob.pushTopic) {
            this.pushTopic = keycloakGroupBlob.pushTopic
            commitHookBits = commitHookBits or HOOK_BIT_NEW_PUSH_TOPIC
        }
        if (this.serializedSharedSettings != keycloakGroupBlob.serializedSharedSettings) {
            this.serializedSharedSettings = keycloakGroupBlob.serializedSharedSettings
            identityManagerSession.session.addSessionCommitListener(SessionCommitListener {
                val userInfo = HashMap<String, Any>()
                userInfo.put(
                    IdentityNotifications.NOTIFICATION_KEYCLOAK_GROUP_V2_SHARED_SETTINGS_OWNED_IDENTITY_KEY,
                    ownedIdentity
                )
                userInfo.put(
                    IdentityNotifications.NOTIFICATION_KEYCLOAK_GROUP_V2_SHARED_SETTINGS_GROUP_IDENTIFIER_KEY,
                    groupIdentifier
                )
                userInfo.put(
                    IdentityNotifications.NOTIFICATION_KEYCLOAK_GROUP_V2_SHARED_SETTINGS_SERIALIZED_SHARED_SETTINGS_KEY,
                    keycloakGroupBlob.serializedSharedSettings!!
                )
                userInfo.put(
                    IdentityNotifications.NOTIFICATION_KEYCLOAK_GROUP_V2_SHARED_SETTINGS_MODIFICATION_TIMESTAMP_KEY,
                    keycloakGroupBlob.timestamp
                )
                identityManagerSession.notificationPostingDelegate?.postNotification(
                    IdentityNotifications.NOTIFICATION_KEYCLOAK_GROUP_V2_SHARED_SETTINGS,
                    userInfo
                )
            })
        }
        update()

        // create the new group details
        var serverPhotoInfo: ServerPhotoInfo? = null
        if (keycloakGroupBlob.photoUid != null && keycloakGroupBlob.encodedPhotoKey != null) {
            try {
                val photoUid = UID(keycloakGroupBlob.photoUid!!)
                val photoKey =
                    Encoded(keycloakGroupBlob.encodedPhotoKey!!).decodeSymmetricKey() as AuthEncKey?

                serverPhotoInfo = ServerPhotoInfo(null, photoUid, photoKey!!)
            } catch (_: Exception) {
                // can't get the photo info --> ignore the photo
            }
        }

        val updatedDetails: ContactGroupV2Details? =
            ContactGroupV2Details.createOrUpdateKeycloak(
                identityManagerSession,
                ownedIdentity,
                groupIdentifier,
                jsonObjectMapper.writeValueAsString(keycloakGroupBlob.groupDetails),
                serverPhotoInfo
            )

        if (updatedDetails == null) {
            return null
        }

        val photoNeedsToBeDownloaded =
            serverPhotoInfo != null && updatedDetails.getPhotoUrl() == null

        /**/////////////////////// */
        // Now, update the members and pending members
        val membersWithNewInvitationNonce: MutableList<Identity?> = ArrayList()

        try {
            for (contactGroupV2Member in ContactGroupV2Member.getAll(
                identityManagerSession,
                ownedIdentity,
                groupIdentifier
            ) ?: emptyList()) {
                contactGroupV2Member ?: continue
                val newPermissionsAndDetails =
                    groupMembersMap.get(contactGroupV2Member.contactIdentity)
                if (newPermissionsAndDetails == null) {
                    // user was removed from the group
                    contactGroupV2Member.delete()
                } else if (!contactGroupV2Member.getGroupInvitationNonce()
                        .contentEquals(newPermissionsAndDetails.groupInvitationNonce)
                ) {
                    // nonce changed --> member must be moved to pending members
                    //  - delete the member
                    //  - do not remove from groupMembersMap so that it is added to pending members a few lines below
                    contactGroupV2Member.delete()
                } else {
                    // remove the member from the map
                    groupMembersMap.remove(contactGroupV2Member.contactIdentity)
                    // check if permissions are equal
                    if (HashSet<String?>(deserializePermissions(contactGroupV2Member.serializedPermissions)) != HashSet<String?>(
                            newPermissionsAndDetails.permissions
                        )
                    ) {
                        contactGroupV2Member.setPermissions(newPermissionsAndDetails.permissions?.filterNotNull()?.toMutableList() ?: mutableListOf())
                    }
                }
            }

            val noVerificationConsumer = JwtConsumerBuilder()
                .setSkipSignatureVerification()
                .setSkipAllValidators()
                .build()

            for (contactGroupV2PendingMember in ContactGroupV2PendingMember.getAll(
                identityManagerSession,
                ownedIdentity,
                groupIdentifier
            ) ?: emptyList()) {
                contactGroupV2PendingMember ?: continue
                val newPermissionsAndDetails =
                    groupMembersMap.remove(contactGroupV2PendingMember.contactIdentity)
                if (newPermissionsAndDetails == null) {
                    // pending member was removed from the group
                    contactGroupV2PendingMember.delete()
                } else {
                    // check if permissions are equal
                    if (HashSet<String?>(deserializePermissions(contactGroupV2PendingMember.serializedPermissions)) != HashSet<String?>(
                            newPermissionsAndDetails.permissions
                        )
                    ) {
                        contactGroupV2PendingMember.setPermissions(newPermissionsAndDetails.permissions?.filterNotNull()?.toMutableList() ?: mutableListOf())
                    }

                    // check the invitation nonce
                    if (!contactGroupV2PendingMember.getGroupInvitationNonce()
                            .contentEquals(newPermissionsAndDetails.groupInvitationNonce)
                    ) {
                        contactGroupV2PendingMember.setGroupInvitationNonce(newPermissionsAndDetails.groupInvitationNonce)
                        membersWithNewInvitationNonce.add(contactGroupV2PendingMember.contactIdentity)
                    }

                    // check the serialized details
                    val serializedUnsignedDetails =
                        noVerificationConsumer.processToClaims(newPermissionsAndDetails.signedUserDetails)
                            .getRawJson()
                    val jsonKeycloakUserDetails =
                        jsonObjectMapper.readValue<JsonKeycloakUserDetails>(
                            serializedUnsignedDetails,
                            JsonKeycloakUserDetails::class.java
                        )
                    val jsonIdentityDetails =
                        jsonKeycloakUserDetails.getIdentityDetails(newPermissionsAndDetails.signedUserDetails)
                    val serializedIdentityDetails =
                        jsonObjectMapper.writeValueAsString(jsonIdentityDetails)

                    if (contactGroupV2PendingMember.getSerializedContactDetails() != serializedIdentityDetails) {
                        contactGroupV2PendingMember.setSerializedContactDetails(
                            serializedIdentityDetails
                        )
                    }
                }
            }

            // add all remaining members to ContactGroupV2PendingMember db
            for (entrySet in groupMembersMap.entries) {
                val pendingMemberIdentity = entrySet.key
                val pendingGroupMember: KeycloakGroupMemberAndPermissions = entrySet.value!!

                membersWithNewInvitationNonce.add(pendingMemberIdentity)

                val serializedUnsignedDetails =
                    noVerificationConsumer.processToClaims(pendingGroupMember.signedUserDetails)
                        .getRawJson()
                val jsonKeycloakUserDetails = jsonObjectMapper.readValue<JsonKeycloakUserDetails>(
                    serializedUnsignedDetails,
                    JsonKeycloakUserDetails::class.java
                )
                val jsonIdentityDetails =
                    jsonKeycloakUserDetails.getIdentityDetails(pendingGroupMember.signedUserDetails)
                val serializedIdentityDetails =
                    jsonObjectMapper.writeValueAsString(jsonIdentityDetails)

                ContactGroupV2PendingMember.create(
                    identityManagerSession,
                    ownedIdentity,
                    groupIdentifier,
                    pendingMemberIdentity,
                    serializedIdentityDetails,
                    pendingGroupMember.permissions?.filterNotNull()?.toMutableList(),
                    pendingGroupMember.groupInvitationNonce
                ) ?: throw Exception("Unable to create new ContactGroupV2PendingMember")
            }
        } catch (e: Exception) {
            Logger.x(e)
            Logger.w("Error while updating group members from new serverBlob")
            return null
        }

        updatedBy = null
        commitHookBits = commitHookBits or HOOK_BIT_UPDATED
        identityManagerSession.session.addSessionCommitListener(this)

        return KeycloakGroupV2UpdateOutput(
            ownGroupInvitationNonce,
            photoNeedsToBeDownloaded,
            membersWithNewInvitationNonce
        )
    }

    @Throws(SQLException::class)
    override fun insert() {
        identityManagerSession.session.prepareStatement(
            "ContactGroupV2.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?, ?,?,?,?,?, ?,?,?,?,?, ?,?,?);"
        ).use { statement ->
            statement.setBytes(1, groupUid.bytes)
            statement.setString(2, serverUrl)
            statement.setInt(3, category)
            statement.setBytes(4, ownedIdentity.getBytes())
            statement.setBytes(5, serializedOwnPermissions)

            statement.setInt(6, version)
            statement.setInt(7, trustedDetailsVersion)
            statement.setBytes(8, verifiedAdministratorsChain)
            statement.setBytes(9, if (blobMainSeed == null) null else blobMainSeed!!.getBytes())
            statement.setBytes(
                10,
                if (blobVersionSeed == null) null else blobVersionSeed!!.getBytes()
            )

            statement.setBytes(
                11,
                if (groupAdminServerAuthenticationPrivateKey == null) null else Encoded.of(
                    groupAdminServerAuthenticationPrivateKey!!
                ).bytes
            )
            statement.setBytes(12, ownGroupInvitationNonce)
            statement.setBoolean(13, frozen)
            statement.setLong(14, lastModificationTimestamp)
            statement.setString(15, pushTopic)

            statement.setString(16, serializedSharedSettings)
            statement.setString(17, serializedJsonGroupType)
            if (alreadyTrustedDetailsVersion == null) {
                statement.setNull(18, Types.INTEGER)
            } else {
                statement.setInt(18, alreadyTrustedDetailsVersion!!)
            }
            statement.executeUpdate()
            commitHookBits = commitHookBits or HOOK_BIT_INSERTED
            identityManagerSession.session.addSessionCommitListener(this)
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        if (!identityManagerSession.session.isInTransaction) {
            Logger.e("Running ContactGroupV2.delete() outside a transaction")
            throw SQLException()
        }

        identityManagerSession.session.prepareStatement(
            "ContactGroupV2.delete",
            "DELETE FROM " + TABLE_NAME +
                    " WHERE " + GROUP_UID + " = ? " +
                    " AND " + SERVER_URL + " = ? " +
                    " AND " + CATEGORY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, groupUid.bytes)
            statement.setString(2, serverUrl)
            statement.setInt(3, category)
            statement.setBytes(4, ownedIdentity.getBytes())
            statement.executeUpdate()
            commitHookBits = commitHookBits or HOOK_BIT_DELETED
            identityManagerSession.session.addSessionCommitListener(this)
        }
        identityManagerSession.session.prepareStatement(
            "ContactGroupV2.delete",
            "DELETE FROM " + ContactGroupV2Details.TABLE_NAME +
                    " WHERE " + ContactGroupV2Details.GROUP_UID + " = ? " +
                    " AND " + ContactGroupV2Details.SERVER_URL + " = ? " +
                    " AND " + ContactGroupV2Details.CATEGORY + " = ? " +
                    " AND " + ContactGroupV2Details.OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, groupUid.bytes)
            statement.setString(2, serverUrl)
            statement.setInt(3, category)
            statement.setBytes(4, ownedIdentity.getBytes())
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    private fun update() {
        identityManagerSession.session.prepareStatement(
            "ContactGroupV2.update",
            "UPDATE " + TABLE_NAME +
                    " SET " + SERIALIZED_OWN_PERMISSIONS + " = ?, " +
                    VERSION + " = ?, " +
                    TRUSTED_DETAILS_VERSION + " = ?, " +
                    VERIFIED_ADMINISTRATORS_CHAIN + " = ?, " +
                    BLOB_MAIN_SEED + " = ?, " +
                    BLOB_VERSION_SEED + " = ?, " +
                    GROUP_ADMIN_SERVER_AUTHENTICATION_PRIVATE_KEY + " = ?, " +
                    OWN_GROUP_INVITATION_NONCE + " = ?, " +
                    FROZEN + " = ?, " +
                    LAST_MODIFICATION_TIMESTAMP + " = ?, " +
                    PUSH_TOPIC + " = ?, " +
                    SERIALIZED_SHARED_SETTINGS + " = ?, " +
                    SERIALIZED_JSON_GROUP_TYPE + " = ?, " +
                    ALREADY_TRUSTED_DETAILS_VERSION + " = ? " +
                    " WHERE " + GROUP_UID + " = ? " +
                    " AND " + SERVER_URL + " = ? " +
                    " AND " + CATEGORY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, serializedOwnPermissions)
            statement.setInt(2, version)
            statement.setInt(3, trustedDetailsVersion)
            statement.setBytes(4, verifiedAdministratorsChain)
            statement.setBytes(5, if (blobVersionSeed == null) null else blobMainSeed!!.getBytes())

            statement.setBytes(
                6,
                if (blobVersionSeed == null) null else blobVersionSeed!!.getBytes()
            )
            statement.setBytes(
                7,
                if (groupAdminServerAuthenticationPrivateKey == null) null else Encoded.of(
                    groupAdminServerAuthenticationPrivateKey!!
                ).bytes
            )
            statement.setBytes(8, ownGroupInvitationNonce)
            statement.setBoolean(9, frozen)
            statement.setLong(10, lastModificationTimestamp)

            statement.setString(11, pushTopic)
            statement.setString(12, serializedSharedSettings)
            statement.setString(13, serializedJsonGroupType)
            if (alreadyTrustedDetailsVersion == null) {
                statement.setNull(14, Types.INTEGER)
            } else {
                statement.setInt(14, alreadyTrustedDetailsVersion!!)
            }

            statement.setBytes(15, groupUid.bytes)
            statement.setString(16, serverUrl)
            statement.setInt(17, category)
            statement.setBytes(18, ownedIdentity.getBytes())
            statement.executeUpdate()
        }
    }

    fun triggerUpdateNotification() {
        updatedBy = null
        commitHookBits = commitHookBits or HOOK_BIT_UPDATED
        identityManagerSession.session.addSessionCommitListener(this)
    }


    // endregion
    // region hooks
    private var labelToDelete: UID? = null
    private var updatedByMe = false
    private var updatedBy: Identity? = null
    private var updatedGroupLeavers: MutableList<Identity?>? = null

    private var commitHookBits: Long = 0
    override fun wasCommitted() {
        if ((commitHookBits and HOOK_BIT_INSERTED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_GROUP_V2_CREATED_OWNED_IDENTITY_KEY,
                ownedIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_GROUP_V2_CREATED_GROUP_IDENTIFIER_KEY,
                this.groupIdentifier
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_GROUP_V2_CREATED_CREATED_BY_ME_KEY,
                (commitHookBits and HOOK_BIT_INSERTED_AS_NEW) != 0L
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_GROUP_V2_CREATED_ON_OTHER_DEVICE_KEY,
                (commitHookBits and HOOK_BIT_CREATED_ON_OTHER_DEVICE) != 0L
            )
            val hookInviterIdentity = inviterIdentity
            if (hookInviterIdentity != null) {
                userInfo.put(
                    IdentityNotifications.NOTIFICATION_GROUP_V2_CREATED_BY_KEY,
                    hookInviterIdentity
                )
            }
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_GROUP_V2_CREATED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_DELETED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_GROUP_V2_DELETED_OWNED_IDENTITY_KEY,
                ownedIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_GROUP_V2_DELETED_GROUP_IDENTIFIER_KEY,
                this.groupIdentifier
            )
            val hookDeletedBy = deletedBy
            if (hookDeletedBy != null) {
                userInfo.put(
                    IdentityNotifications.NOTIFICATION_GROUP_V2_DELETED_DELETED_BY_KEY,
                    hookDeletedBy
                )
            }
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_GROUP_V2_DELETED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_FROZEN_CHANGED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_GROUP_V2_FROZEN_CHANGED_OWNED_IDENTITY_KEY,
                ownedIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_GROUP_V2_FROZEN_CHANGED_GROUP_IDENTIFIER_KEY,
                this.groupIdentifier
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_GROUP_V2_FROZEN_CHANGED_FROZEN_KEY,
                frozen
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_GROUP_V2_FROZEN_CHANGED_NEW_GROUP_KEY,
                (commitHookBits and HOOK_BIT_INSERTED_AS_NEW) != 0L
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_GROUP_V2_FROZEN_CHANGED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_UPDATED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_GROUP_V2_UPDATED_OWNED_IDENTITY_KEY,
                ownedIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_GROUP_V2_UPDATED_GROUP_IDENTIFIER_KEY,
                this.groupIdentifier
            )
            userInfo.put(IdentityNotifications.NOTIFICATION_GROUP_V2_UPDATED_BY_ME_KEY, updatedByMe)
            if (updatedBy != null) {
                userInfo.put(IdentityNotifications.NOTIFICATION_GROUP_V2_UPDATED_BY_KEY, updatedBy!!)
            }
            if (updatedGroupLeavers != null) {
                userInfo.put(
                    IdentityNotifications.NOTIFICATION_GROUP_V2_UPDATED_GROUP_LEAVERS_KEY,
                    updatedGroupLeavers!!
                )
            }
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_GROUP_V2_UPDATED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_PHOTO_UPDATED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_GROUP_V2_PHOTO_UPDATED_OWNED_IDENTITY_KEY,
                ownedIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_GROUP_V2_PHOTO_UPDATED_GROUP_IDENTIFIER_KEY,
                this.groupIdentifier
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_GROUP_V2_PHOTO_UPDATED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_SERVER_USER_DATA_CAN_BE_DELETED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_SERVER_USER_DATA_CAN_BE_DELETED_OWNED_IDENTITY_KEY,
                ownedIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_SERVER_USER_DATA_CAN_BE_DELETED_LABEL_KEY,
                labelToDelete!!
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_SERVER_USER_DATA_CAN_BE_DELETED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_NEW_PUSH_TOPIC) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_NEW_KEYCLOAK_GROUP_V2_PUSH_TOPIC_OWNED_IDENTITY_KEY,
                ownedIdentity
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_NEW_KEYCLOAK_GROUP_V2_PUSH_TOPIC,
                userInfo
            )
        }
        commitHookBits = 0
    }


    @Throws(SQLException::class)
    fun backup(): Pojo_0 {
        val pojo = Pojo_0()
        pojo.group_uid = groupUid.bytes
        pojo.server_url = serverUrl
        pojo.category = category

        pojo.permissions = GroupV2.Permission.deserializePermissions(serializedOwnPermissions!!)
            .toTypedArray<String?>()
        pojo.version = version
        pojo.details = ContactGroupV2Details.get(
            identityManagerSession, ownedIdentity,
            this.groupIdentifier, version
        )?.backup()
        if (trustedDetailsVersion != version) {
            pojo.trusted_details = ContactGroupV2Details.get(
                identityManagerSession, ownedIdentity,
                this.groupIdentifier, trustedDetailsVersion
            )?.backup()
        }

        pojo.verified_admin_chain = verifiedAdministratorsChain
        pojo.main_seed = if (blobMainSeed == null) null else blobMainSeed!!.getBytes()
        pojo.version_seed = if (blobVersionSeed == null) null else blobVersionSeed!!.getBytes()
        if (groupAdminServerAuthenticationPrivateKey != null) {
            pojo.encoded_admin_key = Encoded.of(groupAdminServerAuthenticationPrivateKey!!).bytes
        }
        pojo.invitation_nonce = ownGroupInvitationNonce
        pojo.last_modification_timestamp = lastModificationTimestamp
        pojo.push_topic = pushTopic
        pojo.serialized_shared_settings = serializedSharedSettings
        pojo.serialized_json_group_type = serializedJsonGroupType

        pojo.members = ContactGroupV2Member.backupAll(
            identityManagerSession, ownedIdentity,
            this.groupIdentifier
        )
        pojo.pending_members = ContactGroupV2PendingMember.backupAll(
            identityManagerSession, ownedIdentity,
            this.groupIdentifier
        )
        return pojo
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class Pojo_0 {
        var group_uid: ByteArray? = null
        var server_url: String? = null
        var category: Int = 0
        var permissions: Array<String?>? = null
        var version: Int = 0
        var details: ContactGroupV2Details.Pojo_0? = null
        var trusted_details: ContactGroupV2Details.Pojo_0? =
            null // we do not store the version of the trusted details: we will use (version - 1) on restore

        var verified_admin_chain: ByteArray? = null
        var main_seed: ByteArray? = null
        var version_seed: ByteArray? = null
        var encoded_admin_key: ByteArray? = null
        var invitation_nonce: ByteArray? = null
        var last_modification_timestamp: Long = 0
        var push_topic: String? = null
        var serialized_shared_settings: String? = null
        var serialized_json_group_type: String? = null

        var members: Array<ContactGroupV2Member.Pojo_0?>? = null
        var pending_members: Array<ContactGroupV2PendingMember.Pojo_0?>? = null
    } // endregion

    companion object {
        const val TABLE_NAME: String = "contact_group_v2"

        const val GROUP_UID: String = "group_uid"
        const val SERVER_URL: String = "server_url"
        const val CATEGORY: String = "category"
        const val OWNED_IDENTITY: String = "owned_identity"
        const val SERIALIZED_OWN_PERMISSIONS: String = "serialized_own_permissions"

        const val VERSION: String = "version"
        const val TRUSTED_DETAILS_VERSION: String = "trusted_details_version"
        const val VERIFIED_ADMINISTRATORS_CHAIN: String = "verified_administrators_chain"
        const val BLOB_MAIN_SEED: String = "blob_main_seed"
        const val BLOB_VERSION_SEED: String = "blob_version_seed"

        const val GROUP_ADMIN_SERVER_AUTHENTICATION_PRIVATE_KEY: String =
            "group_admin_server_authentication_private_key"
        const val OWN_GROUP_INVITATION_NONCE: String = "own_group_invitation_nonce"
        const val FROZEN: String = "frozen"
        const val LAST_MODIFICATION_TIMESTAMP: String = "last_modification_timestamp"
        const val PUSH_TOPIC: String = "push_topic"

        const val SERIALIZED_SHARED_SETTINGS: String = "serialized_shared_settings"
        const val SERIALIZED_JSON_GROUP_TYPE: String = "serialized_json_group_type"
        const val ALREADY_TRUSTED_DETAILS_VERSION: String = "already_trusted_details_version"


        // region constructor
        // used only by the group creator to create a new group
        fun createNew(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            groupIdentifier: GroupV2.Identifier?,
            serializedGroupDetails: String?,
            absolutePhotoUrl: String?,
            serverPhotoInfo: ServerPhotoInfo?,
            verifiedAdministratorsChain: ByteArray?,
            blobKeys: BlobKeys?,
            ownGroupInvitationNonce: ByteArray?,
            ownPermissionStrings: MutableList<String?>,
            serializedGroupType: String?
        ): ContactGroupV2? {
            if ((groupIdentifier == null) || (ownedIdentity == null) || (serializedGroupDetails == null) || (verifiedAdministratorsChain == null) || (blobKeys == null) || (ownGroupInvitationNonce == null)) {
                return null
            }

            try {
                if (!identityManagerSession.session.isInTransaction) {
                    Logger.e("Calling ContactGroupV2.createNew() outside a transaction")
                    return null
                }
                val contactGroupDetails: ContactGroupV2Details? =
                    ContactGroupV2Details.createNew(
                        identityManagerSession,
                        ownedIdentity,
                        groupIdentifier,
                        serializedGroupDetails,
                        absolutePhotoUrl,
                        serverPhotoInfo
                    )
                if (contactGroupDetails == null) {
                    Logger.e("Error create contactGroupDetails in ContactGroupV2.createNew()")
                    return null
                }

                val serializedOwnPermissions =
                    GroupV2.Permission.serializePermissionStrings(ownPermissionStrings.filterNotNull().toMutableList())

                // when first creating the group, it is frozen. It will be unfrozen once the group is successfully uploaded to the server and the members can be notified
                val contactGroup = ContactGroupV2(
                    identityManagerSession,
                    groupIdentifier.groupUid,
                    groupIdentifier.serverUrl,
                    groupIdentifier.category,
                    ownedIdentity,
                    serializedOwnPermissions,
                    contactGroupDetails.version,
                    verifiedAdministratorsChain,
                    blobKeys,
                    ownGroupInvitationNonce,
                    true,
                    System.currentTimeMillis(),
                    null,
                    null,
                    serializedGroupType
                )
                contactGroup.insert()
                contactGroup.commitHookBits =
                    contactGroup.commitHookBits or (HOOK_BIT_INSERTED_AS_NEW or HOOK_BIT_FROZEN_CHANGED) // this way the app also receives a frozen notification to mark the group as updating
                return contactGroup
            } catch (e: Exception) {
                Logger.x(e)
                return null
            }
        }


        fun createJoined(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            groupIdentifier: GroupV2.Identifier?,
            version: Int,
            serializedGroupDetails: String?,
            serverPhotoInfo: ServerPhotoInfo?,
            verifiedAdministratorsChain: ByteArray?,
            blobKeys: BlobKeys?,
            ownGroupInvitationNonce: ByteArray?,
            ownPermissionStrings: MutableList<String?>?,
            serializedGroupType: String?,
            createdByMeOnOtherDevice: Boolean,
            inviterIdentity: Identity?,
            groupUpdateTimestamp: Long?
        ): ContactGroupV2? {
            if ((ownedIdentity == null) || (groupIdentifier == null) || (serializedGroupDetails == null) || (verifiedAdministratorsChain == null) || (blobKeys == null) || (ownGroupInvitationNonce == null) || (ownPermissionStrings == null)) {
                return null
            }
            try {
                if (!identityManagerSession.session.isInTransaction) {
                    Logger.e("Calling ContactGroupV2.createJoined() outside a transaction")
                    return null
                }
                val contactGroupDetails: ContactGroupV2Details? =
                    ContactGroupV2Details.createJoined(
                        identityManagerSession,
                        ownedIdentity,
                        groupIdentifier,
                        version,
                        serializedGroupDetails,
                        serverPhotoInfo
                    )
                if (contactGroupDetails == null) {
                    Logger.e("Error create contactGroupDetails in ContactGroupV2.createJoined()")
                    return null
                }

                val contactGroup = ContactGroupV2(
                    identityManagerSession,
                    groupIdentifier.groupUid,
                    groupIdentifier.serverUrl,
                    groupIdentifier.category,
                    ownedIdentity,
                    GroupV2.Permission.serializePermissionStrings(ownPermissionStrings.filterNotNull().toMutableList()),
                    contactGroupDetails.version,
                    verifiedAdministratorsChain,
                    blobKeys,
                    ownGroupInvitationNonce,
                    false,
                    if (groupUpdateTimestamp == null) System.currentTimeMillis() else groupUpdateTimestamp,
                    null,
                    null,
                    serializedGroupType
                )
                contactGroup.inviterIdentity = inviterIdentity
                contactGroup.insert()
                if (createdByMeOnOtherDevice) {
                    contactGroup.commitHookBits =
                        contactGroup.commitHookBits or (HOOK_BIT_INSERTED_AS_NEW or HOOK_BIT_CREATED_ON_OTHER_DEVICE)
                }
                return contactGroup
            } catch (e: Exception) {
                Logger.x(e)
                return null
            }
        }

        fun createKeycloak(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            groupIdentifier: GroupV2.Identifier?,
            serializedGroupDetails: String?,
            serverPhotoInfo: ServerPhotoInfo?,
            ownGroupInvitationNonce: ByteArray?,
            ownPermissionStrings: MutableList<String?>?,
            pushTopic: String?,
            serializedSharedSettings: String?,
            lastModificationTimestamp: Long
        ): ContactGroupV2? {
            if ((ownedIdentity == null) || (groupIdentifier == null) || (serializedGroupDetails == null) || (ownGroupInvitationNonce == null) || (ownPermissionStrings == null)) {
                return null
            }
            try {
                if (!identityManagerSession.session.isInTransaction) {
                    Logger.e("Calling ContactGroupV2.createJoined() outside a transaction")
                    return null
                }

                val contactGroupDetails: ContactGroupV2Details? =
                    ContactGroupV2Details.createOrUpdateKeycloak(
                        identityManagerSession,
                        ownedIdentity,
                        groupIdentifier,
                        serializedGroupDetails,
                        serverPhotoInfo
                    )
                if (contactGroupDetails == null) {
                    Logger.e("Error create contactGroupDetails in ContactGroupV2.createJoined()")
                    return null
                }

                val contactGroup = ContactGroupV2(
                    identityManagerSession,
                    groupIdentifier.groupUid,
                    groupIdentifier.serverUrl,
                    groupIdentifier.category,
                    ownedIdentity,
                    GroupV2.Permission.serializePermissionStrings(ownPermissionStrings.filterNotNull().toMutableList()),
                    contactGroupDetails.version,
                    null,
                    null,
                    ownGroupInvitationNonce,
                    false,
                    lastModificationTimestamp,
                    pushTopic,
                    serializedSharedSettings,
                    null
                )
                contactGroup.insert()
                if (pushTopic != null) {
                    contactGroup.commitHookBits =
                        contactGroup.commitHookBits or HOOK_BIT_NEW_PUSH_TOPIC
                    identityManagerSession.session.addSessionCommitListener(contactGroup)
                }
                return contactGroup
            } catch (e: Exception) {
                Logger.x(e)
                return null
            }
        }

        // endregion
        // region Get and Set
        @Throws(SQLException::class)
        fun getServerBlob(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            groupIdentifier: GroupV2.Identifier?
        ): ServerBlob? {
            if (!identityManagerSession.session.isInTransaction) {
                throw SQLException("Called ContactGroupV2.getServerBlob outside of a transaction!")
            }

            val group: ContactGroupV2? = get(identityManagerSession, ownedIdentity, groupIdentifier)
            if (group == null) {
                return null
            }
            val groupDetails: ContactGroupV2Details? = ContactGroupV2Details.get(
                identityManagerSession,
                ownedIdentity,
                groupIdentifier,
                group.version
            )
            if (groupDetails == null) {
                return null
            }

            val administratorsChain: AdministratorsChain?
            try {
                administratorsChain =
                    AdministratorsChain.of(Encoded(group.verifiedAdministratorsChain!!))
            } catch (_: DecodingException) {
                return null
            }
            val serializedGroupDetails = groupDetails.serializedJsonDetails
            val serverPhotoInfo = groupDetails.serverPhotoInfo

            val groupMemberIdentityAndPermissionsAndDetailsList =
                HashSet<IdentityAndPermissionsAndDetails?>()

            run {
                // add own details to the list
                val serializedDetails: String? =
                    OwnedIdentity.getSerializedPublishedDetails(
                        identityManagerSession,
                        ownedIdentity!!
                    )
                val ownDetails = IdentityAndPermissionsAndDetails(
                    ownedIdentity,
                    group.ownPermissionStrings.filterNotNull().toMutableList(),
                    serializedDetails!!,
                    group.ownGroupInvitationNonce
                )
                groupMemberIdentityAndPermissionsAndDetailsList.add(ownDetails)
            }

            run {
                identityManagerSession.session.prepareStatement(
                    "ContactGroupV2.getServerBlob_members",
                    "SELECT " +
                            " gm." + ContactGroupV2Member.CONTACT_IDENTITY + " AS ci, " +
                            " gm." + ContactGroupV2Member.SERIALIZED_PERMISSIONS + " AS sp, " +
                            " details." + ContactIdentityDetails.SERIALIZED_JSON_DETAILS + " AS sd, " +
                            " gm." + ContactGroupV2Member.GROUP_INVITATION_NONCE + " AS gin " +
                            " FROM " + ContactGroupV2Member.TABLE_NAME + " AS gm " +
                            " INNER JOIN " + ContactIdentity.TABLE_NAME + " AS contact " +
                            " ON gm." + ContactGroupV2Member.CONTACT_IDENTITY + " = contact." + ContactIdentity.CONTACT_IDENTITY +
                            " AND gm." + ContactGroupV2Member.OWNED_IDENTITY + " = contact." + ContactIdentity.OWNED_IDENTITY +
                            " INNER JOIN " + ContactIdentityDetails.TABLE_NAME + " AS details " +
                            " ON details." + ContactIdentityDetails.CONTACT_IDENTITY + " = contact." + ContactIdentity.CONTACT_IDENTITY +
                            " AND details." + ContactIdentityDetails.OWNED_IDENTITY + " = contact." + ContactIdentity.OWNED_IDENTITY +
                            " AND details." + ContactIdentityDetails.VERSION + " = contact." + ContactIdentity.PUBLISHED_DETAILS_VERSION +
                            " WHERE gm." + ContactGroupV2Member.GROUP_UID + " = ? " +
                            " AND gm." + ContactGroupV2Member.SERVER_URL + " = ? " +
                            " AND gm." + ContactGroupV2Member.CATEGORY + " = ? " +
                            " AND gm." + ContactGroupV2Member.OWNED_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, groupIdentifier!!.groupUid.bytes)
                    statement.setString(2, groupIdentifier.serverUrl)
                    statement.setInt(3, groupIdentifier.category)
                    statement.setBytes(4, ownedIdentity!!.getBytes())
                    try {
                        statement.executeQuery().use { res ->
                            while (res.next()) {
                                val contactIdentity = Identity.of(res.getBytes("ci"))
                                val serializedPermissions = res.getBytes("sp")
                                val serializedDetails = res.getString("sd")
                                val groupInvitationNonce = res.getBytes("gin")

                                groupMemberIdentityAndPermissionsAndDetailsList.add(
                                    IdentityAndPermissionsAndDetails(
                                        contactIdentity,
                                        deserializePermissions(serializedPermissions).filterNotNull().toMutableList(),
                                        serializedDetails,
                                        groupInvitationNonce
                                    )
                                )
                            }
                        }
                    } catch (e: DecodingException) {
                        Logger.x(e)
                        return null
                    }
                }
            }

            run {
                identityManagerSession.session.prepareStatement(
                    "ContactGroupV2.getServerBlob_pendings",
                    "SELECT * FROM " + ContactGroupV2PendingMember.TABLE_NAME +
                            " WHERE " + ContactGroupV2Member.GROUP_UID + " = ? " +
                            " AND " + ContactGroupV2Member.SERVER_URL + " = ? " +
                            " AND " + ContactGroupV2Member.CATEGORY + " = ? " +
                            " AND " + ContactGroupV2Member.OWNED_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, groupIdentifier!!.groupUid.bytes)
                    statement.setString(2, groupIdentifier.serverUrl)
                    statement.setInt(3, groupIdentifier.category)
                    statement.setBytes(4, ownedIdentity!!.getBytes())
                    try {
                        statement.executeQuery().use { res ->
                            while (res.next()) {
                                val contactIdentity =
                                    Identity.of(res.getBytes(ContactGroupV2PendingMember.CONTACT_IDENTITY))
                                val serializedPermissions: ByteArray =
                                    res.getBytes(ContactGroupV2PendingMember.SERIALIZED_PERMISSIONS)
                                val serializedDetails: String =
                                    res.getString(ContactGroupV2PendingMember.SERIALIZED_CONTACT_DETAILS)
                                val groupInvitationNonce: ByteArray =
                                    res.getBytes(ContactGroupV2PendingMember.GROUP_INVITATION_NONCE)

                                groupMemberIdentityAndPermissionsAndDetailsList.add(
                                    IdentityAndPermissionsAndDetails(
                                        contactIdentity,
                                        deserializePermissions(serializedPermissions).filterNotNull().toMutableList(),
                                        serializedDetails,
                                        groupInvitationNonce
                                    )
                                )
                            }
                        }
                    } catch (e: DecodingException) {
                        Logger.x(e)
                        return null
                    }
                }
            }

            @Suppress("UNCHECKED_CAST")
            return ServerBlob(
                administratorsChain,
                groupMemberIdentityAndPermissionsAndDetailsList as java.util.HashSet<IdentityAndPermissionsAndDetails>,
                group.version,
                serializedGroupDetails!!,
                serverPhotoInfo,
                group.serializedJsonGroupType
            )
        }

        @Throws(SQLException::class)
        fun getPhotoUrl(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            groupIdentifier: GroupV2.Identifier
        ): String? {
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2.getPhotoUrl",
                "SELECT det." + ContactGroupV2Details.PHOTO_URL + " AS photo " +
                        " FROM " + TABLE_NAME + " AS g " +
                        " INNER JOIN " + ContactGroupV2Details.TABLE_NAME + " AS det " +
                        " ON g." + GROUP_UID + " = det." + ContactGroupV2Details.GROUP_UID +
                        " AND g." + SERVER_URL + " = det." + ContactGroupV2Details.SERVER_URL +
                        " AND g." + CATEGORY + " = det." + ContactGroupV2Details.CATEGORY +
                        " AND g." + OWNED_IDENTITY + " = det." + ContactGroupV2Details.OWNED_IDENTITY +
                        " AND g." + VERSION + " = det." + ContactGroupV2Details.VERSION +
                        " WHERE g." + GROUP_UID + " = ? " +
                        " AND g." + SERVER_URL + " = ? " +
                        " AND g." + CATEGORY + " = ? " +
                        " AND g." + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, groupIdentifier.groupUid.bytes)
                statement.setString(2, groupIdentifier.serverUrl)
                statement.setInt(3, groupIdentifier.category)
                statement.setBytes(4, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    if (res.next()) {
                        return res.getString("photo")
                    } else {
                        return null
                    }
                }
            }
        }

        @Throws(SQLException::class)
        fun getLastModificationTimestamp(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            groupIdentifier: GroupV2.Identifier
        ): Long? {
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2.getLastModificationTimestamp",
                "SELECT " + LAST_MODIFICATION_TIMESTAMP +
                        " FROM " + TABLE_NAME +
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
                    if (res.next()) {
                        return res.getLong(LAST_MODIFICATION_TIMESTAMP)
                    } else {
                        return null
                    }
                }
            }
        }


        @Throws(SQLException::class)
        fun getServerPhotoInfo(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            groupIdentifier: GroupV2.Identifier
        ): ServerPhotoInfo? {
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2.getServerPhotoInfo",
                "SELECT " +
                        " det." + ContactGroupV2Details.PHOTO_SERVER_IDENTITY + " AS ident, " +
                        " det." + ContactGroupV2Details.PHOTO_SERVER_LABEL + " AS label, " +
                        " det." + ContactGroupV2Details.PHOTO_SERVER_KEY + " AS key " +
                        " FROM " + TABLE_NAME + " AS g " +
                        " INNER JOIN " + ContactGroupV2Details.TABLE_NAME + " AS det " +
                        " ON g." + GROUP_UID + " = det." + ContactGroupV2Details.GROUP_UID +
                        " AND g." + SERVER_URL + " = det." + ContactGroupV2Details.SERVER_URL +
                        " AND g." + CATEGORY + " = det." + ContactGroupV2Details.CATEGORY +
                        " AND g." + OWNED_IDENTITY + " = det." + ContactGroupV2Details.OWNED_IDENTITY +
                        " AND g." + VERSION + " = det." + ContactGroupV2Details.VERSION +
                        " WHERE g." + GROUP_UID + " = ? " +
                        " AND g." + SERVER_URL + " = ? " +
                        " AND g." + CATEGORY + " = ? " +
                        " AND g." + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, groupIdentifier.groupUid.bytes)
                statement.setString(2, groupIdentifier.serverUrl)
                statement.setInt(3, groupIdentifier.category)
                statement.setBytes(4, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    if (res.next()) {
                        var photoServerIdentity: Identity? = null
                        val photoServerLabel: UID?
                        var photoServerKey: AuthEncKey? = null
                        var bytes = res.getBytes("ident")
                        if (bytes == null) {
                            photoServerIdentity = null
                        } else {
                            try {
                                photoServerIdentity = Identity.of(bytes)
                            } catch (_: DecodingException) {
                                photoServerIdentity = null
                            }
                        }
                        bytes = res.getBytes("label")
                        if (bytes == null) {
                            photoServerLabel = null
                        } else {
                            photoServerLabel = UID(bytes)
                        }
                        bytes = res.getBytes("key")
                        if (bytes == null) {
                            photoServerKey = null
                        } else {
                            try {
                                photoServerKey = Encoded(bytes).decodeSymmetricKey() as AuthEncKey?
                            } catch (_: DecodingException) {
                                photoServerKey = null
                            }
                        }
                        if (photoServerIdentity != null && photoServerLabel != null && photoServerKey != null) {
                            return ServerPhotoInfo(
                                photoServerIdentity,
                                photoServerLabel,
                                photoServerKey
                            )
                        }
                    }
                    return null
                }
            }
        }


        @Throws(Exception::class)
        fun getGroupV2OtherMembersAndPermissions(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            groupIdentifier: GroupV2.Identifier?
        ): HashSet<IdentityAndPermissions?>? {
            if ((ownedIdentity == null) || (groupIdentifier == null)) {
                return null
            }
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2.getGroupV2OtherMembersAndPermissions",
                " SELECT " + ContactGroupV2Member.CONTACT_IDENTITY + " AS id," +
                        ContactGroupV2Member.OWNED_IDENTITY + " AS oid, " +
                        ContactGroupV2Member.SERIALIZED_PERMISSIONS + " AS perm " +
                        " FROM " + ContactGroupV2Member.TABLE_NAME +
                        " WHERE " + ContactGroupV2Member.GROUP_UID + " = ? " +
                        " AND " + ContactGroupV2Member.SERVER_URL + " = ? " +
                        " AND " + ContactGroupV2Member.CATEGORY + " = ? " +
                        " AND " + ContactGroupV2Member.OWNED_IDENTITY + " = ? " +
                        " UNION SELECT " + ContactGroupV2PendingMember.CONTACT_IDENTITY + " AS id, " +
                        ContactGroupV2PendingMember.OWNED_IDENTITY + " AS oid, " +
                        ContactGroupV2PendingMember.SERIALIZED_PERMISSIONS + " AS perm " +
                        " FROM " + ContactGroupV2PendingMember.TABLE_NAME +
                        " WHERE " + ContactGroupV2PendingMember.GROUP_UID + " = ? " +
                        " AND " + ContactGroupV2PendingMember.SERVER_URL + " = ? " +
                        " AND " + ContactGroupV2PendingMember.CATEGORY + " = ? " +
                        " AND " + ContactGroupV2PendingMember.OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, groupIdentifier.groupUid.bytes)
                statement.setString(2, groupIdentifier.serverUrl)
                statement.setInt(3, groupIdentifier.category)
                statement.setBytes(4, ownedIdentity.getBytes())
                statement.setBytes(5, groupIdentifier.groupUid.bytes)
                statement.setString(6, groupIdentifier.serverUrl)
                statement.setInt(7, groupIdentifier.category)
                statement.setBytes(8, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    val set = HashSet<IdentityAndPermissions?>()
                    while (res.next()) {
                        val identity = Identity.of(res.getBytes("id"))
                        val permissions = deserializeKnownPermissions(res.getBytes("perm"))
                        set.add(IdentityAndPermissions(identity, permissions))
                    }
                    return set
                }
            }
        }

        @Throws(Exception::class)
        fun getGroupV2HasOtherAdminMember(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            groupIdentifier: GroupV2.Identifier
        ): Boolean {
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2.getGroupV2HasOtherAdminMember",
                " SELECT " + ContactGroupV2Member.SERIALIZED_PERMISSIONS + " AS perm " +
                        " FROM " + ContactGroupV2Member.TABLE_NAME +
                        " WHERE " + ContactGroupV2Member.GROUP_UID + " = ? " +
                        " AND " + ContactGroupV2Member.SERVER_URL + " = ? " +
                        " AND " + ContactGroupV2Member.CATEGORY + " = ? " +
                        " AND " + ContactGroupV2Member.OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, groupIdentifier.groupUid.bytes)
                statement.setString(2, groupIdentifier.serverUrl)
                statement.setInt(3, groupIdentifier.category)
                statement.setBytes(4, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    while (res.next()) {
                        val serializedPermissions = res.getBytes("perm")
                        if (deserializeKnownPermissions(serializedPermissions).contains(GroupV2.Permission.GROUP_ADMIN)) {
                            return true
                        }
                    }
                    return false
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllKeycloakPushTopics(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?
        ): MutableList<String>? {
            if (ownedIdentity == null) {
                return null
            }
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2.getAllKeycloakPushTopics",

                " SELECT " + PUSH_TOPIC + " AS pt " +
                        " FROM " + TABLE_NAME +
                        " WHERE " + CATEGORY + " = " + GroupV2.Identifier.CATEGORY_KEYCLOAK +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    val list: MutableList<String> = ArrayList()
                    while (res.next()) {
                        list.add(res.getString("pt"))
                    }
                    return list
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllWithPushTopic(
            identityManagerSession: IdentityManagerSession,
            pushTopic: String?
        ): MutableList<ContactGroupV2?> {
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2.getAllWithPushTopic",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + PUSH_TOPIC + " = ?;"
            ).use { statement ->
                statement.setString(1, pushTopic)
                statement.executeQuery().use { res ->
                    val list: MutableList<ContactGroupV2?> = ArrayList<ContactGroupV2?>()
                    while (res.next()) {
                        list.add(ContactGroupV2(identityManagerSession, res))
                    }
                    return list
                }
            }
        }

        @Throws(SQLException::class)
        fun get(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            groupIdentifier: GroupV2.Identifier?
        ): ContactGroupV2? {
            if ((ownedIdentity == null) || (groupIdentifier == null)) {
                return null
            }
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2.get",
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
                    if (res.next()) {
                        return ContactGroupV2(identityManagerSession, res)
                    } else {
                        return null
                    }
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllForIdentity(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity
        ): MutableList<ContactGroupV2?> {
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2.getAllForIdentity",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    val list: MutableList<ContactGroupV2?> = ArrayList()
                    while (res.next()) {
                        list.add(ContactGroupV2(identityManagerSession, res))
                    }
                    return list
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllKeycloakForIdentity(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity
        ): MutableList<ContactGroupV2> {
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2.getAllKeycloakForIdentity",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + CATEGORY + " = " + GroupV2.Identifier.CATEGORY_KEYCLOAK + ";"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    val list: MutableList<ContactGroupV2> = ArrayList()
                    while (res.next()) {
                        list.add(ContactGroupV2(identityManagerSession, res))
                    }
                    return list
                }
            }
        }

        @Throws(SQLException::class)
        fun getAll(identityManagerSession: IdentityManagerSession): MutableList<ContactGroupV2?> {
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2.getAll",
                "SELECT * FROM " + TABLE_NAME + ";"
            ).use { statement ->
                statement.executeQuery().use { res ->
                    val list: MutableList<ContactGroupV2?> = ArrayList<ContactGroupV2?>()
                    while (res.next()) {
                        list.add(ContactGroupV2(identityManagerSession, res))
                    }
                    return list
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllKeycloak(identityManagerSession: IdentityManagerSession): MutableList<ContactGroupV2?> {
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2.getAllKeycloak",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + CATEGORY + " = " + GroupV2.Identifier.CATEGORY_KEYCLOAK + ";"
            ).use { statement ->
                statement.executeQuery().use { res ->
                    val list: MutableList<ContactGroupV2?> = ArrayList<ContactGroupV2?>()
                    while (res.next()) {
                        list.add(ContactGroupV2(identityManagerSession, res))
                    }
                    return list
                }
            }
        }


        @Throws(Exception::class)
        fun getGroupV2MembersAndPendingMembersFromNonce(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            groupIdentifier: GroupV2.Identifier,
            groupMemberInvitationNonce: ByteArray?
        ): MutableList<Identity?> {
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2.getGroupV2MembersAndPendingMembersFromNonce",
                " SELECT " + ContactGroupV2Member.CONTACT_IDENTITY + " AS id " +
                        " FROM " + ContactGroupV2Member.TABLE_NAME +
                        " WHERE " + ContactGroupV2Member.GROUP_UID + " = ? " +
                        " AND " + ContactGroupV2Member.SERVER_URL + " = ? " +
                        " AND " + ContactGroupV2Member.CATEGORY + " = ? " +
                        " AND " + ContactGroupV2Member.OWNED_IDENTITY + " = ? " +
                        " AND " + ContactGroupV2Member.GROUP_INVITATION_NONCE + " = ? " +
                        " UNION SELECT " + ContactGroupV2PendingMember.CONTACT_IDENTITY + " AS id " +
                        " FROM " + ContactGroupV2PendingMember.TABLE_NAME +
                        " WHERE " + ContactGroupV2PendingMember.GROUP_UID + " = ? " +
                        " AND " + ContactGroupV2PendingMember.SERVER_URL + " = ? " +
                        " AND " + ContactGroupV2PendingMember.CATEGORY + " = ? " +
                        " AND " + ContactGroupV2PendingMember.OWNED_IDENTITY + " = ? " +
                        " AND " + ContactGroupV2PendingMember.GROUP_INVITATION_NONCE + " = ?;"
            ).use { statement ->
                statement.setBytes(1, groupIdentifier.groupUid.bytes)
                statement.setString(2, groupIdentifier.serverUrl)
                statement.setInt(3, groupIdentifier.category)
                statement.setBytes(4, ownedIdentity.getBytes())
                statement.setBytes(5, groupMemberInvitationNonce)
                statement.setBytes(6, groupIdentifier.groupUid.bytes)
                statement.setString(7, groupIdentifier.serverUrl)
                statement.setInt(8, groupIdentifier.category)
                statement.setBytes(9, ownedIdentity.getBytes())
                statement.setBytes(10, groupMemberInvitationNonce)
                statement.executeQuery().use { res ->
                    val list: MutableList<Identity?> = ArrayList<Identity?>()
                    while (res.next()) {
                        list.add(Identity.of(res.getBytes("id")))
                    }
                    return list
                }
            }
        }

        @Throws(SQLException::class)
        fun getServerGroupsV2IdentifierVersionAndKeysForContact(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            contactIdentity: Identity
        ): Array<IdentifierVersionAndKeys?> {
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2.getServerGroupsV2IdentifierVersionAndKeysForContact",
                "SELECT * FROM (SELECT " + ContactGroupV2Member.GROUP_UID + " AS uid, " +
                        ContactGroupV2Member.SERVER_URL + " AS url, " +
                        ContactGroupV2Member.SERIALIZED_PERMISSIONS + " AS perms " +
                        " FROM " + ContactGroupV2Member.TABLE_NAME +
                        " WHERE " + ContactGroupV2Member.CATEGORY + " = " + GroupV2.Identifier.CATEGORY_SERVER +
                        " AND " + ContactGroupV2Member.OWNED_IDENTITY + " = ? " +
                        " AND " + ContactGroupV2Member.CONTACT_IDENTITY + " = ? " +
                        " UNION SELECT " + ContactGroupV2PendingMember.GROUP_UID + " AS uid, " +
                        ContactGroupV2PendingMember.SERVER_URL + " AS url, " +
                        ContactGroupV2PendingMember.SERIALIZED_PERMISSIONS + " AS perms " +
                        " FROM " + ContactGroupV2PendingMember.TABLE_NAME +
                        " WHERE " + ContactGroupV2PendingMember.CATEGORY + " = " + GroupV2.Identifier.CATEGORY_SERVER +
                        " AND " + ContactGroupV2PendingMember.OWNED_IDENTITY + " = ? " +
                        " AND " + ContactGroupV2PendingMember.CONTACT_IDENTITY + " = ?) AS gmj " +
                        " INNER JOIN " + TABLE_NAME + " AS gr " +
                        " ON gmj.uid = gr." + GROUP_UID +
                        " AND gmj.url = gr." + SERVER_URL +
                        " AND gr." + CATEGORY + " = " + GroupV2.Identifier.CATEGORY_SERVER +
                        " AND gr." + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setBytes(2, contactIdentity.getBytes())
                statement.setBytes(3, ownedIdentity.getBytes())
                statement.setBytes(4, contactIdentity.getBytes())
                statement.setBytes(5, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    val list = ArrayList<IdentifierVersionAndKeys?>()
                    while (res.next()) {
                        val groupUid = res.getBytes("uid")
                        val serverUrl = res.getString("url")
                        val serializedContactPermissions = res.getBytes("perms")
                        val version: Int = res.getInt(VERSION)

                        val bytesMainSeed: ByteArray = res.getBytes(BLOB_MAIN_SEED)
                        val bytesVersionSeed: ByteArray = res.getBytes(BLOB_VERSION_SEED)
                        var serverAuthenticationPrivateKey: ServerAuthenticationPrivateKey? = null
                        // only include the serverAuthenticationPrivateKey if both I and the contact are admin
                        if (deserializeKnownPermissions(serializedContactPermissions).contains(
                                GroupV2.Permission.GROUP_ADMIN
                            )
                        ) {
                            val bytesGroupAdminKey: ByteArray? = res.getBytes(
                                GROUP_ADMIN_SERVER_AUTHENTICATION_PRIVATE_KEY
                            ) // this is non-null only when I am admin
                            if (bytesGroupAdminKey != null) {
                                try {
                                    serverAuthenticationPrivateKey =
                                        Encoded(bytesGroupAdminKey).decodePrivateKey() as ServerAuthenticationPrivateKey?
                                } catch (_: Exception) {
                                }
                            }
                        }

                        val blobKeys = BlobKeys(
                            Seed(bytesMainSeed),
                            Seed(bytesVersionSeed),
                            serverAuthenticationPrivateKey
                        )


                        list.add(
                            IdentifierVersionAndKeys(
                                GroupV2.Identifier(
                                    UID(groupUid),
                                    serverUrl,
                                    GroupV2.Identifier.CATEGORY_SERVER
                                ),
                                version,
                                blobKeys
                            )
                        )
                    }
                    return list.toTypedArray<IdentifierVersionAndKeys?>()
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllServerGroupsV2IdentifierVersionAndKeys(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity
        ): Array<IdentifierVersionAndKeys?> {
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2.getAllServerGroupsV2IdentifierVersionAndKeys",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + CATEGORY + " = " + GroupV2.Identifier.CATEGORY_SERVER +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    val list = ArrayList<IdentifierVersionAndKeys?>()
                    while (res.next()) {
                        val groupUid: ByteArray = res.getBytes(GROUP_UID)
                        val serverUrl: String = res.getString(SERVER_URL)
                        val version: Int = res.getInt(VERSION)
                        val bytesMainSeed: ByteArray = res.getBytes(BLOB_MAIN_SEED)
                        val bytesVersionSeed: ByteArray = res.getBytes(BLOB_VERSION_SEED)
                        var serverAuthenticationPrivateKey: ServerAuthenticationPrivateKey? = null
                        val bytesGroupAdminKey: ByteArray? = res.getBytes(
                            GROUP_ADMIN_SERVER_AUTHENTICATION_PRIVATE_KEY
                        ) // this is non-null only when I am admin
                        if (bytesGroupAdminKey != null) {
                            try {
                                serverAuthenticationPrivateKey =
                                    Encoded(bytesGroupAdminKey).decodePrivateKey() as ServerAuthenticationPrivateKey?
                            } catch (_: Exception) {
                            }
                        }

                        val blobKeys = BlobKeys(
                            Seed(bytesMainSeed),
                            Seed(bytesVersionSeed),
                            serverAuthenticationPrivateKey
                        )


                        list.add(
                            IdentifierVersionAndKeys(
                                GroupV2.Identifier(
                                    UID(groupUid),
                                    serverUrl,
                                    GroupV2.Identifier.CATEGORY_SERVER
                                ),
                                version,
                                blobKeys
                            )
                        )
                    }
                    return list.toTypedArray<IdentifierVersionAndKeys?>()
                }
            }
        }


        @Throws(SQLException::class)
        fun getServerGroupsV2IdentifierAndMyAdminStatusForContact(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            contactIdentity: Identity
        ): Array<IdentifierAndAdminStatus?> {
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2.getServerGroupsV2IdentifierAndMyAdminStatusForContact",
                "SELECT * FROM (SELECT " + ContactGroupV2Member.GROUP_UID + " AS uid, " +
                        ContactGroupV2Member.SERVER_URL + " AS url " +
                        " FROM " + ContactGroupV2Member.TABLE_NAME +
                        " WHERE " + ContactGroupV2Member.CATEGORY + " = " + GroupV2.Identifier.CATEGORY_SERVER +
                        " AND " + ContactGroupV2Member.OWNED_IDENTITY + " = ? " +
                        " AND " + ContactGroupV2Member.CONTACT_IDENTITY + " = ? " +
                        " UNION SELECT " + ContactGroupV2PendingMember.GROUP_UID + " AS uid, " +
                        ContactGroupV2PendingMember.SERVER_URL + " AS url " +
                        " FROM " + ContactGroupV2PendingMember.TABLE_NAME +
                        " WHERE " + ContactGroupV2PendingMember.CATEGORY + " = " + GroupV2.Identifier.CATEGORY_SERVER +
                        " AND " + ContactGroupV2PendingMember.OWNED_IDENTITY + " = ? " +
                        " AND " + ContactGroupV2PendingMember.CONTACT_IDENTITY + " = ?) AS gmj " +
                        " INNER JOIN " + TABLE_NAME + " AS gr " +
                        " ON gmj.uid = gr." + GROUP_UID +
                        " AND gmj.url = gr." + SERVER_URL +
                        " AND gr." + CATEGORY + " = " + GroupV2.Identifier.CATEGORY_SERVER +
                        " AND gr." + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setBytes(2, contactIdentity.getBytes())
                statement.setBytes(3, ownedIdentity.getBytes())
                statement.setBytes(4, contactIdentity.getBytes())
                statement.setBytes(5, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    val list = ArrayList<IdentifierAndAdminStatus?>()
                    while (res.next()) {
                        val groupUid = res.getBytes("uid")
                        val serverUld = res.getString("url")
                        val serializedOwnPermissions: ByteArray =
                            res.getBytes(SERIALIZED_OWN_PERMISSIONS)

                        list.add(
                            IdentifierAndAdminStatus(
                                GroupV2.Identifier(
                                    UID(groupUid),
                                    serverUld,
                                    GroupV2.Identifier.CATEGORY_SERVER
                                ),
                                deserializeKnownPermissions(serializedOwnPermissions).contains(
                                    GroupV2.Permission.GROUP_ADMIN
                                )
                            )
                        )
                    }
                    return list.toTypedArray<IdentifierAndAdminStatus?>()
                }
            }
        }

        @Throws(SQLException::class)
        fun deleteAllKeycloakGroupsForOwnedIdentity(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity
        ) {
            for (contactGroupV2 in getAllKeycloakForIdentity(
                identityManagerSession,
                ownedIdentity
            )) {
                contactGroupV2.delete()
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
                            SERIALIZED_OWN_PERMISSIONS + " BLOB NOT NULL, " +
                            VERSION + " INT NOT NULL, " +
                            TRUSTED_DETAILS_VERSION + " INT NOT NULL, " +
                            VERIFIED_ADMINISTRATORS_CHAIN + " BLOB, " +
                            BLOB_MAIN_SEED + " BLOB, " +
                            BLOB_VERSION_SEED + " BLOB, " +
                            GROUP_ADMIN_SERVER_AUTHENTICATION_PRIVATE_KEY + " BLOB, " +
                            OWN_GROUP_INVITATION_NONCE + " BLOB NOT NULL, " +
                            FROZEN + " BIT NOT NULL, " +
                            LAST_MODIFICATION_TIMESTAMP + " INTEGER NOT NULL, " +
                            PUSH_TOPIC + " TEXT, " +
                            SERIALIZED_SHARED_SETTINGS + " TEXT, " +
                            SERIALIZED_JSON_GROUP_TYPE + " TEXT, " +
                            ALREADY_TRUSTED_DETAILS_VERSION + " INT, " +
                            " CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + GROUP_UID + ", " + SERVER_URL + ", " + CATEGORY + ", " + OWNED_IDENTITY + "), " +
                            " FOREIGN KEY (" + OWNED_IDENTITY + ") REFERENCES " + OwnedIdentity.TABLE_NAME + "(" + OwnedIdentity.OWNED_IDENTITY + ")," +
                            " FOREIGN KEY (" + GROUP_UID + ", " + SERVER_URL + ", " + CATEGORY + ", " + OWNED_IDENTITY + ", " + VERSION + ") REFERENCES " + ContactGroupV2Details.TABLE_NAME + "(" + ContactGroupV2Details.GROUP_UID + ", " + ContactGroupV2Details.SERVER_URL + ", " + ContactGroupV2Details.CATEGORY + ", " + ContactGroupV2Details.OWNED_IDENTITY + ", " + ContactGroupV2Details.VERSION + ")," +
                            " FOREIGN KEY (" + GROUP_UID + ", " + SERVER_URL + ", " + CATEGORY + ", " + OWNED_IDENTITY + ", " + TRUSTED_DETAILS_VERSION + ") REFERENCES " + ContactGroupV2Details.TABLE_NAME + "(" + ContactGroupV2Details.GROUP_UID + ", " + ContactGroupV2Details.SERVER_URL + ", " + ContactGroupV2Details.CATEGORY + ", " + ContactGroupV2Details.OWNED_IDENTITY + ", " + ContactGroupV2Details.VERSION + ") );"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 32 && newVersion >= 32) {
                session.createStatement().use { statement ->
                    Logger.d("CREATING contact_group_v2 DATABASE FOR VERSION 32")
                    statement.execute(
                        "CREATE TABLE contact_group_v2 (" +
                                "group_uid BLOB NOT NULL, " +
                                "server_url TEXT NOT NULL, " +
                                "category INT NOT NULL, " +
                                "owned_identity BLOB NOT NULL, " +
                                "serialized_own_permissions BLOB NOT NULL, " +
                                "version INT NOT NULL, " +
                                "trusted_details_version INT NOT NULL, " +
                                "verified_administrators_chain BLOB NOT NULL, " +
                                "blob_main_seed BLOB NOT NULL, " +
                                "blob_version_seed BLOB NOT NULL, " +
                                "group_admin_server_authentication_private_key BLOB, " +
                                "own_group_invitation_nonce BLOB NOT NULL, " +
                                "frozen BIT NOT NULL, " +
                                " CONSTRAINT PK_contact_group_v2 PRIMARY KEY(group_uid, server_url, category, owned_identity), " +
                                " FOREIGN KEY (owned_identity) REFERENCES owned_identity (identity)," +
                                " FOREIGN KEY (group_uid, server_url, category, owned_identity, version) REFERENCES contact_group_v2_details (group_uid, server_url, category, owned_identity, version)," +
                                " FOREIGN KEY (group_uid, server_url, category, owned_identity, trusted_details_version) REFERENCES contact_group_v2_details (group_uid, server_url, category, owned_identity, version) );"
                    )
                }
                oldVersion = 32
            }
            if (oldVersion < 34 && newVersion >= 34) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING `contact_group_v2` DATABASE FROM VERSION " + oldVersion + " to 34")
                    statement.execute(
                        "CREATE TABLE contact_group_v2_new (" +
                                "group_uid BLOB NOT NULL, " +
                                "server_url TEXT NOT NULL, " +
                                "category INT NOT NULL, " +
                                "owned_identity BLOB NOT NULL, " +
                                "serialized_own_permissions BLOB NOT NULL, " +
                                "version INT NOT NULL, " +
                                "trusted_details_version INT NOT NULL, " +
                                "verified_administrators_chain BLOB, " +
                                "blob_main_seed BLOB, " +
                                "blob_version_seed BLOB, " +
                                "group_admin_server_authentication_private_key BLOB, " +
                                "own_group_invitation_nonce BLOB NOT NULL, " +
                                "frozen BIT NOT NULL, " +
                                "last_modification_timestamp INTEGER NOT NULL, " +
                                "push_topic TEXT, " +
                                "serialized_shared_settings TEXT, " +
                                " CONSTRAINT PK_contact_group_v2 PRIMARY KEY(group_uid, server_url, category, owned_identity), " +
                                " FOREIGN KEY (owned_identity) REFERENCES owned_identity (identity)," +
                                " FOREIGN KEY (group_uid, server_url, category, owned_identity, version) REFERENCES contact_group_v2_details (group_uid, server_url, category, owned_identity, version)," +
                                " FOREIGN KEY (group_uid, server_url, category, owned_identity, trusted_details_version) REFERENCES contact_group_v2_details (group_uid, server_url, category, owned_identity, version) );"
                    )
                    statement.execute(
                        "INSERT INTO contact_group_v2_new " +
                                " SELECT group_uid, server_url, category, owned_identity, serialized_own_permissions, version, trusted_details_version, verified_administrators_chain, blob_main_seed, blob_version_seed, group_admin_server_authentication_private_key, own_group_invitation_nonce, frozen, 0, NULL, NULL " +
                                " FROM contact_group_v2"
                    )
                    statement.execute("DROP TABLE contact_group_v2")
                    statement.execute("ALTER TABLE contact_group_v2_new RENAME TO contact_group_v2")
                }
                oldVersion = 34
            }
            if (oldVersion < 35 && newVersion >= 35) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING `contact_group_v2` DATABASE FROM VERSION " + oldVersion + " to 35")
                    statement.execute("ALTER TABLE contact_group_v2 ADD COLUMN `serialized_json_group_type` TEXT DEFAULT NULL")
                }
            }
            if (oldVersion < 48 && newVersion >= 48) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING `contact_group_v2` DATABASE FROM VERSION " + oldVersion + " to 48")
                    statement.execute("ALTER TABLE contact_group_v2 ADD COLUMN `already_trusted_details_version` INT DEFAULT NULL")
                }
            }
        }

        private const val HOOK_BIT_INSERTED: Long = 0x1
        private const val HOOK_BIT_INSERTED_AS_NEW: Long = 0x2
        private const val HOOK_BIT_DELETED: Long = 0x4
        private const val HOOK_BIT_FROZEN_CHANGED: Long = 0x8
        private const val HOOK_BIT_UPDATED: Long = 0x10
        private const val HOOK_BIT_PHOTO_UPDATED: Long = 0x20
        private const val HOOK_BIT_SERVER_USER_DATA_CAN_BE_DELETED: Long = 0x40
        private const val HOOK_BIT_NEW_PUSH_TOPIC: Long = 0x80
        private const val HOOK_BIT_CREATED_ON_OTHER_DEVICE: Long = 0x100

        // endregion
        // region backup
        @Throws(SQLException::class)
        fun backupAll(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity
        ): Array<Pojo_0?> {
            val groups: MutableList<ContactGroupV2?> =
                getAllForIdentity(identityManagerSession, ownedIdentity)
            val pojos = arrayOfNulls<Pojo_0>(groups.size)
            for (i in pojos.indices) {
                pojos[i] = groups.get(i)!!.backup()
            }
            return pojos
        }

        @Throws(SQLException::class)
        fun restoreAll(
            identityManagerSession: IdentityManagerSession,
            protocolStarterDelegate: ProtocolStarterDelegate,
            ownedIdentity: Identity,
            pojos: Array<Pojo_0>?
        ) {
            if (pojos == null) {
                return
            }
            for (pojo in pojos) {
                restore(identityManagerSession, protocolStarterDelegate, ownedIdentity, pojo)
            }
        }

        @Throws(SQLException::class)
        fun restore(
            identityManagerSession: IdentityManagerSession,
            protocolStarterDelegate: ProtocolStarterDelegate,
            ownedIdentity: Identity,
            pojo: Pojo_0
        ) {
            val groupIdentifier = GroupV2.Identifier(
                UID(pojo.group_uid!!),
                pojo.server_url!!,
                pojo.category
            )

            identityManagerSession.session.startTransaction()
            // first restore the details
            ContactGroupV2Details.restore(
                identityManagerSession,
                ownedIdentity,
                groupIdentifier,
                pojo.version,
                pojo.details!!
            )
            val trustedDetailsPojo = pojo.trusted_details
            if (trustedDetailsPojo != null) {
                ContactGroupV2Details.restore(
                    identityManagerSession,
                    ownedIdentity,
                    groupIdentifier,
                    pojo.version - 1,
                    trustedDetailsPojo
                )
            }

            val detailsPojo = pojo.details!!
            if (detailsPojo.photo_server_identity.contentEquals(ownedIdentity.getBytes()) && detailsPojo.photo_server_label != null) {
                // If I am the photo owner, also create the corresponding ServerUserData to maintain it
                try {
                    ServerUserData.createForGroupV2(
                        identityManagerSession,
                        ownedIdentity,
                        UID(detailsPojo.photo_server_label!!),
                        groupIdentifier.bytes
                    )
                } catch (_: Exception) {
                }
            }

            // then the group
            var serverAuthenticationPrivateKey: ServerAuthenticationPrivateKey? = null
            if (pojo.encoded_admin_key != null) {
                try {
                    serverAuthenticationPrivateKey =
                        Encoded(pojo.encoded_admin_key!!).decodePrivateKey() as ServerAuthenticationPrivateKey?
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }
            val blobKeys =
                if ((pojo.main_seed == null) || (pojo.version_seed == null)) null else BlobKeys(
                    Seed(pojo.main_seed!!),
                    Seed(pojo.version_seed!!),
                    serverAuthenticationPrivateKey
                )
            val groupV2 = ContactGroupV2(
                identityManagerSession,
                groupIdentifier.groupUid,
                pojo.server_url!!,
                pojo.category,
                ownedIdentity,
                serializePermissionStrings(Arrays.asList<String>(*pojo.permissions!!.filterNotNull().toTypedArray())),
                pojo.version,
                pojo.verified_admin_chain,
                blobKeys,
                pojo.invitation_nonce!!,
                false,
                pojo.last_modification_timestamp,
                pojo.push_topic,
                pojo.serialized_shared_settings,
                pojo.serialized_json_group_type
            )
            groupV2.insert()

            // finally the members and pending members
            @Suppress("UNCHECKED_CAST")
            ContactGroupV2Member.restoreAll(
                identityManagerSession,
                ownedIdentity,
                groupIdentifier,
                pojo.members as Array<ContactGroupV2Member.Pojo_0>?
            )
            @Suppress("UNCHECKED_CAST")
            ContactGroupV2PendingMember.restoreAll(
                identityManagerSession,
                ownedIdentity,
                groupIdentifier,
                pojo.pending_members as Array<ContactGroupV2PendingMember.Pojo_0>?
            )

            try {
                protocolStarterDelegate.initiateGroupV2ReDownloadWithinTransaction(
                    identityManagerSession.session,
                    ownedIdentity,
                    groupIdentifier
                )
            } catch (e: Exception) {
                Logger.x(e)
            }

            identityManagerSession.session.commit()
        }
    }
}
