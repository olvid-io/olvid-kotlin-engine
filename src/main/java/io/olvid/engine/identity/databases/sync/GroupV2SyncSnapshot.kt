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
package io.olvid.engine.identity.databases.sync

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.containers.GroupV2.BlobKeys
import io.olvid.engine.datatypes.containers.GroupV2.Permission.Companion.deserializePermissions
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPrivateKey
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.ObvBytesKey
import io.olvid.engine.engine.types.sync.ObvSyncDiff
import io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode
import io.olvid.engine.identity.databases.ContactGroupV2
import io.olvid.engine.identity.databases.ContactGroupV2Details
import io.olvid.engine.identity.databases.ContactGroupV2Member
import io.olvid.engine.identity.databases.ContactGroupV2PendingMember
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import io.olvid.engine.protocol.datatypes.ProtocolStarterDelegate
import java.sql.SQLException
import java.util.Arrays

@JsonIgnoreProperties(ignoreUnknown = true)
class GroupV2SyncSnapshot : ObvSyncSnapshotNode {
    @JvmField var permissions: HashSet<String?>? = null
    @JvmField var version: Int? = null
    @JvmField var details: GroupDetailsSyncSnapshot? = null
    var trusted_details: GroupDetailsSyncSnapshot? =
        null // on restore use version - 1 as a version number for this
    @JvmField var verified_admin_chain: ByteArray? = null
    @JvmField var main_seed: ByteArray? = null
    @JvmField var version_seed: ByteArray? = null
    @JvmField var encoded_admin_key: ByteArray? = null
    @JvmField var invitation_nonce: ByteArray? = null
    @JvmField var last_modification_timestamp: Long? = null
    @JvmField var push_topic: String? = null
    @JvmField var serialized_shared_settings: String? = null
    @JvmField var serialized_group_type: String? = null

    @JsonSerialize(keyUsing = ObvBytesKey.KeySerializer::class)
    @JsonDeserialize(keyUsing = ObvBytesKey.KeyDeserializer::class)
    var members: HashMap<ObvBytesKey?, GroupV2Member?>? = null

    @JsonSerialize(keyUsing = ObvBytesKey.KeySerializer::class)
    @JsonDeserialize(keyUsing = ObvBytesKey.KeyDeserializer::class)
    var pending_members: HashMap<ObvBytesKey?, GroupV2PendingMember?>? = null
    @JvmField var domain: HashSet<String>? = null


    @JsonIgnore
    @Throws(Exception::class)
    fun restore(
        identityManagerSession: IdentityManagerSession,
        protocolStarterDelegate: ProtocolStarterDelegate,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier
    ): ContactGroupV2 {
        if (!domain!!.contains(PERMISSIONS) || !domain!!.contains(DETAILS) || !domain!!.contains(
                INVITATION_NONCE
            ) || !domain!!.contains(MEMBERS) || !domain!!.contains(PENDING_MEMBERS) || (groupIdentifier.category == GroupV2.Identifier.CATEGORY_SERVER && (!domain!!.contains(
                VERSION
            ) || !domain!!.contains(VERIFIED_ADMIN_CHAIN) || !domain!!.contains(MAIN_SEED) || !domain!!.contains(
                VERSION_SEED
            ) || !domain!!.contains(ENCODED_ADMIN_KEY)))
        ) {
            Logger.e("Trying to restore an incomplete GroupV2SyncSnapshot. Domain: " + domain)
            throw Exception()
        }

        // restore the details
        val contactGroupV2Details = details!!.restoreGroupV2(
            identityManagerSession,
            ownedIdentity!!,
            groupIdentifier,
            (if (version == null) 0 else version)!!
        )
        val trustedDetails: ContactGroupV2Details?
        if (domain!!.contains(TRUSTED_DETAILS) && trusted_details != null && groupIdentifier.category == GroupV2.Identifier.CATEGORY_SERVER) {
            trustedDetails = trusted_details!!.restoreGroupV2(
                identityManagerSession,
                ownedIdentity,
                groupIdentifier,
                if (version == null) -1 else version!! - 1
            )
        } else {
            trustedDetails = null
        }

        // restore the group
        val blobKeys: BlobKeys?
        if (groupIdentifier.category == GroupV2.Identifier.CATEGORY_SERVER) {
            val serverAuthenticationPrivateKey: ServerAuthenticationPrivateKey?
            if (encoded_admin_key != null) {
                serverAuthenticationPrivateKey =
                    Encoded(encoded_admin_key!!).decodePrivateKey() as ServerAuthenticationPrivateKey?
            } else {
                serverAuthenticationPrivateKey = null
            }
            blobKeys = if ((main_seed == null) || (version_seed == null)) null else BlobKeys(
                Seed(main_seed!!),
                Seed(version_seed!!),
                serverAuthenticationPrivateKey
            )
        } else {
            blobKeys = null
        }

        val groupV2 = ContactGroupV2(
            identityManagerSession,
            groupIdentifier.groupUid,
            groupIdentifier.serverUrl,
            groupIdentifier.category,
            ownedIdentity,
            GroupV2.Permission.serializePermissionStrings(permissions?.filterNotNull()?.toMutableList() ?: mutableListOf()),
            contactGroupV2Details.version,
            verified_admin_chain,
            blobKeys,
            invitation_nonce!!,
            false,
            (if (domain!!.contains(io.olvid.engine.identity.databases.sync.GroupV2SyncSnapshot.LAST_MODIFICATION_TIMESTAMP) && last_modification_timestamp != null) last_modification_timestamp else java.lang.System.currentTimeMillis())!!,
            if (domain!!.contains(PUSH_TOPIC)) push_topic else null,
            if (domain!!.contains(SERIALIZED_SHARED_SETTINGS)) serialized_shared_settings else null,
            serialized_group_type
        )
        if (trustedDetails != null) {
            groupV2.trustedDetailsVersion = trustedDetails.version
        }
        groupV2.insert()

        // restore members
        for (memberEntry in members!!.entries) {
            val memberIdentity = Identity.of(memberEntry.key!!.getBytes())
            ContactGroupV2Member.create(
                identityManagerSession,
                ownedIdentity,
                groupIdentifier,
                memberIdentity,
                memberEntry.value!!.permissions?.filterNotNull()?.toMutableList(),
                memberEntry.value!!.invitation_nonce
            )
        }

        // restore pending members
        for (pendingMemberEntry in pending_members!!.entries) {
            val pendingMemberIdentity = Identity.of(pendingMemberEntry.key!!.getBytes())
            ContactGroupV2PendingMember.create(
                identityManagerSession,
                ownedIdentity,
                groupIdentifier,
                pendingMemberIdentity,
                pendingMemberEntry.value!!.serialized_details,
                pendingMemberEntry.value!!.permissions?.filterNotNull()?.toMutableList(),
                pendingMemberEntry.value!!.invitation_nonce
            )
        }

        try {
            protocolStarterDelegate.initiateGroupV2ReDownloadWithinTransaction(
                identityManagerSession.session,
                ownedIdentity,
                groupIdentifier
            )
        } catch (e: Exception) {
            Logger.x(e)
        }

        return groupV2
    }

    override fun areContentsTheSame(otherSnapshotNode: ObvSyncSnapshotNode?): Boolean {
        // TODO areContentsTheSame
        return false
    }

    @Throws(Exception::class)
    override fun computeDiff(otherSnapshotNode: ObvSyncSnapshotNode?): MutableList<ObvSyncDiff?>? {
        // TODO computeDiff
        return null
    }


    @JsonIgnoreProperties(ignoreUnknown = true)
    class GroupV2Member {
        @JvmField var permissions: HashSet<String?>? = null
        @JvmField var invitation_nonce: ByteArray? = null

        companion object {
            fun of(groupMember: ContactGroupV2Member): GroupV2Member {
                val groupV2Member = GroupV2Member()
                groupV2Member.permissions =
                    HashSet<String?>(deserializePermissions(groupMember.serializedPermissions))
                groupV2Member.invitation_nonce = groupMember.getGroupInvitationNonce()
                return groupV2Member
            }
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class GroupV2PendingMember {
        @JvmField var serialized_details: String? = null
        @JvmField var permissions: HashSet<String?>? = null
        @JvmField var invitation_nonce: ByteArray? = null

        companion object {
            fun of(pendingGroupMember: ContactGroupV2PendingMember): GroupV2PendingMember {
                val groupV2PendingMember = GroupV2PendingMember()
                groupV2PendingMember.serialized_details =
                    pendingGroupMember.getSerializedContactDetails()
                groupV2PendingMember.permissions =
                    HashSet<String?>(deserializePermissions(pendingGroupMember.serializedPermissions))
                groupV2PendingMember.invitation_nonce = pendingGroupMember.getGroupInvitationNonce()
                return groupV2PendingMember
            }
        }
    }

    companion object {
        const val PERMISSIONS: String = "permissions"
        const val VERSION: String = "version"
        const val DETAILS: String = "details"
        const val TRUSTED_DETAILS: String = "trusted_details"
        const val VERIFIED_ADMIN_CHAIN: String = "verified_admin_chain"
        const val MAIN_SEED: String = "main_seed"
        const val VERSION_SEED: String = "version_seed"
        const val ENCODED_ADMIN_KEY: String = "encoded_admin_key"
        const val INVITATION_NONCE: String = "invitation_nonce"
        const val LAST_MODIFICATION_TIMESTAMP: String = "last_modification_timestamp"
        const val PUSH_TOPIC: String = "push_topic"
        const val SERIALIZED_SHARED_SETTINGS: String = "serialized_shared_settings"
        const val SERIALIZED_GROUP_TYPE: String = "serialized_group_type"
        const val MEMBERS: String = "members"
        const val PENDING_MEMBERS: String = "pending_members"
        var DEFAULT_SERVER_DOMAIN: HashSet<String> = HashSet(
            listOf(
                PERMISSIONS,
                VERSION,
                DETAILS,
                TRUSTED_DETAILS,
                VERIFIED_ADMIN_CHAIN,
                MAIN_SEED,
                VERSION_SEED,
                ENCODED_ADMIN_KEY,
                INVITATION_NONCE,
                SERIALIZED_GROUP_TYPE,
                MEMBERS,
                PENDING_MEMBERS
            )
        )
        var DEFAULT_KEYCLOAK_DOMAIN: HashSet<String> = HashSet(
            listOf(
                PERMISSIONS,
                DETAILS,
                INVITATION_NONCE,
                LAST_MODIFICATION_TIMESTAMP,
                PUSH_TOPIC,
                SERIALIZED_SHARED_SETTINGS,
                MEMBERS,
                PENDING_MEMBERS
            )
        )


        @JvmStatic
        @Throws(SQLException::class)
        fun of(
            identityManagerSession: IdentityManagerSession?,
            group2: ContactGroupV2
        ): GroupV2SyncSnapshot {
            val groupV2SyncSnapshot = GroupV2SyncSnapshot()

            groupV2SyncSnapshot.permissions = HashSet<String?>(group2.ownPermissionStrings)

            val publishedDetails: ContactGroupV2Details? = ContactGroupV2Details.get(
                identityManagerSession!!,
                group2.ownedIdentity,
                group2.groupIdentifier,
                group2.version
            )
            if (publishedDetails != null) {
                groupV2SyncSnapshot.details =
                    GroupDetailsSyncSnapshot.of(identityManagerSession, publishedDetails)
            }
            groupV2SyncSnapshot.invitation_nonce = group2.ownGroupInvitationNonce

            if (group2.groupIdentifier.category == GroupV2.Identifier.CATEGORY_SERVER) {
                // normal group v2
                groupV2SyncSnapshot.version = group2.version
                if (group2.getTrustedDetailsVersion() != group2.version) {
                    val trustedDetails: ContactGroupV2Details? =
                        ContactGroupV2Details.get(
                            identityManagerSession,
                            group2.ownedIdentity,
                            group2.groupIdentifier,
                            group2.getTrustedDetailsVersion()
                        )
                    if (trustedDetails != null) {
                        groupV2SyncSnapshot.trusted_details = GroupDetailsSyncSnapshot.of(
                            identityManagerSession,
                            trustedDetails
                        )
                    }
                }
                groupV2SyncSnapshot.verified_admin_chain = group2.verifiedAdministratorsChain
                groupV2SyncSnapshot.main_seed = group2.blobMainSeed?.getBytes()
                groupV2SyncSnapshot.version_seed = group2.blobVersionSeed?.getBytes()
                val adminKey = group2.groupAdminServerAuthenticationPrivateKey
                if (adminKey != null) {
                    groupV2SyncSnapshot.encoded_admin_key = Encoded.of(adminKey).bytes
                }
                groupV2SyncSnapshot.serialized_group_type = group2.serializedJsonGroupType
                groupV2SyncSnapshot.last_modification_timestamp = null
                groupV2SyncSnapshot.domain = DEFAULT_SERVER_DOMAIN
            } else {
                // keycloak group v2
                groupV2SyncSnapshot.last_modification_timestamp =
                    group2.lastModificationTimestamp
                groupV2SyncSnapshot.push_topic = group2.pushTopic
                groupV2SyncSnapshot.serialized_shared_settings =
                    group2.serializedSharedSettings
                groupV2SyncSnapshot.domain = DEFAULT_KEYCLOAK_DOMAIN
            }

            groupV2SyncSnapshot.members = HashMap<ObvBytesKey?, GroupV2Member?>()
            for (groupV2Member in ContactGroupV2Member.getAll(
                identityManagerSession,
                group2.ownedIdentity,
                group2.groupIdentifier
            ) ?: emptyList()) {
                val m = groupV2Member ?: continue
                groupV2SyncSnapshot.members!![ObvBytesKey(m.contactIdentity.getBytes())] = GroupV2Member.of(m)
            }

            groupV2SyncSnapshot.pending_members = HashMap<ObvBytesKey?, GroupV2PendingMember?>()
            for (groupV2PendingMember in ContactGroupV2PendingMember.getAll(
                identityManagerSession,
                group2.ownedIdentity,
                group2.groupIdentifier
            ) ?: emptyList()) {
                val pm = groupV2PendingMember ?: continue
                groupV2SyncSnapshot.pending_members!![ObvBytesKey(pm.contactIdentity.getBytes())] = GroupV2PendingMember.of(pm)
            }

            return groupV2SyncSnapshot
        }
    }
}
