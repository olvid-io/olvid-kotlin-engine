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
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.ObvBytesKey
import io.olvid.engine.engine.types.sync.ObvSyncDiff
import io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode
import io.olvid.engine.identity.databases.ContactGroup
import io.olvid.engine.identity.databases.ContactGroupDetails
import io.olvid.engine.identity.databases.ContactGroupMembersJoin
import io.olvid.engine.identity.databases.PendingGroupMember
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import java.sql.SQLException
import java.util.Arrays

@JsonIgnoreProperties(ignoreUnknown = true)
class GroupV1SyncSnapshot : ObvSyncSnapshotNode {
    @JvmField var published_details: GroupDetailsSyncSnapshot? = null
    var trusted_details: GroupDetailsSyncSnapshot? =
        null // only for groups you do not own, null if same as published
    @JvmField var group_members_version: Long? = null

    @JsonSerialize(contentUsing = ObvBytesKey.Serializer::class)
    @JsonDeserialize(contentUsing = ObvBytesKey.Deserializer::class)
    @JvmField var members: HashSet<ObvBytesKey>? = null

    @JsonSerialize(keyUsing = ObvBytesKey.KeySerializer::class)
    @JsonDeserialize(keyUsing = ObvBytesKey.KeyDeserializer::class)
    var pending_members: HashMap<ObvBytesKey?, GroupV1PendingMember?>? = null
    @JvmField var domain: HashSet<String>? = null

    @JsonIgnore
    @Throws(Exception::class)
    fun restore(
        identityManagerSession: IdentityManagerSession?,
        ownedIdentity: Identity,
        groupOwnerIdentity: Identity,
        groupOwnerAndUid: ByteArray
    ): ContactGroup {
        if (!domain!!.contains(GROUP_MEMBERS_VERSION) || !domain!!.contains(MEMBERS) || !domain!!.contains(
                PENDING_MEMBERS
            ) || !domain!!.contains(PUBLISHED_DETAILS)
        ) {
            Logger.e("Trying to restore an incomplete GroupV1SyncSnapshot. Domain: " + domain)
            throw Exception()
        }

        val contactGroup: ContactGroup
        if (groupOwnerIdentity == ownedIdentity) {
            val publishedDetails = published_details!!.restoreGroup(
                identityManagerSession,
                ownedIdentity,
                groupOwnerIdentity,
                groupOwnerAndUid
            )

            contactGroup = ContactGroup(
                identityManagerSession!!,
                groupOwnerAndUid,
                ownedIdentity,
                null,
                publishedDetails.version
            )
            contactGroup.groupMembersVersion = group_members_version!!
            contactGroup.insert()
        } else {
            val trustedDetails: ContactGroupDetails?
            val publishedDetails = published_details!!.restoreGroup(
                identityManagerSession,
                ownedIdentity,
                groupOwnerIdentity,
                groupOwnerAndUid
            )
            if (domain!!.contains(TRUSTED_DETAILS) && trusted_details != null && (trusted_details!!.version != published_details!!.version)) {
                trustedDetails = trusted_details!!.restoreGroup(
                    identityManagerSession,
                    ownedIdentity,
                    groupOwnerIdentity,
                    groupOwnerAndUid
                )
            } else {
                trustedDetails = null
            }
            contactGroup = ContactGroup(
                identityManagerSession!!,
                groupOwnerAndUid,
                ownedIdentity,
                groupOwnerIdentity,
                publishedDetails.version
            )
            if (trustedDetails != null) {
                contactGroup.latestOrTrustedDetailsVersion = trustedDetails.version
            }
            contactGroup.groupMembersVersion = group_members_version!!
            contactGroup.insert()
        }

        // restore members
        for (member in members!!) {
            val memberIdentity = Identity.of(member.getBytes())
            ContactGroupMembersJoin.create(
                identityManagerSession,
                groupOwnerAndUid,
                ownedIdentity,
                memberIdentity
            )
        }

        // restore pending members
        for (pendingMemberEntry in pending_members!!.entries) {
            val pendingMemberIdentity = Identity.of(pendingMemberEntry.key!!.getBytes())
            val pendingGroupMember = PendingGroupMember(
                identityManagerSession,
                groupOwnerAndUid,
                ownedIdentity,
                pendingMemberIdentity,
                pendingMemberEntry.value!!.serialized_details ?: ""
            )
            pendingGroupMember.declined =
                pendingMemberEntry.value!!.declined != null && pendingMemberEntry.value!!.declined == true
            pendingGroupMember.insert()
        }

        return contactGroup
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
    class GroupV1PendingMember {
        @JvmField var serialized_details: String? = null
        @JvmField var declined: Boolean? = null

        companion object {
            fun of(pendingGroupMember: PendingGroupMember): GroupV1PendingMember {
                val groupV1PendingMember = GroupV1PendingMember()
                groupV1PendingMember.serialized_details =
                    pendingGroupMember.contactSerializedDetails
                groupV1PendingMember.declined = if (pendingGroupMember.isDeclined()) true else null
                return groupV1PendingMember
            }
        }
    }

    companion object {
        const val PUBLISHED_DETAILS: String = "published_details"
        const val TRUSTED_DETAILS: String = "trusted_details"
        const val GROUP_MEMBERS_VERSION: String = "group_members_version"
        const val MEMBERS: String = "members"
        const val PENDING_MEMBERS: String = "pending_members"
        var DEFAULT_JOINED_DOMAIN: HashSet<String> = HashSet(
            listOf(
                PUBLISHED_DETAILS, TRUSTED_DETAILS, GROUP_MEMBERS_VERSION, MEMBERS, PENDING_MEMBERS
            )
        )
        var DEFAULT_OWNED_DOMAIN: HashSet<String> = HashSet(
            listOf(
                PUBLISHED_DETAILS, GROUP_MEMBERS_VERSION, MEMBERS, PENDING_MEMBERS
            )
        )


        @JvmStatic
        @Throws(SQLException::class)
        fun of(
            identityManagerSession: IdentityManagerSession?,
            group: ContactGroup
        ): GroupV1SyncSnapshot {
            val groupV1SyncSnapshot = GroupV1SyncSnapshot()

            groupV1SyncSnapshot.published_details = GroupDetailsSyncSnapshot.of(
                identityManagerSession,
                group.publishedDetails!!
            )
            if (group.groupOwner == null) {
                groupV1SyncSnapshot.domain = DEFAULT_OWNED_DOMAIN
            } else {
                if (group.publishedDetailsVersion != group.latestOrTrustedDetailsVersion) {
                    groupV1SyncSnapshot.trusted_details = GroupDetailsSyncSnapshot.of(
                        identityManagerSession,
                        group.latestOrTrustedDetails!!
                    )
                }
                groupV1SyncSnapshot.domain = DEFAULT_JOINED_DOMAIN
            }

            groupV1SyncSnapshot.group_members_version = group.getGroupMembersVersion()

            groupV1SyncSnapshot.members = HashSet<ObvBytesKey>()
            for (memberIdentity in ContactGroupMembersJoin.getContactIdentitiesInGroup(
                identityManagerSession!!,
                group.groupOwnerAndUid,
                group.getOwnedIdentity()
            )) {
                groupV1SyncSnapshot.members!!.add(ObvBytesKey(memberIdentity.getBytes()))
            }

            groupV1SyncSnapshot.pending_members = HashMap()
            for (pendingGroupMember in PendingGroupMember.getAllInGroup(
                identityManagerSession,
                group.groupOwnerAndUid,
                group.getOwnedIdentity()
            )) {
                val pgm = pendingGroupMember ?: continue
                groupV1SyncSnapshot.pending_members!![ObvBytesKey(
                    pgm.getContactIdentity().getBytes()
                )] = GroupV1PendingMember.of(pgm)
            }

            return groupV1SyncSnapshot
        }
    }
}
