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
import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.sync.ObvSyncDiff
import io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode
import io.olvid.engine.identity.databases.ContactGroupDetails
import io.olvid.engine.identity.databases.ContactGroupV2Details
import io.olvid.engine.identity.databases.ServerUserData
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import java.util.Arrays
import kotlin.collections.HashSet
import kotlin.collections.MutableList
import kotlin.collections.contentEquals

// This class is used for both owned identity and contacts
@JsonIgnoreProperties(ignoreUnknown = true)
class GroupDetailsSyncSnapshot : ObvSyncSnapshotNode {
    @JvmField var version: Int? = null
    @JvmField var serialized_details: String? = null
    @JvmField var photo_server_identity: ByteArray? = null // non-null only for group v2 (as we don't know which admin hosts the photo)
    @JvmField var photo_server_label: ByteArray? = null
    @JvmField var photo_server_key: ByteArray? = null
    @JvmField var domain: HashSet<String>? = null


    @JsonIgnore
    @Throws(Exception::class)
    fun restoreGroup(
        identityManagerSession: IdentityManagerSession?,
        ownedIdentity: Identity?,
        groupOwnerIdentity: Identity,
        groupOwnerAndUid: ByteArray
    ): ContactGroupDetails {
        if (!domain!!.contains(VERSION) || !domain!!.contains(SERIALIZED_DETAILS)) {
            Logger.e("Trying to restoreGroup an incomplete GroupDetailsSyncSnapshot. Domain: " + domain)
            throw Exception()
        }

        var photoServerLabel: UID? = null
        var photoServerKey: AuthEncKey? = null
        if (domain!!.contains(PHOTO_SERVER_LABEL) && domain!!.contains(PHOTO_SERVER_KEY) && photo_server_key != null && photo_server_label != null) {
            try {
                photoServerLabel = UID(photo_server_label!!)
                photoServerKey = Encoded(photo_server_key!!).decodeSymmetricKey() as AuthEncKey?
            } catch (e: Exception) {
                Logger.x(e)
                photoServerLabel = null
                photoServerKey = null
            }
        } else {
            photoServerLabel = null
            photoServerKey = null
        }

        val contactGroupDetails = ContactGroupDetails(
            identityManagerSession!!,
            groupOwnerAndUid,
            ownedIdentity!!,
            version!!,
            serialized_details,
            null,
            photoServerLabel,
            photoServerKey
        )
        contactGroupDetails.insert()
        if (groupOwnerIdentity.equals(ownedIdentity) && photoServerLabel != null && photoServerKey != null) {
            ServerUserData.createForOwnedGroupDetails(
                identityManagerSession,
                ownedIdentity,
                photoServerLabel,
                groupOwnerAndUid
            )
        }
        return contactGroupDetails
    }

    @JsonIgnore
    @Throws(Exception::class)
    fun restoreGroupV2(
        identityManagerSession: IdentityManagerSession?,
        ownedIdentity: Identity,
        groupIdentifier: GroupV2.Identifier,
        version: Int
    ): ContactGroupV2Details {
        if (!domain!!.contains(SERIALIZED_DETAILS)) {
            Logger.e("Trying to restoreGroupV2 an incomplete GroupDetailsSyncSnapshot. Domain: " + domain)
            throw Exception()
        }

        var photoServerIdentity: Identity? = null
        var photoServerLabel: UID? = null
        var photoServerKey: AuthEncKey? = null
        if (domain!!.contains(PHOTO_SERVER_IDENTITY) && domain!!.contains(PHOTO_SERVER_LABEL) && domain!!.contains(
                PHOTO_SERVER_KEY
            ) && photo_server_key != null && photo_server_label != null
        ) {
            try {
                photoServerIdentity =
                    if (photo_server_identity == null) null else Identity.of(photo_server_identity!!)
                photoServerLabel = UID(photo_server_label!!)
                photoServerKey = Encoded(photo_server_key!!).decodeSymmetricKey() as AuthEncKey?
            } catch (e: Exception) {
                Logger.x(e)
                photoServerIdentity = null
                photoServerLabel = null
                photoServerKey = null
            }
        } else {
            photoServerIdentity = null
            photoServerLabel = null
            photoServerKey = null
        }

        val contactGroupV2Details = ContactGroupV2Details(
            identityManagerSession!!,
            groupIdentifier.groupUid,
            groupIdentifier.serverUrl,
            groupIdentifier.category,
            ownedIdentity,
            version,
            serialized_details,
            null,
            photoServerIdentity,
            photoServerLabel,
            photoServerKey
        )
        contactGroupV2Details.insert()
        if (ownedIdentity.equals(photoServerIdentity)) {
            ServerUserData.createForGroupV2(
                identityManagerSession,
                ownedIdentity,
                photoServerLabel,
                groupIdentifier.bytes
            )
        }
        return contactGroupV2Details
    }

    override fun areContentsTheSame(otherSnapshotNode: ObvSyncSnapshotNode?): Boolean {
        if (otherSnapshotNode !is GroupDetailsSyncSnapshot) {
            return false
        }

        val other = otherSnapshotNode
        val domainIntersection = HashSet<String?>(domain)
        domainIntersection.retainAll(other.domain ?: emptySet())

        for (item in domainIntersection) {
            when (item) {
                VERSION -> {
                    if (version != other.version) {
                        return false
                    }
                }

                SERIALIZED_DETAILS -> {
                    // TODO: we need to deserialize here for the comparison
                    if (serialized_details != other.serialized_details) {
                        return false
                    }
                }

                PHOTO_SERVER_IDENTITY -> {
                    if (!photo_server_identity.contentEquals(other.photo_server_identity)) {
                        return false
                    }
                }

                PHOTO_SERVER_LABEL -> {
                    if (!photo_server_label.contentEquals(other.photo_server_label)) {
                        return false
                    }
                }

                PHOTO_SERVER_KEY -> {
                    try {
                        if ((photo_server_key == null && other.photo_server_key != null)
                            || (photo_server_key != null && other.photo_server_key == null)
                            || (photo_server_key != null && Encoded(photo_server_key!!).decodeSymmetricKey() != Encoded(
                                other.photo_server_key!!
                            ).decodeSymmetricKey())
                        ) {
                            return false
                        }
                    } catch (_: DecodingException) {
                        return false
                    }
                }
            }
        }
        return true
    }

    @Throws(Exception::class)
    override fun computeDiff(otherSnapshotNode: ObvSyncSnapshotNode?): MutableList<ObvSyncDiff?>? {
        // TODO computeDiff
        return null
    }

    companion object {
        const val VERSION: String = "version"
        const val SERIALIZED_DETAILS: String = "serialized_details"
        const val PHOTO_SERVER_IDENTITY: String = "photo_server_identity"
        const val PHOTO_SERVER_LABEL: String = "photo_server_label"
        const val PHOTO_SERVER_KEY: String = "photo_server_key"
        var DEFAULT_V1_DOMAIN: HashSet<String> = HashSet(
            listOf(
                VERSION,
                SERIALIZED_DETAILS,
                PHOTO_SERVER_LABEL,
                PHOTO_SERVER_KEY
            )
        )
        var DEFAULT_V2_DOMAIN: HashSet<String> = HashSet(
            listOf(
                SERIALIZED_DETAILS, PHOTO_SERVER_IDENTITY, PHOTO_SERVER_LABEL, PHOTO_SERVER_KEY
            )
        )


        @JvmStatic
        fun of(
            identityManagerSession: IdentityManagerSession?,
            contactGroupDetails: ContactGroupDetails
        ): GroupDetailsSyncSnapshot {
            val groupDetailsSyncSnapshot = GroupDetailsSyncSnapshot()
            groupDetailsSyncSnapshot.version = contactGroupDetails.version
            groupDetailsSyncSnapshot.serialized_details =
                contactGroupDetails.serializedJsonDetails
            val psl = contactGroupDetails.photoServerLabel
            val psk = contactGroupDetails.photoServerKey
            if (psl != null && psk != null) {
                groupDetailsSyncSnapshot.photo_server_label = psl.bytes
                groupDetailsSyncSnapshot.photo_server_key = Encoded.of(psk).bytes
            }
            groupDetailsSyncSnapshot.domain = DEFAULT_V1_DOMAIN
            return groupDetailsSyncSnapshot
        }

        fun of(
            identityManagerSession: IdentityManagerSession?,
            contactGroupV2Details: ContactGroupV2Details
        ): GroupDetailsSyncSnapshot {
            val groupDetailsSyncSnapshot = GroupDetailsSyncSnapshot()
            groupDetailsSyncSnapshot.serialized_details =
                contactGroupV2Details.serializedJsonDetails
            val psi = contactGroupV2Details.photoServerIdentity
            val psl2 = contactGroupV2Details.photoServerLabel
            val psk2 = contactGroupV2Details.photoServerKey
            if (psl2 != null && psk2 != null) {
                groupDetailsSyncSnapshot.photo_server_identity = psi?.getBytes()
                groupDetailsSyncSnapshot.photo_server_label = psl2.bytes
                groupDetailsSyncSnapshot.photo_server_key = Encoded.of(psk2).bytes
            }
            groupDetailsSyncSnapshot.domain = DEFAULT_V2_DOMAIN
            return groupDetailsSyncSnapshot
        }
    }
}
