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
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.sync.ObvSyncDiff
import io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode
import io.olvid.engine.identity.databases.ContactIdentityDetails
import io.olvid.engine.identity.databases.OwnedIdentityDetails
import io.olvid.engine.identity.databases.ServerUserData
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import java.util.Arrays
import kotlin.collections.HashSet
import kotlin.collections.MutableList
import kotlin.collections.contentEquals

// This class is used for both owned identity and contacts
@JsonIgnoreProperties(ignoreUnknown = true)
class IdentityDetailsSyncSnapshot : ObvSyncSnapshotNode {
    @JvmField var version: Int? = null
    @JvmField var serialized_details: String? = null
    @JvmField var photo_server_label: ByteArray? = null
    @JvmField var photo_server_key: ByteArray? = null
    @JvmField var domain: HashSet<String>? = null


    @JsonIgnore
    @Throws(Exception::class)
    fun restoreOwned(
        identityManagerSession: IdentityManagerSession?,
        ownedIdentity: Identity?
    ): OwnedIdentityDetails {
        if (!domain!!.contains(VERSION) || !domain!!.contains(SERIALIZED_DETAILS)) {
            Logger.e("Trying to restore an incomplete IdentityDetailsSyncSnapshot. Domain: " + domain)
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
        val ownedIdentityDetails = OwnedIdentityDetails(
            identityManagerSession!!,
            ownedIdentity!!,
            version!!,
            serialized_details,
            null,
            photoServerLabel,
            photoServerKey
        )
        ownedIdentityDetails.insert()
        if (photoServerLabel != null && photoServerKey != null) {
            ServerUserData.createForOwnedIdentityDetails(
                identityManagerSession,
                ownedIdentity,
                photoServerLabel
            )
        }
        return ownedIdentityDetails
    }

    @JsonIgnore
    @Throws(Exception::class)
    fun restoreContact(
        identityManagerSession: IdentityManagerSession?,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): ContactIdentityDetails {
        if (!domain!!.contains(VERSION) || !domain!!.contains(SERIALIZED_DETAILS)) {
            Logger.e("Trying to restore an incomplete IdentityDetailsSyncSnapshot. Domain: " + domain)
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
        val contactIdentityDetails = ContactIdentityDetails(
            identityManagerSession!!,
            contactIdentity!!,
            ownedIdentity!!,
            version!!,
            serialized_details,
            null,
            photoServerLabel,
            photoServerKey
        )
        contactIdentityDetails.insert()
        return contactIdentityDetails
    }

    override fun areContentsTheSame(otherSnapshotNode: ObvSyncSnapshotNode?): Boolean {
        if (otherSnapshotNode !is IdentityDetailsSyncSnapshot) {
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
        const val PHOTO_SERVER_LABEL: String = "photo_server_label"
        const val PHOTO_SERVER_KEY: String = "photo_server_key"
        var DEFAULT_DOMAIN: HashSet<String> = HashSet(
            listOf(
                VERSION,
                SERIALIZED_DETAILS,
                PHOTO_SERVER_LABEL,
                PHOTO_SERVER_KEY
            )
        )


        @JvmStatic
        fun of(
            identityManagerSession: IdentityManagerSession?,
            ownedIdentityDetails: OwnedIdentityDetails
        ): IdentityDetailsSyncSnapshot {
            val identityDetailsSyncSnapshot = IdentityDetailsSyncSnapshot()
            identityDetailsSyncSnapshot.version = ownedIdentityDetails.version
            identityDetailsSyncSnapshot.serialized_details =
                ownedIdentityDetails.serializedJsonDetails
            val opsl = ownedIdentityDetails.photoServerLabel
            val opsk = ownedIdentityDetails.photoServerKey
            if (opsl != null && opsk != null) {
                identityDetailsSyncSnapshot.photo_server_label = opsl.bytes
                identityDetailsSyncSnapshot.photo_server_key = Encoded.of(opsk).bytes
            }
            identityDetailsSyncSnapshot.domain = DEFAULT_DOMAIN
            return identityDetailsSyncSnapshot
        }

        fun of(
            identityManagerSession: IdentityManagerSession?,
            contactIdentityDetails: ContactIdentityDetails
        ): IdentityDetailsSyncSnapshot {
            val identityDetailsSyncSnapshot = IdentityDetailsSyncSnapshot()
            identityDetailsSyncSnapshot.version = contactIdentityDetails.version
            identityDetailsSyncSnapshot.serialized_details =
                contactIdentityDetails.getSerializedJsonDetails()
            val cpsl = contactIdentityDetails.photoServerLabel
            val cpsk = contactIdentityDetails.photoServerKey
            if (cpsl != null && cpsk != null) {
                identityDetailsSyncSnapshot.photo_server_label = cpsl.bytes
                identityDetailsSyncSnapshot.photo_server_key = Encoded.of(cpsk).bytes
            }
            identityDetailsSyncSnapshot.domain = DEFAULT_DOMAIN
            return identityDetailsSyncSnapshot
        }
    }
}
