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
import io.olvid.engine.datatypes.TrustLevel
import io.olvid.engine.engine.types.sync.ObvSyncDiff
import io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode
import io.olvid.engine.identity.databases.ContactIdentity
import io.olvid.engine.identity.databases.ContactIdentityDetails
import io.olvid.engine.identity.databases.ContactTrustOrigin
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import java.sql.SQLException

@JsonIgnoreProperties(ignoreUnknown = true)
class ContactSyncSnapshot : ObvSyncSnapshotNode {
    @JvmField var trusted_details: IdentityDetailsSyncSnapshot? = null
    @JvmField var published_details: IdentityDetailsSyncSnapshot? = null // null if equal to trusted details
    @JvmField var one_to_one: Boolean? = null
    @JvmField var revoked: Boolean? = null
    @JvmField var forcefully_trusted: Boolean? = null
    var trust_level: String? =
        null // only used for backup/transfer, not taken into account when comparing for synchronization
    var trust_origins: MutableList<TrustOrigin>? =
        null // only used for backup/transfer, not taken into account when comparing for synchronization
    @JvmField var domain: HashSet<String>? = null


    @JsonIgnore
    @Throws(Exception::class)
    fun restore(
        identityManagerSession: IdentityManagerSession,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): ContactIdentity {
        if (!domain!!.contains(TRUSTED_DETAILS)) {
            Logger.e("Trying to restore an incomplete ContactSyncSnapshot. Domain: " + domain)
            throw Exception()
        }

        // restore the trusted details
        val trustedDetails =
            trusted_details!!.restoreContact(identityManagerSession, ownedIdentity, contactIdentity)
        val publishedDetails: ContactIdentityDetails?
        if (domain!!.contains(PUBLISHED_DETAILS) && published_details != null && (trusted_details!!.version != published_details!!.version)) {
            publishedDetails = published_details!!.restoreContact(
                identityManagerSession,
                ownedIdentity,
                contactIdentity
            )
        } else {
            publishedDetails = null
        }

        val trustLevel =
            if (domain!!.contains(TRUST_LEVEL) && trust_level != null) TrustLevel.of(trust_level!!) else TrustLevel(
                0,
                0
            )
        val oneToOne: Int =
            if (domain!!.contains(ONE_TO_ONE) && one_to_one != null) (if (one_to_one == true) ContactIdentity.ONE_TO_ONE_STATUS_TRUE else ContactIdentity.ONE_TO_ONE_STATUS_FALSE) else ContactIdentity.ONE_TO_ONE_STATUS_UNKNOWN

        val contactIdentityObject = ContactIdentity(
            identityManagerSession,
            contactIdentity!!,
            ownedIdentity!!,
            trustedDetails.version,
            trustLevel,
            oneToOne
        )
        if (publishedDetails != null) {
            contactIdentityObject.publishedDetailsVersion = publishedDetails.version
        }
        contactIdentityObject.revokedAsCompromised =
            domain!!.contains(REVOKED) && revoked != null && revoked == true
        contactIdentityObject.forcefullyTrustedByUser =
            domain!!.contains(FORCEFULLY_TRUSTED) && forcefully_trusted != null && forcefully_trusted == true
        contactIdentityObject.insert()

        // check for keycloak badge
        val jsonKeycloakUserDetails =
            identityManagerSession.identityDelegate?.verifyKeycloakIdentitySignature(
                identityManagerSession.session,
                ownedIdentity,
                trustedDetails.jsonIdentityDetailsWithVersionAndPhoto?.getIdentityDetails()
                    ?.getSignedUserDetails()
            )
        if (jsonKeycloakUserDetails != null) {
            contactIdentityObject.setCertifiedByOwnKeycloak(
                true,
                trustedDetails.getSerializedJsonDetails()
            )
        }

        // restore trust origin
        if (domain!!.contains(TRUST_ORIGINS) && trust_origins != null) {
            for (trustOrigin in trust_origins) {
                var mediatorOrGroupOwnerIdentity: Identity? = null
                try {
                    if (trustOrigin.mediator_or_group_owner_identity != null) {
                        mediatorOrGroupOwnerIdentity =
                            Identity.of(trustOrigin.mediator_or_group_owner_identity!!)
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                }
                val trustType: Int
                when (TrustOrigin.TrustType.fromIntValue(trustOrigin.trust_type)) {
                    TrustOrigin.TrustType.TYPE_DIRECT -> trustType =
                        ContactTrustOrigin.TRUST_TYPE_DIRECT

                    TrustOrigin.TrustType.TYPE_GROUP -> trustType =
                        ContactTrustOrigin.TRUST_TYPE_GROUP

                    TrustOrigin.TrustType.TYPE_INTRODUCTION -> trustType =
                        ContactTrustOrigin.TRUST_TYPE_INTRODUCTION

                    TrustOrigin.TrustType.TYPE_KEYCLOAK -> trustType =
                        ContactTrustOrigin.TRUST_TYPE_IDENTITY_SERVER

                    TrustOrigin.TrustType.TYPE_SERVER_GROUP_V2 -> trustType =
                        ContactTrustOrigin.TRUST_TYPE_SERVER_GROUP_V2

                    else ->                         // ignore unknown trust types
                        continue
                }
                val contactTrustOrigin = ContactTrustOrigin(
                    identityManagerSession,
                    contactIdentity,
                    ownedIdentity,
                    trustOrigin.timestamp,
                    trustType,
                    mediatorOrGroupOwnerIdentity,
                    0,
                    trustOrigin.identity_server,
                    trustOrigin.raw_obv_group_v2_identifier
                )
                contactTrustOrigin.insert()
            }
        }

        return contactIdentityObject
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
    class TrustOrigin {
        internal enum class TrustType(val value: Int) {
            TYPE_DIRECT(0),
            TYPE_GROUP(1),
            TYPE_INTRODUCTION(2),
            TYPE_KEYCLOAK(3),
            TYPE_SERVER_GROUP_V2(4);

            companion object {
                private val valueMap: MutableMap<Int?, TrustType?> = HashMap()

                init {
                    for (trustType in entries) {
                        valueMap[trustType.value] = trustType
                    }
                }

                fun fromIntValue(value: Int): TrustType? {
                    return valueMap.get(value)
                }
            }
        }


        @JvmField var timestamp: Long = 0
        @JvmField var trust_type: Int = 0
        @JvmField var mediator_or_group_owner_identity: ByteArray? = null
        @JvmField var identity_server: String? = null
        @JvmField var raw_obv_group_v2_identifier: ByteArray? = null

        companion object {
            fun of(contactTrustOrigin: ContactTrustOrigin): TrustOrigin {
                val trustOrigin = contactTrustOrigin.trustOrigin!!

                val to = TrustOrigin()
                to.timestamp = trustOrigin.getTimestamp()
                when (trustOrigin.getType()) {
                    io.olvid.engine.datatypes.containers.TrustOrigin.TYPE.DIRECT -> {
                        to.trust_type = TrustType.TYPE_DIRECT.value
                    }

                    io.olvid.engine.datatypes.containers.TrustOrigin.TYPE.INTRODUCTION -> {
                        to.trust_type = TrustType.TYPE_INTRODUCTION.value
                        to.mediator_or_group_owner_identity =
                            trustOrigin.getMediatorOrGroupOwnerIdentity()?.getBytes()
                    }

                    io.olvid.engine.datatypes.containers.TrustOrigin.TYPE.GROUP -> {
                        to.trust_type = TrustType.TYPE_GROUP.value
                        to.mediator_or_group_owner_identity =
                            trustOrigin.getMediatorOrGroupOwnerIdentity()?.getBytes()
                    }

                    io.olvid.engine.datatypes.containers.TrustOrigin.TYPE.KEYCLOAK -> {
                        to.trust_type = TrustType.TYPE_KEYCLOAK.value
                        to.identity_server = trustOrigin.getKeycloakServer()
                    }

                    io.olvid.engine.datatypes.containers.TrustOrigin.TYPE.SERVER_GROUP_V2 -> {
                        to.trust_type = TrustType.TYPE_SERVER_GROUP_V2.value
                        to.raw_obv_group_v2_identifier = trustOrigin.getGroupIdentifier()?.bytes
                    }
                }

                return to
            }
        }
    }

    companion object {
        const val TRUSTED_DETAILS: String = "trusted_details"
        const val PUBLISHED_DETAILS: String = "published_details"
        const val ONE_TO_ONE: String = "one_to_one"
        const val REVOKED: String = "revoked"
        const val FORCEFULLY_TRUSTED: String = "forcefully_trusted"
        const val TRUST_LEVEL: String = "trust_level"
        const val TRUST_ORIGINS: String = "trust_origins"
        var DEFAULT_DOMAIN: HashSet<String> = HashSet(
            listOf(
                TRUSTED_DETAILS,
                PUBLISHED_DETAILS,
                ONE_TO_ONE,
                REVOKED,
                FORCEFULLY_TRUSTED,
                TRUST_LEVEL,
                TRUST_ORIGINS
            )
        )

        @JvmStatic
        @Throws(SQLException::class)
        fun of(
            identityManagerSession: IdentityManagerSession?,
            contact: ContactIdentity
        ): ContactSyncSnapshot {
            val contactSyncSnapshot = ContactSyncSnapshot()

            val trustedDetails = contact.trustedDetails
            contactSyncSnapshot.trusted_details =
                IdentityDetailsSyncSnapshot.of(identityManagerSession, trustedDetails!!)

            if (contact.trustedDetailsVersion != contact.publishedDetailsVersion) {
                val publishedDetails = contact.publishedDetails
                contactSyncSnapshot.published_details = IdentityDetailsSyncSnapshot.of(
                    identityManagerSession,
                    publishedDetails!!
                )
            }

            contactSyncSnapshot.one_to_one =
                if (contact.isOneToOne()) true else (if (contact.isNotOneToOne) false else null)

            contactSyncSnapshot.revoked = if (contact.isRevokedAsCompromised()) true else null

            contactSyncSnapshot.forcefully_trusted =
                if (contact.isForcefullyTrustedByUser()) true else null

            contactSyncSnapshot.trust_level = contact.getTrustLevel().toString()

            contactSyncSnapshot.trust_origins = ArrayList<TrustOrigin>()
            for (contactTrustOrigin in ContactTrustOrigin.getAll(
                identityManagerSession!!,
                contact.getContactIdentity(),
                contact.getOwnedIdentity()
            )) {
                contactSyncSnapshot.trust_origins!!.add(TrustOrigin.of(contactTrustOrigin ?: continue))
            }

            contactSyncSnapshot.domain = DEFAULT_DOMAIN
            return contactSyncSnapshot
        }
    }
}
