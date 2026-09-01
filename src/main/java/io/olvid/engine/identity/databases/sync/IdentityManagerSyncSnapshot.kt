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
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.sync.ObvSyncDiff
import io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode
import io.olvid.engine.identity.databases.OwnedIdentity
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import io.olvid.engine.protocol.datatypes.ProtocolStarterDelegate
import java.sql.SQLException
import java.util.Arrays
import kotlin.collections.ArrayList
import kotlin.collections.HashSet
import kotlin.collections.MutableList
import kotlin.collections.contentEquals

@JsonIgnoreProperties(ignoreUnknown = true)
class IdentityManagerSyncSnapshot : ObvSyncSnapshotNode {
    @JvmField var owned_identity: ByteArray? = null
    @JvmField var owned_identity_node: OwnedIdentitySyncSnapshot? = null
    @JvmField var domain: HashSet<String>? = null

    @JsonIgnore
    @Throws(Exception::class)
    fun restore(
        identityManagerSession: IdentityManagerSession,
        protocolStarterDelegate: ProtocolStarterDelegate?
    ) {
        if (!domain!!.contains(OWNED_IDENTITY) || !domain!!.contains(OWNED_IDENTITY_NODE)) {
            Logger.e("Trying to restore an incomplete IdentityManagerSyncSnapshot. Domain: " + domain)
            throw Exception()
        }
        val ownedIdentity = Identity.of(owned_identity!!)
        if (identityManagerSession.identityDelegate?.isOwnedIdentity(
                identityManagerSession.session,
                ownedIdentity,
                true
            ) != true
        ) {
            Logger.e("Trying to restore a snapshot of an unknown owned identity")
            throw Exception()
        }

        owned_identity_node!!.restore(
            identityManagerSession,
            protocolStarterDelegate,
            ownedIdentity
        )
    }

    override fun areContentsTheSame(otherSnapshotNode: ObvSyncSnapshotNode?): Boolean {
        if (otherSnapshotNode !is IdentityManagerSyncSnapshot) {
            return false
        }

        val other = otherSnapshotNode
        val domainIntersection = HashSet<String?>(domain)
        domainIntersection.retainAll(other.domain ?: emptySet())

        for (item in domainIntersection) {
            when (item) {
                OWNED_IDENTITY -> {
                    if (!owned_identity.contentEquals(other.owned_identity)) {
                        return false
                    }
                }

                OWNED_IDENTITY_NODE -> {
                    if (!owned_identity_node!!.areContentsTheSame(other.owned_identity_node)) {
                        return false
                    }
                }
            }
        }
        return true
    }

    @Throws(Exception::class)
    override fun computeDiff(otherSnapshotNode: ObvSyncSnapshotNode?): MutableList<ObvSyncDiff?> {
        if (otherSnapshotNode !is IdentityManagerSyncSnapshot) {
            throw Exception()
        }
        val other = otherSnapshotNode
        val domainIntersection = HashSet<String?>(domain)
        domainIntersection.retainAll(other.domain ?: emptySet())

        val diffs: MutableList<ObvSyncDiff?> = ArrayList<ObvSyncDiff?>()
        for (item in domainIntersection) {
            when (item) {
                OWNED_IDENTITY -> {
                    if (!owned_identity.contentEquals(other.owned_identity)) {
                        throw Exception()
                    }
                }

                OWNED_IDENTITY_NODE -> {
                    diffs.addAll(owned_identity_node!!.computeDiff(other.owned_identity_node) ?: emptyList())
                }
            }
        }
        return diffs
    }

    companion object {
        const val OWNED_IDENTITY: String = "owned_identity"
        const val OWNED_IDENTITY_NODE: String = "owned_identity_node"
        var DEFAULT_DOMAIN: HashSet<String> = HashSet(
            listOf(
                OWNED_IDENTITY, OWNED_IDENTITY_NODE
            )
        )

        @JvmStatic
        @Throws(SQLException::class)
        fun of(
            identityManagerSession: IdentityManagerSession?,
            ownedIdentity: Identity
        ): IdentityManagerSyncSnapshot {
            val identityManagerSyncSnapshot = IdentityManagerSyncSnapshot()
            identityManagerSyncSnapshot.owned_identity = ownedIdentity.getBytes()
            val ownedIdentityObject: OwnedIdentity? =
                OwnedIdentity.get(identityManagerSession!!, ownedIdentity)
            if (ownedIdentityObject != null) {
                identityManagerSyncSnapshot.owned_identity_node =
                    OwnedIdentitySyncSnapshot.of(
                        identityManagerSession,
                        ownedIdentityObject
                    )
            }
            identityManagerSyncSnapshot.domain = DEFAULT_DOMAIN
            return identityManagerSyncSnapshot
        }
    }
}
