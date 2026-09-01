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
package io.olvid.engine.identity.databases.backups

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import io.olvid.engine.engine.types.ObvBytesKey
import io.olvid.engine.engine.types.sync.ObvSyncDiff
import io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode
import io.olvid.engine.identity.databases.OwnedIdentity
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import java.sql.SQLException

@JsonIgnoreProperties(ignoreUnknown = true)
class IdentityManagerDeviceSnapshot : ObvSyncSnapshotNode {
    @JsonSerialize(keyUsing = ObvBytesKey.KeySerializer::class)
    @JsonDeserialize(keyUsing = ObvBytesKey.KeyDeserializer::class)
    var owned_identities: HashMap<ObvBytesKey?, OwnedIdentityDeviceSnapshot?>? = null
    @JvmField var domain: HashSet<String?>? = null

    fun validate(): Boolean {
        return domain!!.containsAll(DEFAULT_DOMAIN)
                && owned_identities != null
    }


    override fun areContentsTheSame(otherSnapshotNode: ObvSyncSnapshotNode?): Boolean {
        return false
    }

    @Throws(Exception::class)
    override fun computeDiff(otherSnapshotNode: ObvSyncSnapshotNode?): MutableList<ObvSyncDiff?>? {
        return null
    }

    companion object {
        const val OWNED_IDENTITIES: String = "owned_identities"
        var DEFAULT_DOMAIN: HashSet<String?> = HashSet(listOf(OWNED_IDENTITIES))

        @JvmStatic
        @Throws(SQLException::class)
        fun of(identityManagerSession: IdentityManagerSession?): IdentityManagerDeviceSnapshot {
            val identityManagerDeviceSnapshot = IdentityManagerDeviceSnapshot()
            identityManagerDeviceSnapshot.owned_identities =
                HashMap()

            for (ownedIdentity in OwnedIdentity.getAll(identityManagerSession!!)) {
                val oi = ownedIdentity
                identityManagerDeviceSnapshot.owned_identities!![ObvBytesKey(oi.ownedIdentity.getBytes())] = OwnedIdentityDeviceSnapshot.of(identityManagerSession, oi)
            }

            identityManagerDeviceSnapshot.domain = DEFAULT_DOMAIN
            return identityManagerDeviceSnapshot
        }
    }
}
