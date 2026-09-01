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
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.sync.ObvSyncDiff
import io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode
import io.olvid.engine.identity.databases.OwnedIdentity
import io.olvid.engine.identity.databases.OwnedIdentityDetails
import io.olvid.engine.identity.databases.sync.IdentityDetailsSyncSnapshot
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import java.sql.SQLException
import java.util.Arrays

@JsonIgnoreProperties(ignoreUnknown = true)
class OwnedIdentityDeviceSnapshot : ObvSyncSnapshotNode {
    @JvmField var published_details: IdentityDetailsSyncSnapshot? = null
    @JvmField var keycloak_managed: Boolean? = null
    @JvmField var backup_seed: ByteArray? = null
    @JvmField var domain: HashSet<String?>? = null


    fun validate(): Boolean {
        return domain!!.containsAll(DEFAULT_DOMAIN)
                && backup_seed != null && keycloak_managed != null && published_details != null
    }


    override fun areContentsTheSame(otherSnapshotNode: ObvSyncSnapshotNode?): Boolean {
        return false
    }

    @Throws(Exception::class)
    override fun computeDiff(otherSnapshotNode: ObvSyncSnapshotNode?): MutableList<ObvSyncDiff?>? {
        return null
    }

    companion object {
        const val PUBLISHED_DETAILS: String = "published_details"
        const val KEYCLOAK_MANAGED: String = "keycloak_managed"
        const val BACKUP_SEED: String = "backup_seed"
        var DEFAULT_DOMAIN: HashSet<String?> = HashSet(
            listOf(
                PUBLISHED_DETAILS, KEYCLOAK_MANAGED, BACKUP_SEED
            )
        )


        @JvmStatic
        @Throws(SQLException::class)
        fun of(
            identityManagerSession: IdentityManagerSession?,
            ownedIdentity: OwnedIdentity
        ): OwnedIdentityDeviceSnapshot {
            val ownedIdentityDeviceSnapshot = OwnedIdentityDeviceSnapshot()

            val publishedDetails: OwnedIdentityDetails? = OwnedIdentityDetails.get(
                identityManagerSession!!,
                ownedIdentity.ownedIdentity,
                ownedIdentity.publishedDetailsVersion
            )
            if (publishedDetails != null) {
                ownedIdentityDeviceSnapshot.published_details =
                    IdentityDetailsSyncSnapshot.of(
                        identityManagerSession,
                        publishedDetails
                    )
            }

            ownedIdentityDeviceSnapshot.keycloak_managed = ownedIdentity.isKeycloakManaged
            ownedIdentityDeviceSnapshot.backup_seed = ownedIdentity.getBackupSeed()?.backupSeedBytes

            ownedIdentityDeviceSnapshot.domain = DEFAULT_DOMAIN
            return ownedIdentityDeviceSnapshot
        }
    }
}
