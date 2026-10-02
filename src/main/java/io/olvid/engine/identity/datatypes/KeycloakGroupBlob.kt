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
package io.olvid.engine.identity.datatypes

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import io.olvid.engine.engine.types.JsonGroupDetails
import io.olvid.engine.engine.types.ObvBytesKey

@JsonIgnoreProperties(ignoreUnknown = true)
class KeycloakGroupBlob {
    @field:JsonProperty("guid")
    @JvmField var bytesGroupUid: ByteArray? = null // 32-bytes UID

    @field:JsonProperty("details")
    @JvmField var groupDetails: JsonGroupDetails? = null

    @field:JsonProperty("photo_label")
    @JvmField var photoUid: ByteArray? = null

    @field:JsonProperty("photo_key")
    @JvmField var encodedPhotoKey: ByteArray? = null

    @field:JsonProperty("pt")
    @JvmField var pushTopic: String? = null

    // LinkedHashSet keeps the blob order, required by deduplicatedGroupMembersAndPermissions()
    @field:JsonProperty("gm_perms")
    @JvmField var groupMembersAndPermissions: List<KeycloakGroupMemberAndPermissions?>? = null

    @field:JsonProperty("sss")
    @JvmField var serializedSharedSettings: String? = null
    @JvmField var timestamp: Long = 0

    // Keycloak may list the same identity several times (e.g. bound to several keycloak users).
    // Every device must keep the same entry, otherwise the invitation nonce one member signs in
    // its group join ping does not match the one others stored for it: keep the first occurrence.
    fun deduplicatedGroupMembersAndPermissions(): List<KeycloakGroupMemberAndPermissions> {
        val seenIdentities = HashSet<ObvBytesKey>()
        return groupMembersAndPermissions.orEmpty()
            .filterNotNull()
            .filter { seenIdentities.add(it.identity?.let { identityBytes -> ObvBytesKey(identityBytes) } ?: return@filter true) }
    }
}
