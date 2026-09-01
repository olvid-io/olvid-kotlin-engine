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
import io.olvid.engine.engine.types.JsonGroupDetails

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

    @field:JsonProperty("gm_perms")
    @JvmField var groupMembersAndPermissions: HashSet<KeycloakGroupMemberAndPermissions?>? = null

    @field:JsonProperty("sss")
    @JvmField var serializedSharedSettings: String? = null
    @JvmField var timestamp: Long = 0
}
