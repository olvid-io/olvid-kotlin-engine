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

@JsonIgnoreProperties(ignoreUnknown = true)
class KeycloakGroupMemberAndPermissions {
    @JvmField var keycloakUserId: String? = null

    @field:JsonProperty("identity")
    @JvmField var identity: ByteArray? = null

    @field:JsonProperty("signature")
    @JvmField var signedUserDetails: String? = null

    @field:JsonProperty("permissions")
    @JvmField var permissions: MutableList<String?>? = null

    @field:JsonProperty("nonce")
    @JvmField var groupInvitationNonce: ByteArray? = null

    @JsonProperty("id")
    fun getKeycloakUserId(): String {
        return keycloakUserId!!
    }

    @JsonProperty("id")
    fun setKeycloakUserId(keycloakUserId: String) {
        this.keycloakUserId = keycloakUserId
    }

    override fun hashCode(): Int {
        return keycloakUserId!!.hashCode()
    }

    // equals only matches the keycloakUserId to avoid duplicate group members when building sets of GroupMember
    override fun equals(other: Any?): Boolean {
        if (other !is KeycloakGroupMemberAndPermissions) {
            return false
        }
        return keycloakUserId == other.keycloakUserId
    }
}
