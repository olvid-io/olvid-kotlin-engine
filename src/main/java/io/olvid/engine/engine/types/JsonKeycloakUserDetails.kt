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
package io.olvid.engine.engine.types

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty

@JsonIgnoreProperties(ignoreUnknown = true)
class JsonKeycloakUserDetails {
    @JvmField var id: String? = null
    @JvmField var identity: ByteArray? = null
    @JvmField var firstName: String? = null
    @JvmField var lastName: String? = null
    @JvmField var position: String? = null
    @JvmField var company: String? = null
    @JvmField var timestamp: Long? = null

    fun getId(): String? {
        return id
    }

    fun setId(id: String?) {
        this.id = id
    }

    fun getIdentity(): ByteArray? {
        return identity
    }

    fun setIdentity(identity: ByteArray?) {
        this.identity = identity
    }

    @JsonProperty("first-name")
    fun getFirstName(): String? {
        return firstName
    }

    @JsonProperty("first-name")
    fun setFirstName(firstName: String?) {
        this.firstName = firstName
    }

    @JsonProperty("last-name")
    fun getLastName(): String? {
        return lastName
    }

    @JsonProperty("last-name")
    fun setLastName(lastName: String?) {
        this.lastName = lastName
    }

    fun getPosition(): String? {
        return position
    }

    fun setPosition(position: String?) {
        this.position = position
    }

    fun getCompany(): String? {
        return company
    }

    fun setCompany(company: String?) {
        this.company = company
    }

    fun getTimestamp(): Long? {
        return timestamp
    }

    fun setTimestamp(timestamp: Long?) {
        this.timestamp = timestamp
    }

    @JsonIgnore
    fun getIdentityDetails(signedUserDetails: String?): JsonIdentityDetails {
        val details = JsonIdentityDetails(firstName, lastName, company, position)
        if (signedUserDetails != null) {
            details.setSignedUserDetails(signedUserDetails)
        }
        return details
    }
}
