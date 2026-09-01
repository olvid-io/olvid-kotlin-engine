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
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.datatypes.ObvBase64.Companion.decode
import java.util.Locale

@JsonIgnoreProperties(ignoreUnknown = true)
class JsonIdentityDetails {
    @JvmField var firstName: String? = null
    @JvmField var lastName: String? = null
    @JvmField var company: String? = null
    @JvmField var position: String? = null
    @JvmField var signedUserDetails: String? =
        null // this is a JWT, non null when the identity is managed by a keycloak server
    @JvmField var customFields: HashMap<String?, String?>? = null

    constructor()

    constructor(firstName: String?, lastName: String?, company: String?, position: String?) {
        this.firstName = nullOrTrim(firstName)
        this.lastName = nullOrTrim(lastName)
        this.company = nullOrTrim(company)
        this.position = nullOrTrim(position)
    }

    @JsonProperty("first_name")
    fun getFirstName(): String? {
        return firstName
    }

    @JsonProperty("first_name")
    fun setFirstName(firstName: String?) {
        this.firstName = nullOrTrim(firstName)
    }

    @JsonProperty("last_name")
    fun getLastName(): String? {
        return lastName
    }

    @JsonProperty("last_name")
    fun setLastName(lastName: String?) {
        this.lastName = nullOrTrim(lastName)
    }

    fun getCompany(): String? {
        return company
    }

    fun setCompany(company: String?) {
        this.company = nullOrTrim(company)
    }

    fun getPosition(): String? {
        return position
    }

    fun setPosition(position: String?) {
        this.position = nullOrTrim(position)
    }

    @JsonProperty("custom_fields")
    fun getCustomFields(): HashMap<String?, String?>? {
        return customFields
    }

    @JsonProperty("custom_fields")
    fun setCustomFields(customFields: HashMap<String?, String?>?) {
        this.customFields = customFields
    }

    @JsonProperty("signed_user_details")
    fun getSignedUserDetails(): String? {
        return signedUserDetails
    }

    @JsonProperty("signed_user_details")
    fun setSignedUserDetails(signedUserDetails: String?) {
        this.signedUserDetails = signedUserDetails
    }

    @JsonIgnore
    fun isEmpty(): Boolean {
        return firstName == null && lastName == null
    }


    @JsonIgnore
    fun formatDisplayName(contactDisplayNameFormat: String, uppercaseLastName: Boolean): String {
        var displayName: String?
        when (contactDisplayNameFormat) {
            FORMAT_STRING_FIRST_LAST_COMPANY -> {
                displayName = joinNames(firstName, lastName, false, uppercaseLastName)
                if (company != null) {
                    displayName += " (" + company + ")"
                }
            }

            FORMAT_STRING_FIRST_LAST_POSITION_COMPANY -> {
                displayName = joinNames(firstName, lastName, false, uppercaseLastName)
                val posComp: String? = joinCompany(position, company)
                if (posComp != null) {
                    displayName += " (" + posComp + ")"
                }
            }

            FORMAT_STRING_LAST_FIRST -> {
                displayName = joinNames(firstName, lastName, true, uppercaseLastName)
            }

            FORMAT_STRING_LAST_FIRST_COMPANY -> {
                displayName = joinNames(firstName, lastName, true, uppercaseLastName)
                if (company != null) {
                    displayName += " (" + company + ")"
                }
            }

            FORMAT_STRING_LAST_FIRST_POSITION_COMPANY -> {
                displayName = joinNames(firstName, lastName, true, uppercaseLastName)
                val posComp: String? = joinCompany(position, company)
                if (posComp != null) {
                    displayName += " (" + posComp + ")"
                }
            }

            FORMAT_STRING_FOR_SEARCH -> {
                displayName = joinNames(firstName, lastName, false, false)
                val posComp: String? = joinCompany(position, company)
                if (posComp != null) {
                    displayName += " " + posComp
                }
            }

            FORMAT_STRING_FIRST_LAST -> {
                displayName = joinNames(firstName, lastName, false, uppercaseLastName)
            }

            else -> {
                displayName = joinNames(firstName, lastName, false, uppercaseLastName)
            }
        }
        return displayName
    }


    @JsonIgnore
    fun formatFirstAndLastName(format: String, uppercaseLastName: Boolean): String {
        when (format) {
            FORMAT_STRING_LAST_FIRST, FORMAT_STRING_LAST_FIRST_COMPANY, FORMAT_STRING_LAST_FIRST_POSITION_COMPANY -> return joinNames(
                firstName,
                lastName,
                true,
                uppercaseLastName
            )

            FORMAT_STRING_FIRST_LAST, FORMAT_STRING_FIRST_LAST_COMPANY, FORMAT_STRING_FIRST_LAST_POSITION_COMPANY -> return joinNames(
                firstName,
                lastName,
                false,
                uppercaseLastName
            )

            else -> return joinNames(firstName, lastName, false, uppercaseLastName)
        }
    }

    @JsonIgnore
    fun formatPositionAndCompany(@Suppress("unused") format: String?): String? {
        // for now, format is not used, but it may become necessary if new formats are added
        return joinCompany(position, company)
    }

    // equals does not compare signedUserDetails. It only checks whether these details are null/non-null
    override fun equals(other: Any?): Boolean {
        if (other !is JsonIdentityDetails) {
            return false
        }
        if (firstName != other.firstName) {
            return false
        }
        if (lastName != other.lastName) {
            return false
        }
        if (company != other.company) {
            return false
        }
        if (position != other.position) {
            return false
        }
        if ((signedUserDetails == null && other.signedUserDetails != null) || (signedUserDetails != null && other.signedUserDetails == null)) {
            return false
        }
        val objectMapper = ObjectMapper()
        if (getSignatureKid(objectMapper, signedUserDetails) != getSignatureKid(
                objectMapper,
                other.signedUserDetails
            )
        ) {
            return false
        }
        return customFields == other.customFields
    }

    @JsonIgnore
    fun fieldsAreTheSame(other: JsonIdentityDetails): Boolean {
        if (!(firstName == other.firstName)) {
            return false
        }
        if (!(lastName == other.lastName)) {
            return false
        }
        if (!(company == other.company)) {
            return false
        }
        if (!(position == other.position)) {
            return false
        }
        return customFields == other.customFields
    }

    @JsonIgnore
    fun firstAndLastNamesAreTheSame(other: JsonIdentityDetails): Boolean {
        return firstName == other.firstName && lastName == other.lastName
    }


    companion object {
        const val FORMAT_STRING_FIRST_LAST: String = "%f %l"
        const val FORMAT_STRING_FIRST_LAST_COMPANY: String = "%f %l (%c)"
        const val FORMAT_STRING_FIRST_LAST_POSITION_COMPANY: String = "%f %l (%p @ %c)"
        const val FORMAT_STRING_LAST_FIRST: String = "%l %f"
        const val FORMAT_STRING_LAST_FIRST_COMPANY: String = "%l %f (%c)"
        const val FORMAT_STRING_LAST_FIRST_POSITION_COMPANY: String = "%l %f (%p @ %c)"
        const val FORMAT_STRING_FOR_SEARCH: String = "%f %l %p %c"


        private fun nullOrTrim(`in`: String?): String? {
            if (`in` == null) {
                return null
            }
            val out = `in`.trim { it <= ' ' }
            if (out.isEmpty()) {
                return null
            }
            return out
        }

        @JvmStatic fun joinNames(
            firstName: String?,
            lastName: String?,
            lastFirst: Boolean,
            uppercaseLast: Boolean
        ): String {
            var lastName = lastName
            if (lastName == null) {
                if (firstName == null) {
                    return ""
                }
                return firstName
            }
            if (uppercaseLast) {
                lastName = lastName.uppercase(Locale.getDefault())
            }

            if (firstName == null) {
                return lastName
            }

            if (lastFirst) {
                return lastName + " " + firstName
            } else {
                return firstName + " " + lastName
            }
        }

        private fun joinCompany(position: String?, company: String?): String? {
            if (position == null) {
                return company
            }
            if (company == null) {
                return position
            }
            return position + " @ " + company
        }


        private fun getSignatureKid(objectMapper: ObjectMapper, signature: String?): String? {
            if (signature != null) {
                val pos = signature.indexOf('.')
                if (pos > 0) {
                    val headerString = signature.substring(0, pos)
                    try {
                        val header = objectMapper.readValue<HashMap<String?, String?>>(
                            decode(headerString),
                            object : TypeReference<HashMap<String?, String?>?>() {})
                        return header.get("kid")
                    } catch (_: Exception) {
                        // do nothing
                    }
                }
            }
            return null
        }
    }
}
