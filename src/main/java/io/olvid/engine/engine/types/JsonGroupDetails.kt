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

@JsonIgnoreProperties(ignoreUnknown = true)
class JsonGroupDetails {
    @JvmField var name: String? = null
    @JvmField var description: String? = null

    constructor()

    constructor(name: String?, description: String?) {
        this.name = nullOrTrim(name)
        this.description = nullOrTrim(description)
    }

    fun getName(): String? {
        return name
    }

    fun setName(name: String?) {
        this.name = nullOrTrim(name)
    }

    fun getDescription(): String? {
        return description
    }

    fun setDescription(description: String?) {
        this.description = nullOrTrim(description)
    }

    @JsonIgnore
    fun isEmpty(): Boolean {
        return name == null
    }


    override fun equals(other: Any?): Boolean {
        if (other !is JsonGroupDetails) {
            return false
        }
        return name == other.name && description == other.description
    }

    companion object {
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
    }
}
