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
class JsonGroupType {
    @JvmField var type: String? = null
    @JvmField var readOnly: Boolean? = null
    @JvmField var remoteDelete: String? = null

    constructor()

    private constructor(type: String?, readOnly: Boolean?, remoteDelete: String?) {
        this.type = type
        this.readOnly = readOnly
        this.remoteDelete = remoteDelete
    }

    @JsonProperty("type")
    fun getType(): String? {
        return type
    }

    @JsonProperty("type")
    fun setType(type: String?) {
        this.type = type
    }

    @JsonProperty("ro")
    fun getReadOnly(): Boolean? {
        return readOnly
    }

    @JsonProperty("ro")
    fun setReadOnly(readOnly: Boolean?) {
        this.readOnly = readOnly
    }

    @JsonProperty("del")
    fun getRemoteDelete(): String? {
        return remoteDelete
    }

    @JsonProperty("del")
    fun setRemoteDelete(remoteDelete: String?) {
        this.remoteDelete = remoteDelete
    }

    @JsonIgnore
    fun isEmpty(): Boolean {
        return type == null
    }


    override fun equals(other: Any?): Boolean {
        if (other !is JsonGroupType) {
            return false
        }
        return type == other.type && readOnly == other.readOnly && remoteDelete == other.remoteDelete
    }

    companion object {
        const val TYPE_SIMPLE: String = "simple"
        const val TYPE_PRIVATE: String = "private"
        const val TYPE_READ_ONLY: String = "read_only"
        const val TYPE_CUSTOM: String = "custom"

        const val REMOTE_DELETE_NOBODY: String = "nobody"
        const val REMOTE_DELETE_ADMINS: String = "admins"
        const val REMOTE_DELETE_EVERYONE: String = "everyone"

        @JsonIgnore
        @JvmStatic
        fun createSimple(): JsonGroupType {
            return JsonGroupType(TYPE_SIMPLE, null, null)
        }

        @JsonIgnore
        @JvmStatic
        fun createPrivate(): JsonGroupType {
            return JsonGroupType(TYPE_PRIVATE, null, null)
        }

        @JsonIgnore
        @JvmStatic
        fun createReadOnly(): JsonGroupType {
            return JsonGroupType(TYPE_READ_ONLY, null, null)
        }

        @JsonIgnore
        @JvmStatic
        fun createCustom(readOnly: Boolean, remoteDelete: String?): JsonGroupType {
            var remoteDelete = remoteDelete
            if (remoteDelete == null ||
                !(remoteDelete == REMOTE_DELETE_NOBODY || remoteDelete == REMOTE_DELETE_ADMINS || remoteDelete == REMOTE_DELETE_EVERYONE)
            ) {
                remoteDelete = REMOTE_DELETE_NOBODY
            }
            return JsonGroupType(TYPE_CUSTOM, readOnly, remoteDelete)
        }
    }
}
