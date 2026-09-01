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
class JsonGroupDetailsWithVersionAndPhoto {
    @JvmField var version: Int = 0
    @JvmField var groupDetails: JsonGroupDetails? = null
    @JvmField var photoServerLabel: ByteArray? = null
    @JvmField var photoServerKey: ByteArray? = null
    @JvmField var photoUrl: String? = null // this field will never be serialized

    fun getVersion(): Int {
        return version
    }

    fun setVersion(version: Int) {
        this.version = version
    }

    @JsonProperty("details")
    fun getGroupDetails(): JsonGroupDetails? {
        return groupDetails
    }

    @JsonProperty("details")
    fun setGroupDetails(groupDetails: JsonGroupDetails?) {
        this.groupDetails = groupDetails
    }

    @JsonProperty("photo_label")
    fun getPhotoServerLabel(): ByteArray? {
        return photoServerLabel
    }

    @JsonProperty("photo_label")
    fun setPhotoServerLabel(photoServerLabel: ByteArray?) {
        this.photoServerLabel = photoServerLabel
    }

    @JsonProperty("photo_key")
    fun getPhotoServerKey(): ByteArray? {
        return photoServerKey
    }

    @JsonProperty("photo_key")
    fun setPhotoServerKey(photoServerKey: ByteArray?) {
        this.photoServerKey = photoServerKey
    }

    @JsonIgnore // this field will never be serialized
    fun getPhotoUrl(): String? {
        return photoUrl
    }

    @JsonIgnore
    fun setPhotoUrl(photoUrl: String?) {
        this.photoUrl = photoUrl
    }

    companion object {
        const val DUMMY_GROUP_DETAILS: String = "{\"details\":{\"name\":\"dummy\"}, \"version\": 0}"
    }
}
