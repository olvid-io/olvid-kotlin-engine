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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty

@JsonIgnoreProperties(ignoreUnknown = true)
class JsonKeycloakRevocation {
    @JvmField var bytesRevokedIdentity: ByteArray? = null
    @JvmField var revocationTimestamp: Long = 0
    @JvmField var revocationType: Int = 0

    @JsonProperty("identity")
    fun getBytesRevokedIdentity(): ByteArray? {
        return bytesRevokedIdentity
    }

    @JsonProperty("identity")
    fun setBytesRevokedIdentity(bytesRevokedIdentity: ByteArray?) {
        this.bytesRevokedIdentity = bytesRevokedIdentity
    }

    @JsonProperty("timestamp")
    fun getRevocationTimestamp(): Long {
        return revocationTimestamp
    }

    @JsonProperty("timestamp")
    fun setRevocationTimestamp(revocationTimestamp: Long) {
        this.revocationTimestamp = revocationTimestamp
    }

    @JsonProperty("type")
    fun getRevocationType(): Int {
        return revocationType
    }

    @JsonProperty("type")
    fun setRevocationType(revocationType: Int) {
        this.revocationType = revocationType
    }
}