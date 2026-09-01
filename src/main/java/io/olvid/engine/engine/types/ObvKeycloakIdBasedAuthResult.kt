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


class ObvKeycloakIdBasedAuthResult(
    @JvmField val status: Status?,
    @JvmField val accessToken: String?, // null in case of error
    @JvmField val refreshToken: String?, // null in case of error or if there is no possibility to refresh the accessToken
    @JvmField val clientId: String?, // null in case of error or if refreshToken is null
    @JvmField val clientSecret: String?, // null in case of error or if refreshToken is null (or the openId Connect client has no clientSecret)
) {
    constructor(status: Status?) : this(status, null, null, null, null)

    enum class Status {
        SUCCESS,
        NETWORK_ERROR,
        PERMANENT_ERROR,
        ERROR,
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class GetSessionResponse {
        @JsonProperty("access_token")
        @JvmField var accessToken: String? = null

        @JsonProperty("refresh_token")
        @JvmField var refreshToken: String? = null

        @JsonProperty("client_id")
        @JvmField var clientId: String? = null

        @JsonProperty("client_secret")
        @JvmField var clientSecret: String? = null
    }
}
