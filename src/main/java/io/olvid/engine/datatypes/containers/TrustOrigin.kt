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
package io.olvid.engine.datatypes.containers

import io.olvid.engine.datatypes.Identity

class TrustOrigin(
    @JvmField val type: TYPE,
    @JvmField val timestamp: Long,
    @JvmField val mediatorOrGroupOwnerIdentity: Identity?,
    @JvmField val keycloakServer: String?,
    @JvmField val groupIdentifier: GroupV2.Identifier?
) {
    enum class TYPE {
        DIRECT,
        INTRODUCTION,
        GROUP,
        KEYCLOAK,
        SERVER_GROUP_V2,
    }

    // Note that equals does not check the timestamp
    override fun equals(other: Any?): Boolean {
        if (other !is TrustOrigin) {
            return false
        }
        val castedOther = other
        if (castedOther.type != type) {
            return false
        }
        when (type) {
            TYPE.INTRODUCTION, TYPE.GROUP -> return castedOther.mediatorOrGroupOwnerIdentity == mediatorOrGroupOwnerIdentity
            TYPE.KEYCLOAK -> return castedOther.keycloakServer == keycloakServer
            TYPE.SERVER_GROUP_V2 -> return castedOther.groupIdentifier == groupIdentifier
            TYPE.DIRECT -> return true
        }
    }

    companion object {
        @JvmStatic
        fun createDirectTrustOrigin(timestamp: Long): TrustOrigin {
            return TrustOrigin(
                TYPE.DIRECT,
                timestamp,
                null,
                null,
                null
            )
        }

        @JvmStatic
        fun createIntroductionTrustOrigin(
            timestamp: Long,
            mediatorIdentity: Identity?
        ): TrustOrigin {
            return TrustOrigin(
                TYPE.INTRODUCTION,
                timestamp,
                mediatorIdentity,
                null,
                null
            )
        }

        @JvmStatic
        fun createGroupTrustOrigin(timestamp: Long, groupOwner: Identity?): TrustOrigin {
            return TrustOrigin(
                TYPE.GROUP,
                timestamp,
                groupOwner,
                null,
                null
            )
        }

        @JvmStatic
        fun createKeycloakTrustOrigin(timestamp: Long, keycloakServer: String?): TrustOrigin {
            return TrustOrigin(
                TYPE.KEYCLOAK,
                timestamp,
                null,
                keycloakServer,
                null
            )
        }

        @JvmStatic
        fun createServerGroupV2TrustOrigin(
            timestamp: Long,
            groupIdentifier: GroupV2.Identifier?
        ): TrustOrigin {
            return TrustOrigin(
                TYPE.SERVER_GROUP_V2,
                timestamp,
                null,
                null,
                groupIdentifier
            )
        }
    }
    fun getType(): TYPE = type
    fun getTimestamp(): Long = timestamp
    fun getMediatorOrGroupOwnerIdentity(): Identity? = mediatorOrGroupOwnerIdentity
    fun getKeycloakServer(): String? = keycloakServer
    fun getGroupIdentifier(): GroupV2.Identifier? = groupIdentifier
}
