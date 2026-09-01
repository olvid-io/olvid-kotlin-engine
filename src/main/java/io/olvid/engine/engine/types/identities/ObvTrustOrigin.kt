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
package io.olvid.engine.engine.types.identities

import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.containers.TrustOrigin
import io.olvid.engine.engine.types.JsonIdentityDetails
import io.olvid.engine.metamanager.IdentityDelegate

class ObvTrustOrigin(
    session: Session,
    identityDelegate: IdentityDelegate,
    trustOrigin: TrustOrigin,
    ownedIdentity: Identity?
) {
    enum class TYPE {
        DIRECT,
        INTRODUCTION,
        GROUP,
        KEYCLOAK,
        SERVER_GROUP_V2,
    }

    @JvmField val type: TYPE
    @JvmField val timestamp: Long
    @JvmField val mediatorOrGroupOwner: ObvIdentity?
    @JvmField val keycloakServer: String?
    @JvmField val bytesGroupIdentifier: ByteArray?

    fun getType(): TYPE {
        return type
    }

    fun getTimestamp(): Long {
        return timestamp
    }

    fun getMediatorOrGroupOwner(): ObvIdentity? {
        return mediatorOrGroupOwner
    }

    fun getKeycloakServer(): String? {
        return keycloakServer
    }

    fun getBytesGroupIdentifier(): ByteArray? {
        return bytesGroupIdentifier
    }

    init {
        when (trustOrigin.getType()) {
            TrustOrigin.TYPE.DIRECT -> this.type = TYPE.DIRECT
            TrustOrigin.TYPE.INTRODUCTION -> this.type = TYPE.INTRODUCTION
            TrustOrigin.TYPE.GROUP -> this.type = TYPE.GROUP
            TrustOrigin.TYPE.KEYCLOAK -> this.type = TYPE.KEYCLOAK
            TrustOrigin.TYPE.SERVER_GROUP_V2 -> this.type = TYPE.SERVER_GROUP_V2
        }

        this.timestamp = trustOrigin.getTimestamp()
        var mediatorOrGroupOwner: ObvIdentity? = null
        if (trustOrigin.getMediatorOrGroupOwnerIdentity() != null) {
            try {
                mediatorOrGroupOwner = ObvIdentity(
                    session,
                    identityDelegate,
                    trustOrigin.getMediatorOrGroupOwnerIdentity()!!,
                    ownedIdentity
                )
            } catch (_: Exception) {
                mediatorOrGroupOwner = ObvIdentity(
                    trustOrigin.getMediatorOrGroupOwnerIdentity()!!,
                    JsonIdentityDetails(),
                    false,
                    true
                )
            }
        }
        this.mediatorOrGroupOwner = mediatorOrGroupOwner
        this.keycloakServer = trustOrigin.getKeycloakServer()
        this.bytesGroupIdentifier =
            if (trustOrigin.getGroupIdentifier() == null) null else trustOrigin.getGroupIdentifier()!!.bytes
    }
}
