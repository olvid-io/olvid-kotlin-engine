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

import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Session
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.JsonIdentityDetails
import io.olvid.engine.metamanager.IdentityDelegate


open class ObvIdentity : Comparable<ObvIdentity?> {
    @JvmField val identity: Identity
    @JvmField val identityDetails: JsonIdentityDetails?
    @JvmField val keycloakManaged: Boolean
    @JvmField val active: Boolean

    constructor(
        identity: Identity,
        identityDetails: JsonIdentityDetails?,
        keycloakManaged: Boolean,
        active: Boolean
    ) {
        this.identity = identity
        this.identityDetails = identityDetails
        this.keycloakManaged = keycloakManaged
        this.active = active
    }

    constructor(session: Session, identityDelegate: IdentityDelegate, ownedIdentity: Identity) {
        this.identity = ownedIdentity
        this.identityDetails =
            identityDelegate.getOwnedIdentityPublishedDetails(session, ownedIdentity)!!
                .getIdentityDetails()
        this.keycloakManaged =
            identityDelegate.isOwnedIdentityKeycloakManaged(session, ownedIdentity)
        this.active = identityDelegate.isActiveOwnedIdentity(session, ownedIdentity)
    }

    constructor(
        session: Session,
        identityDelegate: IdentityDelegate,
        contactIdentity: Identity,
        ownedIdentity: Identity?
    ) {
        this.identity = contactIdentity
        this.identityDetails = identityDelegate.getContactIdentityTrustedDetails(
            session,
            ownedIdentity,
            contactIdentity
        )
        this.keycloakManaged = identityDelegate.isContactIdentityCertifiedByOwnKeycloak(
            session,
            ownedIdentity,
            contactIdentity
        )
        this.active = identityDelegate.isIdentityAnActiveContactOfOwnedIdentity(
            session,
            ownedIdentity,
            contactIdentity
        )
    }

    fun getBytesIdentity(): ByteArray {
        return identity.getBytes()
    }

    fun getServer(): String {
        return identity.server
    }

    fun getIdentityDetails(): JsonIdentityDetails? {
        return identityDetails
    }

    fun isKeycloakManaged(): Boolean {
        return keycloakManaged
    }

    fun isActive(): Boolean {
        return active
    }

    @Throws(Exception::class)
    fun encode(jsonObjectMapper: ObjectMapper): Encoded {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(identity),
                Encoded.of(jsonObjectMapper.writeValueAsString(identityDetails)),
            )
        )
    }


    // endregion
    override fun hashCode(): Int {
        return identity.getBytes().contentHashCode()
    }

    override fun equals(other: Any?): Boolean {
        if (other == null || javaClass != other.javaClass) {
            return false
        }
        return identity.equals((other as ObvIdentity).identity)
    }

    override fun compareTo(other: ObvIdentity?): Int {
        if (other == null) return 1
        return identity.computeUniqueUid().compareTo(other.identity.computeUniqueUid())
    }

    fun getIdentity(): Identity {
        return identity
    }

    companion object {
        // region Encoded
        @JvmStatic
        @Throws(Exception::class)
        fun of(encoded: Encoded, jsonObjectMapper: ObjectMapper): ObvIdentity {
            val list: Array<Encoded> = encoded.decodeList()
            if (list.size != 2) {
                throw DecodingException()
            }
            return ObvIdentity(
                list[0].decodeIdentity(),
                jsonObjectMapper.readValue<JsonIdentityDetails?>(
                    list[1].decodeString(),
                    JsonIdentityDetails::class.java
                ),
                false,
                true
            )
        }
    }
}
