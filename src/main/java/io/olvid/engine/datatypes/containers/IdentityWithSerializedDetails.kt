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
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded

class IdentityWithSerializedDetails(@JvmField val identity: Identity, @JvmField val serializedDetails: String) :
    Comparable<IdentityWithSerializedDetails> {
    fun getIdentity(): Identity = identity
    fun getSerializedDetails(): String = serializedDetails

    override fun hashCode(): Int {
        return identity.hashCode()
    }

    override fun equals(other: Any?): Boolean {
        if (other !is IdentityWithSerializedDetails) {
            return false
        }
        return identity.equals(other.identity)
    }

    override fun compareTo(other: IdentityWithSerializedDetails): Int {
        return identity.compareTo(other.identity)
    }

    fun encode(): Encoded {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(identity),
                Encoded.of(serializedDetails),
            )
        )
    }

    companion object {
        @JvmStatic
        @Throws(DecodingException::class)
        fun of(encoded: Encoded): IdentityWithSerializedDetails {
            val encodeds: Array<Encoded> = encoded.decodeList()
            if (encodeds.size != 2) {
                throw DecodingException()
            }
            return IdentityWithSerializedDetails(
                encodeds[0].decodeIdentity(),
                encodeds[1].decodeString()
            )
        }
    }
}
