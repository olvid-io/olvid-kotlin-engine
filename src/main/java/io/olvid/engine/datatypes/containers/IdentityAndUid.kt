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

import io.olvid.engine.crypto.Hash
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.UID

class IdentityAndUid(@JvmField val identity: Identity, @JvmField val uid: UID) {
    override fun equals(other: Any?): Boolean {
        if (other !is IdentityAndUid) {
            return false
        }
        return identity == other.identity && uid == other.uid
    }

    override fun hashCode(): Int {
        return identity.hashCode() xor uid.hashCode()
    }

    override fun toString(): String {
        return identity.toString() + " - " + uid
    }

    companion object {
        @JvmStatic
        fun computeUniqueUid(ownedIdentity: Identity, uid: UID): UID {
            val sha256 = Suite.getHash(Hash.SHA256)
            val input = ByteArray(ownedIdentity.getBytes().size + UID.UID_LENGTH)
            System.arraycopy(ownedIdentity.getBytes(), 0, input, 0, ownedIdentity.getBytes().size)
            System.arraycopy(uid.bytes, 0, input, ownedIdentity.getBytes().size, UID.UID_LENGTH)
            return UID(sha256.digest(input))
        }
    }
    fun getIdentity(): Identity = identity
    fun getUid(): UID = uid
}

