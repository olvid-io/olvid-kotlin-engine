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

import io.olvid.engine.crypto.PRNG
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded

class GroupInformation(
    @JvmField val groupOwnerIdentity: Identity,
    @JvmField val groupUid: UID,
    @JvmField val serializedGroupDetailsWithVersionAndPhoto: String
) {
    fun encode(): Encoded {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(groupOwnerIdentity),
                Encoded.of(groupUid),
                Encoded.of(serializedGroupDetailsWithVersionAndPhoto),
            )
        )
    }

    fun computeProtocolUid(): UID {
        return computeProtocolUid(groupOwnerIdentity.getBytes(), groupUid.bytes)
    }

    fun getGroupOwnerAndUid(): ByteArray {
        val groupOwnerAndUid = ByteArray(groupOwnerIdentity.getBytes().size + UID.UID_LENGTH)
        System.arraycopy(
            groupOwnerIdentity.getBytes(),
            0,
            groupOwnerAndUid,
            0,
            groupOwnerIdentity.getBytes().size
        )
        System.arraycopy(
            groupUid.bytes,
            0,
            groupOwnerAndUid,
            groupOwnerIdentity.getBytes().size,
            UID.UID_LENGTH
        )
        return groupOwnerAndUid
    }

    companion object {
        @JvmStatic
        @Throws(DecodingException::class)
        fun of(encoded: Encoded): GroupInformation {
            val encodeds: Array<Encoded> = encoded.decodeList()
            if (encodeds.size != 3) {
                throw DecodingException()
            }
            return GroupInformation(
                encodeds[0].decodeIdentity(),
                encodeds[1].decodeUid(),
                encodeds[2].decodeString()
            )
        }

        @JvmStatic
        fun generate(
            groupOwner: Identity,
            serializedGroupDetailsWithVersionAndPhoto: String,
            prng: PRNG
        ): GroupInformation {
            val groupUid = UID(prng)
            return GroupInformation(groupOwner, groupUid, serializedGroupDetailsWithVersionAndPhoto)
        }

        @JvmStatic
        fun computeProtocolUid(bytesGroupOwnerIdentity: ByteArray, bytesGroupUid: ByteArray): UID {
            val prngSeed = Seed(Seed(bytesGroupOwnerIdentity), Seed(bytesGroupUid))
            val seededPRNG = Suite.getDefaultPRNG(0, prngSeed)
            return UID(seededPRNG)
        }
    }
    fun getGroupOwnerIdentity(): Identity = groupOwnerIdentity
    fun getGroupUid(): UID = groupUid
    fun getSerializedGroupDetailsWithVersionAndPhoto(): String = serializedGroupDetailsWithVersionAndPhoto
}
