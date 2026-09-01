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

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.KeyDeserializer
import com.fasterxml.jackson.databind.SerializerProvider
import io.olvid.engine.datatypes.UID
import java.io.IOException
import java.util.Arrays

class ObvGroupOwnerAndUidKey {
    @JvmField val groupOwner: ByteArray
    @JvmField val groupUid: ByteArray

    constructor(groupOwnerAndUid: ByteArray) {
        this.groupOwner =
            Arrays.copyOfRange(groupOwnerAndUid, 0, groupOwnerAndUid.size - UID.UID_LENGTH)
        this.groupUid = Arrays.copyOfRange(
            groupOwnerAndUid,
            groupOwnerAndUid.size - UID.UID_LENGTH,
            groupOwnerAndUid.size
        )
    }

    constructor(groupOwner: ByteArray, groupUid: ByteArray) {
        this.groupOwner = groupOwner
        this.groupUid = groupUid
    }

    fun getGroupOwnerAndUid(): ByteArray {
        val out = ByteArray(groupOwner.size + groupUid.size)
        System.arraycopy(groupOwner, 0, out, 0, groupOwner.size)
        System.arraycopy(groupUid, 0, out, groupOwner.size, groupUid.size)
        return out
    }


    override fun equals(other: Any?): Boolean {
        if (other !is ObvGroupOwnerAndUidKey) return false
        return groupOwner.contentEquals(other.groupOwner) && groupUid.contentEquals(other.groupUid)
    }

    override fun hashCode(): Int {
        return groupOwner.contentHashCode() * 31 + groupUid.contentHashCode()
    }


    class Serializer : JsonSerializer<ObvGroupOwnerAndUidKey?>() {
        @Throws(IOException::class)
        override fun serialize(
            value: ObvGroupOwnerAndUidKey?,
            gen: JsonGenerator,
            serializers: SerializerProvider
        ) {
            gen.writeFieldName(
                serializers.getConfig().getBase64Variant()
                    .encode(value!!.groupOwner) + "-" + serializers.getConfig().getBase64Variant()
                    .encode(value.groupUid)
            )
        }
    }

    class Deserializer : KeyDeserializer() {
        @Throws(IOException::class)
        override fun deserializeKey(key: String, context: DeserializationContext): Any {
            val parts: Array<String?> =
                key.split("-".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
            if (parts.size != 2) {
                throw IOException()
            }
            return ObvGroupOwnerAndUidKey(
                context.getConfig().getBase64Variant().decode(parts[0]),
                context.getConfig().getBase64Variant().decode(parts[1])
            )
        }
    }
}
