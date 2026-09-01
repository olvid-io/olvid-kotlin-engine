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
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.SerializerProvider
import java.io.IOException

class ObvBytesKey(bytes: ByteArray) : Comparable<ObvBytesKey?> {
    @JvmField val bytes: ByteArray

    init {
        this.bytes = bytes
    }

    fun getBytes(): ByteArray {
        return bytes
    }

    override fun equals(other: Any?): Boolean {
        if (other !is ObvBytesKey) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int {
        return bytes.contentHashCode()
    }

    override fun compareTo(other: ObvBytesKey?): Int {
        if (other == null) return 1
        if (bytes.size != other.bytes.size) {
            return bytes.size - other.bytes.size
        }
        for (i in bytes.indices) {
            if (bytes[i] != other.bytes[i]) {
                return (bytes[i].toInt() and 0xff) - (other.bytes[i].toInt() and 0xff)
            }
        }
        return 0
    }


    class KeySerializer : JsonSerializer<ObvBytesKey?>() {
        @Throws(IOException::class)
        override fun serialize(
            value: ObvBytesKey?,
            gen: JsonGenerator,
            serializers: SerializerProvider
        ) {
            gen.writeFieldName(serializers.getConfig().getBase64Variant().encode(value!!.bytes))
        }
    }

    class KeyDeserializer : com.fasterxml.jackson.databind.KeyDeserializer() {
        @Throws(IOException::class)
        override fun deserializeKey(key: String, ctxt: DeserializationContext): Any {
            return ObvBytesKey(ctxt.getConfig().getBase64Variant().decode(key))
        }
    }

    class Serializer : JsonSerializer<ObvBytesKey?>() {
        @Throws(IOException::class)
        override fun serialize(
            value: ObvBytesKey?,
            gen: JsonGenerator,
            serializers: SerializerProvider
        ) {
            gen.writeString(serializers.getConfig().getBase64Variant().encode(value!!.bytes))
        }
    }

    class Deserializer : JsonDeserializer<ObvBytesKey?>() {
        @Throws(IOException::class)
        override fun deserialize(p: JsonParser, context: DeserializationContext): ObvBytesKey {
            return ObvBytesKey(context.getConfig().getBase64Variant().decode(p.getValueAsString()))
        }
    }
}
