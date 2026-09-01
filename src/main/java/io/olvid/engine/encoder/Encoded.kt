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
package io.olvid.engine.encoder

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.key.asymmetric.PrivateKey
import io.olvid.engine.datatypes.key.asymmetric.PublicKey
import io.olvid.engine.datatypes.key.symmetric.SymmetricKey
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.util.UUID

class Encoded(val bytes: ByteArray) {
    val isEncodedValue: Boolean
        get() {
            val len: Int =
                uint32FromBytes(this.bytes, 1)
            if (len + 5 != bytes.size) {
                return false
            }
            return when (this.bytes[0]) {
                BYTE_IDS_BYTE_ARRAY, BYTE_IDS_INT, BYTE_IDS_BOOLEAN, BYTE_IDS_LIST, BYTE_IDS_DICTIONARY, BYTE_IDS_BIG_UINT, BYTE_IDS_SYM_KEY, BYTE_IDS_PUB_KEY, BYTE_IDS_PRV_KEY -> true
                else -> false
            }
        }

    // endregion
    // region Decoders
    @Throws(DecodingException::class)
    fun decodeBytes(): ByteArray {
        if (this.bytes[0] != BYTE_IDS_BYTE_ARRAY) {
            throw DecodingException()
        }
        if (!this.isEncodedValue) {
            throw DecodingException()
        }
        return this.bytes.copyOfRange(5, bytes.size)
    }

    @Throws(DecodingException::class)
    fun decodeString(): String {
        return String(decodeBytes(), StandardCharsets.UTF_8)
    }

    @Throws(DecodingException::class)
    fun decodeUid(): UID {
        return UID(decodeBytes())
    }

    @Throws(DecodingException::class)
    fun decodeIdentity(): Identity {
        return Identity.of(decodeBytes())
    }

    @Throws(DecodingException::class)
    fun decodeSeed(): Seed {
        return Seed(decodeBytes())
    }

    @Throws(DecodingException::class)
    fun decodeUuid(): UUID {
        return UUID.fromString(decodeString())
    }

    @Throws(DecodingException::class)
    fun decodeEncryptedData(): EncryptedBytes {
        return EncryptedBytes(decodeBytes())
    }

    @Throws(DecodingException::class)
    fun decodeLong(): Long {
        if (this.bytes[0] != BYTE_IDS_INT) {
            throw DecodingException()
        }
        if ((bytes.size != 5 + INT_ENCODING_LENGTH) || !this.isEncodedValue) {
            throw DecodingException()
        }
        var res: Long = 0
        for (i in 0..<INT_ENCODING_LENGTH) {
            res = res shl 8
            res += (this.bytes[i + 5].toInt() and 0xff).toLong()
        }
        return res
    }

    @Throws(DecodingException::class)
    fun decodeBoolean(): Boolean {
        if (this.bytes[0] != BYTE_IDS_BOOLEAN) {
            throw DecodingException()
        }
        if ((bytes.size != 5 + 1) || !this.isEncodedValue) {
            throw DecodingException()
        }
        return when (this.bytes[5]) {
            0x00.toByte() -> false
            0x01.toByte() -> true
            else -> throw DecodingException()
        }
    }

    @Throws(DecodingException::class)
    fun decodePublicKey(): PublicKey? {
        if (this.bytes[0] != BYTE_IDS_PUB_KEY || !this.isEncodedValue) {
            throw DecodingException()
        }
        val list = unpack()
        if (list.size != 2) {
            throw DecodingException()
        }
        val algoBytes = list[0].decodeBytes()
        if (algoBytes.size != 2) {
            throw DecodingException()
        }
        val key = list[1].decodeDictionary()
        return PublicKey.of(algoBytes[0], algoBytes[1], key)
    }

    @Throws(DecodingException::class)
    fun decodePrivateKey(): PrivateKey? {
        if (this.bytes[0] != BYTE_IDS_PRV_KEY || !this.isEncodedValue) {
            throw DecodingException()
        }
        val list = unpack()
        if (list.size != 2) {
            throw DecodingException()
        }
        val algoBytes = list[0].decodeBytes()
        if (algoBytes.size != 2) {
            throw DecodingException()
        }
        val key = list[1].decodeDictionary()
        return PrivateKey.of(algoBytes[0], algoBytes[1], key)
    }

    @Throws(DecodingException::class)
    fun decodeSymmetricKey(): SymmetricKey? {
        if (this.bytes[0] != BYTE_IDS_SYM_KEY || !this.isEncodedValue) {
            throw DecodingException()
        }
        val list = unpack()
        if (list.size != 2) {
            throw DecodingException()
        }
        val algoBytes = list[0].decodeBytes()
        if (algoBytes.size != 2) {
            throw DecodingException()
        }
        val key = list[1].decodeDictionary()
        return SymmetricKey.of(algoBytes[0], algoBytes[1], key)
    }


    @Throws(DecodingException::class)
    fun decodeBigUInt(): BigInteger {
        if (this.bytes[0] != BYTE_IDS_BIG_UINT || !this.isEncodedValue) {
            throw DecodingException()
        }
        return BigInteger(1, this.bytes.copyOfRange(5, bytes.size))
    }

    // used to decode a list with some additional bytes at the end
    @Throws(DecodingException::class)
    fun decodeListWithPadding(): Array<Encoded> {
        if (this.bytes[0] != BYTE_IDS_LIST) {
            throw DecodingException()
        }
        val totalLen: Int = uint32FromBytes(this.bytes, 1)
        if (totalLen + 5 > bytes.size) {
            throw DecodingException()
        }

        val list: MutableList<Encoded> = ArrayList()
        var offset = 5
        while (offset + 4 < totalLen + 5) {
            val len: Int = uint32FromBytes(this.bytes, offset + 1)
            if (offset + 5 + len > totalLen + 5) {
                throw DecodingException()
            }
            val elem = Encoded(
                this.bytes.copyOfRange(offset, offset + 5 + len)
            )
            list.add(elem)
            offset += 5 + len
        }
        return list.toTypedArray()
    }

    @Throws(DecodingException::class)
    fun decodeList(): Array<Encoded> {
        if (this.bytes[0] != BYTE_IDS_LIST || !this.isEncodedValue) {
            throw DecodingException()
        }
        return unpack()
    }

    @Throws(DecodingException::class)
    private fun unpack(): Array<Encoded> {
        val list: MutableList<Encoded> = ArrayList()
        var offset = 5
        while (offset + 4 < bytes.size) {
            val len: Int = uint32FromBytes(this.bytes, offset + 1)
            if (offset + 5 + len > bytes.size) {
                throw DecodingException()
            }
            val elem = Encoded(
                this.bytes.copyOfRange(offset, offset + 5 + len)
            )
            list.add(elem)
            offset += 5 + len
        }
        return list.toTypedArray()
    }

    @Throws(DecodingException::class)
    fun decodeDictionary(): HashMap<DictionaryKey, Encoded> {
        if (this.bytes[0] != BYTE_IDS_DICTIONARY || !this.isEncodedValue) {
            throw DecodingException()
        }
        val dict = HashMap<DictionaryKey, Encoded>()
        var offset = 5
        while (offset + 4 < bytes.size) {
            var len: Int = uint32FromBytes(this.bytes, offset + 1)
            if (offset + 5 + len > bytes.size) {
                throw DecodingException()
            }
            // Here we do two copyOfRange -> this could be optimized to a single one, assuming we reimplement the decodeBytes checks
            val key = DictionaryKey(
                Encoded(
                    this.bytes.copyOfRange(offset, offset + 5 + len)
                ).decodeBytes()
            )
            offset += 5 + len

            if (offset + 5 > bytes.size) {
                throw DecodingException()
            }
            len = uint32FromBytes(this.bytes, offset + 1)
            if (offset + 5 + len > bytes.size) {
                throw DecodingException()
            }
            val value = Encoded(
                this.bytes.copyOfRange(offset, offset + 5 + len)
            )
            offset += 5 + len
            dict[key] = value
        }
        return dict
    }

    // used to decode a dictionary with some additional bytes at the end
    @Throws(DecodingException::class)
    fun decodeDictionaryWithPadding(): HashMap<DictionaryKey, Encoded> {
        if (this.bytes[0] != BYTE_IDS_DICTIONARY) {
            throw DecodingException()
        }
        val totalLen: Int = uint32FromBytes(this.bytes, 1)
        if (totalLen + 5 > bytes.size) {
            throw DecodingException()
        }

        val dict = HashMap<DictionaryKey, Encoded>()
        var offset = 5
        while (offset + 4 < totalLen + 5) {
            var len: Int = uint32FromBytes(this.bytes, offset + 1)
            if (offset + 5 + len > totalLen + 5) {
                throw DecodingException()
            }
            // Here we do two copyOfRange -> this could be optimized to a single one, assuming we reimplement the decodeBytes checks
            val key = DictionaryKey(
                Encoded(
                    this.bytes.copyOfRange(offset, offset + 5 + len)
                ).decodeBytes()
            )
            offset += 5 + len

            if (offset + 5 > totalLen + 5) {
                throw DecodingException()
            }
            len = uint32FromBytes(this.bytes, offset + 1)
            if (offset + 5 + len > totalLen + 5) {
                throw DecodingException()
            }
            val value = Encoded(
                this.bytes.copyOfRange(offset, offset + 5 + len)
            )
            offset += 5 + len
            dict[key] = value
        }
        return dict
    }

    @Throws(DecodingException::class)
    fun decodeUidArray(): Array<UID?> {
        val encodedUids = decodeList()
        val uids = arrayOfNulls<UID>(encodedUids.size)
        for (i in uids.indices) {
            uids[i] = encodedUids[i].decodeUid()
        }
        return uids
    }

    @Throws(DecodingException::class)
    fun decodeIdentityArray(): Array<Identity> {
        val encodedIdentities = decodeList()
        return Array(encodedIdentities.size) { i -> encodedIdentities[i].decodeIdentity() }
    }

    @Throws(DecodingException::class)
    fun decodeStringArray(): Array<String> {
        val encodedStrings = decodeList()
        return Array(encodedStrings.size) { encodedStrings[it].decodeString() }
    }

    @Throws(DecodingException::class)
    fun decodeStringMap(): MutableMap<String?, String?> {
        val map: MutableMap<String?, String?> = HashMap()
        val dict = decodeDictionary()
        for (entry in dict.entries) {
            map[entry.key.getString()] = entry.value.decodeString()
        }
        return map
    }

    @Throws(DecodingException::class)
    fun decodeDictionaryArray(): Array<HashMap<DictionaryKey, Encoded>> {
        val encodeds = decodeList()
        return Array(encodeds.size) { encodeds[it].decodeDictionary() }
    } // endregion

    companion object {
        const val INT_ENCODING_LENGTH: Int = 8
        const val ENCODED_HEADER_LENGTH: Int = 5

        private const val BYTE_IDS_BYTE_ARRAY = 0x00.toByte()
        private const val BYTE_IDS_INT = 0x01.toByte()
        private const val BYTE_IDS_BOOLEAN = 0x02.toByte()
        private const val BYTE_IDS_LIST = 0x03.toByte()
        private const val BYTE_IDS_DICTIONARY = 0x04.toByte()
        private const val BYTE_IDS_BIG_UINT = 0x80.toByte()
        private const val BYTE_IDS_SYM_KEY = 0x90.toByte()
        private const val BYTE_IDS_PUB_KEY = 0x91.toByte()
        private const val BYTE_IDS_PRV_KEY = 0x92.toByte()


        @JvmStatic
        fun encodeChunk(chunkNumber: Int, buffer: ByteArray, bufferFullness: Int): ByteArray {
            var chunkNumber = chunkNumber
            val output = ByteArray(15 + INT_ENCODING_LENGTH + bufferFullness)
            output[0] = BYTE_IDS_LIST
            System.arraycopy(
                bytesFromUInt32(10 + INT_ENCODING_LENGTH + bufferFullness),
                0,
                output,
                1,
                4
            )
            output[5] = BYTE_IDS_INT
            output[6] = 0
            output[7] = 0
            output[8] = 0
            output[9] = INT_ENCODING_LENGTH.toByte()
            for (j in 0..<INT_ENCODING_LENGTH) {
                output[9 + INT_ENCODING_LENGTH - j] = (chunkNumber and 0xff).toByte()
                chunkNumber = chunkNumber ushr 8
            }
            output[10 + INT_ENCODING_LENGTH] = BYTE_IDS_BYTE_ARRAY
            System.arraycopy(
                bytesFromUInt32(bufferFullness),
                0,
                output,
                11 + INT_ENCODING_LENGTH,
                4
            )
            System.arraycopy(buffer, 0, output, 15 + INT_ENCODING_LENGTH, bufferFullness)
            return output
        }

        // region Encoder.of
        @Throws(DecodingException::class)
        fun fromLongerByteArray(bytes: ByteArray): Encoded {
            if (bytes.size < 5) {
                throw DecodingException()
            }

            val len: Int = uint32FromBytes(bytes, 1)
            if (bytes.size < len + 5) {
                throw DecodingException()
            }
            return Encoded(bytes.copyOfRange(0, 5 + len))
        }

        @JvmStatic
        fun of(bytes: ByteArray): Encoded {
            val data = ByteArray(bytes.size + 5)
            data[0] = BYTE_IDS_BYTE_ARRAY
            val encodedLength: ByteArray = bytesFromUInt32(bytes.size)
            System.arraycopy(encodedLength, 0, data, 1, 4)
            System.arraycopy(bytes, 0, data, 5, bytes.size)
            return Encoded(data)
        }

        @JvmStatic
        fun of(uid: UID): Encoded {
            return of(uid.bytes)
        }

        @JvmStatic
        fun of(uids: Array<UID?>): Encoded {
            val encodedUids = Array(uids.size) { of(uids[it]!!) }
            return of(encodedUids)
        }


        @JvmStatic
        fun of(cipher: EncryptedBytes): Encoded {
            return of(cipher.getBytes())
        }

        @JvmStatic
        fun of(identity: Identity): Encoded {
            return of(identity.getBytes())
        }

        @JvmStatic
        fun of(identities: Array<Identity>): Encoded {
            val encodedIdentities = Array(identities.size) { of(identities[it]) }
            return of(encodedIdentities)
        }

        @JvmStatic
        fun of(seed: Seed): Encoded {
            return of(seed.getBytes())
        }

        @JvmStatic
        fun of(string: String): Encoded {
            return of(string.toByteArray(StandardCharsets.UTF_8))
        }

        @JvmStatic
        fun of(strings: Array<String>): Encoded {
            val encodedStrings = Array(strings.size) { of(strings[it]) }
            return of(encodedStrings)
        }

        @JvmStatic
        fun of(uuid: UUID?): Encoded {
            return of(Logger.getUuidString(uuid))
        }

        @JvmStatic
        fun of(i: Long): Encoded {
            var i = i
            val data = ByteArray(INT_ENCODING_LENGTH + 5)
            data[0] = BYTE_IDS_INT
            data[1] = 0
            data[2] = 0
            data[3] = 0
            data[4] = INT_ENCODING_LENGTH.toByte()
            for (j in 0..<INT_ENCODING_LENGTH) {
                data[4 + INT_ENCODING_LENGTH - j] = (i and 0xffL).toByte()
                i = i ushr 8
            }
            return Encoded(data)
        }

        @JvmStatic
        fun of(b: Boolean): Encoded {
            val data = ByteArray(1 + 5)
            data[0] = BYTE_IDS_BOOLEAN
            data[1] = 0
            data[2] = 0
            data[3] = 0
            data[4] = 1
            if (b) {
                data[5] = 0x01.toByte()
            } else {
                data[5] = 0x00.toByte()
            }
            return Encoded(data)
        }

        @JvmStatic
        fun of(publicKey: PublicKey): Encoded {
            val keyType: Encoded = of(
                byteArrayOf(
                    publicKey.algorithmClass,
                    publicKey.algorithmImplementation
                )
            )
            val encodedDict: Encoded = of(publicKey.key)
            return pack(BYTE_IDS_PUB_KEY, arrayOf(keyType, encodedDict))
        }

        @JvmStatic
        fun of(privateKey: PrivateKey): Encoded {
            val keyType: Encoded = of(
                byteArrayOf(
                    privateKey.algorithmClass,
                    privateKey.algorithmImplementation
                )
            )
            val encodedDict: Encoded = of(privateKey.key)
            return pack(BYTE_IDS_PRV_KEY, arrayOf(keyType, encodedDict))
        }

        @JvmStatic
        fun of(symmetricKey: SymmetricKey): Encoded {
            val keyType: Encoded = of(
                byteArrayOf(
                    symmetricKey.algorithmClass,
                    symmetricKey.algorithmImplementation
                )
            )
            val encodedDict: Encoded = of(symmetricKey.key)
            return pack(BYTE_IDS_SYM_KEY, arrayOf(keyType, encodedDict))
        }

        @JvmStatic
        @Throws(EncodingException::class)
        fun of(bigInt: BigInteger, len: Int): Encoded {
            if ((bigInt.signum() < 0)
                || (bigInt.bitLength() > 8 * len)
            ) {
                throw EncodingException()
            }
            val data = ByteArray(len + 5)
            data[0] = BYTE_IDS_BIG_UINT
            val encodedLength: ByteArray = bytesFromUInt32(len)
            System.arraycopy(encodedLength, 0, data, 1, 4)
            val bytes = bigInt.toByteArray()
            val offset = len - bytes.size
            if (offset == -1) {
                System.arraycopy(bytes, 1, data, 5, len)
            } else {
                System.arraycopy(bytes, 0, data, 5 + offset, bytes.size)
            }
            return Encoded(data)
        }

        @JvmStatic
        @Throws(EncodingException::class)
        fun bytesFromBigUInt(bigInt: BigInteger, len: Int): ByteArray {
            if ((bigInt.signum() < 0)
                || (bigInt.bitLength() > 8 * len)
            ) {
                throw EncodingException()
            }
            val data = ByteArray(len)
            val bytes = bigInt.toByteArray()
            val offset = len - bytes.size
            if (offset == -1) {
                System.arraycopy(bytes, 1, data, 0, len)
            } else {
                System.arraycopy(bytes, 0, data, offset, bytes.size)
            }
            return data
        }

        @JvmStatic
        fun of(list: Array<Encoded>): Encoded {
            return pack(BYTE_IDS_LIST, list)
        }


        private fun pack(byteId: Byte, list: Array<Encoded>): Encoded {
            var len = 0
            for (encoded in list) {
                len += encoded.bytes.size
            }
            val data = ByteArray(len + 5)
            data[0] = byteId
            val encodedLength: ByteArray = bytesFromUInt32(len)
            System.arraycopy(encodedLength, 0, data, 1, 4)
            var offset = 5
            for (encoded in list) {
                System.arraycopy(encoded.bytes, 0, data, offset, encoded.bytes.size)
                offset += encoded.bytes.size
            }
            return Encoded(data)
        }

        @JvmStatic
        fun of(dict: HashMap<DictionaryKey, Encoded>): Encoded {
            var len = 0
            for (entry in dict.entries) {
                len += 5 + entry.key.data.size
                len += entry.value.bytes.size
            }
            val data = ByteArray(len + 5)
            data[0] = BYTE_IDS_DICTIONARY
            val encodedLength: ByteArray = bytesFromUInt32(len)
            System.arraycopy(encodedLength, 0, data, 1, 4)
            var offset = 5
            for (entry in dict.entries) {
                val encodedKey: Encoded = of(entry.key.data)
                System.arraycopy(encodedKey.bytes, 0, data, offset, encodedKey.bytes.size)
                offset += encodedKey.bytes.size
                val encodedValue: Encoded = entry.value
                System.arraycopy(encodedValue.bytes, 0, data, offset, encodedValue.bytes.size)
                offset += encodedValue.bytes.size
            }
            return Encoded(data)
        }

        @JvmStatic
        fun of(dictionaryArray: Array<HashMap<DictionaryKey, Encoded>>): Encoded {
            val encodeds = Array(dictionaryArray.size) { of(dictionaryArray[it]) }
            return of(encodeds)
        }

        @JvmStatic
        fun of(stringMap: MutableMap<String?, String?>): Encoded {
            val dict = HashMap<DictionaryKey, Encoded>()
            for (entry in stringMap.entries) {
                dict[DictionaryKey(entry.key!!)] = of(entry.value!!)
            }
            return of(dict)
        }

        @JvmStatic
        fun bigUIntFromBytes(data: ByteArray?): BigInteger {
            return BigInteger(1, data)
        }


        // endregion
        // region Utility
        fun bytesFromUInt32(length: Int): ByteArray {
            var length = length
            val res = ByteArray(4)
            for (i in 0..3) {
                res[3 - i] = (length and 0xff).toByte()
                length = length ushr 8
            }
            return res
        }

        @JvmOverloads
        fun uint32FromBytes(bytes: ByteArray, offset: Int = 0): Int {
            var res = 0
            for (i in 0..3) {
                res = res shl 8
                res += bytes[i + offset].toInt() and 0xff
            }
            return res
        }
    }

    override fun equals(other: Any?): Boolean {
        return (other is Encoded) && bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int {
        return bytes.contentHashCode()
    }
}


