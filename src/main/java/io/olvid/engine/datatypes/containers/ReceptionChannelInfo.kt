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
import io.olvid.engine.datatypes.UID
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded


class ReceptionChannelInfo private constructor(
    @JvmField val channelType: Int,
    @JvmField val remoteDeviceUid: UID? = null,
    @JvmField val remoteIdentity: Identity? = null
) {
    fun encode(): Encoded {
        if (channelType == OBLIVIOUS_CHANNEL_TYPE || channelType == PRE_KEY_CHANNEL_TYPE) {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(channelType.toLong()),
                    Encoded.of(remoteDeviceUid!!),
                    Encoded.of(remoteIdentity!!),
                )
            )
        }
        return Encoded.of(arrayOf<Encoded>(Encoded.of(channelType.toLong())))
    }

    override fun equals(other: Any?): Boolean {
        if (other !is ReceptionChannelInfo) {
            return false
        }
        if (other.channelType != this.channelType) {
            return false
        }
        return when (this.channelType) {
            OBLIVIOUS_CHANNEL_TYPE, PRE_KEY_CHANNEL_TYPE ->
                other.remoteDeviceUid == remoteDeviceUid && other.remoteIdentity == remoteIdentity

            else -> true
        }
    }

    companion object {
        const val LOCAL_TYPE: Int = 0
        const val OBLIVIOUS_CHANNEL_TYPE: Int = 1
        const val ASYMMETRIC_CHANNEL_TYPE: Int = 2
        const val PRE_KEY_CHANNEL_TYPE: Int = 5
        const val ANY_OBLIVIOUS_CHANNEL_OR_PRE_KEY_WITH_OWNED_DEVICE_TYPE: Int =
            3 // dummy type, never serialized
        const val ANY_OBLIVIOUS_OR_PRE_KEY_CHANNEL_TYPE: Int = 4 // dummy type, never serialized
        const val ANY_OBLIVIOUS_CHANNEL_TYPE: Int = 6 // dummy type, never serialized

        @JvmStatic
        fun createLocalChannelInfo(): ReceptionChannelInfo {
            return ReceptionChannelInfo(LOCAL_TYPE)
        }

        @JvmStatic
        fun createObliviousChannelInfo(
            remoteDeviceUid: UID,
            remoteIdentity: Identity
        ): ReceptionChannelInfo {
            return ReceptionChannelInfo(OBLIVIOUS_CHANNEL_TYPE, remoteDeviceUid, remoteIdentity)
        }

        @JvmStatic
        fun createAsymmetricChannelInfo(): ReceptionChannelInfo {
            return ReceptionChannelInfo(ASYMMETRIC_CHANNEL_TYPE)
        }

        @JvmStatic
        fun createPreKeyChannelInfo(
            remoteDeviceUid: UID,
            remoteIdentity: Identity
        ): ReceptionChannelInfo {
            return ReceptionChannelInfo(PRE_KEY_CHANNEL_TYPE, remoteDeviceUid, remoteIdentity)
        }


        @JvmStatic
        fun createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(): ReceptionChannelInfo {
            return ReceptionChannelInfo(ANY_OBLIVIOUS_CHANNEL_OR_PRE_KEY_WITH_OWNED_DEVICE_TYPE)
        }

        @JvmStatic
        fun createAnyObliviousChannelOrPreKeyInfo(): ReceptionChannelInfo {
            return ReceptionChannelInfo(ANY_OBLIVIOUS_OR_PRE_KEY_CHANNEL_TYPE)
        }

        @JvmStatic
        fun createAnyObliviousChannelInfo(): ReceptionChannelInfo {
            return ReceptionChannelInfo(ANY_OBLIVIOUS_CHANNEL_TYPE)
        }

        @JvmStatic
        @Throws(DecodingException::class)
        fun of(encodedChannelInfo: Encoded): ReceptionChannelInfo {
            val listOfEncoded: Array<Encoded> = encodedChannelInfo.decodeList()
            if (listOfEncoded.size == 0) {
                throw DecodingException()
            }
            val type = listOfEncoded[0].decodeLong().toInt()
            when (type) {
                LOCAL_TYPE -> {
                    if (listOfEncoded.size != 1) {
                        throw DecodingException()
                    }
                    return createLocalChannelInfo()
                }

                OBLIVIOUS_CHANNEL_TYPE -> {
                    if (listOfEncoded.size != 4 && listOfEncoded.size != 3) { // 4 is here for legacy compatibility
                        throw DecodingException()
                    }
                    return createObliviousChannelInfo(
                        listOfEncoded[1].decodeUid(),
                        listOfEncoded[2].decodeIdentity()
                    )
                }

                ASYMMETRIC_CHANNEL_TYPE -> {
                    if (listOfEncoded.size != 1) {
                        throw DecodingException()
                    }
                    return createAsymmetricChannelInfo()
                }

                PRE_KEY_CHANNEL_TYPE -> {
                    if (listOfEncoded.size != 3) {
                        throw DecodingException()
                    }
                    return createPreKeyChannelInfo(
                        listOfEncoded[1].decodeUid(),
                        listOfEncoded[2].decodeIdentity()
                    )
                }

                else -> throw DecodingException("Unknown reception channel type " + type)
            }
        }
    }
    fun getChannelType(): Int = channelType
    fun getRemoteDeviceUid(): UID? = remoteDeviceUid
    fun getRemoteIdentity(): Identity? = remoteIdentity
}
