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

import io.olvid.engine.datatypes.UID
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded

class ObvDeviceManagementRequest private constructor(
    action: Int,
    bytesDeviceUid: ByteArray?,
    nickname: String?
) {
    val action: Int
    val bytesDeviceUid: ByteArray?
    val nickname: String?

    init {
        this.action = action
        this.bytesDeviceUid = bytesDeviceUid
        this.nickname = nickname
    }

    fun getDeviceUid(): UID? {
        if (bytesDeviceUid == null) {
            return null
        }
        return UID(bytesDeviceUid)
    }


    fun encode(): Encoded? {
        when (action) {
            ACTION_SET_NICKNAME -> {
                return Encoded.of(
                    arrayOf<Encoded>(
                        Encoded.of(ACTION_SET_NICKNAME.toLong()),
                        Encoded.of(bytesDeviceUid!!),
                        Encoded.of(nickname!!),
                    )
                )
            }

            ACTION_DEACTIVATE_DEVICE -> {
                return Encoded.of(
                    arrayOf<Encoded>(
                        Encoded.of(ACTION_DEACTIVATE_DEVICE.toLong()),
                        Encoded.of(bytesDeviceUid!!),
                    )
                )
            }

            ACTION_SET_UNEXPIRING_DEVICE -> {
                return Encoded.of(
                    arrayOf<Encoded>(
                        Encoded.of(ACTION_SET_UNEXPIRING_DEVICE.toLong()),
                        Encoded.of(bytesDeviceUid!!),
                    )
                )
            }

            else -> {
                return null
            }
        }
    }

    companion object {
        const val ACTION_SET_NICKNAME: Int = 0
        const val ACTION_DEACTIVATE_DEVICE: Int = 1
        const val ACTION_SET_UNEXPIRING_DEVICE: Int = 2

        @JvmStatic
        fun createSetNicknameRequest(
            bytesDeviceUid: ByteArray?,
            nickname: String?
        ): ObvDeviceManagementRequest {
            var nickname = nickname
            if (nickname == null) {
                nickname = ""
            }
            return ObvDeviceManagementRequest(ACTION_SET_NICKNAME, bytesDeviceUid, nickname)
        }

        @JvmStatic
        fun createDeactivateDeviceRequest(bytesDeviceUid: ByteArray?): ObvDeviceManagementRequest {
            return ObvDeviceManagementRequest(ACTION_DEACTIVATE_DEVICE, bytesDeviceUid, null)
        }

        @JvmStatic
        fun createSetUnexpiringDeviceRequest(bytesDeviceUid: ByteArray?): ObvDeviceManagementRequest {
            return ObvDeviceManagementRequest(ACTION_SET_UNEXPIRING_DEVICE, bytesDeviceUid, null)
        }


        @Throws(DecodingException::class)
        fun of(encoded: Encoded): ObvDeviceManagementRequest {
            val encodeds: Array<Encoded> = encoded.decodeList()
            val action = encodeds[0].decodeLong().toInt()
            when (action) {
                ACTION_SET_NICKNAME -> {
                    if (encodeds.size != 3) {
                        throw DecodingException()
                    }
                    val deviceUid = encodeds[1].decodeUid()
                    val nickname = encodeds[2].decodeString()
                    return ObvDeviceManagementRequest(
                        ACTION_SET_NICKNAME,
                        deviceUid.bytes,
                        nickname
                    )
                }

                ACTION_DEACTIVATE_DEVICE -> {
                    if (encodeds.size != 2) {
                        throw DecodingException()
                    }
                    val deviceUid = encodeds[1].decodeUid()
                    return ObvDeviceManagementRequest(
                        ACTION_DEACTIVATE_DEVICE,
                        deviceUid.bytes,
                        null
                    )
                }

                ACTION_SET_UNEXPIRING_DEVICE -> {
                    if (encodeds.size != 2) {
                        throw DecodingException()
                    }
                    val deviceUid = encodeds[1].decodeUid()
                    return ObvDeviceManagementRequest(
                        ACTION_SET_UNEXPIRING_DEVICE,
                        deviceUid.bytes,
                        null
                    )
                }

                else -> {
                    throw DecodingException()
                }
            }
        }
    }
}
