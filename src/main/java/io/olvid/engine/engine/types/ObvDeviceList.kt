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

import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPrivateKey
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.identities.ObvOwnedDevice.ServerDeviceInfo
import java.nio.charset.StandardCharsets

class ObvDeviceList(
    multiDevice: Boolean?,
    deviceUidsAndServerInfo: HashMap<ObvBytesKey?, ServerDeviceInfo?>?
) {
    @JvmField val multiDevice: Boolean? // null if the server is not able to determine if the user has multi-device permission
    @JvmField val deviceUidsAndServerInfo: HashMap<ObvBytesKey?, ServerDeviceInfo?>?

    init {
        this.deviceUidsAndServerInfo = deviceUidsAndServerInfo
        this.multiDevice = multiDevice
    }

    companion object {
        @JvmStatic
        @Throws(Exception::class)
        fun of(
            encryptedPayload: EncryptedBytes?,
            privateKey: EncryptionPrivateKey?
        ): ObvDeviceList {
            val publicKeyEncryption = Suite.getPublicKeyEncryption(privateKey)!!

            // decrypt the received device list
            val decryptedPayload = publicKeyEncryption.decrypt(privateKey, encryptedPayload)!!

            val map: HashMap<DictionaryKey, Encoded> =
                Encoded(decryptedPayload).decodeDictionary()

            // check for multi-device (is null if server could not determine if multi-device is available)
            val encodedMulti = map.get(DictionaryKey("multi"))
            val multiDevice: Boolean?
            if (encodedMulti != null) {
                multiDevice = encodedMulti.decodeBoolean()
            } else {
                multiDevice = null
            }

            // now get the actual device list
            val deviceUidsAndServerInfo = HashMap<ObvBytesKey?, ServerDeviceInfo?>()

            val encodedDevices = map.get(DictionaryKey("dev"))!!.decodeList()
            for (encodedDevice in encodedDevices) {
                val deviceMap: HashMap<DictionaryKey, Encoded> = encodedDevice.decodeDictionary()
                val deviceUid = deviceMap.get(DictionaryKey("uid"))!!.decodeUid()

                val encodedExpiration = deviceMap.get(DictionaryKey("exp"))
                val expirationTimestamp =
                    if (encodedExpiration == null) null else encodedExpiration.decodeLong()

                val encodedRegistration = deviceMap.get(DictionaryKey("reg"))
                val lastRegistrationTimestamp =
                    if (encodedRegistration == null) null else encodedRegistration.decodeLong()

                val encodedName = deviceMap.get(DictionaryKey("name"))
                var deviceName: String? = null
                if (encodedName != null) {
                    try {
                        val plaintext = publicKeyEncryption.decrypt(
                            privateKey,
                            encodedName.decodeEncryptedData()
                        )!!
                        val bytesDeviceName =
                            Encoded(plaintext).decodeListWithPadding()[0].decodeBytes()
                        if (bytesDeviceName.size != 0) {
                            deviceName = String(bytesDeviceName, StandardCharsets.UTF_8)
                        }
                    } catch (_: Exception) {
                    }
                }

                deviceUidsAndServerInfo.put(
                    ObvBytesKey(deviceUid.bytes),
                    ServerDeviceInfo(deviceName, expirationTimestamp, lastRegistrationTimestamp)
                )
            }

            return ObvDeviceList(multiDevice, deviceUidsAndServerInfo)
        }
    }
}
