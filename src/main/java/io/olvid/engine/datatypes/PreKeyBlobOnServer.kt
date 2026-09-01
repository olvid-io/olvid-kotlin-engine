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

package io.olvid.engine.datatypes

import io.olvid.engine.Logger
import io.olvid.engine.crypto.Signature
import io.olvid.engine.datatypes.containers.PreKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.encoder.Encoded

class PreKeyBlobOnServer(
    @JvmField val preKey: PreKey,
    @JvmField val rawDeviceCapabilities: Array<String>?
) {
    companion object {
        @JvmStatic
        fun verifySignatureAndDecode(
            encodedSignedPreKey: Encoded,
            preKeyOwnerIdentity: Identity,
            expectedDeviceUid: UID,
            serverTimestamp: Long?
        ): PreKeyBlobOnServer? {
            var verifiedEncodedPreKey: Encoded? = null // will remain null if the signature is invalid
            try {
                val encodeds = encodedSignedPreKey.decodeList()
                val payload = encodeds[0].bytes
                val signature = encodeds[1].decodeBytes()
                if (Signature.verify(Constants.SignatureContext.DEVICE_PRE_KEY, payload, preKeyOwnerIdentity, signature)) {
                    verifiedEncodedPreKey = encodeds[0]
                } else {
                    Logger.i("PreKey signature verification failed.")
                }
            } catch (e: Exception) {
                Logger.x(e)
            }

            if (verifiedEncodedPreKey != null) {
                try {
                    val dict = verifiedEncodedPreKey.decodeDictionary()
                    val encodedPreKey = dict[DictionaryKey("prk")] ?: throw Exception()
                    val encodeds = encodedPreKey.decodeList()
                    val deviceUid = encodeds[2].decodeUid()
                    if (expectedDeviceUid != deviceUid) {
                        Logger.w("Device UID mismatch for a preKey received from server")
                        throw Exception()
                    }
                    val keyId = KeyId(encodeds[0].decodeBytes())
                    val compactEncryptionPublicKey = encodeds[1].decodeBytes()
                    val encryptionPublicKey = EncryptionPublicKey.of(compactEncryptionPublicKey)
                    val expirationTimestamp = encodeds[3].decodeLong()

                    val capabilityStrings: Array<String>?
                    val encodedCapabilities = dict[DictionaryKey("cap")]
                    if (encodedCapabilities != null) {
                        capabilityStrings = encodedCapabilities.decodeStringArray()
                    } else {
                        capabilityStrings = null
                    }

                    // check that the received preKey is not already expired
                    if (serverTimestamp != null && expirationTimestamp > serverTimestamp) {
                        return PreKeyBlobOnServer(
                            PreKey(expectedDeviceUid, keyId, encryptionPublicKey, expirationTimestamp),
                            capabilityStrings
                        )
                    }
                } catch (_: Exception) {
                    Logger.i("PreKey decoding failed.")
                }
            }
            return null
        }
    }
}
