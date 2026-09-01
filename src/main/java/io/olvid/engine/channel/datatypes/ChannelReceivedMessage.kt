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
package io.olvid.engine.channel.datatypes

import io.olvid.engine.Logger
import io.olvid.engine.crypto.Suite
import io.olvid.engine.crypto.exceptions.DecryptionException
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.NetworkReceivedMessage
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.Encoded


class ChannelReceivedMessage(
    message: NetworkReceivedMessage,
    messageKey: AuthEncKey,
    receptionChannelInfo: ReceptionChannelInfo?
) {
    @JvmField val messageType: Int
    @JvmField val encodedElements: Encoded?
    @JvmField val extendedPayloadKey: AuthEncKey?
    @JvmField val receptionChannelInfo: ReceptionChannelInfo?
    @JvmField val message: NetworkReceivedMessage

    init {
        try {
            // decrypt
            val authEnc = Suite.getAuthEnc(messageKey)!!
            val decryptedMessage =
                Encoded(authEnc.decrypt(messageKey, message.getEncryptedContent())!!)

            // verify the messageKey is properly formatted
            val messageKeyCheckPassed = authEnc.verifyMessageKey(messageKey, decryptedMessage.bytes)
            if (!messageKeyCheckPassed) {
                Logger.e("Received a message not passing the messageKey check. Discarding it!!!!")
                throw Exception()
            }

            // if needed, compute the extended payload key
            if (message.hasExtendedPayload()) {
                val extendedPayloadPRNG = Suite.getDefaultPRNG(0, Seed.of(messageKey))
                extendedPayloadKey = authEnc.generateKey(extendedPayloadPRNG)
            } else {
                extendedPayloadKey = null
            }

            // parse
            val listOfEncoded: Array<Encoded> = decryptedMessage.decodeListWithPadding()
            if (listOfEncoded.size != 2) {
                throw Exception()
            }
            this.messageType = listOfEncoded[0].decodeLong().toInt()
            this.encodedElements = listOfEncoded[1]

            this.receptionChannelInfo = receptionChannelInfo
            this.message = message
        } catch (_: DecryptionException) {
            throw Exception("Undecipherable message.")
        }
    }


    val ownedIdentity: Identity?
        get() = message.ownedIdentity

    val messageUid: UID?
        get() = message.getMessageUid()
}
