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
import io.olvid.engine.channel.databases.ObliviousChannel
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.NoAcceptableChannelException
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelApplicationMessageToSend
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.ChannelProtocolMessageToSend
import io.olvid.engine.datatypes.containers.MessageToSend
import io.olvid.engine.datatypes.containers.MessageType
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.Encoded


abstract class NetworkChannel : Channel() {
    abstract fun wrapMessageKey(
        messageKey: AuthEncKey?,
        prng: PRNGService?,
        partOfFullRatchetProtocol: Boolean
    ): MessageToSend.Header?

    companion object {
        @Throws(Exception::class)
        fun acceptableChannelsForPosting(
            channelManagerSession: ChannelManagerSession,
            message: ChannelMessageToSend
        ): Array<NetworkChannel?> {
            when (message.sendChannelInfo!!.getChannelType()) {
                SendChannelInfo.OBLIVIOUS_CHANNEL_TYPE, SendChannelInfo.ALL_CONFIRMED_OBLIVIOUS_CHANNELS_OR_PRE_KEY_ON_SAME_SERVER_TYPE, SendChannelInfo.ALL_OWNED_CONFIRMED_OBLIVIOUS_CHANNELS_OR_PRE_KEY_TYPE, SendChannelInfo.OBLIVIOUS_CHANNEL_OR_PRE_KEY_TYPE -> return ObliviousChannel.acceptableChannelsForPosting(
                    channelManagerSession,
                    message
                )

                SendChannelInfo.ASYMMETRIC_CHANNEL_TYPE, SendChannelInfo.ASYMMETRIC_BROADCAST_CHANNEL_TYPE -> return AsymmetricChannel.acceptableChannelsForPosting(
                    message,
                    channelManagerSession.encryptionForIdentityDelegate
                ).map { it as NetworkChannel? }.toTypedArray()

                else -> return arrayOfNulls<NetworkChannel>(0)
            }
        }


        @Throws(Exception::class)
        fun post(
            channelManagerSession: ChannelManagerSession,
            message: ChannelMessageToSend,
            prng: PRNGService
        ): UID {
            if (channelManagerSession.networkSendDelegate == null) {
                Logger.w("NetworkSendDelegate not set yet when posting a ChannelMessageToSend.")
                throw Exception()
            }

            val networkChannels: Array<NetworkChannel?> =
                acceptableChannelsForPosting(channelManagerSession, message)

            if (networkChannels.size == 0) {
                Logger.i("No acceptable channels were found for posting")
                throw NoAcceptableChannelException()
            }

            // get the minimum suite version of all network channels
            var suiteVersion = Suite.LATEST_VERSION
            for (networkChannel in networkChannels) {
                if (networkChannel != null && networkChannel.obliviousEngineVersion < suiteVersion) {
                    suiteVersion = networkChannel.obliviousEngineVersion
                }
            }

            val authEnc = Suite.getDefaultAuthEnc(suiteVersion)

            val messageToSend: MessageToSend?
            val messageUid = UID(prng)
            when (message.messageType) {
                MessageType.APPLICATION_MESSAGE_TYPE -> {
                    if (message !is ChannelApplicationMessageToSend) {
                        Logger.w("Trying to post a message of type " + message.messageType + " that is not a ChannelApplicationMessageToSend.")
                        throw Exception()
                    }
                    val channelApplicationMessageToSend = message
                    val attachments = channelApplicationMessageToSend.getAttachments()
                    val listOfEncodedAttachments = arrayOfNulls<Encoded>(attachments!!.size + 1)
                    val messageToSendAttachments =
                        arrayOfNulls<MessageToSend.Attachment>(attachments.size)

                    var i = 0
                    while (i < attachments.size) {
                        val attachmentKey = authEnc.generateKey(prng)
                        listOfEncodedAttachments[i] = Encoded.of(
                            arrayOf<Encoded>(
                                Encoded.of(attachmentKey!!),
                                Encoded.of(attachments[i]!!.metadata!!)
                            )
                        )
                        messageToSendAttachments[i] = MessageToSend.Attachment(
                            attachments[i]!!.getUrl(),
                            attachments[i]!!.isDeleteAfterSend(),
                            attachments[i]!!.getAttachmentLength(),
                            attachmentKey
                        )
                        i++
                    }
                    // add the message payload after the attachment keys and metadata
                    listOfEncodedAttachments[attachments.size] =
                        Encoded.of(channelApplicationMessageToSend.getMessagePayload()!!)

                    val plaintextContent = Encoded.of(
                        arrayOf<Encoded>(
                            Encoded.of(MessageType.APPLICATION_MESSAGE_TYPE.toLong()),
                            Encoded.of(listOfEncodedAttachments.filterNotNull().toTypedArray<Encoded>())
                        )
                    )

                    /**///// */
                    // Add a padding to message to obfuscate content length
                    val paddedPlaintext = ByteArray(((plaintextContent.bytes.size - 1) or 511) + 1)
                    System.arraycopy(
                        plaintextContent.bytes,
                        0,
                        paddedPlaintext,
                        0,
                        plaintextContent.bytes.size
                    )

                    val messageKey = authEnc.generateMessageKey(prng, paddedPlaintext)

                    val headers: Array<MessageToSend.Header?> =
                        generateHeaders(networkChannels, false, messageKey, prng)

                    // check that all headers are for the same server
                    val server: String = getServer(headers)


                    val encryptedContent = authEnc.encrypt(messageKey, paddedPlaintext, prng)

                    val encryptedExtendedContent: EncryptedBytes?
                    if (channelApplicationMessageToSend.getExtendedMessagePayload() != null) {
                        val extendedMessagePRNG = Suite.getDefaultPRNG(0, Seed.of(messageKey!!))
                        val extendedMessageAuthEncKey = authEnc.generateKey(extendedMessagePRNG)
                        encryptedExtendedContent = authEnc.encrypt(
                            extendedMessageAuthEncKey,
                            channelApplicationMessageToSend.getExtendedMessagePayload(),
                            prng
                        )
                    } else {
                        encryptedExtendedContent = null
                    }
                    messageToSend = MessageToSend(
                        message.sendChannelInfo!!.getFromIdentity(),
                        messageUid,
                        server,
                        encryptedContent,
                        encryptedExtendedContent,
                        headers,
                        messageToSendAttachments,
                        channelApplicationMessageToSend.hasUserContent(),
                        channelApplicationMessageToSend.isVoipMessage()
                    )
                }

                MessageType.PROTOCOL_MESSAGE_TYPE -> {
                    if (message !is ChannelProtocolMessageToSend) {
                        Logger.w("Trying to post a message of type " + message.messageType + " that is not a ChannelProtocolMessageToSend.")
                        throw Exception()
                    }
                    val channelProtocolMessageToSend = message
                    val plaintextContent: Encoded = Encoded.of(
                        arrayOf<Encoded>(
                            Encoded.of(MessageType.PROTOCOL_MESSAGE_TYPE.toLong()),
                            channelProtocolMessageToSend.getEncodedElements()!!
                        )
                    )

                    /**///// */
                    // Add a padding to message to obfuscate content length
                    val paddedPlaintext = ByteArray(((plaintextContent.bytes.size - 1) or 511) + 1)
                    System.arraycopy(
                        plaintextContent.bytes,
                        0,
                        paddedPlaintext,
                        0,
                        plaintextContent.bytes.size
                    )

                    val messageKey = authEnc.generateMessageKey(prng, paddedPlaintext)

                    val headers: Array<MessageToSend.Header?> =
                        generateHeaders(networkChannels, true, messageKey, prng)

                    // check that all headers are for the same server
                    val server: String = getServer(headers)


                    val encryptedContent = authEnc.encrypt(messageKey, paddedPlaintext, prng)
                    messageToSend = MessageToSend(
                        message.sendChannelInfo!!.getFromIdentity(),
                        messageUid,
                        server,
                        encryptedContent,
                        headers,
                        channelProtocolMessageToSend.hasUserContent()
                    )
                }

                else -> {
                    Logger.w("Trying to post a message of type " + message.messageType + " on a network channel.")
                    throw Exception()
                }
            }
            channelManagerSession.networkSendDelegate.post(
                channelManagerSession.session,
                messageToSend
            )
            return messageUid
        }

        private fun generateHeaders(
            networkChannels: Array<NetworkChannel?>,
            protocolMessage: Boolean,
            messageKey: AuthEncKey?,
            prng: PRNGService?
        ): Array<MessageToSend.Header?> {
            val headers = arrayOfNulls<MessageToSend.Header>(networkChannels.size)
            for (i in networkChannels.indices) {
                headers[i] = networkChannels[i]?.wrapMessageKey(messageKey, prng, protocolMessage)
            }

            return headers
        }

        @Throws(Exception::class)
        private fun getServer(headers: Array<MessageToSend.Header?>): String {
            // check that all headers are for the same server
            val server = headers[0]!!.getToIdentity()!!.server
            for (i in 1..<headers.size) {
                if (server != headers[i]!!.getToIdentity()!!.server) {
                    Logger.w("Server mismatch in the headers of a ChannelMessageToSend")
                    throw Exception()
                }
            }
            return server
        }
    }
}
