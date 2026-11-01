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
package io.olvid.engine.protocol.protocols

import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.GroupV2.ServerPhotoInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createServerQueryChannelInfo
import io.olvid.engine.datatypes.containers.ServerQuery.GetUserDataQuery
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.sync.ObvSyncAtom.DiscussionIdentifier
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolState
import io.olvid.engine.protocol.protocol_engine.InitialProtocolState
import io.olvid.engine.protocol.protocol_engine.ProtocolStep
import java.io.ByteArrayOutputStream

// Downloads a custom photo uploaded by another owned device (or found in a snapshot)
class DownloadCustomPhotoProtocol(
    protocolManagerSession: ProtocolManagerSession?,
    protocolInstanceUid: UID?,
    currentStateId: Int,
    encodedCurrentState: Encoded?,
    ownedIdentity: Identity,
    prng: PRNGService,
    jsonObjectMapper: ObjectMapper
) : ConcreteProtocol(
    protocolManagerSession,
    protocolInstanceUid,
    currentStateId,
    encodedCurrentState,
    ownedIdentity,
    prng,
    jsonObjectMapper
) {
    override val protocolId: Int = DOWNLOAD_CUSTOM_PHOTO_PROTOCOL_ID

    override val finalStateIds: IntArray = intArrayOf(PHOTO_DOWNLOADED_STATE_ID)

    override fun getStateClass(stateId: Int): Class<*>? {
        return when (stateId) {
            INITIAL_STATE_ID -> InitialProtocolState::class.java
            DOWNLOADING_PHOTO_STATE_ID -> DownloadingPhotoState::class.java
            PHOTO_DOWNLOADED_STATE_ID -> PhotoDownloadedState::class.java
            else -> null
        }
    }

    // region States

    class DownloadingPhotoState : ConcreteProtocolState {
        internal val target: DiscussionIdentifier
        internal val serverPhotoInfo: ServerPhotoInfo

        constructor(target: DiscussionIdentifier, serverPhotoInfo: ServerPhotoInfo) : super(DOWNLOADING_PHOTO_STATE_ID) {
            this.target = target
            this.serverPhotoInfo = serverPhotoInfo
        }

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(DOWNLOADING_PHOTO_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 2) {
                throw Exception()
            }
            this.target = DiscussionIdentifier.of(list[0])
            this.serverPhotoInfo = ServerPhotoInfo.of(list[1])
        }

        override fun encode(): Encoded {
            return Encoded.of(arrayOf(target.encode()!!, serverPhotoInfo.encode()))
        }
    }

    class PhotoDownloadedState : ConcreteProtocolState(PHOTO_DOWNLOADED_STATE_ID) {
        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }

    // endregion
    // region Messages

    override fun getMessageClass(protocolMessageId: Int): Class<*>? {
        return when (protocolMessageId) {
            INITIAL_MESSAGE_ID -> InitialMessage::class.java
            SERVER_GET_PHOTO_MESSAGE_ID -> ServerGetPhotoMessage::class.java
            else -> null
        }
    }

    class InitialMessage : ConcreteProtocolMessage {
        internal val target: DiscussionIdentifier
        internal val serverPhotoInfo: ServerPhotoInfo

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            target: DiscussionIdentifier,
            serverPhotoInfo: ServerPhotoInfo
        ) : super(coreProtocolMessage!!) {
            this.target = target
            this.serverPhotoInfo = serverPhotoInfo
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val list = receivedMessage.inputs
            if (list.size != 2) {
                throw Exception()
            }
            this.target = DiscussionIdentifier.of(list[0])
            this.serverPhotoInfo = ServerPhotoInfo.of(list[1])
        }

        override val protocolMessageId: Int = INITIAL_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf(target.encode()!!, serverPhotoInfo.encode())
    }

    class ServerGetPhotoMessage : ConcreteProtocolMessage {
        internal val encryptedPhoto: EncryptedBytes?
        internal val photoPathToDelete: String?

        internal constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!) {
            this.encryptedPhoto = null
            this.photoPathToDelete = null
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.encodedResponse == null) {
                throw Exception()
            }
            this.photoPathToDelete = receivedMessage.encodedResponse.decodeString()
            if ("" == this.photoPathToDelete) {
                // the GetUserDataServerMethod returns an empty String when the photo was deleted from the server
                encryptedPhoto = null
            } else {
                receivedMessage.protocolManagerSession!!.fileIo.file(
                    receivedMessage.protocolManagerSession.engineBaseDirectory,
                    this.photoPathToDelete
                ).openInput().use { fis ->
                    ByteArrayOutputStream().use { baos ->
                        fis.copyTo(baos)
                        this.encryptedPhoto = EncryptedBytes(baos.toByteArray())
                    }
                }
            }
        }

        override val protocolMessageId: Int = SERVER_GET_PHOTO_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf()
    }

    // endregion
    // region Steps

    override fun getPossibleStepClasses(stateId: Int): Array<Class<*>> {
        return when (stateId) {
            INITIAL_STATE_ID -> arrayOf(QueryServerStep::class.java)
            DOWNLOADING_PHOTO_STATE_ID -> arrayOf(ProcessPhotoStep::class.java)
            else -> arrayOf()
        }
    }

    class QueryServerStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitialMessage,
        protocol: DownloadCustomPhotoProtocol?
    ) : ProtocolStep(ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!) {
        @Throws(Exception::class)
        override fun executeStep(): DownloadingPhotoState {
            val protocolManagerSession = protocolManagerSession!!

            val coreProtocolMessage = buildCoreProtocolMessage(
                createServerQueryChannelInfo(
                    ownedIdentity,
                    // retry if not found: the other device may still be uploading it
                    GetUserDataQuery(ownedIdentity, receivedMessage.serverPhotoInfo.serverPhotoLabel, true)
                )
            )
            val messageToSend = ServerGetPhotoMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
            protocolManagerSession.channelDelegate!!.post(protocolManagerSession.session, messageToSend, prng)

            return DownloadingPhotoState(receivedMessage.target, receivedMessage.serverPhotoInfo)
        }
    }

    class ProcessPhotoStep(
        internal val startState: DownloadingPhotoState,
        internal val receivedMessage: ServerGetPhotoMessage,
        protocol: DownloadCustomPhotoProtocol?
    ) : ProtocolStep(ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            if (receivedMessage.encryptedPhoto == null) {
                // photo was deleted from the server
                return PhotoDownloadedState()
            }

            val serverPhotoKey = startState.serverPhotoInfo.serverPhotoKey
            val decryptedPhoto = Suite.getAuthEnc(serverPhotoKey)!!.decrypt(serverPhotoKey, receivedMessage.encryptedPhoto) ?: return PhotoDownloadedState()

            protocolManagerSession.identityDelegate!!.setCustomPhotoDownloaded(
                protocolManagerSession.session,
                ownedIdentity,
                startState.target,
                startState.serverPhotoInfo,
                decryptedPhoto
            )

            try {
                protocolManagerSession.fileIo.file(
                    protocolManagerSession.engineBaseDirectory,
                    receivedMessage.photoPathToDelete!!
                ).delete()
            } catch (e: Exception) {
                Logger.x(e)
            }
            return PhotoDownloadedState()
        }
    }

    // endregion

    companion object {
        const val DOWNLOADING_PHOTO_STATE_ID: Int = 1
        const val PHOTO_DOWNLOADED_STATE_ID: Int = 2

        const val INITIAL_MESSAGE_ID: Int = 0
        const val SERVER_GET_PHOTO_MESSAGE_ID: Int = 1
    }
}
