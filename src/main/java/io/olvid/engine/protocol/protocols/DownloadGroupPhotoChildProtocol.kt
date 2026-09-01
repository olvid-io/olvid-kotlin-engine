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
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.GroupInformation
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createServerQueryChannelInfo
import io.olvid.engine.datatypes.containers.ServerQuery.GetUserDataQuery
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.JsonGroupDetailsWithVersionAndPhoto
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolState
import io.olvid.engine.protocol.protocol_engine.InitialProtocolState
import io.olvid.engine.protocol.protocol_engine.ProtocolStep
import java.io.ByteArrayOutputStream


class DownloadGroupPhotoChildProtocol(
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
    override val protocolId: Int = ConcreteProtocol.DOWNLOAD_GROUP_PHOTO_CHILD_PROTOCOL_ID


    override val finalStateIds: IntArray = intArrayOf(PHOTO_DOWNLOADED_STATE_ID)

    override fun getStateClass(stateId: Int): Class<*>? {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return InitialProtocolState::class.java
            DOWNLOADING_PHOTO_STATE_ID -> return DownloadingPhotoState::class.java
            PHOTO_DOWNLOADED_STATE_ID -> return PhotoDownloadedState::class.java
            else -> return null
        }
    }

    class DownloadingPhotoState : ConcreteProtocolState {
        internal val groupInformation: GroupInformation

        constructor(encodedState: Encoded) : super(DOWNLOADING_PHOTO_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 1) {
                throw Exception()
            }
            this.groupInformation = GroupInformation.of(list[0])
        }

        constructor(groupInformation: GroupInformation) : super(DOWNLOADING_PHOTO_STATE_ID) {
            this.groupInformation = groupInformation
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    groupInformation.encode(),
                )
            )
        }
    }

    class PhotoDownloadedState : ConcreteProtocolState {
        constructor(encodedState: Encoded) : super(PHOTO_DOWNLOADED_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        constructor() : super(PHOTO_DOWNLOADED_STATE_ID)

        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }


    override fun getMessageClass(protocolMessageId: Int): Class<*>? {
        when (protocolMessageId) {
            INITIAL_MESSAGE_ID -> return InitialMessage::class.java
            SERVER_GET_PHOTO_MESSAGE_ID -> return ServerGetPhotoMessage::class.java
            else -> return null
        }
    }

    class InitialMessage : ConcreteProtocolMessage {
        internal val groupInformation: GroupInformation

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupInformation: GroupInformation
        ) : super(coreProtocolMessage!!) {
            this.groupInformation = groupInformation
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.groupInformation = GroupInformation.of(receivedMessage.inputs[0])
        }

        override val protocolMessageId: Int = INITIAL_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                groupInformation.encode(),
            )
            }
    }

    class ServerGetPhotoMessage : ConcreteProtocolMessage {
        internal val encryptedPhoto: EncryptedBytes?
        internal val photoPathToDelete: String?

        internal constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!) {
            this.encryptedPhoto = null
            this.photoPathToDelete = null
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.encodedResponse == null) {
                throw Exception()
            }
            this.photoPathToDelete = receivedMessage.encodedResponse.decodeString()
            if ("" == this.photoPathToDelete) {
                // if the photo was deleted from the server, the GetUserDataServerMethod return an empty String
                encryptedPhoto = null
            } else {
                receivedMessage.protocolManagerSession!!.fileIo.file(
                    receivedMessage.protocolManagerSession.engineBaseDirectory,
                    this.photoPathToDelete
                ).openInput().use { fis ->
                    ByteArrayOutputStream().use { baos ->
                        val buffer = ByteArray(32768)
                        var c: Int
                        while ((fis.read(buffer).also { c = it }) > 0) {
                            baos.write(buffer, 0, c)
                        }
                        this.encryptedPhoto = EncryptedBytes(baos.toByteArray())
                    }
                }
            }
        }

        override val protocolMessageId: Int = SERVER_GET_PHOTO_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }


    // endregion
    // region Steps
    override fun getPossibleStepClasses(stateId: Int): Array<Class<*>> {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return arrayOf<Class<*>>(
                QueryServerStep::class.java
            )

            DOWNLOADING_PHOTO_STATE_ID -> return arrayOf<Class<*>>(ProcessPhotoStep::class.java)
            PHOTO_DOWNLOADED_STATE_ID -> return arrayOf<Class<*>>()
            else -> return arrayOf<Class<*>>()
        }
    }


    class QueryServerStep(
        internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitialMessage,
        protocol: DownloadGroupPhotoChildProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): DownloadingPhotoState? {
            val protocolManagerSession = protocolManagerSession!!

            val jsonGroupDetailsWithVersionAndPhoto = protocol.jsonObjectMapper
                .readValue<JsonGroupDetailsWithVersionAndPhoto>(
                    receivedMessage.groupInformation.serializedGroupDetailsWithVersionAndPhoto,
                    JsonGroupDetailsWithVersionAndPhoto::class.java
                )

            if (jsonGroupDetailsWithVersionAndPhoto.getPhotoServerLabel() == null || jsonGroupDetailsWithVersionAndPhoto.getPhotoServerKey() == null) {
                return null
            }
            val photoServerLabel = UID(jsonGroupDetailsWithVersionAndPhoto.getPhotoServerLabel()!!)

            val coreProtocolMessage = buildCoreProtocolMessage(
                createServerQueryChannelInfo(
                    ownedIdentity,
                    GetUserDataQuery(
                        receivedMessage.groupInformation.groupOwnerIdentity,
                        photoServerLabel,
                        false
                    )
                )
            )
            val messageToSend: ChannelMessageToSend? =
                DownloadGroupPhotoChildProtocol.ServerGetPhotoMessage(coreProtocolMessage)
                    .generateChannelServerQueryMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                messageToSend,
                prng
            )
            return DownloadingPhotoState(receivedMessage.groupInformation)
        }
    }

    class ProcessPhotoStep(
        internal val startState: DownloadingPhotoState,
        internal val receivedMessage: ServerGetPhotoMessage,
        protocol: DownloadGroupPhotoChildProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            if (receivedMessage.encryptedPhoto == null) {
                // photo was delete from the server
                return PhotoDownloadedState()
            }
            val jsonGroupDetailsWithVersionAndPhoto = protocol.jsonObjectMapper
                .readValue<JsonGroupDetailsWithVersionAndPhoto>(
                    startState.groupInformation.serializedGroupDetailsWithVersionAndPhoto,
                    JsonGroupDetailsWithVersionAndPhoto::class.java
                )

            val key =
                Encoded(jsonGroupDetailsWithVersionAndPhoto.getPhotoServerKey()!!).decodeSymmetricKey() as AuthEncKey?
            val decryptedPhoto = Suite.getAuthEnc(key)!!.decrypt(key, receivedMessage.encryptedPhoto)

            protocolManagerSession.identityDelegate!!.setContactGroupDownloadedPhoto(
                protocolManagerSession.session,
                ownedIdentity,
                startState.groupInformation.getGroupOwnerAndUid(),
                jsonGroupDetailsWithVersionAndPhoto.getVersion(),
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
    } // endregion

    companion object {
        // region States
        const val DOWNLOADING_PHOTO_STATE_ID: Int = 1
        const val PHOTO_DOWNLOADED_STATE_ID: Int = 2

        // endregion
        // region Messages
        const val INITIAL_MESSAGE_ID: Int = 0
        const val SERVER_GET_PHOTO_MESSAGE_ID: Int = 1
    }
}