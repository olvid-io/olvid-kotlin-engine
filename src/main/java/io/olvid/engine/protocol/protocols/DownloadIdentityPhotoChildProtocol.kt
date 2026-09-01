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
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createServerQueryChannelInfo
import io.olvid.engine.datatypes.containers.ServerQuery.GetUserDataQuery
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.JsonIdentityDetailsWithVersionAndPhoto
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolState
import io.olvid.engine.protocol.protocol_engine.InitialProtocolState
import io.olvid.engine.protocol.protocol_engine.ProtocolStep
import java.io.ByteArrayOutputStream


class DownloadIdentityPhotoChildProtocol(
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
    override val protocolId: Int = ConcreteProtocol.DOWNLOAD_IDENTITY_PHOTO_CHILD_PROTOCOL_ID


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
        internal val contactIdentity: Identity
        internal val jsonIdentityDetailsWithVersionAndPhoto: String

        constructor(encodedState: Encoded) : super(DOWNLOADING_PHOTO_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 2) {
                throw Exception()
            }
            this.contactIdentity = list[0].decodeIdentity()
            this.jsonIdentityDetailsWithVersionAndPhoto = list[1].decodeString()
        }

        constructor(
            contactIdentity: Identity,
            jsonIdentityDetailsWithVersionAndPhoto: String
        ) : super(
            DOWNLOADING_PHOTO_STATE_ID
        ) {
            this.contactIdentity = contactIdentity
            this.jsonIdentityDetailsWithVersionAndPhoto = jsonIdentityDetailsWithVersionAndPhoto
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(contactIdentity),
                    Encoded.of(jsonIdentityDetailsWithVersionAndPhoto),
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
        internal val contactIdentity: Identity
        internal val jsonIdentityDetailsWithVersionAndPhoto: String

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            contactIdentity: Identity,
            jsonIdentityDetailsWithVersionAndPhoto: String
        ) : super(coreProtocolMessage!!) {
            this.contactIdentity = contactIdentity
            this.jsonIdentityDetailsWithVersionAndPhoto = jsonIdentityDetailsWithVersionAndPhoto
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.contactIdentity = receivedMessage.inputs[0].decodeIdentity()
            this.jsonIdentityDetailsWithVersionAndPhoto =
                receivedMessage.inputs[1].decodeString()
        }

        override val protocolMessageId: Int = INITIAL_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactIdentity),
                Encoded.of(jsonIdentityDetailsWithVersionAndPhoto),
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
            if (this.photoPathToDelete == "") {
                // if the photo was deleted from the server, the GetUserDataServerMethod return an empty String
                this.encryptedPhoto = null
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
        protocol: DownloadIdentityPhotoChildProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): DownloadingPhotoState? {
            val protocolManagerSession = protocolManagerSession!!

            val jsonIdentityDetailsWithVersionAndPhoto = protocol.jsonObjectMapper
                .readValue<JsonIdentityDetailsWithVersionAndPhoto>(
                    receivedMessage.jsonIdentityDetailsWithVersionAndPhoto,
                    JsonIdentityDetailsWithVersionAndPhoto::class.java
                )

            if (jsonIdentityDetailsWithVersionAndPhoto.getPhotoServerLabel() == null || jsonIdentityDetailsWithVersionAndPhoto.getPhotoServerKey() == null) {
                return null
            }
            val photoServerLabel = UID(jsonIdentityDetailsWithVersionAndPhoto.getPhotoServerLabel()!!)

            val coreProtocolMessage = buildCoreProtocolMessage(
                createServerQueryChannelInfo(
                    ownedIdentity,
                    GetUserDataQuery(receivedMessage.contactIdentity, photoServerLabel, false)
                )
            )
            val messageToSend: ChannelMessageToSend? =
                DownloadIdentityPhotoChildProtocol.ServerGetPhotoMessage(coreProtocolMessage)
                    .generateChannelServerQueryMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                messageToSend,
                prng
            )
            return DownloadingPhotoState(
                receivedMessage.contactIdentity,
                receivedMessage.jsonIdentityDetailsWithVersionAndPhoto
            )
        }
    }

    class ProcessPhotoStep(
        internal val startState: DownloadingPhotoState,
        internal val receivedMessage: ServerGetPhotoMessage,
        protocol: DownloadIdentityPhotoChildProtocol?
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
            val jsonIdentityDetailsWithVersionAndPhoto = protocol.jsonObjectMapper
                .readValue<JsonIdentityDetailsWithVersionAndPhoto>(
                    startState.jsonIdentityDetailsWithVersionAndPhoto,
                    JsonIdentityDetailsWithVersionAndPhoto::class.java
                )

            val key =
                Encoded(jsonIdentityDetailsWithVersionAndPhoto.getPhotoServerKey()!!).decodeSymmetricKey() as AuthEncKey?
            val decryptedPhoto = Suite.getAuthEnc(key)!!.decrypt(key, receivedMessage.encryptedPhoto)

            // check whether you downloaded your own photo or a contact photo
            if (startState.contactIdentity.equals(ownedIdentity)) {
                protocolManagerSession.identityDelegate!!.setOwnedDetailsDownloadedPhoto(
                    protocolManagerSession.session,
                    ownedIdentity,
                    jsonIdentityDetailsWithVersionAndPhoto.getVersion(),
                    decryptedPhoto
                )
            } else {
                protocolManagerSession.identityDelegate!!.setContactDetailsDownloadedPhoto(
                    protocolManagerSession.session,
                    startState.contactIdentity,
                    ownedIdentity,
                    jsonIdentityDetailsWithVersionAndPhoto.getVersion(),
                    decryptedPhoto
                )
            }
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