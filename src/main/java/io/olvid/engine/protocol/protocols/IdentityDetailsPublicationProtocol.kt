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
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoAcceptableChannelException
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createAnyObliviousChannelOrPreKeyInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createServerQueryChannelInfo
import io.olvid.engine.datatypes.containers.ServerQuery.PutUserDataQuery
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


class IdentityDetailsPublicationProtocol(
    protocolManagerSession: ProtocolManagerSession?,
    protocolInstanceUid: UID?,
    currentStateId: Int,
    encodedCurrentState: Encoded?,
    ownedIdentity: Identity?,
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
    override val protocolId: Int = ConcreteProtocol.IDENTITY_DETAILS_PUBLICATION_PROTOCOL_ID


    override val finalStateIds: IntArray = intArrayOf(DETAILS_SENT_STATE_ID, DETAILS_RECEIVED_STATE_ID)

    override fun getStateClass(stateId: Int): Class<*>? {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return InitialProtocolState::class.java
            UPLOADING_PHOTO_STATE_ID -> return UploadingPhotoState::class.java
            DETAILS_SENT_STATE_ID -> return DetailsSentState::class.java
            DETAILS_RECEIVED_STATE_ID -> return DetailsReceivedState::class.java
            else -> return null
        }
    }

    class UploadingPhotoState : ConcreteProtocolState {
        internal val jsonIdentityDetailsWithVersionAndPhoto: String

        constructor(encodedState: Encoded) : super(UPLOADING_PHOTO_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 1) {
                throw Exception()
            }
            this.jsonIdentityDetailsWithVersionAndPhoto = list[0].decodeString()
        }

        constructor(jsonIdentityDetailsWithVersionAndPhoto: String) : super(UPLOADING_PHOTO_STATE_ID) {
            this.jsonIdentityDetailsWithVersionAndPhoto = jsonIdentityDetailsWithVersionAndPhoto
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(jsonIdentityDetailsWithVersionAndPhoto),
                )
            )
        }
    }

    class DetailsSentState : ConcreteProtocolState {
        constructor(encodedState: Encoded) : super(DETAILS_SENT_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        constructor() : super(DETAILS_SENT_STATE_ID)

        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }

    class DetailsReceivedState : ConcreteProtocolState {
        constructor(encodedState: Encoded) : super(DETAILS_RECEIVED_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        constructor() : super(DETAILS_RECEIVED_STATE_ID)

        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }


    override fun getMessageClass(protocolMessageId: Int): Class<*>? {
        when (protocolMessageId) {
            INITIAL_MESSAGE_ID -> return InitialMessage::class.java
            SERVER_PUT_PHOTO_MESSAGE_ID -> return ServerPutPhotoMessage::class.java
            SEND_DETAILS_MESSAGE_ID -> return SendDetailsMessage::class.java
            PROPAGATE_OWN_DETAILS_MESSAGE_ID -> return PropagateOwnDetailsMessage::class.java
            else -> return null
        }
    }

    class InitialMessage : ConcreteProtocolMessage {
        internal val version: Int

        constructor(coreProtocolMessage: CoreProtocolMessage?, version: Int) : super(
            coreProtocolMessage!!
        ) {
            this.version = version
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.version = receivedMessage.inputs[0].decodeLong().toInt()
        }

        override val protocolMessageId: Int = INITIAL_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(version.toLong()),
            )
            }
    }

    class ServerPutPhotoMessage : ConcreteProtocolMessage {
        internal constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!)

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.encodedResponse != null) {
                throw Exception()
            }
        }

        override val protocolMessageId: Int = SERVER_PUT_PHOTO_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }

    class SendDetailsMessage : ConcreteProtocolMessage {
        internal val jsonIdentityDetailsWithVersionAndPhoto: String

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            jsonIdentityDetailsWithVersionAndPhoto: String
        ) : super(coreProtocolMessage!!) {
            this.jsonIdentityDetailsWithVersionAndPhoto = jsonIdentityDetailsWithVersionAndPhoto
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.jsonIdentityDetailsWithVersionAndPhoto =
                receivedMessage.inputs[0].decodeString()
        }

        override val protocolMessageId: Int = SEND_DETAILS_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(jsonIdentityDetailsWithVersionAndPhoto),
            )
            }
    }


    class PropagateOwnDetailsMessage : ConcreteProtocolMessage {
        internal val jsonIdentityDetailsWithVersionAndPhoto: String

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            jsonIdentityDetailsWithVersionAndPhoto: String
        ) : super(coreProtocolMessage!!) {
            this.jsonIdentityDetailsWithVersionAndPhoto = jsonIdentityDetailsWithVersionAndPhoto
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.jsonIdentityDetailsWithVersionAndPhoto =
                receivedMessage.inputs[0].decodeString()
        }

        override val protocolMessageId: Int = PROPAGATE_OWN_DETAILS_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(jsonIdentityDetailsWithVersionAndPhoto),
            )
            }
    }


    // endregion
    // region Steps
    override fun getPossibleStepClasses(stateId: Int): Array<Class<*>> {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return arrayOf<Class<*>>(
                StartPhotoUploadStep::class.java,
                ReceiveDetailsStep::class.java,
                ReceiveOwnDetailsStep::class.java
            )

            UPLOADING_PHOTO_STATE_ID -> return arrayOf<Class<*>>(SendDetailsStep::class.java)
            DETAILS_SENT_STATE_ID, DETAILS_RECEIVED_STATE_ID -> return arrayOf<Class<*>>()
            else -> return arrayOf<Class<*>>()
        }
    }

    class StartPhotoUploadStep(
        internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitialMessage,
        protocol: IdentityDetailsPublicationProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            val ownedIdentity = ownedIdentity
            val jsons: Array<JsonIdentityDetailsWithVersionAndPhoto?>? =
                protocolManagerSession.identityDelegate!!.getOwnedIdentityPublishedAndLatestDetails(
                    protocolManagerSession.session,
                    ownedIdentity
                )

            // check that the published details match the version we are trying to publish
            if (jsons == null) {
                return null
            }
            if (jsons[0]!!.getVersion() != receivedMessage.version) {
                Logger.i("Version mismatch in IdentityDetailsPublicationProtocol " + jsons[0]!!.getVersion() + " " + receivedMessage.version)
                return null
            }

            val publishedDetails = jsons[0]!!

            if (publishedDetails.getPhotoUrl() != null && (publishedDetails.getPhotoServerLabel() == null || publishedDetails.getPhotoServerKey() == null)) {
                // we need to upload a photo
                val photoServerLabel = UID(prng)
                val authEnc = Suite.getDefaultAuthEnc(0)
                val photoServerKey = authEnc.generateKey(prng)!!

                publishedDetails.setPhotoServerKey(Encoded.of(photoServerKey).bytes)
                publishedDetails.setPhotoServerLabel(photoServerLabel.bytes)

                // store the label and key in the details
                protocolManagerSession.identityDelegate.setOwnedIdentityDetailsServerLabelAndKey(
                    protocolManagerSession.session,
                    ownedIdentity,
                    publishedDetails.getVersion(),
                    photoServerLabel,
                    photoServerKey
                )

                val coreProtocolMessage = buildCoreProtocolMessage(
                    createServerQueryChannelInfo(
                        ownedIdentity,
                        PutUserDataQuery(
                            ownedIdentity,
                            photoServerLabel,
                            publishedDetails.getPhotoUrl()!!,
                            photoServerKey
                        )
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    ServerPutPhotoMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )


                val jsonPublishedDetails =
                    protocol.jsonObjectMapper.writeValueAsString(publishedDetails)
                return UploadingPhotoState(jsonPublishedDetails)
            } else {
                // we can directly send the details
                val jsonPublishedDetails =
                    protocol.jsonObjectMapper.writeValueAsString(publishedDetails)

                val contactIdentities =
                    protocolManagerSession.identityDelegate.getContactsOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity
                    )
                if (!contactIdentities.isNullOrEmpty()) {
                    val sendChannelInfos =
                        SendChannelInfo.createAllConfirmedObliviousChannelsOrPreKeysInfoForMultipleIdentities(
                            contactIdentities,
                            ownedIdentity
                        )
                    for (sendChannelInfo in sendChannelInfos!!) {
                        try {
                            val coreProtocolMessage = buildCoreProtocolMessage(sendChannelInfo)
                            val messageToSend: ChannelMessageToSend? = SendDetailsMessage(
                                coreProtocolMessage,
                                jsonPublishedDetails
                            ).generateChannelProtocolMessageToSend()
                            protocolManagerSession.channelDelegate!!.post(
                                protocolManagerSession.session,
                                messageToSend,
                                prng
                            )
                        } catch (_: Exception) {
                            Logger.d("One contact with no channel during IdentityDetailsPublicationProtocol.StartPhotoUploadStep")
                        }
                    }
                }

                run {
                    // send the details to other owned devices
                    val numberOfOtherDevices =
                        protocolManagerSession.identityDelegate.getOtherDeviceUidsOfOwnedIdentity(
                            protocolManagerSession.session,
                            ownedIdentity
                        )!!.size
                    if (numberOfOtherDevices > 0) {
                        try {
                            val coreProtocolMessage = buildCoreProtocolMessage(
                                createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo(
                                    ownedIdentity
                                )
                            )
                            val messageToSend: ChannelMessageToSend? = PropagateOwnDetailsMessage(
                                coreProtocolMessage,
                                jsonPublishedDetails
                            ).generateChannelProtocolMessageToSend()
                            protocolManagerSession.channelDelegate!!.post(
                                protocolManagerSession.session,
                                messageToSend,
                                prng
                            )
                        } catch (_: NoAcceptableChannelException) {
                        }
                    }
                }

                return DetailsSentState()
            }
        }
    }

    class SendDetailsStep(
        internal val startState: UploadingPhotoState,
        internal val receivedMessage: ServerPutPhotoMessage?,
        protocol: IdentityDetailsPublicationProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage!!, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
                val contactIdentities =
                    protocolManagerSession.identityDelegate!!.getContactsOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity
                    )
                if (!contactIdentities.isNullOrEmpty()) {
                    val sendChannelInfos =
                        SendChannelInfo.createAllConfirmedObliviousChannelsOrPreKeysInfoForMultipleIdentities(
                            contactIdentities,
                            ownedIdentity
                        )
                    for (sendChannelInfo in sendChannelInfos!!) {
                        try {
                            val coreProtocolMessage = buildCoreProtocolMessage(sendChannelInfo)
                            val messageToSend: ChannelMessageToSend? = SendDetailsMessage(
                                coreProtocolMessage,
                                startState.jsonIdentityDetailsWithVersionAndPhoto
                            ).generateChannelProtocolMessageToSend()
                            protocolManagerSession.channelDelegate!!.post(
                                protocolManagerSession.session,
                                messageToSend,
                                prng
                            )
                        } catch (_: Exception) {
                            Logger.d("One contact with no channel during IdentityDetailsPublicationProtocol.SendDetailsStep")
                        }
                    }
                }
            }

            run {
                // send the details to other owned devices
                val numberOfOtherDevices =
                    protocolManagerSession.identityDelegate!!.getOtherDeviceUidsOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity
                    )!!.size
                if (numberOfOtherDevices > 0) {
                    try {
                        val coreProtocolMessage = buildCoreProtocolMessage(
                            createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo(ownedIdentity)
                        )
                        val messageToSend: ChannelMessageToSend? = PropagateOwnDetailsMessage(
                            coreProtocolMessage,
                            startState.jsonIdentityDetailsWithVersionAndPhoto
                        ).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    } catch (_: NoAcceptableChannelException) {
                    }
                }
            }

            return DetailsSentState()
        }
    }

    class ReceiveDetailsStep(
        internal val startState: InitialProtocolState?,
        internal val receivedMessage: SendDetailsMessage,
        protocol: IdentityDetailsPublicationProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val contactIdentity = receivedMessage.receptionChannelInfo!!.getRemoteIdentity()
            val ownedIdentity = ownedIdentity
            val jsonIdentityDetailsWithVersionAndPhoto = protocol.jsonObjectMapper
                .readValue<JsonIdentityDetailsWithVersionAndPhoto>(
                    receivedMessage.jsonIdentityDetailsWithVersionAndPhoto,
                    JsonIdentityDetailsWithVersionAndPhoto::class.java
                )

            if (jsonIdentityDetailsWithVersionAndPhoto.getPhotoServerLabel() != null && jsonIdentityDetailsWithVersionAndPhoto.getPhotoServerKey() != null) {
                val publishedDetails: JsonIdentityDetailsWithVersionAndPhoto =
                    protocolManagerSession.identityDelegate!!.getContactPublishedAndTrustedDetails(
                        protocolManagerSession.session,
                        ownedIdentity,
                        contactIdentity
                    )!![0]!!

                if (!(jsonIdentityDetailsWithVersionAndPhoto.getPhotoServerLabel()
                        .contentEquals(publishedDetails.getPhotoServerLabel()) &&
                            ((jsonIdentityDetailsWithVersionAndPhoto.getPhotoServerKey() == null && publishedDetails.getPhotoServerKey() == null) ||
                                    (jsonIdentityDetailsWithVersionAndPhoto.getPhotoServerKey() != null && publishedDetails.getPhotoServerKey() != null && Encoded(
                                        jsonIdentityDetailsWithVersionAndPhoto.getPhotoServerKey()!!
                                    ).decodeSymmetricKey() == Encoded(publishedDetails.getPhotoServerKey()!!).decodeSymmetricKey())) && publishedDetails.getPhotoUrl() != null)
                ) {
                    // we need to download the photo, so we start a child protocol

                    val coreProtocolMessage = CoreProtocolMessage(
                        SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                        ConcreteProtocol.DOWNLOAD_IDENTITY_PHOTO_CHILD_PROTOCOL_ID,
                        UID(prng)
                    )
                    val messageToSend: ChannelMessageToSend? =
                        DownloadIdentityPhotoChildProtocol.InitialMessage(
                            coreProtocolMessage,
                            contactIdentity!!,
                            receivedMessage.jsonIdentityDetailsWithVersionAndPhoto
                        ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
            }

            // update the contact published details
            protocolManagerSession.identityDelegate!!.setContactPublishedDetails(
                protocolManagerSession.session,
                contactIdentity,
                ownedIdentity,
                jsonIdentityDetailsWithVersionAndPhoto,
                false
            )

            return DetailsReceivedState()
        }
    }

    class ReceiveOwnDetailsStep(
        internal val startState: InitialProtocolState?,
        internal val receivedMessage: PropagateOwnDetailsMessage,
        protocol: IdentityDetailsPublicationProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val ownedIdentity = ownedIdentity
            val ownDetailsWithVersionAndPhoto = protocol.jsonObjectMapper
                .readValue<JsonIdentityDetailsWithVersionAndPhoto>(
                    receivedMessage.jsonIdentityDetailsWithVersionAndPhoto,
                    JsonIdentityDetailsWithVersionAndPhoto::class.java
                )

            // update the published details
            val photoDownloadNeeded =
                protocolManagerSession.identityDelegate!!.setOwnedIdentityDetailsFromOtherDevice(
                    protocolManagerSession.session,
                    ownedIdentity,
                    ownDetailsWithVersionAndPhoto
                )

            if (photoDownloadNeeded) {
                // even though another device set the photo, we create a ServerUserData to ensure this photo is retained on server
                protocolManagerSession.identityDelegate.createOwnedIdentityServerUserData(
                    protocolManagerSession.session,
                    ownedIdentity,
                    UID(ownDetailsWithVersionAndPhoto.getPhotoServerLabel()!!)
                )

                // we need to download a photo
                val coreProtocolMessage = CoreProtocolMessage(
                    SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                    ConcreteProtocol.DOWNLOAD_IDENTITY_PHOTO_CHILD_PROTOCOL_ID,
                    UID(prng)
                )
                val messageToSend: ChannelMessageToSend? =
                    DownloadIdentityPhotoChildProtocol.InitialMessage(
                        coreProtocolMessage,
                        ownedIdentity,
                        receivedMessage.jsonIdentityDetailsWithVersionAndPhoto
                    ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return DetailsReceivedState()
        }
    } // endregion

    companion object {
        // region States
        const val UPLOADING_PHOTO_STATE_ID: Int = 1
        const val DETAILS_SENT_STATE_ID: Int = 2
        const val DETAILS_RECEIVED_STATE_ID: Int = 3

        // endregion
        // region Messages
        const val INITIAL_MESSAGE_ID: Int = 0
        const val SERVER_PUT_PHOTO_MESSAGE_ID: Int = 1
        const val SEND_DETAILS_MESSAGE_ID: Int = 2
        const val PROPAGATE_OWN_DETAILS_MESSAGE_ID: Int = 3
    }
}