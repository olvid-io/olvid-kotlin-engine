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
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.PreKeyBlobOnServer
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.OwnedDeviceAndPreKey
import io.olvid.engine.datatypes.containers.PreKey
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createServerQueryChannelInfo
import io.olvid.engine.datatypes.containers.ServerQuery.OwnedDeviceDiscoveryQuery
import io.olvid.engine.datatypes.containers.ServerQuery.UploadPreKeyQuery
import io.olvid.engine.datatypes.notifications.ProtocolNotifications
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.identities.ObvOwnedDevice.ServerDeviceInfo
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolState
import io.olvid.engine.protocol.protocol_engine.EmptyProtocolMessage
import io.olvid.engine.protocol.protocol_engine.InitialProtocolState
import io.olvid.engine.protocol.protocol_engine.ProtocolStep
import java.nio.charset.StandardCharsets
import java.util.Collections

class OwnedDeviceDiscoveryProtocol(
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
    override val protocolId: Int = ConcreteProtocol.OWNED_DEVICE_DISCOVERY_PROTOCOL_ID

    override val finalStateIds: IntArray = intArrayOf(CANCELLED_STATE_ID, FINISHED_STATE_ID)

    override fun getStateClass(stateId: Int): Class<*>? {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return InitialProtocolState::class.java
            REQUEST_SENT_STATE_ID -> return RequestSentState::class.java
            FINISHED_STATE_ID -> return FinishedState::class.java
            UPLOADING_PRE_KEY_STATE_ID -> return UploadingPreKeyState::class.java
            CANCELLED_STATE_ID -> return CancelledState::class.java
            else -> return null
        }
    }

    class RequestSentState : ConcreteProtocolState {
        @Suppress("unused")
        constructor(encodedState: Encoded) : super(REQUEST_SENT_STATE_ID) {
            val list = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        constructor() : super(REQUEST_SENT_STATE_ID)

        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }

    class FinishedState : ConcreteProtocolState {
        @Suppress("unused")
        constructor(encodedState: Encoded) : super(FINISHED_STATE_ID) {
            val list = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        constructor() : super(FINISHED_STATE_ID)

        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }

    class UploadingPreKeyState : ConcreteProtocolState {
        @Suppress("unused")
        constructor(encodedState: Encoded) : super(UPLOADING_PRE_KEY_STATE_ID) {
            val list = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        constructor() : super(UPLOADING_PRE_KEY_STATE_ID)

        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }

    class CancelledState : ConcreteProtocolState {
        @Suppress("unused")
        constructor(encodedState: Encoded) : super(CANCELLED_STATE_ID) {
            val list = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        constructor() : super(CANCELLED_STATE_ID)

        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }


    override fun getMessageClass(protocolMessageId: Int): Class<*>? {
        when (protocolMessageId) {
            INITIAL_MESSAGE_ID -> return InitialMessage::class.java
            SERVER_QUERY_MESSAGE_ID -> return ServerQueryMessage::class.java
            TRIGGER_OWNED_DEVICE_DISCOVERY_MESSAGE_ID -> return TriggerOwnedDeviceDiscoveryMessage::class.java
            else -> return null
        }
    }

    class InitialMessage : ConcreteProtocolMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!)

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 0) {
                throw Exception()
            }
        }

        override val protocolMessageId: Int = INITIAL_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }


    class ServerQueryMessage : ConcreteProtocolMessage {
        internal val encryptedOwnedDeviceList: EncryptedBytes?

        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!) {
            encryptedOwnedDeviceList = null
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.encodedResponse == null) {
                throw Exception()
            }
            encryptedOwnedDeviceList = receivedMessage.encodedResponse.decodeEncryptedData()
        }

        override val protocolMessageId: Int = SERVER_QUERY_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }

    class TriggerOwnedDeviceDiscoveryMessage : EmptyProtocolMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!)

        constructor(receivedMessage: ReceivedMessage?) : super(receivedMessage)

        override val protocolMessageId: Int = TRIGGER_OWNED_DEVICE_DISCOVERY_MESSAGE_ID
    }

    class UploadPreKeyMessage : ConcreteProtocolMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!))

        override val protocolMessageId: Int = UPLOAD_PRE_KEY_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }


    // endregion
    // region Steps
    override fun getPossibleStepClasses(stateId: Int): Array<Class<*>> {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return arrayOf<Class<*>>(
                SendRequestStep::class.java
            )

            REQUEST_SENT_STATE_ID -> return arrayOf<Class<*>>(ProcessResponseStateStep::class.java)
            UPLOADING_PRE_KEY_STATE_ID -> return arrayOf<Class<*>>(PreKeyUploadedStep::class.java)
            FINISHED_STATE_ID, CANCELLED_STATE_ID -> return arrayOf<Class<*>>()
            else -> return arrayOf<Class<*>>()
        }
    }

    class SendRequestStep : ProtocolStep {
        internal val startState: InitialProtocolState?

        constructor(
            startState: InitialProtocolState?,
            receivedMessage: InitialMessage?,
            protocol: OwnedDeviceDiscoveryProtocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage!!, protocol!!
        ) {
            this.startState = startState
        }

        constructor(
            startState: InitialProtocolState?,
            receivedMessage: TriggerOwnedDeviceDiscoveryMessage?,
            protocol: OwnedDeviceDiscoveryProtocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage!!, protocol!!
        ) {
            this.startState = startState
        }

        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val coreProtocolMessage = buildCoreProtocolMessage(
                createServerQueryChannelInfo(
                    ownedIdentity,
                    OwnedDeviceDiscoveryQuery(ownedIdentity)
                )
            )
            val messageToSend: ChannelMessageToSend? =
                ServerQueryMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                messageToSend,
                prng
            )

            return RequestSentState()
        }
    }


    class ProcessResponseStateStep(
        @field:Suppress("unused") internal val startState: RequestSentState?,
        internal val receivedMessage: ServerQueryMessage,
        protocol: OwnedDeviceDiscoveryProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            // decrypt the received device list
            val decryptedPayload = protocolManagerSession.encryptionForIdentityDelegate!!.decrypt(
                protocolManagerSession.session,
                receivedMessage.encryptedOwnedDeviceList,
                ownedIdentity
            )
            if (decryptedPayload == null) {
                Logger.w("Unable to DECRYPT received OwnedDeviceDiscoveryProtocol payload (or expired query)!")
                return CancelledState()
            }

            // we ignore the multi-device boolean received from the server --> it is only used when querying outside the protocol
            val serverOwnedDevices: HashMap<UID?, SignedPreKeyAndServerInfo?> =
                HashMap<UID?, SignedPreKeyAndServerInfo?>()
            var serverTimestamp: Long? = null
            try {
                val map: HashMap<DictionaryKey, Encoded> =
                    Encoded(decryptedPayload).decodeDictionary()

                val encodedTimestamp = map.get(DictionaryKey("st"))
                if (encodedTimestamp != null) {
                    serverTimestamp = encodedTimestamp.decodeLong()
                }

                val encodedDevices = map.get(DictionaryKey("dev"))!!.decodeList()
                for (encodedDevice in encodedDevices) {
                    val deviceMap: HashMap<DictionaryKey, Encoded> =
                        encodedDevice.decodeDictionary()
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
                            val plaintext =
                                protocolManagerSession.encryptionForIdentityDelegate.decrypt(
                                    protocolManagerSession.session,
                                    encodedName.decodeEncryptedData(),
                                    ownedIdentity
                                )
                            val bytesDeviceName =
                                Encoded(plaintext!!).decodeListWithPadding()[0].decodeBytes()
                            if (bytesDeviceName.size != 0) {
                                deviceName = String(bytesDeviceName, StandardCharsets.UTF_8)
                            }
                        } catch (_: Exception) {
                        }
                    }

                    val encodedSignedPreKey = deviceMap.get(DictionaryKey("prk"))

                    serverOwnedDevices.put(
                        deviceUid, SignedPreKeyAndServerInfo(
                            encodedSignedPreKey,
                            ServerDeviceInfo(
                                deviceName,
                                expirationTimestamp,
                                lastRegistrationTimestamp
                            )
                        )
                    )
                }
            } catch (_: Exception) {
                Logger.w("Unable to DECODE received OwnedDeviceDiscoveryProtocol payload!")
                return CancelledState()
            }

            val oldOwnedDevices: MutableList<OwnedDeviceAndPreKey?>? =
                protocolManagerSession.identityDelegate!!.getDevicesAndPreKeysOfOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity
                )
            var currentDeviceUid: UID? = null
            var currentDevicePreKeyOnServer: PreKey? = null

            for (oldDeviceNullable in oldOwnedDevices!!) {
                val oldDevice = oldDeviceNullable!!
                val signedPreKeyAndServerInfo = serverOwnedDevices.remove(oldDevice.deviceUid)
                if (signedPreKeyAndServerInfo == null) {
                    // device was removed from the server
                    if (oldDevice.currentDevice) {
                        currentDeviceUid = oldDevice.deviceUid
                        // our current device was removed! Do not deactivate it yet, but force a registerPushNotification so it gets deactivated if it should be
                        protocolManagerSession.pushNotificationDelegate!!.forceRegisterPushNotification(
                            ownedIdentity,
                            true
                        )
                    } else {
                        // a deviceUid was removed --> delete the channel and the deviceUid
                        protocolManagerSession.channelDelegate!!.deleteObliviousChannelIfItExists(
                            protocolManagerSession.session,
                            ownedIdentity,
                            oldDevice.deviceUid,
                            ownedIdentity
                        )
                        protocolManagerSession.identityDelegate.removeDeviceForOwnedIdentity(
                            protocolManagerSession.session,
                            ownedIdentity,
                            oldDevice.deviceUid
                        )
                    }
                } else {
                    if (oldDevice.currentDevice) {
                        currentDeviceUid = oldDevice.deviceUid
                        if (signedPreKeyAndServerInfo.encodedSignedPreKey != null) {
                            val preKeyBlob = PreKeyBlobOnServer.verifySignatureAndDecode(
                                signedPreKeyAndServerInfo.encodedSignedPreKey,
                                ownedIdentity,
                                oldDevice.deviceUid!!,
                                serverTimestamp
                            )
                            currentDevicePreKeyOnServer =
                                if (preKeyBlob == null) null else preKeyBlob.preKey
                        } else {
                            currentDevicePreKeyOnServer = null
                        }
                        if (oldDevice.serverDeviceInfo != signedPreKeyAndServerInfo.serverDeviceInfo) {
                            protocolManagerSession.identityDelegate.updateOwnedDevice(
                                protocolManagerSession.session,
                                ownedIdentity,
                                oldDevice.deviceUid,
                                signedPreKeyAndServerInfo.serverDeviceInfo.displayName,
                                signedPreKeyAndServerInfo.serverDeviceInfo.expirationTimestamp,
                                signedPreKeyAndServerInfo.serverDeviceInfo.lastRegistrationTimestamp,
                                null
                            )
                        }
                        continue
                    }

                    val newPreKeyBlob: PreKeyBlobOnServer?
                    val preKeyChanged: Boolean

                    if (signedPreKeyAndServerInfo.encodedSignedPreKey != null) {
                        // there is a preKey on the server, check if it changed and has a valid signature
                        val preKeyBlob = PreKeyBlobOnServer.verifySignatureAndDecode(
                            signedPreKeyAndServerInfo.encodedSignedPreKey,
                            ownedIdentity,
                            oldDevice.deviceUid!!,
                            serverTimestamp
                        )
                        if (preKeyBlob != null &&
                            (oldDevice.preKey == null || (!preKeyBlob.preKey.keyId!!.equals(
                                oldDevice.preKey.keyId
                            ) && oldDevice.preKey.expirationTimestamp < preKeyBlob.preKey.expirationTimestamp))
                        ) {
                            newPreKeyBlob = preKeyBlob
                            preKeyChanged = true
                        } else {
                            newPreKeyBlob = PreKeyBlobOnServer(oldDevice.preKey!!, null)
                            preKeyChanged = false
                        }
                    } else if (oldDevice.preKey != null) {
                        // the preKey was removed!
                        Logger.w("A preKey was removed from the server, this should never happen...")
                        newPreKeyBlob = null
                        preKeyChanged = true
                    } else {
                        newPreKeyBlob = null
                        preKeyChanged = false
                    }


                    // the device exists both locally and on the server --> check what has changed
                    if (preKeyChanged || oldDevice.serverDeviceInfo != signedPreKeyAndServerInfo.serverDeviceInfo) {
                        protocolManagerSession.identityDelegate.updateOwnedDevice(
                            protocolManagerSession.session,
                            ownedIdentity,
                            oldDevice.deviceUid,
                            signedPreKeyAndServerInfo.serverDeviceInfo.displayName,
                            signedPreKeyAndServerInfo.serverDeviceInfo.expirationTimestamp,
                            signedPreKeyAndServerInfo.serverDeviceInfo.lastRegistrationTimestamp,
                            newPreKeyBlob
                        )
                    }
                }
            }

            // now create all new server devices locally
            for (entry in serverOwnedDevices.entries) {
                val serverDeviceInfo = entry.value!!.serverDeviceInfo
                val preKeyBlob =
                    if (entry.value!!.encodedSignedPreKey == null) null else PreKeyBlobOnServer.verifySignatureAndDecode(
                        entry.value!!.encodedSignedPreKey!!,
                        ownedIdentity,
                        entry.key!!,
                        serverTimestamp
                    )

                protocolManagerSession.identityDelegate.addDeviceForOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity,
                    entry.key,
                    serverDeviceInfo.displayName,
                    serverDeviceInfo.expirationTimestamp,
                    serverDeviceInfo.lastRegistrationTimestamp,
                    preKeyBlob,
                    false
                )
            }

            if (serverTimestamp != null) {
                run {
                    // delete expired pre keys (for our server)
                    protocolManagerSession.identityDelegate.expireContactAndOwnedPreKeys(
                        protocolManagerSession.session,
                        ownedIdentity,
                        ownedIdentity.server,
                        serverTimestamp
                    )
                }

                run {
                    val generatePreKey: Boolean
                    val uploadLatestPreKey: Boolean
                    val latestPreKey =
                        protocolManagerSession.identityDelegate.getLatestPreKeyForOwnedIdentity(
                            protocolManagerSession.session,
                            ownedIdentity
                        )
                    val latestPreKeyIsValid =
                        latestPreKey != null && latestPreKey.expirationTimestamp > (serverTimestamp + Constants.PRE_KEY_VALIDITY_DURATION - Constants.PRE_KEY_RENEWAL_INTERVAL)
                    if (currentDevicePreKeyOnServer != null) {
                        if (latestPreKeyIsValid) {
                            if (latestPreKey.keyId == currentDevicePreKeyOnServer.keyId) {
                                // our latest key is already on the server --> do nothing
                                generatePreKey = false
                                uploadLatestPreKey = false
                            } else {
                                // a different key is on the server --> do something!
                                if (currentDevicePreKeyOnServer.expirationTimestamp < latestPreKey.expirationTimestamp) {
                                    // our latest key is more recent --> upload it
                                    generatePreKey = false
                                    uploadLatestPreKey = true
                                } else {
                                    // our latest key is older, this should never happen! --> generate a new one
                                    Logger.e("Found an unknown newer PreKey on the server!")
                                    generatePreKey = true
                                    uploadLatestPreKey = false
                                }
                            }
                        } else {
                            // our local key is too old --> generate a new one
                            generatePreKey = true
                            uploadLatestPreKey = false
                        }
                    } else {
                        // there is no pre key on the server
                        if (latestPreKeyIsValid) {
                            // we have a suitable one --> upload it
                            generatePreKey = false
                            uploadLatestPreKey = true
                        } else {
                            // our local key is too old --> generate a new one
                            generatePreKey = true
                            uploadLatestPreKey = false
                        }
                    }

                    val encodedPreKeyToUpload: ByteArray?

                    if (generatePreKey) {
                        val encodedNewPreKey =
                            protocolManagerSession.identityDelegate.generateNewPreKey(
                                protocolManagerSession.session,
                                ownedIdentity,
                                serverTimestamp + Constants.PRE_KEY_VALIDITY_DURATION
                            )
                        if (encodedNewPreKey != null) {
                            encodedPreKeyToUpload = encodedNewPreKey.bytes
                        } else {
                            encodedPreKeyToUpload = null
                        }
                    } else if (uploadLatestPreKey) {
                        encodedPreKeyToUpload = latestPreKey!!.encodedSignedPreKey!!.bytes
                    } else {
                        encodedPreKeyToUpload = null
                    }
                    if (encodedPreKeyToUpload != null && currentDeviceUid != null) {
                        val coreProtocolMessage = buildCoreProtocolMessage(
                            createServerQueryChannelInfo(
                                ownedIdentity,
                                UploadPreKeyQuery(
                                    ownedIdentity,
                                    currentDeviceUid,
                                    encodedPreKeyToUpload
                                )
                            )
                        )
                        val messageToSend: ChannelMessageToSend? =
                            UploadPreKeyMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )

                        return UploadingPreKeyState()
                    }
                }
            }

            protocolManagerSession.notificationPostingDelegate?.postNotification(
                ProtocolNotifications.NOTIFICATION_OWNED_DEVICE_DISCOVERY_DONE,
                Collections.singletonMap<String, Any>(
                    ProtocolNotifications.NOTIFICATION_OWNED_DEVICE_DISCOVERY_DONE_OWNED_IDENTITY_KEY,
                    ownedIdentity
                )
            )

            return FinishedState()
        }

        private class SignedPreKeyAndServerInfo(
            @JvmField val encodedSignedPreKey: Encoded?,
            @JvmField val serverDeviceInfo: ServerDeviceInfo
        )
    }


    class PreKeyUploadedStep(
        @field:Suppress("unused") internal val startState: RequestSentState?, @field:Suppress(
            "unused"
        ) internal val receivedMessage: UploadPreKeyMessage?, protocol: OwnedDeviceDiscoveryProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage!!, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            return FinishedState()
        }
    } // endregion


    companion object {
        // region States
        const val REQUEST_SENT_STATE_ID: Int = 1
        const val FINISHED_STATE_ID: Int = 2
        const val CANCELLED_STATE_ID: Int = 3
        const val UPLOADING_PRE_KEY_STATE_ID: Int = 4

        // endregion
        // region Messages
        const val INITIAL_MESSAGE_ID: Int = 0
        const val SERVER_QUERY_MESSAGE_ID: Int = 1
        const val TRIGGER_OWNED_DEVICE_DISCOVERY_MESSAGE_ID: Int = 2
        const val UPLOAD_PRE_KEY_MESSAGE_ID: Int = 3
    }
}
