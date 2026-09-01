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
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoAcceptableChannelException
import io.olvid.engine.datatypes.SessionCommitListener
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo
import io.olvid.engine.datatypes.notifications.ProtocolNotifications
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.identities.ObvKeycloakAuthType
import io.olvid.engine.engine.types.identities.ObvKeycloakAuthType.OpenIdConnect
import io.olvid.engine.engine.types.identities.ObvKeycloakState
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolState
import io.olvid.engine.protocol.protocol_engine.InitialProtocolState
import io.olvid.engine.protocol.protocol_engine.ProtocolStep
import org.jose4j.jwk.JsonWebKey
import org.jose4j.jwk.JsonWebKeySet

class KeycloakBindingAndUnbindingProtocol(
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
    override val protocolId: Int = ConcreteProtocol.KEYCLOAK_BINDING_AND_UNBINDING_PROTOCOL_ID

    override val finalStateIds: IntArray = intArrayOf(FINISHED_STATED_ID)


    override fun getStateClass(stateId: Int): Class<*>? {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return InitialProtocolState::class.java
            FINISHED_STATED_ID -> return FinishedProtocolState::class.java
            else -> return null
        }
    }


    class FinishedProtocolState : ConcreteProtocolState {
        @Suppress("unused")
        constructor(encodedState: Encoded) : super(KeycloakContactAdditionProtocol.FINISHED_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        constructor() : super(KeycloakContactAdditionProtocol.FINISHED_STATE_ID)

        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }


    override fun getMessageClass(protocolMessageId: Int): Class<*>? {
        when (protocolMessageId) {
            OWNED_IDENTITY_KEYCLOAK_BINDING_MESSAGE_ID -> return OwnedIdentityKeycloakBindingMessage::class.java
            OWNED_IDENTITY_KEYCLOAK_UNBINDING_MESSAGE_ID -> return OwnedIdentityKeycloakUnbindingMessage::class.java
            PROPAGATE_KEYCLOAK_BINDING_MESSAGE_ID -> return PropagateKeycloakBindingMessage::class.java
            PROPAGATE_KEYCLOAK_UNBINDING_MESSAGE_ID -> return PropagateKeycloakUnbindingMessage::class.java
            else -> return null
        }
    }

    class OwnedIdentityKeycloakBindingMessage : ConcreteProtocolMessage {
        internal val keycloakState: ObvKeycloakState
        internal val keycloakUserId: String

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            keycloakState: ObvKeycloakState,
            keycloakUserId: String
        ) : super(coreProtocolMessage!!) {
            this.keycloakState = keycloakState
            this.keycloakUserId = keycloakUserId
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.keycloakState = ObvKeycloakState.of(receivedMessage.inputs[0])
            this.keycloakUserId = receivedMessage.inputs[1].decodeString()
        }


        override val protocolMessageId: Int = OWNED_IDENTITY_KEYCLOAK_BINDING_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                keycloakState.encode(),
                Encoded.of(keycloakUserId),
            )
            }
    }

    class OwnedIdentityKeycloakUnbindingMessage : ConcreteProtocolMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 0) {
                throw Exception()
            }
        }

        override val protocolMessageId: Int = OWNED_IDENTITY_KEYCLOAK_UNBINDING_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }


    class PropagateKeycloakBindingMessage : ConcreteProtocolMessage {
        @JvmField val keycloakUserId: String
        @JvmField val keycloakServer: String
        @JvmField val clientId: String? // may be null --> encoded as an empty String in this case
        @JvmField val clientSecret: String? // may be null --> encoded as an empty String in this case
        @JvmField val jwks: String
        @JvmField val signatureKey: String

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            keycloakUserId: String,
            keycloakState: ObvKeycloakState
        ) : super(coreProtocolMessage!!) {
            this.keycloakUserId = keycloakUserId
            this.keycloakServer = keycloakState.keycloakServer!!

            var oidc: OpenIdConnect? = null
            for (authType in keycloakState.supportedAuthenticationMethods) {
                if (authType is OpenIdConnect) {
                    oidc = authType

                }
            }
            if (oidc != null) {
                this.clientId = oidc.clientId
                this.clientSecret = oidc.clientSecret
            } else {
                this.clientId = null
                this.clientSecret = null
            }
            this.jwks = keycloakState.jwks!!.toJson()
            this.signatureKey = keycloakState.signatureKey!!.toJson()
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 6) {
                throw Exception()
            }
            this.keycloakUserId = receivedMessage.inputs[0].decodeString()
            this.keycloakServer = receivedMessage.inputs[1].decodeString()
            val clientId = receivedMessage.inputs[2].decodeString()
            this.clientId = if (clientId.isEmpty()) null else clientId
            val clientSecret = receivedMessage.inputs[3].decodeString()
            this.clientSecret = if (clientSecret.isEmpty()) null else clientSecret
            this.jwks = receivedMessage.inputs[4].decodeString()
            this.signatureKey = receivedMessage.inputs[5].decodeString()
        }

        override val protocolMessageId: Int = PROPAGATE_KEYCLOAK_BINDING_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(keycloakUserId),
                Encoded.of(keycloakServer),
                Encoded.of(if (clientId == null) "" else clientId),
                Encoded.of(if (clientSecret == null) "" else clientSecret),
                Encoded.of(jwks),
                Encoded.of(signatureKey),
            )
            }
    }

    class PropagateKeycloakUnbindingMessage : ConcreteProtocolMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 0) {
                throw Exception()
            }
        }

        override val protocolMessageId: Int = PROPAGATE_KEYCLOAK_UNBINDING_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }


    // endregion
    // region steps
    override fun getPossibleStepClasses(stateId: Int): Array<Class<*>> {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return arrayOf<Class<*>>(
                OwnedIdentityKeycloakBindingStep::class.java,
                OwnedIdentityKeycloakUnbindingStep::class.java
            )

            FINISHED_STATED_ID -> return arrayOf<Class<*>>()
            else -> return arrayOf<Class<*>>()
        }
    }

    class OwnedIdentityKeycloakBindingStep : ProtocolStep {
        @JvmField var startState: InitialProtocolState?
        @JvmField var keycloakUserId: String?
        @JvmField var keycloakState: ObvKeycloakState?
        @JvmField var propagationNeeded: Boolean


        @Suppress("unused")
        constructor(
            startState: InitialProtocolState?,
            receivedMessage: OwnedIdentityKeycloakBindingMessage,
            protocol: KeycloakBindingAndUnbindingProtocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.keycloakUserId = receivedMessage.keycloakUserId
            this.keycloakState = receivedMessage.keycloakState
            this.propagationNeeded = true
        }

        @Suppress("unused")
        constructor(
            startState: InitialProtocolState?,
            receivedMessage: PropagateKeycloakBindingMessage,
            protocol: KeycloakBindingAndUnbindingProtocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.keycloakUserId = receivedMessage.keycloakUserId
            val supportedAuthTypes: MutableList<ObvKeycloakAuthType?> =
                ArrayList<ObvKeycloakAuthType?>()
            if (receivedMessage.clientId != null) {
                supportedAuthTypes.add(
                    OpenIdConnect(
                        receivedMessage.clientId,
                        receivedMessage.clientSecret
                    )
                )
            }
            this.keycloakState = ObvKeycloakState(
                receivedMessage.keycloakServer,
                supportedAuthTypes,
                JsonWebKeySet(receivedMessage.jwks),
                JsonWebKey.Factory.newJwk(receivedMessage.signatureKey),
                null,
                false,
                null,
                0,
                0
            )
            this.propagationNeeded = false
        }

        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            /**////// */
            // re-check all inputs
            if (keycloakUserId == null || keycloakState == null || keycloakState!!.keycloakServer == null || keycloakState!!.jwks == null) {
                Logger.w("Bad inputs for OwnedIdentityKeycloakBindingStep, aborting.")
                return FinishedProtocolState()
            }

            /**////// */
            // switch owned identity to keycloak managed, but
            // do not update details
            //   --> this will be done once we upload our key and download new signed details from keycloak
            protocolManagerSession.identityDelegate!!.bindOwnedIdentityToKeycloak(
                protocolManagerSession.session,
                ownedIdentity,
                keycloakUserId,
                keycloakState
            )


            /**////// */
            // re-check all contacts
            protocolManagerSession.identityDelegate.reCheckAllCertifiedByOwnKeycloakContacts(
                protocolManagerSession.session,
                ownedIdentity
            )

            /**/////// */
            // propagate the binding to other owned devices (if any)
            if (propagationNeeded) {
                val numberOfOtherDevices =
                    protocolManagerSession.identityDelegate.getOtherDeviceUidsOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity
                    )!!.size
                if (numberOfOtherDevices > 0) {
                    try {
                        val coreProtocolMessage = buildCoreProtocolMessage(
                            createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo(ownedIdentity)
                        )
                        val messageToSend: ChannelMessageToSend? = PropagateKeycloakBindingMessage(
                            coreProtocolMessage,
                            keycloakUserId!!,
                            keycloakState!!
                        ).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    } catch (_: NoAcceptableChannelException) {
                    }
                }
            } else {
                // notify the app that a keycloak registration & synchronization is required
                protocolManagerSession.session.addSessionCommitListener(SessionCommitListener {
                    val userInfo = HashMap<String, Any>()
                    userInfo.put(
                        ProtocolNotifications.NOTIFICATION_KEYCLOAK_SYNCHRONIZATION_REQUIRED_OWNED_IDENTITY_KEY,
                        ownedIdentity
                    )
                    protocolManagerSession.notificationPostingDelegate?.postNotification(
                        ProtocolNotifications.NOTIFICATION_KEYCLOAK_SYNCHRONIZATION_REQUIRED,
                        userInfo
                    )
                })
            }

            return FinishedProtocolState()
        }
    }


    class OwnedIdentityKeycloakUnbindingStep : ProtocolStep {
        @JvmField var startState: InitialProtocolState?
        @JvmField var propagationNeeded: Boolean

        @Suppress("unused")
        constructor(
            startState: InitialProtocolState?,
            receivedMessage: OwnedIdentityKeycloakUnbindingMessage?,
            protocol: KeycloakBindingAndUnbindingProtocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage!!, protocol!!
        ) {
            this.startState = startState
            this.propagationNeeded = true
        }

        @Suppress("unused")
        constructor(
            startState: InitialProtocolState?,
            receivedMessage: PropagateKeycloakUnbindingMessage?,
            protocol: KeycloakBindingAndUnbindingProtocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage!!, protocol!!
        ) {
            this.startState = startState
            this.propagationNeeded = false
        }

        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            /**////// */
            // un-switch owned identity from keycloak managed, and update details
            val version: Int
            run {
                version = protocolManagerSession.identityDelegate!!.unbindOwnedIdentityFromKeycloak(
                    protocolManagerSession.session,
                    ownedIdentity
                )
                if (version == -2) {
                    throw Exception()
                }
            }

            /**////// */
            // start a child identityDetailsPublicationProtocol
            run {
                val childProtocolInstanceUid = UID(prng)
                val coreProtocolMessage = CoreProtocolMessage(
                    SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                    ConcreteProtocol.IDENTITY_DETAILS_PUBLICATION_PROTOCOL_ID,
                    childProtocolInstanceUid
                )
                val messageToSend: ChannelMessageToSend? =
                    IdentityDetailsPublicationProtocol.InitialMessage(coreProtocolMessage, version)
                        .generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }


            /**////// */
            // unmark all certified contacts
            run {
                protocolManagerSession.identityDelegate!!.unmarkAllCertifiedByOwnKeycloakContacts(
                    protocolManagerSession.session,
                    ownedIdentity
                )
            }

            /**/////// */
            // propagate the unbinding to other owned devices (if any)
            if (propagationNeeded) {
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
                        val messageToSend: ChannelMessageToSend? =
                            PropagateKeycloakUnbindingMessage(coreProtocolMessage).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    } catch (_: NoAcceptableChannelException) {
                    }
                }
            }

            return FinishedProtocolState()
        }
    } // endregion

    companion object {
        // region states
        const val FINISHED_STATED_ID: Int = 1

        // endregion
        // region messages
        const val OWNED_IDENTITY_KEYCLOAK_BINDING_MESSAGE_ID: Int = 0
        const val OWNED_IDENTITY_KEYCLOAK_UNBINDING_MESSAGE_ID: Int = 1
        const val PROPAGATE_KEYCLOAK_BINDING_MESSAGE_ID: Int = 2
        const val PROPAGATE_KEYCLOAK_UNBINDING_MESSAGE_ID: Int = 3
    }
}
