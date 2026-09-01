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
package io.olvid.engine.protocol.protocol_engine

import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.UID
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.protocol.databases.ProtocolInstance
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocols.ChannelCreationWithContactDeviceProtocol
import io.olvid.engine.protocol.protocols.ChannelCreationWithOwnedDeviceProtocol
import io.olvid.engine.protocol.protocols.ContactManagementProtocol
import io.olvid.engine.protocol.protocols.ContactMutualIntroductionProtocol
import io.olvid.engine.protocol.protocols.DeviceCapabilitiesDiscoveryProtocol
import io.olvid.engine.protocol.protocols.DeviceDiscoveryChildProtocol
import io.olvid.engine.protocol.protocols.DeviceDiscoveryProtocol
import io.olvid.engine.protocol.protocols.DownloadGroupPhotoChildProtocol
import io.olvid.engine.protocol.protocols.DownloadGroupV2PhotoProtocol
import io.olvid.engine.protocol.protocols.DownloadIdentityPhotoChildProtocol
import io.olvid.engine.protocol.protocols.FullRatchetProtocol
import io.olvid.engine.protocol.protocols.GroupInvitationProtocol
import io.olvid.engine.protocol.protocols.GroupManagementProtocol
import io.olvid.engine.protocol.protocols.GroupsV2Protocol
import io.olvid.engine.protocol.protocols.IdentityDetailsPublicationProtocol
import io.olvid.engine.protocol.protocols.KeycloakBindingAndUnbindingProtocol
import io.olvid.engine.protocol.protocols.KeycloakContactAdditionProtocol
import io.olvid.engine.protocol.protocols.OneToOneContactInvitationProtocol
import io.olvid.engine.protocol.protocols.OwnedDeviceDiscoveryProtocol
import io.olvid.engine.protocol.protocols.OwnedDeviceManagementProtocol
import io.olvid.engine.protocol.protocols.OwnedIdentityDeletionProtocol
import io.olvid.engine.protocol.protocols.OwnedIdentityTransferProtocol
import io.olvid.engine.protocol.protocols.SynchronizationProtocol
import io.olvid.engine.protocol.protocols.TrustEstablishmentWithMutualScanProtocol
import io.olvid.engine.protocol.protocols.TrustEstablishmentWithSasProtocol
import java.lang.reflect.Constructor


abstract class ConcreteProtocol(
    @JvmField val protocolManagerSession: ProtocolManagerSession?,
    @JvmField val protocolInstanceUid: UID?,
    currentStateId: Int,
    encodedCurrentState: Encoded?,
    @JvmField val ownedIdentity: Identity?,
    @JvmField val prng: PRNGService,
    @JvmField val jsonObjectMapper: ObjectMapper
) {
    @JvmField var currentState: ConcreteProtocolState

    @JvmField var eraseReceivedMessagesAfterReachingAFinalState: Boolean = true
    @JvmField var mayBeRunAsLinkedChildProtocol: Boolean = false
    @JvmField var requiresProtocolInstanceToBeInsertedBeforeInitialStep: Boolean = false

    fun updateCurrentState(newState: ConcreteProtocolState) {
        currentState = newState
    }

    init {
        this.currentState = getProtocolState(getStateClass(currentStateId)!!, encodedCurrentState)
    }

    abstract val protocolId: Int

    protected abstract fun getStateClass(stateId: Int): Class<*>?

    @Throws(Exception::class)
    protected fun getProtocolState(
        currentState: Class<*>,
        encodedCurrentState: Encoded?
    ): ConcreteProtocolState {
        val constructor: Constructor<*> = currentState.getConstructor(Encoded::class.java)
        return constructor.newInstance(encodedCurrentState) as ConcreteProtocolState
    }

    abstract val finalStateIds: IntArray?
    fun hasReachedFinalState(): Boolean {
        for (finalStateId in this.finalStateIds!!) {
            if (currentState.id == finalStateId) {
                return true
            }
        }
        return false
    }

    protected abstract fun getMessageClass(protocolMessageId: Int): Class<*>?
    fun getConcreteProtocolMessage(receivedMessage: ReceivedMessage): ConcreteProtocolMessage? {
        try {
            val messageClass = getMessageClass(receivedMessage.protocolMessageId)
            if (messageClass == null) {
                return null
            }
            val constructor: Constructor<*> =
                messageClass.getConstructor(ReceivedMessage::class.java)
            return constructor.newInstance(receivedMessage) as ConcreteProtocolMessage
        } catch (e: Exception) {
            Logger.x(e)
            return null
        }
    }

    protected abstract fun getPossibleStepClasses(stateId: Int): Array<Class<*>>
    fun getStepToExecute(concreteProtocolMessage: ConcreteProtocolMessage): ProtocolStep? {
        try {
            var matches = 0
            var constructor: Constructor<*>? = null
            val classes = getPossibleStepClasses(currentState.id)
            for (clazz in classes) {
                try {
                    constructor = clazz.getConstructor(
                        currentState.javaClass,
                        concreteProtocolMessage.javaClass,
                        this.javaClass
                    )
                    matches++
                } catch (_: NoSuchMethodException) {
                }
            }
            if (matches != 1) {
                Logger.d("Found " + matches + " protocolStep to execute in " + this.javaClass + " for state " + currentState.javaClass + " and message " + concreteProtocolMessage.javaClass)
                return null
            }
            return constructor!!.newInstance(
                currentState,
                concreteProtocolMessage,
                this
            ) as ProtocolStep
        } catch (e: Exception) {
            Logger.x(e)
            return null
        }
    }

    companion object {
        const val INITIAL_STATE_ID: Int = 0


        const val DEVICE_DISCOVERY_PROTOCOL_ID: Int = 0
        const val TRUST_ESTABLISHMENT_PROTOCOL_ID: Int = 1 // no longer used (superseded by 11)
        const val CHANNEL_CREATION_WITH_CONTACT_DEVICE_PROTOCOL_ID: Int = 2
        const val DEVICE_DISCOVERY_CHILD_PROTOCOL_ID: Int = 3
        const val CONTACT_MUTUAL_INTRODUCTION_PROTOCOL_ID: Int = 4
        const val GROUP_CREATION_PROTOCOL_ID: Int = 5 // no longer used
        const val IDENTITY_DETAILS_PUBLICATION_PROTOCOL_ID: Int = 6
        const val DOWNLOAD_IDENTITY_PHOTO_CHILD_PROTOCOL_ID: Int = 7
        const val GROUP_INVITATION_PROTOCOL_ID: Int = 8
        const val GROUP_MANAGEMENT_PROTOCOL_ID: Int = 9
        const val CONTACT_MANAGEMENT_PROTOCOL_ID: Int = 10
        const val TRUST_ESTABLISHMENT_WITH_SAS_PROTOCOL_ID: Int = 11
        const val TRUST_ESTABLISHMENT_WITH_MUTUAL_SCAN_PROTOCOL_ID: Int = 12
        const val FULL_RATCHET_PROTOCOL_ID: Int = 13
        const val DOWNLOAD_GROUP_PHOTO_CHILD_PROTOCOL_ID: Int = 14
        const val KEYCLOAK_CONTACT_ADDITION_PROTOCOL_ID: Int = 15
        const val DEVICE_CAPABILITIES_DISCOVERY_PROTOCOL_ID: Int = 16
        const val ONE_TO_ONE_CONTACT_INVITATION_PROTOCOL_ID: Int = 17
        const val GROUPS_V2_PROTOCOL_ID: Int = 18
        const val DOWNLOAD_GROUPS_V2_PHOTO_PROTOCOL_ID: Int = 19
        const val OWNED_IDENTITY_DELETION_PROTOCOL_ID: Int = 20
        const val OWNED_DEVICE_DISCOVERY_PROTOCOL_ID: Int = 21
        const val CHANNEL_CREATION_WITH_OWNED_DEVICE_PROTOCOL_ID: Int = 22
        const val KEYCLOAK_BINDING_AND_UNBINDING_PROTOCOL_ID: Int = 23
        const val OWNED_DEVICE_MANAGEMENT_PROTOCOL_ID: Int = 24
        const val SYNCHRONIZATION_PROTOCOL_ID: Int = 25
        const val OWNED_IDENTITY_TRANSFER_PROTOCOL_ID: Int = 26

        // internal protocols, Android only
        const val LEGACY_KEYCLOAK_BINDING_AND_UNBINDING_PROTOCOL_ID: Int = 1000


        @Throws(Exception::class)
        fun getConcreteProtocol(
            protocolInstance: ProtocolInstance?,
            prng: PRNGService,
            jsonObjectMapper: ObjectMapper
        ): ConcreteProtocol? {
            if (protocolInstance == null) {
                return null
            }
            val protocolManagerSession = protocolInstance.protocolManagerSession
            val protocolId = protocolInstance.protocolId
            val protocolInstanceUid = protocolInstance.uid
            val currentStateId = protocolInstance.currentStateId
            val encodedCurrentState = protocolInstance.encodedCurrentState
            val ownedIdentity = protocolInstance.ownedIdentity
            return getConcreteProtocol(
                protocolManagerSession,
                protocolId,
                protocolInstanceUid,
                currentStateId,
                encodedCurrentState,
                ownedIdentity,
                prng,
                jsonObjectMapper
            )
        }

        @Throws(Exception::class)
        fun getConcreteProtocolInInitialState(
            protocolManagerSession: ProtocolManagerSession?,
            protocolId: Int,
            protocolInstanceUid: UID?,
            ownedIdentity: Identity,
            prng: PRNGService,
            jsonObjectMapper: ObjectMapper
        ): ConcreteProtocol? {
            return getConcreteProtocol(
                protocolManagerSession,
                protocolId,
                protocolInstanceUid,
                INITIAL_STATE_ID,
                Encoded.of(
                    arrayOf<Encoded>()
                ),
                ownedIdentity,
                prng,
                jsonObjectMapper
            )
        }

        @Throws(Exception::class)
        private fun getConcreteProtocol(
            protocolManagerSession: ProtocolManagerSession?,
            protocolId: Int,
            protocolInstanceUid: UID?,
            stateId: Int,
            encodedState: Encoded?,
            ownedIdentity: Identity,
            prng: PRNGService,
            jsonObjectMapper: ObjectMapper
        ): ConcreteProtocol? {
            when (protocolId) {
                DEVICE_DISCOVERY_PROTOCOL_ID -> return DeviceDiscoveryProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                CHANNEL_CREATION_WITH_CONTACT_DEVICE_PROTOCOL_ID -> return ChannelCreationWithContactDeviceProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                DEVICE_DISCOVERY_CHILD_PROTOCOL_ID -> return DeviceDiscoveryChildProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                CONTACT_MUTUAL_INTRODUCTION_PROTOCOL_ID -> return ContactMutualIntroductionProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                IDENTITY_DETAILS_PUBLICATION_PROTOCOL_ID -> return IdentityDetailsPublicationProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                DOWNLOAD_IDENTITY_PHOTO_CHILD_PROTOCOL_ID -> return DownloadIdentityPhotoChildProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                GROUP_INVITATION_PROTOCOL_ID -> return GroupInvitationProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                GROUP_MANAGEMENT_PROTOCOL_ID -> return GroupManagementProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                CONTACT_MANAGEMENT_PROTOCOL_ID -> return ContactManagementProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                TRUST_ESTABLISHMENT_WITH_SAS_PROTOCOL_ID -> return TrustEstablishmentWithSasProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                TRUST_ESTABLISHMENT_WITH_MUTUAL_SCAN_PROTOCOL_ID -> return TrustEstablishmentWithMutualScanProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                FULL_RATCHET_PROTOCOL_ID -> return FullRatchetProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                DOWNLOAD_GROUP_PHOTO_CHILD_PROTOCOL_ID -> return DownloadGroupPhotoChildProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                KEYCLOAK_CONTACT_ADDITION_PROTOCOL_ID -> return KeycloakContactAdditionProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                DEVICE_CAPABILITIES_DISCOVERY_PROTOCOL_ID -> return DeviceCapabilitiesDiscoveryProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                LEGACY_KEYCLOAK_BINDING_AND_UNBINDING_PROTOCOL_ID, KEYCLOAK_BINDING_AND_UNBINDING_PROTOCOL_ID -> return KeycloakBindingAndUnbindingProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                ONE_TO_ONE_CONTACT_INVITATION_PROTOCOL_ID -> return OneToOneContactInvitationProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                GROUPS_V2_PROTOCOL_ID -> return GroupsV2Protocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                DOWNLOAD_GROUPS_V2_PHOTO_PROTOCOL_ID -> return DownloadGroupV2PhotoProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                OWNED_IDENTITY_DELETION_PROTOCOL_ID -> return OwnedIdentityDeletionProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                OWNED_DEVICE_DISCOVERY_PROTOCOL_ID -> return OwnedDeviceDiscoveryProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                CHANNEL_CREATION_WITH_OWNED_DEVICE_PROTOCOL_ID -> return ChannelCreationWithOwnedDeviceProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                OWNED_DEVICE_MANAGEMENT_PROTOCOL_ID -> return OwnedDeviceManagementProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                SYNCHRONIZATION_PROTOCOL_ID -> return SynchronizationProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                OWNED_IDENTITY_TRANSFER_PROTOCOL_ID -> return OwnedIdentityTransferProtocol(
                    protocolManagerSession,
                    protocolInstanceUid,
                    stateId,
                    encodedState,
                    ownedIdentity,
                    prng,
                    jsonObjectMapper
                )

                else -> {
                    Logger.w("Unknown protocol id: " + protocolId)
                    return null
                }
            }
        }

        // defines a priority between different protocol to allow running important operations faster
        //   --> range is 0 - 1023 to fit on 10 bits
        fun getProtocolPriority(protocolId: Int): Long {
            when (protocolId) {
                DEVICE_DISCOVERY_PROTOCOL_ID -> return 599L
                CHANNEL_CREATION_WITH_CONTACT_DEVICE_PROTOCOL_ID -> return 300L
                DEVICE_DISCOVERY_CHILD_PROTOCOL_ID -> return 600L
                CONTACT_MUTUAL_INTRODUCTION_PROTOCOL_ID -> return 13L
                IDENTITY_DETAILS_PUBLICATION_PROTOCOL_ID -> return 150L
                DOWNLOAD_IDENTITY_PHOTO_CHILD_PROTOCOL_ID -> return 200L
                GROUP_INVITATION_PROTOCOL_ID -> return 101L
                GROUP_MANAGEMENT_PROTOCOL_ID -> return 102L
                CONTACT_MANAGEMENT_PROTOCOL_ID -> return 12L
                TRUST_ESTABLISHMENT_WITH_SAS_PROTOCOL_ID -> return 9L
                TRUST_ESTABLISHMENT_WITH_MUTUAL_SCAN_PROTOCOL_ID -> return 8L
                FULL_RATCHET_PROTOCOL_ID -> return 1023L
                DOWNLOAD_GROUP_PHOTO_CHILD_PROTOCOL_ID -> return 202L
                KEYCLOAK_CONTACT_ADDITION_PROTOCOL_ID -> return 11L
                DEVICE_CAPABILITIES_DISCOVERY_PROTOCOL_ID -> return 500L
                LEGACY_KEYCLOAK_BINDING_AND_UNBINDING_PROTOCOL_ID, KEYCLOAK_BINDING_AND_UNBINDING_PROTOCOL_ID -> return 5L
                ONE_TO_ONE_CONTACT_INVITATION_PROTOCOL_ID -> return 10L
                GROUPS_V2_PROTOCOL_ID -> return 100L
                DOWNLOAD_GROUPS_V2_PHOTO_PROTOCOL_ID -> return 201L
                OWNED_IDENTITY_DELETION_PROTOCOL_ID -> return 1L
                OWNED_DEVICE_DISCOVERY_PROTOCOL_ID -> return 50L
                CHANNEL_CREATION_WITH_OWNED_DEVICE_PROTOCOL_ID -> return 51L
                OWNED_DEVICE_MANAGEMENT_PROTOCOL_ID -> return 20L
                SYNCHRONIZATION_PROTOCOL_ID -> return 900L
                OWNED_IDENTITY_TRANSFER_PROTOCOL_ID -> return 0L
                else -> throw RuntimeException("Unknown protocol type!!!")
            }
        }
    }
}
