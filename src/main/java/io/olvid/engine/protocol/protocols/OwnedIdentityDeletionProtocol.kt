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
import io.olvid.engine.crypto.KDF
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.crypto.Signature
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.GroupMembersChangedCallback
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoAcceptableChannelException
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.Group
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAllConfirmedObliviousChannelsOrPreKeysInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAsymmetricBroadcastChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createServerQueryChannelInfo
import io.olvid.engine.datatypes.containers.ServerQuery.DeleteGroupBlobQuery
import io.olvid.engine.datatypes.containers.ServerQuery.DeviceManagementDeactivateDeviceQuery
import io.olvid.engine.datatypes.containers.ServerQuery.PutGroupLogQuery
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.datatypes.notifications.ProtocolNotifications
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.identities.ObvGroupV2
import io.olvid.engine.engine.types.identities.ObvGroupV2.ObvGroupV2ChangeSet
import io.olvid.engine.protocol.databases.IdentityDeletionSignatureReceived
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolState
import io.olvid.engine.protocol.protocol_engine.EmptyProtocolMessage
import io.olvid.engine.protocol.protocol_engine.InitialProtocolState
import io.olvid.engine.protocol.protocol_engine.ProtocolStep
import io.olvid.engine.protocol.protocols.ContactManagementProtocol.PerformContactDeviceDiscoveryMessage
import io.olvid.engine.protocol.protocols.GroupManagementProtocol.GroupMembersOrDetailsChangedTriggerMessage
import io.olvid.engine.protocol.protocols.GroupManagementProtocol.KickFromGroupMessage
import io.olvid.engine.protocol.protocols.GroupManagementProtocol.NotifyGroupLeftMessage
import io.olvid.engine.protocol.protocols.GroupsV2Protocol.DeleteGroupBlobFromServerMessage
import io.olvid.engine.protocol.protocols.GroupsV2Protocol.GroupUpdateInitialMessage
import io.olvid.engine.protocol.protocols.GroupsV2Protocol.KickMessage
import io.olvid.engine.protocol.protocols.GroupsV2Protocol.PutGroupLogOnServerMessage
import io.olvid.engine.protocol.protocols.OwnedDeviceDiscoveryProtocol.TriggerOwnedDeviceDiscoveryMessage
import java.util.Arrays


class OwnedIdentityDeletionProtocol(
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
    override val protocolId: Int = ConcreteProtocol.OWNED_IDENTITY_DELETION_PROTOCOL_ID

    override val finalStateIds: IntArray = intArrayOf(FINISHED_STATED_ID)


    override fun getStateClass(stateId: Int): Class<*>? {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return InitialProtocolState::class.java
            FINISHED_STATED_ID -> return FinishedProtocolState::class.java
            UNREGISTERING_FROM_SERVER_STATE_ID -> return UnregisteringFromServerState::class.java
            else -> return null
        }
    }


    class FinishedProtocolState : ConcreteProtocolState {
        constructor() : super(TrustEstablishmentWithMutualScanProtocol.FINISHED_STATE_ID)

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(TrustEstablishmentWithMutualScanProtocol.FINISHED_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }


    class UnregisteringFromServerState : ConcreteProtocolState {
        internal val deleteEverywhere: Boolean
        internal val propagated: Boolean

        constructor(deleteEverywhere: Boolean, propagated: Boolean) : super(
            UNREGISTERING_FROM_SERVER_STATE_ID
        ) {
            this.deleteEverywhere = deleteEverywhere
            this.propagated = propagated
        }

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(UNREGISTERING_FROM_SERVER_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 2) {
                throw Exception()
            }
            this.deleteEverywhere = list[0].decodeBoolean()
            this.propagated = list[1].decodeBoolean()
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(deleteEverywhere),
                    Encoded.of(propagated),
                )
            )
        }
    }


    override fun getMessageClass(protocolMessageId: Int): Class<*>? {
        when (protocolMessageId) {
            INITIAL_MESSAGE_ID -> return InitialMessage::class.java
            CONTACT_OWNED_IDENTITY_WAS_DELETED_MESSAGE_ID -> return ContactOwnedIdentityWasDeletedMessage::class.java
            PROPAGATE_OWNED_IDENTITY_DELETED_MESSAGE_ID -> return PropagateOwnedIdentityDeletedMessage::class.java
            SKIP_SERVER_QUERY_MESSAGE_ID -> return SkipServerQueryMessage::class.java
            DEACTIVATE_CURRENT_DEVICE_SERVER_QUERY_MESSAGE_ID -> return DeactivateCurrentDeviceServerQueryMessage::class.java
            else -> return null
        }
    }

    class InitialMessage : ConcreteProtocolMessage {
        @JvmField val deleteEverywhere: Boolean

        constructor(coreProtocolMessage: CoreProtocolMessage?, deleteEverywhere: Boolean) : super(
            coreProtocolMessage!!
        ) {
            this.deleteEverywhere = deleteEverywhere
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.deleteEverywhere = receivedMessage.inputs[0].decodeBoolean()
        }

        override val protocolMessageId: Int = INITIAL_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(deleteEverywhere)
            )
            }
    }

    class ContactOwnedIdentityWasDeletedMessage : ConcreteProtocolMessage {
        internal val deletedContactOwnedIdentity: Identity
        internal val signature: ByteArray

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            deletedContactOwnedIdentity: Identity,
            signature: ByteArray
        ) : super(coreProtocolMessage!!) {
            this.deletedContactOwnedIdentity = deletedContactOwnedIdentity
            this.signature = signature
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val inputs = receivedMessage.inputs
            if (inputs.size != 2) {
                throw Exception()
            }
            this.deletedContactOwnedIdentity = inputs[0].decodeIdentity()
            this.signature = inputs[1].decodeBytes()
        }

        override val protocolMessageId: Int = CONTACT_OWNED_IDENTITY_WAS_DELETED_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(deletedContactOwnedIdentity),
                Encoded.of(signature),
            )
            }
    }

    class PropagateOwnedIdentityDeletedMessage : EmptyProtocolMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(receivedMessage)

        override val protocolMessageId: Int = PROPAGATE_OWNED_IDENTITY_DELETED_MESSAGE_ID
    }

    class SkipServerQueryMessage : EmptyProtocolMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(receivedMessage)

        override val protocolMessageId: Int = SKIP_SERVER_QUERY_MESSAGE_ID
    }

    class DeactivateCurrentDeviceServerQueryMessage : EmptyProtocolMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(receivedMessage)

        override val protocolMessageId: Int = DEACTIVATE_CURRENT_DEVICE_SERVER_QUERY_MESSAGE_ID
    }


    // endregion
    // region steps
    override fun getPossibleStepClasses(stateId: Int): Array<Class<*>> {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return arrayOf<Class<*>>(
                StartDeletionStep::class.java,
                ProcessContactOwnedIdentityWasDeletedMessageStep::class.java
            )

            UNREGISTERING_FROM_SERVER_STATE_ID -> return arrayOf<Class<*>>(FinalizeDeletionStep::class.java)
            FINISHED_STATED_ID -> return arrayOf<Class<*>>()
            else -> return arrayOf<Class<*>>()
        }
    }

    class StartDeletionStep : ProtocolStep {
        @JvmField var startState: InitialProtocolState?
        @JvmField var deleteEverywhere: Boolean
        @JvmField var propagated: Boolean

        @Suppress("unused")
        constructor(
            startState: InitialProtocolState?,
            receivedMessage: InitialMessage,
            protocol: OwnedIdentityDeletionProtocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.deleteEverywhere = receivedMessage.deleteEverywhere
            this.propagated = false
        }

        @Suppress("unused")
        constructor(
            startState: InitialProtocolState?,
            receivedMessage: PropagateOwnedIdentityDeletedMessage?,
            protocol: OwnedIdentityDeletionProtocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage!!, protocol!!
        ) {
            this.startState = startState
            this.deleteEverywhere = true
            this.propagated = true
        }


        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val ownedIdentityIsActive =
                protocolManagerSession.identityDelegate!!.isActiveOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity
                )

            if (!ownedIdentityIsActive && !propagated && deleteEverywhere) {
                Logger.e("Error: running OwnedIdentityDeletionProtocol.StartDeletionStep with deleteEverywhere and an inactive identity.")
                throw Exception()
            }

            /**///////// */
            // before anything, cleanup inbox, outbox, and protocols. This MUST be done before sending notifications!
            protocolManagerSession.engineOwnedIdentityCleanupDelegate!!.deleteOwnedIdentityFromInboxOutboxProtocolsAndDialogs(
                protocolManagerSession.session,
                ownedIdentity,
                protocolInstanceUid
            )

            /**///////// */
            // also mark the owned identity for deletion so it is not recreated on app side
            protocolManagerSession.identityDelegate.markOwnedIdentityForDeletion(
                protocolManagerSession.session,
                ownedIdentity
            )

            if (ownedIdentityIsActive) { /**///////// */
                // delete current device from server
                try {
                    val currentDeviceUid =
                        protocolManagerSession.identityDelegate.getCurrentDeviceUidOfOwnedIdentity(
                            protocolManagerSession.session,
                            ownedIdentity
                        )

                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createServerQueryChannelInfo(
                            ownedIdentity,
                            DeviceManagementDeactivateDeviceQuery(
                                ownedIdentity,
                                currentDeviceUid!!
                            )
                        )
                    )
                    val messageToSend: ChannelMessageToSend? =
                        DeactivateCurrentDeviceServerQueryMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                } catch (e: Exception) {
                    Logger.x(e)
                }


                if (!propagated && deleteEverywhere) { /**//////// */
                    // if in deleteEverywhere mode, propagate to other owned devices
                    run {
                        val numberOfOtherDevices =
                            protocolManagerSession.identityDelegate.getOtherDeviceUidsOfOwnedIdentity(
                                protocolManagerSession.session,
                                ownedIdentity
                            )!!.size
                        if (numberOfOtherDevices > 0) {
                            try {
                                // send an owned identity deletion propagation message
                                val coreProtocolMessage = buildCoreProtocolMessage(
                                    createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo(
                                        ownedIdentity
                                    )
                                )
                                val messageToSend: ChannelMessageToSend? =
                                    PropagateOwnedIdentityDeletedMessage(coreProtocolMessage).generateChannelProtocolMessageToSend()
                                protocolManagerSession.channelDelegate!!.post(
                                    protocolManagerSession.session,
                                    messageToSend,
                                    prng
                                )
                            } catch (_: NoAcceptableChannelException) {
                            }
                        }
                    }
                }
            } else {
                val coreProtocolMessage =
                    buildCoreProtocolMessage(SendChannelInfo.createLocalChannelInfo(ownedIdentity))
                val messageToSend: ChannelMessageToSend? =
                    SkipServerQueryMessage(coreProtocolMessage).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return UnregisteringFromServerState(deleteEverywhere, propagated)
        }
    }


    class FinalizeDeletionStep : ProtocolStep {
        @JvmField var startState: UnregisteringFromServerState

        @Suppress("unused")
        constructor(
            startState: UnregisteringFromServerState,
            receivedMessage: DeactivateCurrentDeviceServerQueryMessage?,
            protocol: OwnedIdentityDeletionProtocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage!!, protocol!!
        ) {
            this.startState = startState
        }

        @Suppress("unused")
        constructor(
            startState: UnregisteringFromServerState,
            receivedMessage: SkipServerQueryMessage?,
            protocol: OwnedIdentityDeletionProtocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage!!, protocol!!
        ) {
            this.startState = startState
        }

        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val ownedIdentityIsActive =
                protocolManagerSession.identityDelegate!!.isActiveOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity
                )


            /**//////// */
            // if not in deleteEverywhere mode, notify other owned devices to do a device discovery
            if (ownedIdentityIsActive && !startState.propagated && !startState.deleteEverywhere) {
                val numberOfOtherDevices =
                    protocolManagerSession.identityDelegate.getOtherDeviceUidsOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity
                    )!!.size
                if (numberOfOtherDevices > 0) {
                    try {
                        // trigger a device discovery on other devices
                        val coreProtocolMessage = CoreProtocolMessage(
                            createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo(ownedIdentity),
                            ConcreteProtocol.OWNED_DEVICE_DISCOVERY_PROTOCOL_ID,
                            UID(prng)
                        )
                        val messageToSend: ChannelMessageToSend? =
                            TriggerOwnedDeviceDiscoveryMessage(coreProtocolMessage).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    } catch (_: NoAcceptableChannelException) {
                    }
                }
            }

            /**///////// */
            // send delete notifications to contacts
            if (ownedIdentityIsActive && !startState.propagated) {
                val contactIdentities: Array<Identity>? =
                    protocolManagerSession.identityDelegate.getContactsOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity
                    )
                if (contactIdentities!!.size > 0) {
                    if (startState.deleteEverywhere) {
                        for (contactIdentity in contactIdentities) {
                            try {
                                val signature = protocolManagerSession.identityDelegate.signBlock(
                                    protocolManagerSession.session,
                                    Constants.SignatureContext.OWNED_IDENTITY_DELETION,
                                    contactIdentity.getBytes(),
                                    ownedIdentity,
                                    prng
                                )

                                val coreProtocolMessage = buildCoreProtocolMessage(
                                    createAsymmetricBroadcastChannelInfo(
                                        contactIdentity,
                                        ownedIdentity
                                    )
                                )
                                val messageToSend: ChannelMessageToSend? =
                                    ContactOwnedIdentityWasDeletedMessage(
                                        coreProtocolMessage,
                                        ownedIdentity,
                                        signature!!
                                    ).generateChannelProtocolMessageToSend()
                                protocolManagerSession.channelDelegate!!.post(
                                    protocolManagerSession.session,
                                    messageToSend,
                                    prng
                                )
                            } catch (_: Exception) {
                                // continue even if there is an exception, contact notification is only best effort!
                            }
                        }

                        // We no longer send the "legacy" delete contact message as it may mess up the treatment of our new ContactOwnedIdentityWasDeletedMessage
                    } else {
                        // if not a global deletion, simply trigger a device discovery on contact side
                        val sendChannelInfos =
                            SendChannelInfo.createAllConfirmedObliviousChannelsOrPreKeysInfoForMultipleIdentities(
                                contactIdentities,
                                ownedIdentity
                            )
                        for (sendChannelInfo in sendChannelInfos!!) {
                            try {
                                val coreProtocolMessage = CoreProtocolMessage(
                                    sendChannelInfo,
                                    ConcreteProtocol.CONTACT_MANAGEMENT_PROTOCOL_ID,
                                    UID(prng)
                                )
                                val messageToSend: ChannelMessageToSend? =
                                    PerformContactDeviceDiscoveryMessage(coreProtocolMessage).generateChannelProtocolMessageToSend()
                                protocolManagerSession.channelDelegate!!.post(
                                    protocolManagerSession.session,
                                    messageToSend,
                                    prng
                                )
                            } catch (_: Exception) {
                                // continue even if there is an exception, contact notification is only best effort!
                            }
                        }
                    }
                }
            }


            /**///////// */
            // only actually disband/leave groups if appropriate
            /**///////// */
            if (ownedIdentityIsActive && !startState.propagated && startState.deleteEverywhere) { /**///////// */
                // disband all owned groups & leave all joined groups

                run {
                    @Suppress("UNCHECKED_CAST")
                    val groups: Array<Group?>? =
                        protocolManagerSession.identityDelegate.getGroupsForOwnedIdentity(
                            protocolManagerSession.session,
                            ownedIdentity
                        ) as Array<Group?>?
                    for (groupNullable in groups!!) {
                        val group = groupNullable!!
                        val groupInformation =
                            protocolManagerSession.identityDelegate.getGroupInformation(
                                protocolManagerSession.session,
                                ownedIdentity,
                                group.getGroupOwnerAndUid()
                            )
                        val protocolInstanceUid = groupInformation!!.computeProtocolUid()

                        if (group.getGroupOwner() == null) { /**///////// */
                            // owned group -> kick all members and pending members
                            if (group.getGroupMembers().isNotEmpty()) {
                                val sendChannelInfos =
                                    SendChannelInfo.createAllConfirmedObliviousChannelsOrPreKeysInfoForMultipleIdentities(
                                        group.getGroupMembers(),
                                        ownedIdentity
                                    )
                                for (sendChannelInfo in sendChannelInfos!!) {
                                    try {
                                        val coreProtocolMessage = CoreProtocolMessage(
                                            sendChannelInfo,
                                            ConcreteProtocol.GROUP_MANAGEMENT_PROTOCOL_ID,
                                            protocolInstanceUid
                                        )
                                        val messageToSend: ChannelMessageToSend? =
                                            KickFromGroupMessage(
                                                coreProtocolMessage,
                                                groupInformation
                                            ).generateChannelProtocolMessageToSend()
                                        protocolManagerSession.channelDelegate!!.post(
                                            protocolManagerSession.session,
                                            messageToSend,
                                            prng
                                        )
                                    } catch (_: Exception) {
                                        // continue even if there is an exception, contact notification is only best effort!
                                    }
                                }
                            }
                            if (group.getPendingGroupMembers().isNotEmpty()) {
                                val pendingMemberIdentities: Array<Identity> = group.pendingGroupMembers.map { it.identity }.toTypedArray()

                                val sendChannelInfos =
                                    SendChannelInfo.createAllConfirmedObliviousChannelsOrPreKeysInfoForMultipleIdentities(
                                        pendingMemberIdentities,
                                        ownedIdentity
                                    )
                                for (sendChannelInfo in sendChannelInfos!!) {
                                    try {
                                        val coreProtocolMessage = CoreProtocolMessage(
                                            sendChannelInfo,
                                            ConcreteProtocol.GROUP_MANAGEMENT_PROTOCOL_ID,
                                            protocolInstanceUid
                                        )
                                        val messageToSend: ChannelMessageToSend? =
                                            KickFromGroupMessage(
                                                coreProtocolMessage,
                                                groupInformation
                                            ).generateChannelProtocolMessageToSend()
                                        protocolManagerSession.channelDelegate!!.post(
                                            protocolManagerSession.session,
                                            messageToSend,
                                            prng
                                        )
                                    } catch (_: Exception) {
                                        // continue even if there is an exception, contact notification is only best effort!
                                    }
                                }
                            }
                        } else { /**///////// */
                            // joined group -> notify group owner
                            try {
                                val coreProtocolMessage = CoreProtocolMessage(
                                    createAllConfirmedObliviousChannelsOrPreKeysInfo(
                                        group.getGroupOwner(),
                                        ownedIdentity
                                    ),
                                    ConcreteProtocol.GROUP_MANAGEMENT_PROTOCOL_ID,
                                    protocolInstanceUid
                                )
                                val message: ChannelMessageToSend? = NotifyGroupLeftMessage(
                                    coreProtocolMessage,
                                    groupInformation
                                ).generateChannelProtocolMessageToSend()
                                protocolManagerSession.channelDelegate!!.post(
                                    protocolManagerSession.session,
                                    message,
                                    prng
                                )
                            } catch (_: Exception) {
                                // continue even if there is an exception, contact notification is only best effort!
                            }
                        }
                    }
                }

                /**///////// */
                // leave all groups v2 & disband those where I am the only admin
                run {
                    val groupsV2: MutableList<ObvGroupV2> =
                        protocolManagerSession.identityDelegate.getObvGroupsV2ForOwnedIdentity(
                            protocolManagerSession.session,
                            ownedIdentity
                        )
                    for (groupV2 in groupsV2) {
                        if (groupV2.groupIdentifier.category == GroupV2.Identifier.CATEGORY_SERVER) {
                            // only consider non-keycloak groups
                            try {
                                // check if I am the only non-pending admin of this group
                                var iAmTheOnlyAdmin: Boolean
                                if (groupV2.ownPermissions.contains(GroupV2.Permission.GROUP_ADMIN)) {
                                    iAmTheOnlyAdmin = true
                                    for (member in groupV2.otherGroupMembers!!) {
                                        if (member.permissions.contains(GroupV2.Permission.GROUP_ADMIN)) {
                                            iAmTheOnlyAdmin = false
                                            
                                        }
                                    }
                                } else {
                                    iAmTheOnlyAdmin = false
                                }

                                if (iAmTheOnlyAdmin) {
                                    // delete the blob on the server
                                    val blobKeys =
                                        protocolManagerSession.identityDelegate.getGroupV2BlobKeys(
                                            protocolManagerSession.session,
                                            ownedIdentity,
                                            groupV2.groupIdentifier
                                        )
                                    run {
                                        val signature = Signature.sign(
                                            Constants.SignatureContext.GROUP_DELETE_ON_SERVER,
                                            blobKeys!!.groupAdminServerAuthenticationPrivateKey!!.signaturePrivateKey,
                                            prng
                                        )
                                        val coreProtocolMessage = CoreProtocolMessage(
                                            createServerQueryChannelInfo(
                                                ownedIdentity,
                                                DeleteGroupBlobQuery(
                                                    groupV2.groupIdentifier,
                                                    signature!!
                                                )
                                            ),
                                            ConcreteProtocol.GROUPS_V2_PROTOCOL_ID,
                                            UID(prng)
                                        )
                                        val messageToSend: ChannelMessageToSend? =
                                            DeleteGroupBlobFromServerMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                                        protocolManagerSession.channelDelegate!!.post(
                                            protocolManagerSession.session,
                                            messageToSend,
                                            prng
                                        )
                                    }

                                    // immediately kick all members
                                    val chainPlaintext =
                                        protocolManagerSession.identityDelegate.getGroupV2AdministratorsChain(
                                            protocolManagerSession.session,
                                            ownedIdentity,
                                            groupV2.groupIdentifier
                                        )!!.encode().bytes
                                    val encryptionKey = Suite.getKDF(KDF.KDF_SHA256).gen(
                                        blobKeys!!.blobMainSeed,
                                        Suite.getDefaultAuthEnc(0).getKDFDelegate()
                                    )[0] as AuthEncKey?
                                    val encryptedChain = Suite.getAuthEnc(encryptionKey)!!
                                        .encrypt(encryptionKey, chainPlaintext, prng)

                                    val serverBlob =
                                        protocolManagerSession.identityDelegate.getGroupV2ServerBlob(
                                            protocolManagerSession.session,
                                            ownedIdentity,
                                            groupV2.groupIdentifier
                                        )

                                    for (member in serverBlob!!.groupMemberIdentityAndPermissionsAndDetailsList) {
                                        if (member.identity.equals(ownedIdentity)) {
                                            continue
                                        }

                                        val dataToSign =
                                            ByteArray(encryptedChain.length + member.groupInvitationNonce.size)
                                        System.arraycopy(
                                            encryptedChain.getBytes(),
                                            0,
                                            dataToSign,
                                            0,
                                            encryptedChain.length
                                        )
                                        System.arraycopy(
                                            member.groupInvitationNonce,
                                            0,
                                            dataToSign,
                                            encryptedChain.length,
                                            member.groupInvitationNonce.size
                                        )

                                        val signature =
                                            protocolManagerSession.identityDelegate.signBlock(
                                                protocolManagerSession.session,
                                                Constants.SignatureContext.GROUP_KICK,
                                                dataToSign,
                                                ownedIdentity,
                                                prng
                                            )

                                        val coreProtocolMessage = CoreProtocolMessage(
                                            createAsymmetricBroadcastChannelInfo(
                                                member.identity,
                                                ownedIdentity
                                            ),
                                            ConcreteProtocol.GROUPS_V2_PROTOCOL_ID,
                                            groupV2.groupIdentifier.computeProtocolInstanceUid()
                                        )
                                        val messageToSend: ChannelMessageToSend? = KickMessage(
                                            coreProtocolMessage,
                                            groupV2.groupIdentifier,
                                            encryptedChain,
                                            signature!!
                                        ).generateChannelProtocolMessageToSend()
                                        protocolManagerSession.channelDelegate!!.post(
                                            protocolManagerSession.session,
                                            messageToSend,
                                            prng
                                        )
                                    }
                                } else {
                                    val ownGroupInvitationNonce =
                                        protocolManagerSession.identityDelegate.getGroupV2OwnGroupInvitationNonce(
                                            protocolManagerSession.session,
                                            ownedIdentity,
                                            groupV2.groupIdentifier
                                        )
                                    if (ownGroupInvitationNonce != null) {
                                        // put a group left log on server
                                        // we do not notify the group members: they will refresh the groups when we send them the contact deletion message
                                        val leaveSignature =
                                            protocolManagerSession.identityDelegate.signGroupInvitationNonce(
                                                protocolManagerSession.session,
                                                Constants.SignatureContext.GROUP_LEAVE_NONCE,
                                                groupV2.groupIdentifier,
                                                ownGroupInvitationNonce,
                                                null,
                                                ownedIdentity,
                                                prng
                                            )

                                        val coreProtocolMessage = CoreProtocolMessage(
                                            createServerQueryChannelInfo(
                                                ownedIdentity,
                                                PutGroupLogQuery(
                                                    groupV2.groupIdentifier,
                                                    leaveSignature!!
                                                )
                                            ),
                                            ConcreteProtocol.GROUPS_V2_PROTOCOL_ID,
                                            UID(prng)
                                        )
                                        val messageToSend: ChannelMessageToSend? =
                                            PutGroupLogOnServerMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                                        protocolManagerSession.channelDelegate!!.post(
                                            protocolManagerSession.session,
                                            messageToSend,
                                            prng
                                        )
                                    }
                                }
                            } catch (_: Exception) {
                                // continue even if there is an exception, contact notification is only best effort!
                            }
                        }
                    }
                }
            }


            // finally, delete the server session, all channels (all notifications message have already been encrypted) and actually delete owned identity
            protocolManagerSession.engineOwnedIdentityCleanupDelegate!!.deleteOwnedIdentityServerSession(
                protocolManagerSession.session,
                ownedIdentity
            )
            protocolManagerSession.channelDelegate!!.deleteAllChannelsForOwnedIdentity(
                protocolManagerSession.session,
                ownedIdentity
            )
            protocolManagerSession.identityDelegate.deleteOwnedIdentity(
                protocolManagerSession.session,
                ownedIdentity
            )

            if (startState.propagated) {
                protocolManagerSession.session.addSessionCommitListener {
                    val userInfo = HashMap<String, Any>()
                    userInfo[ProtocolNotifications.NOTIFICATION_OWNED_IDENTITY_DELETED_FROM_ANOTHER_DEVICE_OWNED_IDENTITY_KEY] = ownedIdentity
                    protocolManagerSession.notificationPostingDelegate?.postNotification(
                        ProtocolNotifications.NOTIFICATION_OWNED_IDENTITY_DELETED_FROM_ANOTHER_DEVICE,
                        userInfo
                    )
                }
            }

            return FinishedProtocolState()
        }
    }


    class ProcessContactOwnedIdentityWasDeletedMessageStep(
        @JvmField var startState: InitialProtocolState?,
        @JvmField var receivedMessage: ContactOwnedIdentityWasDeletedMessage,
        protocol: OwnedIdentityDeletionProtocol?
    ) : ProtocolStep(
        if (receivedMessage.receptionChannelInfo!!
                .getChannelType() == ReceptionChannelInfo.ASYMMETRIC_CHANNEL_TYPE
        ) ReceptionChannelInfo.createAsymmetricChannelInfo() else createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
        receivedMessage, protocol!!
    ) {
        @JvmField var propagated: Boolean

        init {
            propagated = receivedMessage.receptionChannelInfo!!
                .getChannelType() != ReceptionChannelInfo.ASYMMETRIC_CHANNEL_TYPE
        }


        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
                // check the message is not a replay
                if (IdentityDeletionSignatureReceived.exists(
                        protocolManagerSession,
                        ownedIdentity,
                        receivedMessage.signature
                    )
                ) {
                    Logger.w("Received a ContactOwnedIdentityWasDeletedMessage with a known signature")
                    return FinishedProtocolState()
                }
            }

            run {
                // verify the signature
                if (!Signature.verify(
                        Constants.SignatureContext.OWNED_IDENTITY_DELETION,
                        ownedIdentity.getBytes(),
                        receivedMessage.deletedContactOwnedIdentity,
                        receivedMessage.signature
                    )
                ) {
                    Logger.w("Received a ContactOwnedIdentityWasDeletedMessage with an invalid signature")
                    return FinishedProtocolState()
                }
            }

            // save the signature to prevent replay
            IdentityDeletionSignatureReceived.create(
                protocolManagerSession,
                ownedIdentity,
                receivedMessage.signature
            )

            if (!propagated) {
                // propagate the message to other owned devices

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
                            ContactOwnedIdentityWasDeletedMessage(
                                coreProtocolMessage,
                                receivedMessage.deletedContactOwnedIdentity,
                                receivedMessage.signature
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


            // now we can delete everything related to this contact
            run {
                // delete all channels
                protocolManagerSession.channelDelegate!!.deleteObliviousChannelsWithContact(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.deletedContactOwnedIdentity
                )
            }

            run {
                // deal with group v1
                val groupOwnerAndUids: MutableList<ByteArray> = ArrayList(
                    protocolManagerSession.identityDelegate!!.getGroupOwnerAndUidOfGroupsWhereContactIsPending(
                        protocolManagerSession.session,
                        receivedMessage.deletedContactOwnedIdentity,
                        ownedIdentity
                    ).toList()
                )
                groupOwnerAndUids.addAll(
                    protocolManagerSession.identityDelegate.getGroupOwnerAndUidsOfGroupsContainingContact(
                        protocolManagerSession.session,
                        receivedMessage.deletedContactOwnedIdentity,
                        ownedIdentity
                    )
                )
                for (groupOwnerAndUid in groupOwnerAndUids) {
                    val group = protocolManagerSession.identityDelegate.getGroup(
                        protocolManagerSession.session,
                        ownedIdentity,
                        groupOwnerAndUid
                    )
                    if (!propagated && group!!.groupOwner == null) {
                        // I own the group --> properly remove the member from the group and trigger the step to notify others
                        val groupInformation =
                            protocolManagerSession.identityDelegate.getGroupInformation(
                                protocolManagerSession.session,
                                ownedIdentity,
                                groupOwnerAndUid
                            )

                        val groupMembersChangedCallback = GroupMembersChangedCallback {
                            val coreProtocolMessage = CoreProtocolMessage(
                                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                                ConcreteProtocol.GROUP_MANAGEMENT_PROTOCOL_ID,
                                groupInformation!!.computeProtocolUid()
                            )
                            val messageToSend: ChannelMessageToSend? =
                                GroupMembersOrDetailsChangedTriggerMessage(
                                    coreProtocolMessage,
                                    groupInformation
                                ).generateChannelProtocolMessageToSend()
                            protocolManagerSession.channelDelegate!!.post(
                                protocolManagerSession.session,
                                messageToSend,
                                prng
                            )
                        }

                        protocolManagerSession.identityDelegate.removeMembersAndPendingFromGroup(
                            protocolManagerSession.session,
                            groupOwnerAndUid,
                            ownedIdentity,
                            arrayOf(receivedMessage.deletedContactOwnedIdentity),
                            groupMembersChangedCallback
                        )
                    } else {
                        // I joined the group (or it is propagated)
                        if (receivedMessage.deletedContactOwnedIdentity.equals(group!!.groupOwner)) {
                            // the removed contact was the group owner --> leave the group
                            protocolManagerSession.identityDelegate.leaveGroup(
                                protocolManagerSession.session,
                                groupOwnerAndUid,
                                ownedIdentity
                            )
                        } else {
                            // remove the member/pending member before receiving the notification from the group owner
                            protocolManagerSession.identityDelegate.forcefullyRemoveMemberOrPendingFromJoinedGroup(
                                protocolManagerSession.session,
                                ownedIdentity,
                                groupOwnerAndUid,
                                receivedMessage.deletedContactOwnedIdentity
                            )
                        }
                    }
                }
            }


            run {
                // deal with group v2
                for (identifierAndAdminStatus in protocolManagerSession.identityDelegate!!.getServerGroupsV2IdentifierAndMyAdminStatusForContact(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.deletedContactOwnedIdentity
                )!!) {
                    if (!propagated && identifierAndAdminStatus!!.iAmAdmin) {
                        // I am a group admin --> start the standard group update protocol
                        val changeSet = ObvGroupV2ChangeSet()
                        changeSet.removedMembers.add(receivedMessage.deletedContactOwnedIdentity.getBytes())

                        val coreProtocolMessage = CoreProtocolMessage(
                            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                            ConcreteProtocol.GROUPS_V2_PROTOCOL_ID,
                            identifierAndAdminStatus.groupIdentifier!!.computeProtocolInstanceUid()
                        )

                        val messageToSend: ChannelMessageToSend? = GroupUpdateInitialMessage(
                            coreProtocolMessage,
                            identifierAndAdminStatus.groupIdentifier,
                            changeSet
                        ).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    }

                    // always remove contact from the group immediately: if admin, this does not prevent the update to work, if not, we will get an update/disband message soon
                    protocolManagerSession.identityDelegate.forcefullyRemoveMemberOrPendingFromNonAdminGroupV2(
                        protocolManagerSession.session,
                        ownedIdentity,
                        identifierAndAdminStatus!!.groupIdentifier,
                        receivedMessage.deletedContactOwnedIdentity
                    )
                }
            }

            // delete contact, do not fail if there are still some groups (typically, groups v2 where I am admin)
            protocolManagerSession.identityDelegate!!.deleteContactIdentity(
                protocolManagerSession.session,
                ownedIdentity,
                receivedMessage.deletedContactOwnedIdentity,
                false
            )

            return FinishedProtocolState()
        }
    } // endregion

    companion object {
        // region states
        const val FINISHED_STATED_ID: Int = 1
        const val UNREGISTERING_FROM_SERVER_STATE_ID: Int = 2

        // endregion
        // region messages
        const val INITIAL_MESSAGE_ID: Int = 0
        const val CONTACT_OWNED_IDENTITY_WAS_DELETED_MESSAGE_ID: Int = 1
        const val PROPAGATE_OWNED_IDENTITY_DELETED_MESSAGE_ID: Int = 2
        const val SKIP_SERVER_QUERY_MESSAGE_ID: Int = 3
        const val DEACTIVATE_CURRENT_DEVICE_SERVER_QUERY_MESSAGE_ID: Int = 4
    }
}
