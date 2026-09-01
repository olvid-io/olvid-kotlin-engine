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
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoAcceptableChannelException
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createAnyObliviousChannelOrPreKeyInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAllConfirmedObliviousChannelsOrPreKeysInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolState
import io.olvid.engine.protocol.protocol_engine.EmptyProtocolMessage
import io.olvid.engine.protocol.protocol_engine.InitialProtocolState
import io.olvid.engine.protocol.protocol_engine.ProtocolStep
import io.olvid.engine.protocol.protocols.GroupManagementProtocol.RemoveGroupMembersMessage

class ContactManagementProtocol(
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
    override val protocolId: Int = ConcreteProtocol.CONTACT_MANAGEMENT_PROTOCOL_ID


    override val finalStateIds: IntArray = intArrayOf(FINAL_STATE_ID)

    override fun getStateClass(stateId: Int): Class<*>? {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return InitialProtocolState::class.java
            FINAL_STATE_ID -> return FinalState::class.java
            else -> return null
        }
    }


    class FinalState : ConcreteProtocolState {
        @Suppress("unused")
        constructor(encodedState: Encoded) : super(FINAL_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        internal constructor() : super(FINAL_STATE_ID)

        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }


    init {
        eraseReceivedMessagesAfterReachingAFinalState = false
    }

    override fun getMessageClass(protocolMessageId: Int): Class<*>? {
        when (protocolMessageId) {
            INITIATE_CONTACT_DELETION_MESSAGE_ID -> return InitiateContactDeletionMessage::class.java
            CONTACT_DELETION_NOTIFICATION_MESSAGE_ID -> return ContactDeletionNotificationMessage::class.java
            PROPAGATE_CONTACT_DELETION_MESSAGE_ID -> return PropagateContactDeletionMessage::class.java
            INITIATE_CONTACT_DOWNGRADE_MESSAGE_ID -> return InitiateContactDowngradeMessage::class.java
            CONTACT_DOWNGRADE_NOTIFICATION_MESSAGE_ID -> return ContactDowngradeNotificationMessage::class.java
            PROPAGATE_CONTACT_DOWNGRADE_MESSAGE_ID -> return PropagateContactDowngradeMessage::class.java
            PERFORM_CONTACT_DEVICE_DISCOVERY_MESSAGE_ID -> return PerformContactDeviceDiscoveryMessage::class.java
            else -> return null
        }
    }

    class InitiateContactDeletionMessage : ConcreteProtocolMessage {
        @JvmField var contactIdentity: Identity

        constructor(coreProtocolMessage: CoreProtocolMessage?, contactIdentity: Identity) : super(
            coreProtocolMessage!!
        ) {
            this.contactIdentity = contactIdentity
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.contactIdentity = receivedMessage.inputs[0].decodeIdentity()
        }

        override val protocolMessageId: Int = INITIATE_CONTACT_DELETION_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactIdentity),
            )
            }
    }


    class ContactDeletionNotificationMessage : EmptyProtocolMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(receivedMessage)

        override val protocolMessageId: Int = CONTACT_DELETION_NOTIFICATION_MESSAGE_ID
    }


    class PropagateContactDeletionMessage : ConcreteProtocolMessage {
        @JvmField var contactIdentity: Identity

        constructor(coreProtocolMessage: CoreProtocolMessage?, contactIdentity: Identity) : super(
            coreProtocolMessage!!
        ) {
            this.contactIdentity = contactIdentity
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.contactIdentity = receivedMessage.inputs[0].decodeIdentity()
        }

        override val protocolMessageId: Int = PROPAGATE_CONTACT_DELETION_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactIdentity),
            )
            }
    }

    class InitiateContactDowngradeMessage : ConcreteProtocolMessage {
        @JvmField var contactIdentity: Identity

        constructor(coreProtocolMessage: CoreProtocolMessage?, contactIdentity: Identity) : super(
            coreProtocolMessage!!
        ) {
            this.contactIdentity = contactIdentity
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.contactIdentity = receivedMessage.inputs[0].decodeIdentity()
        }

        override val protocolMessageId: Int = INITIATE_CONTACT_DOWNGRADE_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactIdentity),
            )
            }
    }

    class ContactDowngradeNotificationMessage : EmptyProtocolMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(receivedMessage)

        override val protocolMessageId: Int = CONTACT_DOWNGRADE_NOTIFICATION_MESSAGE_ID
    }

    class PropagateContactDowngradeMessage : ConcreteProtocolMessage {
        @JvmField var contactIdentity: Identity

        constructor(coreProtocolMessage: CoreProtocolMessage?, contactIdentity: Identity) : super(
            coreProtocolMessage!!
        ) {
            this.contactIdentity = contactIdentity
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.contactIdentity = receivedMessage.inputs[0].decodeIdentity()
        }

        override val protocolMessageId: Int = PROPAGATE_CONTACT_DOWNGRADE_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactIdentity),
            )
            }
    }


    class PerformContactDeviceDiscoveryMessage : EmptyProtocolMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(receivedMessage)

        override val protocolMessageId: Int = PERFORM_CONTACT_DEVICE_DISCOVERY_MESSAGE_ID
    }


    // endregion
    // region Steps
    override fun getPossibleStepClasses(stateId: Int): Array<Class<*>> {
        if (stateId == ConcreteProtocol.INITIAL_STATE_ID) {
            return arrayOf<Class<*>>(
                DeleteContactStep::class.java,
                ProcessContactDeletionNotificationStep::class.java,
                ProcessPropagatedContactDeletionStep::class.java,
                DowngradeContactStep::class.java,
                ProcessContactDowngradeNotificationStep::class.java,
                ProcessPropagatedContactDowngradeStep::class.java,
                ProcessPerformContactDeviceDiscoveryMessageStep::class.java,
            )
        }
        return arrayOf<Class<*>>()
    }


    class DeleteContactStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitiateContactDeletionMessage,
        protocol: ContactManagementProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            // propagate to other devices
            run {
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
                        val messageToSend: ChannelMessageToSend? = PropagateContactDeletionMessage(
                            coreProtocolMessage,
                            receivedMessage.contactIdentity
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

            // notify contact (we need the oblivious channel --> before deleting the contact)
            try {
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createAllConfirmedObliviousChannelsOrPreKeysInfo(
                        receivedMessage.contactIdentity,
                        ownedIdentity
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    ContactDeletionNotificationMessage(coreProtocolMessage).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            } catch (_: Exception) {
                // if the contact has no channel, throw an exception but proceed with the deletion
            }

            // delete all channels
            protocolManagerSession.channelDelegate!!.deleteObliviousChannelsWithContact(
                protocolManagerSession.session,
                ownedIdentity,
                receivedMessage.contactIdentity
            )


            // remove contact from all owned groups where it is pending
            val groupOwnerAndUids =
                protocolManagerSession.identityDelegate!!.getGroupOwnerAndUidOfGroupsWhereContactIsPending(
                    protocolManagerSession.session,
                    receivedMessage.contactIdentity,
                    ownedIdentity
                )

            val removedMemberIdentities = HashSet<Identity>(1)
            removedMemberIdentities.add(receivedMessage.contactIdentity)

            for (groupOwnerAndUid in groupOwnerAndUids) {
                val groupInformation = protocolManagerSession.identityDelegate.getGroupInformation(
                    protocolManagerSession.session,
                    ownedIdentity,
                    groupOwnerAndUid
                )

                val coreProtocolMessage = CoreProtocolMessage(
                    SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                    ConcreteProtocol.GROUP_MANAGEMENT_PROTOCOL_ID,
                    groupInformation!!.computeProtocolUid()
                )
                val messageToSend: ChannelMessageToSend? = RemoveGroupMembersMessage(
                    coreProtocolMessage,
                    groupInformation,
                    removedMemberIdentities
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }


            // delete contact (if there are no groups)
            protocolManagerSession.identityDelegate.deleteContactIdentity(
                protocolManagerSession.session,
                ownedIdentity,
                receivedMessage.contactIdentity,
                true
            )


            return FinalState()
        }
    }

    class ProcessPropagatedContactDeletionStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: PropagateContactDeletionMessage,
        protocol: ContactManagementProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            // delete all channels
            protocolManagerSession.channelDelegate!!.deleteObliviousChannelsWithContact(
                protocolManagerSession.session,
                ownedIdentity,
                receivedMessage.contactIdentity
            )

            // we do not do anything about own group pending members: the GroupManagementProtocol will propagate the information itself

            // delete the contact (even if still in some groups, this is only temporary)
            protocolManagerSession.identityDelegate!!.deleteContactIdentity(
                protocolManagerSession.session,
                ownedIdentity,
                receivedMessage.contactIdentity,
                false
            )

            return FinalState()
        }
    }

    class ProcessContactDeletionNotificationStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: ContactDeletionNotificationMessage,
        protocol: ContactManagementProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!
            val contactIdentity = receivedMessage.receptionChannelInfo!!.getRemoteIdentity()

            // delete all channels
            protocolManagerSession.channelDelegate!!.deleteObliviousChannelsWithContact(
                protocolManagerSession.session,
                ownedIdentity,
                contactIdentity
            )

            // delete contact, fails if there are still some groups, but catch Exception to still delete channels (destroyed on sender side).
            try {
                run {
                    // first, leave all groups where contact is the owner (as this should never be a fail cause)
                    val groupOwnerAndUids =
                        protocolManagerSession.identityDelegate!!.getGroupOwnerAndUidsOfGroupsOwnedByContact(
                            protocolManagerSession.session,
                            ownedIdentity,
                            contactIdentity
                        )
                    for (groupOwnerAndUid in groupOwnerAndUids!!) {
                        protocolManagerSession.identityDelegate.leaveGroup(
                            protocolManagerSession.session,
                            groupOwnerAndUid,
                            ownedIdentity
                        )
                    }
                }

                // delete contact, fails if there are still some groups
                protocolManagerSession.identityDelegate!!.deleteContactIdentity(
                    protocolManagerSession.session,
                    ownedIdentity,
                    contactIdentity,
                    true
                )

                // if the contact was indeed deleted (no exception thrown) remove contact from all owned groups where it is pending
                val groupOwnerAndUids =
                    protocolManagerSession.identityDelegate.getGroupOwnerAndUidOfGroupsWhereContactIsPending(
                        protocolManagerSession.session,
                        contactIdentity,
                        ownedIdentity
                    )

                val removedMemberIdentities = HashSet<Identity>(1)
                removedMemberIdentities.add(contactIdentity!!)

                for (groupOwnerAndUid in groupOwnerAndUids) {
                    val groupInformation =
                        protocolManagerSession.identityDelegate.getGroupInformation(
                            protocolManagerSession.session,
                            ownedIdentity,
                            groupOwnerAndUid
                        )

                    val coreProtocolMessage = CoreProtocolMessage(
                        SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                        ConcreteProtocol.GROUP_MANAGEMENT_PROTOCOL_ID,
                        groupInformation!!.computeProtocolUid()
                    )
                    val messageToSend: ChannelMessageToSend? = RemoveGroupMembersMessage(
                        coreProtocolMessage,
                        groupInformation,
                        removedMemberIdentities
                    ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
            } catch (_: Exception) {
            }
            return FinalState()
        }
    }


    class DowngradeContactStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitiateContactDowngradeMessage,
        protocol: ContactManagementProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
                // mark contact as not oneToOne
                protocolManagerSession.identityDelegate!!.setContactOneToOne(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.contactIdentity,
                    false
                )
            }

            run {
                try {
                    // notify the contact he has been downgraded
                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createAllConfirmedObliviousChannelsOrPreKeysInfo(
                            receivedMessage.contactIdentity,
                            ownedIdentity
                        )
                    )
                    val messageToSend: ChannelMessageToSend? =
                        ContactDowngradeNotificationMessage(coreProtocolMessage).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                } catch (_: Exception) {
                }
            }

            run {
                // propagate downgrade to other owned devices
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
                        val messageToSend: ChannelMessageToSend? = PropagateContactDowngradeMessage(
                            coreProtocolMessage,
                            receivedMessage.contactIdentity
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

            return FinalState()
        }
    }


    class ProcessContactDowngradeNotificationStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: ContactDowngradeNotificationMessage,
        protocol: ContactManagementProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
                // mark contact as not oneToOne
                protocolManagerSession.identityDelegate!!.setContactOneToOne(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.receptionChannelInfo!!.getRemoteIdentity(),
                    false
                )
            }

            return FinalState()
        }
    }


    class ProcessPropagatedContactDowngradeStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: PropagateContactDowngradeMessage,
        protocol: ContactManagementProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
                // mark contact as not oneToOne
                protocolManagerSession.identityDelegate!!.setContactOneToOne(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.contactIdentity,
                    false
                )
            }

            return FinalState()
        }
    }

    class ProcessPerformContactDeviceDiscoveryMessageStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: PerformContactDeviceDiscoveryMessage,
        protocol: ContactManagementProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.DEVICE_DISCOVERY_PROTOCOL_ID,
                UID(prng)
            )
            val message: ChannelMessageToSend? = DeviceDiscoveryProtocol.InitialMessage(
                coreProtocolMessage,
                receivedMessage.receptionChannelInfo!!.getRemoteIdentity()!!
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )

            return FinalState()
        }
    } // endregion

    companion object {
        // region States
        const val FINAL_STATE_ID: Int = 1


        // endregion
        // region Messages
        private const val INITIATE_CONTACT_DELETION_MESSAGE_ID = 0
        private const val CONTACT_DELETION_NOTIFICATION_MESSAGE_ID = 1
        private const val PROPAGATE_CONTACT_DELETION_MESSAGE_ID = 2

        private const val INITIATE_CONTACT_DOWNGRADE_MESSAGE_ID = 3
        private const val CONTACT_DOWNGRADE_NOTIFICATION_MESSAGE_ID = 4
        private const val PROPAGATE_CONTACT_DOWNGRADE_MESSAGE_ID = 5
        private const val PERFORM_CONTACT_DEVICE_DISCOVERY_MESSAGE_ID = 6
    }
}






