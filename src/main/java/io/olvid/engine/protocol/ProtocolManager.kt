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
package io.olvid.engine.protocol

import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoAcceptableChannelException
import io.olvid.engine.datatypes.NotificationListener
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.GroupInformation
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.containers.GroupV2.IdentityAndPermissions
import io.olvid.engine.datatypes.containers.GroupV2.ServerPhotoInfo
import io.olvid.engine.datatypes.containers.IdentityWithSerializedDetails
import io.olvid.engine.datatypes.containers.ProtocolReceivedDialogResponse
import io.olvid.engine.datatypes.containers.ProtocolReceivedMessage
import io.olvid.engine.datatypes.containers.ProtocolReceivedServerResponse
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.JsonGroupDetailsWithVersionAndPhoto
import io.olvid.engine.engine.types.JsonIdentityDetailsWithVersionAndPhoto
import io.olvid.engine.engine.types.ObvCapability
import io.olvid.engine.engine.types.ObvDeviceManagementRequest
import io.olvid.engine.engine.types.identities.ObvGroupV2.ObvGroupV2ChangeSet
import io.olvid.engine.engine.types.identities.ObvKeycloakState
import io.olvid.engine.engine.types.sync.ObvBackupAndSyncDelegate
import io.olvid.engine.engine.types.sync.ObvSyncAtom
import io.olvid.engine.metamanager.ChannelDelegate
import io.olvid.engine.metamanager.CreateSessionDelegate
import io.olvid.engine.metamanager.EncryptionForIdentityDelegate
import io.olvid.engine.metamanager.EngineOwnedIdentityCleanupDelegate
import io.olvid.engine.metamanager.FullRatchetProtocolStarterDelegate
import io.olvid.engine.metamanager.IdentityDelegate
import io.olvid.engine.metamanager.MetaManager
import io.olvid.engine.metamanager.NotificationListeningDelegate
import io.olvid.engine.metamanager.NotificationPostingDelegate
import io.olvid.engine.metamanager.ObvManager
import io.olvid.engine.metamanager.ProtocolDelegate
import io.olvid.engine.metamanager.PushNotificationDelegate
import io.olvid.engine.protocol.coordinators.ProtocolStepCoordinator
import io.olvid.engine.protocol.databases.ChannelCreationPingSignatureReceived
import io.olvid.engine.protocol.databases.ChannelCreationProtocolInstance
import io.olvid.engine.protocol.databases.GroupV2PreShotVersionSeedReceived
import io.olvid.engine.protocol.databases.GroupV2SignatureReceived
import io.olvid.engine.protocol.databases.IdentityDeletionSignatureReceived
import io.olvid.engine.protocol.databases.LinkBetweenProtocolInstances
import io.olvid.engine.protocol.databases.MutualScanSignatureReceived
import io.olvid.engine.protocol.databases.ProtocolInstance
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.databases.TrustEstablishmentCommitmentReceived
import io.olvid.engine.protocol.databases.WaitingForOneToOneContactProtocolInstance
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.GenericProtocolMessageToSend
import io.olvid.engine.protocol.datatypes.GenericReceivedProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.datatypes.ProtocolManagerSessionFactory
import io.olvid.engine.protocol.datatypes.ProtocolStarterDelegate
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import io.olvid.engine.protocol.protocols.ChannelCreationWithContactDeviceProtocol
import io.olvid.engine.protocol.protocols.ChannelCreationWithOwnedDeviceProtocol
import io.olvid.engine.protocol.protocols.ContactManagementProtocol.InitiateContactDeletionMessage
import io.olvid.engine.protocol.protocols.ContactManagementProtocol.InitiateContactDowngradeMessage
import io.olvid.engine.protocol.protocols.ContactMutualIntroductionProtocol
import io.olvid.engine.protocol.protocols.DeviceCapabilitiesDiscoveryProtocol.InitialForAddingOwnCapabilitiesMessage
import io.olvid.engine.protocol.protocols.DeviceDiscoveryProtocol
import io.olvid.engine.protocol.protocols.DownloadGroupPhotoChildProtocol
import io.olvid.engine.protocol.protocols.DownloadGroupV2PhotoProtocol
import io.olvid.engine.protocol.protocols.DownloadIdentityPhotoChildProtocol
import io.olvid.engine.protocol.protocols.FullRatchetProtocol
import io.olvid.engine.protocol.protocols.GroupManagementProtocol.AddGroupMembersMessage
import io.olvid.engine.protocol.protocols.GroupManagementProtocol.DisbandGroupMessage
import io.olvid.engine.protocol.protocols.GroupManagementProtocol.GroupMembersOrDetailsChangedTriggerMessage
import io.olvid.engine.protocol.protocols.GroupManagementProtocol.InitiateGroupCreationMessage
import io.olvid.engine.protocol.protocols.GroupManagementProtocol.InitiateGroupMembersQueryMessage
import io.olvid.engine.protocol.protocols.GroupManagementProtocol.LeaveGroupMessage
import io.olvid.engine.protocol.protocols.GroupManagementProtocol.ReinvitePendingMemberMessage
import io.olvid.engine.protocol.protocols.GroupManagementProtocol.RemoveGroupMembersMessage
import io.olvid.engine.protocol.protocols.GroupManagementProtocol.TriggerReinviteMessage
import io.olvid.engine.protocol.protocols.GroupsV2Protocol.CreateOrUpdateKeycloakGroupMessage
import io.olvid.engine.protocol.protocols.GroupsV2Protocol.GroupCreationInitialMessage
import io.olvid.engine.protocol.protocols.GroupsV2Protocol.GroupDisbandInitialMessage
import io.olvid.engine.protocol.protocols.GroupsV2Protocol.GroupLeaveInitialMessage
import io.olvid.engine.protocol.protocols.GroupsV2Protocol.GroupReDownloadInitialMessage
import io.olvid.engine.protocol.protocols.GroupsV2Protocol.GroupUpdateInitialMessage
import io.olvid.engine.protocol.protocols.GroupsV2Protocol.InitiateBatchKeysResendMessage
import io.olvid.engine.protocol.protocols.GroupsV2Protocol.InitiateTargetedPingMessage
import io.olvid.engine.protocol.protocols.IdentityDetailsPublicationProtocol
import io.olvid.engine.protocol.protocols.KeycloakBindingAndUnbindingProtocol.OwnedIdentityKeycloakBindingMessage
import io.olvid.engine.protocol.protocols.KeycloakBindingAndUnbindingProtocol.OwnedIdentityKeycloakUnbindingMessage
import io.olvid.engine.protocol.protocols.KeycloakContactAdditionProtocol
import io.olvid.engine.protocol.protocols.OneToOneContactInvitationProtocol
import io.olvid.engine.protocol.protocols.OwnedDeviceDiscoveryProtocol
import io.olvid.engine.protocol.protocols.OwnedDeviceManagementProtocol
import io.olvid.engine.protocol.protocols.OwnedIdentityDeletionProtocol
import io.olvid.engine.protocol.protocols.OwnedIdentityTransferProtocol.InitiateTransferOnSourceDeviceMessage
import io.olvid.engine.protocol.protocols.OwnedIdentityTransferProtocol.InitiateTransferOnTargetDeviceMessage
import io.olvid.engine.protocol.protocols.SynchronizationProtocol.InitiateSingleItemSyncMessage
import io.olvid.engine.protocol.protocols.TrustEstablishmentWithMutualScanProtocol
import io.olvid.engine.protocol.protocols.TrustEstablishmentWithSasProtocol
import io.olvid.engine.storage.EngineFileIo
import java.sql.SQLException
import java.util.Arrays


class ProtocolManager(
    metaManager: MetaManager,
    internal val appBackupAndSyncDelegate: ObvBackupAndSyncDelegate?,
    internal val engineBaseDirectory: String?,
    internal val fileIo: EngineFileIo,
    internal val prng: PRNGService,
    internal val jsonObjectMapper: ObjectMapper
) : ProtocolDelegate, ProtocolStarterDelegate, FullRatchetProtocolStarterDelegate,
    ProtocolManagerSessionFactory, ObvManager {
    internal var createSessionDelegate: CreateSessionDelegate? = null
    internal var channelDelegate: ChannelDelegate? = null
    internal var identityDelegate: IdentityDelegate? = null
    internal var identityBackupAndSyncDelegate: ObvBackupAndSyncDelegate? = null
    internal var encryptionForIdentityDelegate: EncryptionForIdentityDelegate? = null
    internal var notificationPostingDelegate: NotificationPostingDelegate? = null
    internal var notificationListeningDelegate: NotificationListeningDelegate? = null
    internal var engineOwnedIdentityCleanupDelegate: EngineOwnedIdentityCleanupDelegate? = null
    internal var pushNotificationDelegate: PushNotificationDelegate? = null

    internal val protocolStepCoordinator: ProtocolStepCoordinator
    internal val newDeviceListener: NewDeviceListener
    internal val contactDeletedListener: ContactDeletedListener
    internal val contactTrustLevelListener: ContactTrustLevelListener

    //    private final ScheduledExecutorService schedulerForPeriodicSync;
    init {
        this.protocolStepCoordinator =
            ProtocolStepCoordinator(this, this.prng, this.jsonObjectMapper)
        this.newDeviceListener = NewDeviceListener()
        this.contactDeletedListener = ContactDeletedListener()
        this.contactTrustLevelListener = ContactTrustLevelListener()

        //        this.schedulerForPeriodicSync = Executors.newScheduledThreadPool(1);
        metaManager.requestDelegate(this, CreateSessionDelegate::class.java)
        metaManager.requestDelegate(this, ChannelDelegate::class.java)
        metaManager.requestDelegate(this, EncryptionForIdentityDelegate::class.java)
        metaManager.requestDelegate(this, IdentityDelegate::class.java)
        metaManager.requestDelegate(this, ObvBackupAndSyncDelegate::class.java)
        metaManager.requestDelegate(this, NotificationListeningDelegate::class.java)
        metaManager.requestDelegate(this, NotificationPostingDelegate::class.java)
        metaManager.requestDelegate(this, EngineOwnedIdentityCleanupDelegate::class.java)
        metaManager.requestDelegate(this, PushNotificationDelegate::class.java)
        metaManager.registerImplementedDelegates(this)
    }

    override fun initialQueueingPriority(): Int {
        return 100
    }

    override fun initialisationComplete() {
        protocolStepCoordinator.initialQueueing()

        // check all contact oneToOne for WaitingForTLIncreaseProtocolInstance
        try {
            session.use { protocolManagerSession ->
                for (waitingForOneToOneContactProtocolInstance in WaitingForOneToOneContactProtocolInstance.getAll(
                    protocolManagerSession
                )) {
                    val oneToOne = identityDelegate!!.isIdentityAOneToOneContactOfOwnedIdentity(
                        protocolManagerSession.session,
                        waitingForOneToOneContactProtocolInstance.ownedIdentity,
                        waitingForOneToOneContactProtocolInstance.contactIdentity
                    )
                    if (oneToOne) {
                        val message: GenericProtocolMessageToSend =
                            waitingForOneToOneContactProtocolInstance.genericProtocolMessageToSendWhenTrustLevelIncreased
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            message.generateChannelProtocolMessageToSend(),
                            prng
                        )
                    }
                }
                //            // trigger all SynchronizationProtocol instances to detect new changes and re-notify the app of current diffs
//            for (ProtocolInstance protocolInstance : ProtocolInstance.getAllForProtocolId(protocolManagerSession, ConcreteProtocol.SYNCHRONIZATION_PROTOCOL_ID)) {
//                CoreProtocolMessage coreProtocolMessage = new CoreProtocolMessage(SendChannelInfo.createLocalChannelInfo(protocolInstance.getOwnedIdentity()),
//                        ConcreteProtocol.SYNCHRONIZATION_PROTOCOL_ID,
//                        protocolInstance.getUid(),
//                        false);
//                ChannelMessageToSend message = new SynchronizationProtocol.TriggerSyncMessage(coreProtocolMessage, false).generateChannelProtocolMessageToSend();
//                protocolManagerSession!!.channelDelegate!!.post(protocolManagerSession!!.session, message, prng);
//            }
//
//            // for all confirmed oblivious channels, initiate a SynchronizationProtocol in case one is not already running (message is ignored if protocol is already running)
//            for (Identity ownedIdentity : identityDelegate!!.getOwnedIdentities(protocolManagerSession!!.session)) {
//                UID currentDeviceUid = identityDelegate!!.getCurrentDeviceUidOfOwnedIdentity(protocolManagerSession!!.session, ownedIdentity);
//                for (UID otherDeviceUid : channelDelegate!!.getConfirmedObliviousChannelDeviceUids(protocolManagerSession!!.session, ownedIdentity, ownedIdentity)) {
//                    CoreProtocolMessage coreProtocolMessage = new CoreProtocolMessage(SendChannelInfo.createLocalChannelInfo(ownedIdentity),
//                            ConcreteProtocol.SYNCHRONIZATION_PROTOCOL_ID,
//                            SynchronizationProtocol.computeOngoingProtocolInstanceUid(ownedIdentity, currentDeviceUid, otherDeviceUid),
//                            false);
//                    ChannelMessageToSend message = new SynchronizationProtocol.InitiateSyncMessage(coreProtocolMessage, otherDeviceUid).generateChannelProtocolMessageToSend();
//                    protocolManagerSession!!.channelDelegate!!.post(protocolManagerSession!!.session, message, prng);
//                }
//            }

                // delete all unfinished transfer instances
                ProtocolInstance.deleteAllTransfer(protocolManagerSession)

                // expire some GroupV2PreShotVersionSeedReceived
                GroupV2PreShotVersionSeedReceived.expire(
                    protocolManagerSession,
                    System.currentTimeMillis() - Constants.GROUP_V2_PRE_SHOT_VERSION_SEED_TTL
                )

                protocolManagerSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }

        //        schedulerForPeriodicSync.schedule(this::triggerOwnedDevicesSync, Constants.PERIODIC_OWNED_DEVICE_SYNC_INTERVAL, Constants.PERIODIC_OWNED_DEVICE_SYNC_INTERVAL, TimeUnit.MILLISECONDS);
    }

    fun startProcessing() {
        protocolStepCoordinator.startProcessing()
    }


    //    private void triggerOwnedDevicesSync() {
    //        try (ProtocolManagerSession protocolManagerSession = getSession()) {
    //            for (ProtocolInstance protocolInstance : ProtocolInstance.getAllForProtocolId(protocolManagerSession, ConcreteProtocol.SYNCHRONIZATION_PROTOCOL_ID)) {
    //                CoreProtocolMessage coreProtocolMessage = new CoreProtocolMessage(SendChannelInfo.createLocalChannelInfo(protocolInstance.getOwnedIdentity()),
    //                        ConcreteProtocol.SYNCHRONIZATION_PROTOCOL_ID,
    //                        protocolInstance.getUid(),
    //                        false);
    //                ChannelMessageToSend message = new SynchronizationProtocol.TriggerSyncMessage(coreProtocolMessage, false).generateChannelProtocolMessageToSend();
    //                protocolManagerSession!!.channelDelegate!!.post(protocolManagerSession!!.session, message, prng);
    //            }
    //
    //            protocolManagerSession!!.session.commit();
    //        } catch (Exception e) {
    //            Logger.x(e);
    //        }
    //    }
    // region SetDelegate
    fun setDelegate(createSessionDelegate: CreateSessionDelegate) {
        this.createSessionDelegate = createSessionDelegate

        try {
            session.use { protocolManagerSession ->
                ReceivedMessage.createTable(protocolManagerSession.session)
                ProtocolInstance.createTable(protocolManagerSession.session)
                LinkBetweenProtocolInstances.createTable(protocolManagerSession.session)
                ChannelCreationProtocolInstance.createTable(protocolManagerSession.session)
                WaitingForOneToOneContactProtocolInstance.createTable(
                    protocolManagerSession.session
                )
                ChannelCreationPingSignatureReceived.createTable(protocolManagerSession.session)
                TrustEstablishmentCommitmentReceived.createTable(protocolManagerSession.session)
                MutualScanSignatureReceived.createTable(protocolManagerSession.session)
                GroupV2SignatureReceived.createTable(protocolManagerSession.session)
                GroupV2PreShotVersionSeedReceived.createTable(protocolManagerSession.session)
                IdentityDeletionSignatureReceived.createTable(protocolManagerSession.session)
                protocolManagerSession.session.commit()
            }
        } catch (e: SQLException) {
            Logger.x(e)
            throw RuntimeException("Unable to create protocol databases")
        }
    }

    fun setDelegate(channelDelegate: ChannelDelegate) {
        this.channelDelegate = channelDelegate
    }

    fun setDelegate(identityDelegate: IdentityDelegate) {
        this.identityDelegate = identityDelegate
    }

    fun setDelegate(identityBackupAndSyncDelegate: ObvBackupAndSyncDelegate?) {
        this.identityBackupAndSyncDelegate = identityBackupAndSyncDelegate
    }

    fun setDelegate(encryptionForIdentityDelegate: EncryptionForIdentityDelegate?) {
        this.encryptionForIdentityDelegate = encryptionForIdentityDelegate
    }

    fun setDelegate(notificationListeningDelegate: NotificationListeningDelegate) {
        this.notificationListeningDelegate = notificationListeningDelegate
        notificationListeningDelegate.addListener(
            IdentityNotifications.NOTIFICATION_NEW_CONTACT_DEVICE,
            newDeviceListener
        )
        notificationListeningDelegate.addListener(
            IdentityNotifications.NOTIFICATION_NEW_OWNED_DEVICE,
            newDeviceListener
        )
        notificationListeningDelegate.addListener(
            IdentityNotifications.NOTIFICATION_CONTACT_IDENTITY_DELETED,
            contactDeletedListener
        )
        notificationListeningDelegate.addListener(
            IdentityNotifications.NOTIFICATION_CONTACT_ONE_TO_ONE_CHANGED,
            contactTrustLevelListener
        )
    }

    fun setDelegate(notificationPostingDelegate: NotificationPostingDelegate?) {
        this.notificationPostingDelegate = notificationPostingDelegate
    }

    fun setDelegate(engineOwnedIdentityCleanupDelegate: EngineOwnedIdentityCleanupDelegate?) {
        this.engineOwnedIdentityCleanupDelegate = engineOwnedIdentityCleanupDelegate
    }

    fun setDelegate(pushNotificationDelegate: PushNotificationDelegate?) {
        this.pushNotificationDelegate = pushNotificationDelegate
    }

    // endregion
    internal inner class NewDeviceListener : NotificationListener {
        override fun callback(notificationName: String?, userInfo: Map<String, Any>?) {
            when (notificationName) {
                IdentityNotifications.NOTIFICATION_NEW_CONTACT_DEVICE -> {
                    try {
                        val contactDeviceUid =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_NEW_CONTACT_DEVICE_CONTACT_DEVICE_UID_KEY) as UID?
                        val contactIdentity =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_NEW_CONTACT_DEVICE_CONTACT_IDENTITY_KEY) as Identity?
                        val ownedIdentity =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_NEW_CONTACT_DEVICE_OWNED_IDENTITY_KEY) as Identity?
                        val channelCreationAlreadyInProgress =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_NEW_CONTACT_DEVICE_CHANNEL_CREATION_ALREADY_IN_PROGRESS_KEY) as Boolean?
                        if (channelCreationAlreadyInProgress == null || !channelCreationAlreadyInProgress) {
                            startChannelCreationWithContactDeviceProtocol(
                                ownedIdentity,
                                contactIdentity!!,
                                contactDeviceUid
                            )
                        }
                    } catch (e: Exception) {
                        Logger.x(e)
                    }
                }

                IdentityNotifications.NOTIFICATION_NEW_OWNED_DEVICE -> {
                    try {
                        val ownedDeviceUid =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_NEW_OWNED_DEVICE_DEVICE_UID_KEY) as UID?
                        val ownedIdentity =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_NEW_OWNED_DEVICE_OWNED_IDENTITY_KEY) as Identity?
                        val channelCreationAlreadyInProgress =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_NEW_OWNED_DEVICE_CHANNEL_CREATION_ALREADY_IN_PROGRESS_KEY) as Boolean?
                        if (channelCreationAlreadyInProgress == null || !channelCreationAlreadyInProgress) {
                            startChannelCreationWithOwnedDeviceProtocol(
                                ownedIdentity,
                                ownedDeviceUid
                            )
                        }
                    } catch (e: Exception) {
                        Logger.x(e)
                    }
                }
            }
        }
    }

    internal inner class ContactDeletedListener : NotificationListener {
        override fun callback(notificationName: String?, userInfo: Map<String, Any>?) {
            when (notificationName) {
                IdentityNotifications.NOTIFICATION_CONTACT_IDENTITY_DELETED -> try {
                    val contactIdentity =
                        userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_IDENTITY_DELETED_CONTACT_IDENTITY_KEY) as Identity?
                    val ownedIdentity =
                        userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_IDENTITY_DELETED_OWNED_IDENTITY_KEY) as Identity?
                    session.use { protocolManagerSession ->
                        val channelCreationProtocolInstances: Array<ChannelCreationProtocolInstance?>? =
                            ChannelCreationProtocolInstance.getAllForContact(
                                protocolManagerSession,
                                contactIdentity,
                                ownedIdentity!!
                            )
                        if (channelCreationProtocolInstances == null) {
                            return@use
                        }
                        for (channelCreationProtocolInstance in channelCreationProtocolInstances) {
                            if (channelCreationProtocolInstance == null) continue
                            abortProtocol(
                                protocolManagerSession.session,
                                channelCreationProtocolInstance.protocolInstanceUid,
                                ownedIdentity
                            )
                        }
                        protocolManagerSession.session.commit()
                    }                         // To improve: delete any other protocol related to this contact
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }
        }
    }

    internal inner class ContactTrustLevelListener : NotificationListener {
        override fun callback(notificationName: String?, userInfo: Map<String, Any>?) {
            when (notificationName) {
                IdentityNotifications.NOTIFICATION_CONTACT_ONE_TO_ONE_CHANGED -> try {
                    val ownedIdentity =
                        userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_ONE_TO_ONE_CHANGED_OWNED_IDENTITY_KEY) as Identity?
                    val contactIdentity =
                        userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_ONE_TO_ONE_CHANGED_CONTACT_IDENTITY_KEY) as Identity?
                    val oneToOne =
                        userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_ONE_TO_ONE_CHANGED_ONE_TO_ONE_KEY) as Boolean
                    if (oneToOne) {
                        session.use { protocolManagerSession ->
                            val waitingForOneToOneContactProtocolInstances: Array<WaitingForOneToOneContactProtocolInstance> =
                                WaitingForOneToOneContactProtocolInstance.getAllForContact(
                                    protocolManagerSession,
                                    ownedIdentity,
                                    contactIdentity
                                )
                            for (waitingForOneToOneContactProtocolInstance in waitingForOneToOneContactProtocolInstances) {
                                val message =
                                    waitingForOneToOneContactProtocolInstance.genericProtocolMessageToSendWhenTrustLevelIncreased
                                protocolManagerSession.channelDelegate!!.post(
                                    protocolManagerSession.session,
                                    message.generateChannelProtocolMessageToSend(),
                                    prng
                                )
                            }
                            protocolManagerSession.session.commit()
                        }
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }
        }
    }

    @Throws(SQLException::class)
    fun deleteOwnedIdentity(
        session: Session,
        ownedIdentity: Identity,
        excludedProtocolInstanceUid: UID?
    ) {
        // delete ReceivedMessage
        ReceivedMessage.deleteAllForOwnedIdentity(wrapSession(session), ownedIdentity)
        // delete ProtocolInstance
        ProtocolInstance.deleteAllForOwnedIdentity(
            wrapSession(session),
            ownedIdentity,
            excludedProtocolInstanceUid
        )
        // delete TrustEstablishmentCommitmentReceived
        TrustEstablishmentCommitmentReceived.deleteAllForOwnedIdentity(
            wrapSession(session),
            ownedIdentity
        )
        // delete MutualScanNonceReceived
        MutualScanSignatureReceived.deleteAllForOwnedIdentity(
            wrapSession(session),
            ownedIdentity
        )
        // delete GroupV2SignatureReceived
        GroupV2SignatureReceived.deleteAllForOwnedIdentity(
            wrapSession(session),
            ownedIdentity
        )
        // delete GroupV2PreShotVersionSeedReceived
        GroupV2PreShotVersionSeedReceived.deleteAllForOwnedIdentity(
            wrapSession(session),
            ownedIdentity
        )
        // delete LinkBetweenProtocolInstances
        LinkBetweenProtocolInstances.deleteAllForOwnedIdentity(
            wrapSession(session),
            ownedIdentity
        )
        // delete ChannelCreationProtocolInstance
        ChannelCreationProtocolInstance.deleteAllForOwnedIdentity(
            wrapSession(session),
            ownedIdentity
        )
        // delete ChannelCreationPingSignatureReceived
        ChannelCreationPingSignatureReceived.deleteAllForOwnedIdentity(
            wrapSession(session),
            ownedIdentity
        )
        // delete WaitingForTrustLevelIncreaseProtocolInstance
        WaitingForOneToOneContactProtocolInstance.deleteAllForOwnedIdentity(
            wrapSession(
                session
            ), ownedIdentity
        )
        // delete IdentityDeletionSignatureReceived
        IdentityDeletionSignatureReceived.deleteAllForOwnedIdentity(
            wrapSession(session),
            ownedIdentity
        )
    }


    // region Implement ProtocolDelegate
    @Throws(Exception::class)
    override fun abortProtocol(
        session: Session,
        protocolInstanceUid: UID?,
        ownedIdentity: Identity?
    ) {
        // To improve: execute this on the protocol step execution thread
        //       move this to the ProtocolReceivedMessageProcessorDelegate API instead (in the ProtocolStepCoordinator)
        //       do something "protocol specific" to notify other devices that protocol was aborted when necessary.
        val protocolManagerSession = wrapSession(session)
        Logger.w("Aborting Protocol " + protocolInstanceUid)

        // Find child protocol instances (and delete them just after)
        val linksToParent: Array<LinkBetweenProtocolInstances?> =
            LinkBetweenProtocolInstances.getAllParentLinks(
            protocolManagerSession,
            protocolInstanceUid!!,
            ownedIdentity!!
        )
        val linksToChild: Array<LinkBetweenProtocolInstances?> =
            LinkBetweenProtocolInstances.getAllChildLinks(
            protocolManagerSession,
            protocolInstanceUid,
            ownedIdentity
        )

        // Delete the associated ProtocolInstance
        val protocolInstance: ProtocolInstance? = ProtocolInstance.get(
            protocolManagerSession,
            protocolInstanceUid,
            ownedIdentity
        )
        if (protocolInstance != null) {
            protocolInstance.delete()
        }

        // Delete all remaining ReceivedMessage for this protocol
        for (receivedMessage in ReceivedMessage.getAll(
            protocolManagerSession,
            protocolInstanceUid,
            ownedIdentity
        )) {
            receivedMessage?.delete()
        }


        // recursively abort child and parent protocols
        for (linkToParent in linksToParent) {
            val parentProtocolInstance: ProtocolInstance? = ProtocolInstance.get(
            protocolManagerSession,
            protocolInstanceUid,
            ownedIdentity
        )
            if (parentProtocolInstance != null) {
                if (linkToParent == null) continue
            abortProtocol(session, linkToParent.parentProtocolInstanceUid, ownedIdentity)
            }
        }

        for (linkToChild in linksToChild) {
            val childProtocolInstance: ProtocolInstance? = ProtocolInstance.get(
            protocolManagerSession,
            protocolInstanceUid,
            ownedIdentity
        )
            if (childProtocolInstance != null) {
                if (linkToChild == null) continue
            abortProtocol(session, linkToChild.childProtocolInstanceUid, ownedIdentity)
            }
        }
    }

    @Throws(Exception::class)
    override fun process(session: Session, message: ProtocolReceivedMessage?) {
        if (!identityDelegate!!.isOwnedIdentity(session, message?.getOwnedIdentity(), false)
            && message?.getOwnedIdentity()!!.server != Constants.EPHEMERAL_IDENTITY_SERVER
        ) {
            throw Exception()
        }
        val genericReceivedProtocolMessage: GenericReceivedProtocolMessage? =
            GenericReceivedProtocolMessage.of(message!!)
        ReceivedMessage.create(
            wrapSession(session),
            genericReceivedProtocolMessage,
            prng
        )
    }

    @Throws(Exception::class)
    override fun process(session: Session, message: ProtocolReceivedDialogResponse?) {
        if (!identityDelegate!!.isOwnedIdentity(session, message?.getToIdentity(), false)
            && message?.getToIdentity()!!.server != Constants.EPHEMERAL_IDENTITY_SERVER
        ) {
            throw Exception()
        }
        val genericReceivedProtocolMessage: GenericReceivedProtocolMessage? =
            GenericReceivedProtocolMessage.of(message!!)
        ReceivedMessage.create(
            wrapSession(session),
            genericReceivedProtocolMessage,
            prng
        )
    }

    @Throws(Exception::class)
    override fun process(session: Session, message: ProtocolReceivedServerResponse?) {
        if (!identityDelegate!!.isOwnedIdentity(session, message?.getToIdentity(), false)
            && message?.getToIdentity()!!.server != Constants.EPHEMERAL_IDENTITY_SERVER
        ) {
            throw Exception()
        }
        val genericReceivedProtocolMessage: GenericReceivedProtocolMessage? =
            GenericReceivedProtocolMessage.of(message!!)
        ReceivedMessage.create(
            wrapSession(session),
            genericReceivedProtocolMessage,
            prng
        )
    }

    @Throws(Exception::class)
    override fun isChannelCreationInProgress(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        contactDeviceUid: UID?
    ): Boolean {
        return ChannelCreationProtocolInstance.get(
            wrapSession(session),
            contactDeviceUid,
            contactIdentity,
            ownedIdentity!!
        ) != null
    }


    // endregion
    // region Implement ProtocolManagerSessionFactory
    override val session: ProtocolManagerSession
        @Throws(SQLException::class)
        get() {
            if (createSessionDelegate == null) {
                throw SQLException("No CreateSessionDelegate was set in ChannelManager.")
            }
            return ProtocolManagerSession(
                createSessionDelegate!!.session,
                channelDelegate,
                identityDelegate,
                encryptionForIdentityDelegate,
                protocolStepCoordinator,
                this,
                this,
                notificationPostingDelegate,
                notificationListeningDelegate,
                engineOwnedIdentityCleanupDelegate,
                pushNotificationDelegate,
                engineBaseDirectory,
                fileIo,
                identityBackupAndSyncDelegate,
                appBackupAndSyncDelegate
            )
        }

    private fun wrapSession(session: Session): ProtocolManagerSession {
        return ProtocolManagerSession(
            session,
            channelDelegate,
            identityDelegate,
            encryptionForIdentityDelegate,
            protocolStepCoordinator,
            this,
            this,
            notificationPostingDelegate,
            notificationListeningDelegate,
            engineOwnedIdentityCleanupDelegate,
            pushNotificationDelegate,
            engineBaseDirectory,
            fileIo,
            identityBackupAndSyncDelegate,
            appBackupAndSyncDelegate
        )
    }


    // endregion
    // region Implement ProtocolStarterDelegate
    @Throws(Exception::class)
    override fun startDeviceDiscoveryProtocol(ownedIdentity: Identity?, contactIdentity: Identity?) {
        if (contactIdentity?.equals(ownedIdentity) == true) {
            Logger.w("Cannot start a DeviceDiscovery protocol with contactIdentity == ownedIdentity")
            return
        }
        session.use { protocolManagerSession ->
            val protocolInstanceUid = UID(prng)
            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.DEVICE_DISCOVERY_PROTOCOL_ID,
                protocolInstanceUid
            )
            val message: ChannelMessageToSend? =
                DeviceDiscoveryProtocol.InitialMessage(coreProtocolMessage, contactIdentity!!)
                    .generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun startDeviceDiscoveryProtocolWithinTransaction(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ) {
        if (contactIdentity?.equals(ownedIdentity) == true) {
            Logger.w("Cannot start a DeviceDiscovery protocol with contactIdentity == ownedIdentity")
            return
        }
        val protocolManagerSession = wrapSession(session)
        val protocolInstanceUid = UID(prng)
        val coreProtocolMessage = CoreProtocolMessage(
            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
            ConcreteProtocol.DEVICE_DISCOVERY_PROTOCOL_ID,
            protocolInstanceUid
        )
        val message: ChannelMessageToSend? =
            DeviceDiscoveryProtocol.InitialMessage(coreProtocolMessage, contactIdentity!!)
                .generateChannelProtocolMessageToSend()
        protocolManagerSession.channelDelegate!!.post(protocolManagerSession.session, message, prng)
    }

    @Throws(Exception::class)
    override fun startOwnedDeviceDiscoveryProtocol(ownedIdentity: Identity?) {
        session.use { protocolManagerSession ->
            val protocolInstanceUid = UID(prng)
            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.OWNED_DEVICE_DISCOVERY_PROTOCOL_ID,
                protocolInstanceUid
            )
            val message: ChannelMessageToSend? =
                OwnedDeviceDiscoveryProtocol.InitialMessage(coreProtocolMessage)
                    .generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun startOwnedDeviceDiscoveryProtocolWithinTransaction(
        session: Session,
        ownedIdentity: Identity?
    ) {
        val protocolManagerSession = wrapSession(session)
        val protocolInstanceUid = UID(prng)
        val coreProtocolMessage = CoreProtocolMessage(
            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
            ConcreteProtocol.OWNED_DEVICE_DISCOVERY_PROTOCOL_ID,
            protocolInstanceUid
        )
        val message: ChannelMessageToSend? =
            OwnedDeviceDiscoveryProtocol.InitialMessage(coreProtocolMessage)
                .generateChannelProtocolMessageToSend()
        protocolManagerSession.channelDelegate!!.post(session, message, prng)
    }

    @Throws(Exception::class)
    override fun startChannelCreationProtocolWithOwnedDevice(
        session: Session,
        ownedIdentity: Identity?,
        ownedDeviceUid: UID?
    ) {
        val protocolManagerSession = wrapSession(session)
        val protocolInstanceUid = UID(prng)
        val coreProtocolMessage = CoreProtocolMessage(
            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
            ConcreteProtocol.CHANNEL_CREATION_WITH_OWNED_DEVICE_PROTOCOL_ID,
            protocolInstanceUid
        )
        val message: ChannelMessageToSend? = ChannelCreationWithOwnedDeviceProtocol.InitialMessage(
            coreProtocolMessage,
            ownedDeviceUid!!
        ).generateChannelProtocolMessageToSend()
        protocolManagerSession.channelDelegate!!.post(session, message, prng)
    }

    @Throws(Exception::class)
    override fun startChannelCreationProtocolWithContactDevice(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        contactDeviceUid: UID?
    ) {
        if (contactIdentity?.equals(ownedIdentity) == true) {
            Logger.w("Cannot start a ChannelCreationWithContactDeviceProtocol with contactIdentity == ownedIdentity")
            return
        }
        val protocolManagerSession = wrapSession(session)
        val protocolInstanceUid = UID(prng)
        val coreProtocolMessage = CoreProtocolMessage(
            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
            ConcreteProtocol.CHANNEL_CREATION_WITH_CONTACT_DEVICE_PROTOCOL_ID,
            protocolInstanceUid
        )
        val message: ChannelMessageToSend? =
            ChannelCreationWithContactDeviceProtocol.InitialMessage(
            coreProtocolMessage,
            contactIdentity!!,
            contactDeviceUid!!
        ).generateChannelProtocolMessageToSend()
        protocolManagerSession.channelDelegate!!.post(session, message, prng)
    }

    @Throws(Exception::class)
    override fun startDownloadIdentityPhotoProtocolWithinTransaction(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        jsonIdentityDetailsWithVersionAndPhoto: JsonIdentityDetailsWithVersionAndPhoto?
    ) {
        if (ownedIdentity == null || contactIdentity == null || jsonIdentityDetailsWithVersionAndPhoto == null) {
            return
        }
        val protocolManagerSession = wrapSession(session)
        val protocolInstanceUid = UID(prng)
        val coreProtocolMessage = CoreProtocolMessage(
            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
            ConcreteProtocol.DOWNLOAD_IDENTITY_PHOTO_CHILD_PROTOCOL_ID,
            protocolInstanceUid
        )
        val message: ChannelMessageToSend? = DownloadIdentityPhotoChildProtocol.InitialMessage(
            coreProtocolMessage,
            contactIdentity,
            jsonObjectMapper.writeValueAsString(jsonIdentityDetailsWithVersionAndPhoto)
        ).generateChannelProtocolMessageToSend()
        protocolManagerSession.channelDelegate!!.post(protocolManagerSession.session, message, prng)
    }

    @Throws(Exception::class)
    override fun startDownloadGroupPhotoProtocolWithinTransaction(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?,
        jsonGroupDetailsWithVersionAndPhoto: JsonGroupDetailsWithVersionAndPhoto?
    ) {
        if (ownedIdentity == null || groupOwnerAndUid == null || groupOwnerAndUid.size < UID.UID_LENGTH || jsonGroupDetailsWithVersionAndPhoto == null) {
            return
        }

        val groupInformation = GroupInformation(
            Identity.of(
                Arrays.copyOfRange(
                    groupOwnerAndUid,
                    0,
                    groupOwnerAndUid.size - UID.UID_LENGTH
                )
            ),
            UID(
                Arrays.copyOfRange(
                    groupOwnerAndUid,
                    groupOwnerAndUid.size - UID.UID_LENGTH,
                    groupOwnerAndUid.size
                )
            ),
            jsonObjectMapper.writeValueAsString(jsonGroupDetailsWithVersionAndPhoto)
        )
        val protocolManagerSession = wrapSession(session)
        val protocolInstanceUid = UID(prng)
        val coreProtocolMessage = CoreProtocolMessage(
            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
            ConcreteProtocol.DOWNLOAD_GROUP_PHOTO_CHILD_PROTOCOL_ID,
            protocolInstanceUid
        )
        val message: ChannelMessageToSend? =
            DownloadGroupPhotoChildProtocol.InitialMessage(coreProtocolMessage, groupInformation)
                .generateChannelProtocolMessageToSend()
        protocolManagerSession.channelDelegate!!.post(protocolManagerSession.session, message, prng)
    }

    @Throws(Exception::class)
    override fun startDownloadGroupV2PhotoProtocolWithinTransaction(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        serverPhotoInfo: ServerPhotoInfo?
    ) {
        if (ownedIdentity == null || groupIdentifier == null || serverPhotoInfo == null) {
            return
        }

        val protocolManagerSession = wrapSession(session)
        val protocolInstanceUid = UID(prng)
        val coreProtocolMessage = CoreProtocolMessage(
            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
            ConcreteProtocol.DOWNLOAD_GROUPS_V2_PHOTO_PROTOCOL_ID,
            protocolInstanceUid
        )
        val message: ChannelMessageToSend? = DownloadGroupV2PhotoProtocol.InitialMessage(
            coreProtocolMessage,
            groupIdentifier,
            serverPhotoInfo
        ).generateChannelProtocolMessageToSend()
        protocolManagerSession.channelDelegate!!.post(protocolManagerSession.session, message, prng)
    }

    @Throws(Exception::class)
    override fun startTrustEstablishmentProtocol(
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        contactDisplayName: String?
    ) {
        startTrustEstablishmentWithSasProtocol(contactIdentity!!, contactDisplayName, ownedIdentity)
    }

    @Throws(Exception::class)
    override fun initiateGroupV2ReDownloadWithinTransaction(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ) {
        if (ownedIdentity == null || groupIdentifier == null) {
            throw Exception()
        }

        val protocolInstanceUid = groupIdentifier.computeProtocolInstanceUid()

        val coreProtocolMessage = CoreProtocolMessage(
            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
            ConcreteProtocol.GROUPS_V2_PROTOCOL_ID,
            protocolInstanceUid
        )

        val message: ChannelMessageToSend? = GroupReDownloadInitialMessage(
            coreProtocolMessage,
            groupIdentifier
        ).generateChannelProtocolMessageToSend()
        channelDelegate!!.post(session, message, prng)
    }


    @Throws(Exception::class)
    override fun initiateKeycloakGroupV2TargetedPing(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        contactIdentity: Identity?
    ) {
        if (ownedIdentity == null || groupIdentifier == null || groupIdentifier.category != GroupV2.Identifier.CATEGORY_KEYCLOAK) {
            throw Exception()
        }

        val protocolInstanceUid = groupIdentifier.computeProtocolInstanceUid()

        val coreProtocolMessage = CoreProtocolMessage(
            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
            ConcreteProtocol.GROUPS_V2_PROTOCOL_ID,
            protocolInstanceUid
        )

        val message: ChannelMessageToSend? = InitiateTargetedPingMessage(
            coreProtocolMessage,
            groupIdentifier,
            contactIdentity!!
        ).generateChannelProtocolMessageToSend()
        channelDelegate!!.post(session, message, prng)
    }

    @Throws(Exception::class)
    private fun startTrustEstablishmentWithSasProtocol(
        contactIdentity: Identity,
        contactDisplayName: String?,
        ownedIdentity: Identity?
    ) {
        if (contactIdentity.equals(ownedIdentity)) {
            Logger.w("Cannot start a trust establishment protocol with contactIdentity == ownedIdentity")
            return
        }
        session.use { protocolManagerSession ->
            val protocolInstanceUid = UID(prng)
            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.TRUST_ESTABLISHMENT_WITH_SAS_PROTOCOL_ID,
                protocolInstanceUid
            )
            val ownedIdentityDetails =
                identityDelegate!!.getSerializedPublishedDetailsOfOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity
                )
            if (ownedIdentityDetails == null) {
                Logger.e("Error finding own identity details in startTrustEstablishmentProtocol")
                return
            }
            val message: ChannelMessageToSend? = TrustEstablishmentWithSasProtocol.InitialMessage(
                coreProtocolMessage,
                contactIdentity,
                contactDisplayName!!,
                ownedIdentityDetails
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun startMutualScanTrustEstablishmentProtocol(
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        signature: ByteArray?
    ) {
        if (contactIdentity?.equals(ownedIdentity) == true) {
            Logger.w("Cannot start a mutual scan protocol with contactIdentity == ownedIdentity")
            return
        }
        session.use { protocolManagerSession ->
            val protocolInstanceUid = UID(prng)
            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.TRUST_ESTABLISHMENT_WITH_MUTUAL_SCAN_PROTOCOL_ID,
                protocolInstanceUid
            )

            val message: ChannelMessageToSend? =
                TrustEstablishmentWithMutualScanProtocol.InitialMessage(
                coreProtocolMessage,
                contactIdentity!!,
                signature!!
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }

    @Throws(Exception::class)
    private fun startChannelCreationWithContactDeviceProtocol(
        ownedIdentity: Identity?,
        contactIdentity: Identity,
        contactDeviceUid: UID?
    ) {
        if (contactIdentity.equals(ownedIdentity)) {
            Logger.w("Cannot start a protocol with contactIdentity == ownedIdentity")
            return
        }
        session.use { protocolManagerSession ->
            val protocolInstanceUid = UID(prng)
            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.CHANNEL_CREATION_WITH_CONTACT_DEVICE_PROTOCOL_ID,
                protocolInstanceUid
            )
            val message: ChannelMessageToSend? =
                ChannelCreationWithContactDeviceProtocol.InitialMessage(
            coreProtocolMessage,
            contactIdentity,
            contactDeviceUid!!
        ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }

    @Throws(Exception::class)
    fun startChannelCreationWithOwnedDeviceProtocol(
        ownedIdentity: Identity?,
        ownedDeviceUid: UID?
    ) {
        session.use { protocolManagerSession ->
            val protocolInstanceUid = UID(prng)
            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.CHANNEL_CREATION_WITH_OWNED_DEVICE_PROTOCOL_ID,
                protocolInstanceUid
            )
            val message: ChannelMessageToSend? =
                ChannelCreationWithOwnedDeviceProtocol.InitialMessage(
                    coreProtocolMessage,
                    ownedDeviceUid!!
                ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun startContactMutualIntroductionProtocol(
        ownedIdentity: Identity?,
        contactIdentityA: Identity?,
        contactIdentities: Array<Identity?>?
    ) {
        if (contactIdentityA?.equals(ownedIdentity) == true) {
            Logger.w("Cannot start a protocol with contactIdentity == ownedIdentity")
            return
        }
        session.use { protocolManagerSession ->
            protocolManagerSession.session.startTransaction()
            for (contactIdentityB in contactIdentities!!) {
                if (contactIdentityB?.equals(ownedIdentity) == true) {
                    Logger.w("Cannot start a protocol with contactIdentity == ownedIdentity")
                    return
                }
                val protocolInstanceUid = UID(prng)
                val coreProtocolMessage = CoreProtocolMessage(
                    SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                    ConcreteProtocol.CONTACT_MUTUAL_INTRODUCTION_PROTOCOL_ID,
                    protocolInstanceUid
                )
                val message: ChannelMessageToSend? =
                    ContactMutualIntroductionProtocol.InitialMessage(
                    coreProtocolMessage,
                    contactIdentityA!!,
                    contactIdentityB!!
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    message,
                    prng
                )
            }
            protocolManagerSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun startGroupCreationProtocol(
        ownedIdentity: Identity?,
        serializedGroupDetailsWithVersionAndPhoto: String?,
        absolutePhotoUrl: String?,
        groupMemberIdentitiesAndSerializedDetails: HashSet<IdentityWithSerializedDetails?>?
    ) {
        if (serializedGroupDetailsWithVersionAndPhoto == null || ownedIdentity == null || groupMemberIdentitiesAndSerializedDetails == null) {
            throw Exception()
        }

        if (groupMemberIdentitiesAndSerializedDetails.contains(
                IdentityWithSerializedDetails(
                    ownedIdentity,
                    ""
                )
            )
        ) {
            Logger.e("Error in startGroupCreationProtocol: ownedIdentity contained in groupMemberIdentitiesAndSerializedDetails")
            throw Exception()
        }


        session.use { protocolManagerSession ->
            val groupInformation =
                GroupInformation.generate(ownedIdentity, serializedGroupDetailsWithVersionAndPhoto, prng)
            val protocolInstanceUid = groupInformation.computeProtocolUid()

            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.GROUP_MANAGEMENT_PROTOCOL_ID,
                protocolInstanceUid
            )

            val message: ChannelMessageToSend? = InitiateGroupCreationMessage(
                coreProtocolMessage,
                groupInformation,
                absolutePhotoUrl,
                @Suppress("UNCHECKED_CAST") (groupMemberIdentitiesAndSerializedDetails as HashSet<IdentityWithSerializedDetails>)
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }


    @Throws(Exception::class)
    override fun startGroupV2CreationProtocol(
        ownedIdentity: Identity?,
        serializedGroupDetails: String?,
        absolutePhotoUrl: String?,
        ownPermissions: HashSet<GroupV2.Permission?>?,
        otherGroupMembers: HashSet<IdentityAndPermissions?>?,
        serializedGroupType: String?
    ) {
        if (serializedGroupDetails == null || ownedIdentity == null || ownPermissions == null || otherGroupMembers == null) {
            throw Exception()
        }

        if (otherGroupMembers.any { it?.identity == ownedIdentity } == true) {
            Logger.e("Error in startGroupV2CreationProtocol: ownedIdentity contained in otherGroupMembers")
            throw Exception()
        }

        if (!ownPermissions.contains(GroupV2.Permission.GROUP_ADMIN)) {
            Logger.e("Error in startGroupV2CreationProtocol: ownedPermissions do not containt GROUP_ADMIN")
            throw Exception()
        }

        session.use { protocolManagerSession ->
            val protocolInstanceUid = UID(prng)
            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.GROUPS_V2_PROTOCOL_ID,
                protocolInstanceUid
            )

            val message: ChannelMessageToSend? = GroupCreationInitialMessage(
                coreProtocolMessage,
                @Suppress("UNCHECKED_CAST") (ownPermissions as HashSet<GroupV2.Permission>),
                @Suppress("UNCHECKED_CAST") (otherGroupMembers as HashSet<IdentityAndPermissions>),
                serializedGroupDetails,
                absolutePhotoUrl,
                serializedGroupType
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun initiateGroupV2Update(
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        changeSet: ObvGroupV2ChangeSet?
    ) {
        if (ownedIdentity == null || groupIdentifier == null) {
            throw Exception()
        }

        session.use { protocolManagerSession ->
            val protocolInstanceUid = groupIdentifier.computeProtocolInstanceUid()
            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.GROUPS_V2_PROTOCOL_ID,
                protocolInstanceUid
            )

            val message: ChannelMessageToSend? = GroupUpdateInitialMessage(
                coreProtocolMessage,
                groupIdentifier,
                changeSet!!
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun initiateGroupV2Leave(
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ) {
        if (ownedIdentity == null || groupIdentifier == null || groupIdentifier.category == GroupV2.Identifier.CATEGORY_KEYCLOAK) {
            throw Exception()
        }

        session.use { protocolManagerSession ->
            val protocolInstanceUid = groupIdentifier.computeProtocolInstanceUid()
            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.GROUPS_V2_PROTOCOL_ID,
                protocolInstanceUid
            )

            val message: ChannelMessageToSend? = GroupLeaveInitialMessage(
                coreProtocolMessage,
                groupIdentifier
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun initiateGroupV2Disband(
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ) {
        if (ownedIdentity == null || groupIdentifier == null || groupIdentifier.category == GroupV2.Identifier.CATEGORY_KEYCLOAK) {
            throw Exception()
        }

        session.use { protocolManagerSession ->
            val protocolInstanceUid = groupIdentifier.computeProtocolInstanceUid()
            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.GROUPS_V2_PROTOCOL_ID,
                protocolInstanceUid
            )

            val message: ChannelMessageToSend? = GroupDisbandInitialMessage(
                coreProtocolMessage,
                groupIdentifier
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }


    @Throws(Exception::class)
    override fun initiateGroupV2ReDownload(
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ) {
        if (ownedIdentity == null || groupIdentifier == null) {
            throw Exception()
        }

        session.use { protocolManagerSession ->
            val protocolInstanceUid = groupIdentifier.computeProtocolInstanceUid()
            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.GROUPS_V2_PROTOCOL_ID,
                protocolInstanceUid
            )

            val message: ChannelMessageToSend? = GroupReDownloadInitialMessage(
                coreProtocolMessage,
                groupIdentifier
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun initiateGroupV2BatchKeysResend(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        contactDeviceUid: UID?
    ) {
        if (ownedIdentity == null || contactIdentity == null) {
            throw Exception()
        }

        val protocolInstanceUid = UID(prng)
        val coreProtocolMessage = CoreProtocolMessage(
            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
            ConcreteProtocol.GROUPS_V2_PROTOCOL_ID,
            protocolInstanceUid
        )
        val message: ChannelMessageToSend? = InitiateBatchKeysResendMessage(
            coreProtocolMessage,
            contactIdentity,
            contactDeviceUid!!
        ).generateChannelProtocolMessageToSend()
        channelDelegate!!.post(session, message, prng)
    }

    @Throws(Exception::class)
    override fun createOrUpdateKeycloakGroupV2(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        serializedKeycloakGroupBlob: String?
    ) {
        if (ownedIdentity == null || groupIdentifier == null || serializedKeycloakGroupBlob == null) {
            throw Exception()
        }

        val protocolInstanceUid = groupIdentifier.computeProtocolInstanceUid()
        val coreProtocolMessage = CoreProtocolMessage(
            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
            ConcreteProtocol.GROUPS_V2_PROTOCOL_ID,
            protocolInstanceUid
        )
        val message: ChannelMessageToSend? = CreateOrUpdateKeycloakGroupMessage(
            coreProtocolMessage,
            groupIdentifier,
            serializedKeycloakGroupBlob
        ).generateChannelProtocolMessageToSend()
        channelDelegate!!.post(session, message, prng)
    }


    @Throws(Exception::class)
    override fun processDeviceManagementRequest(
        ownedIdentity: Identity?,
        deviceManagementRequest: ObvDeviceManagementRequest?
    ) {
        session.use { protocolManagerSession ->
            processDeviceManagementRequest(
                protocolManagerSession.session,
                ownedIdentity,
                deviceManagementRequest
            )
            protocolManagerSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun processDeviceManagementRequest(
        session: Session,
        ownedIdentity: Identity?,
        deviceManagementRequest: ObvDeviceManagementRequest?
    ) {
        if (ownedIdentity == null || deviceManagementRequest == null) {
            throw Exception()
        }

        val protocolInstanceUid = UID(prng)
        val coreProtocolMessage = CoreProtocolMessage(
            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
            ConcreteProtocol.OWNED_DEVICE_MANAGEMENT_PROTOCOL_ID,
            protocolInstanceUid
        )
        val message: ChannelMessageToSend? = OwnedDeviceManagementProtocol.InitialMessage(
            coreProtocolMessage,
            deviceManagementRequest
        ).generateChannelProtocolMessageToSend()
        channelDelegate!!.post(session, message, prng)
    }

    @Throws(Exception::class)
    override fun startIdentityDetailsPublicationProtocol(
        session: Session,
        ownedIdentity: Identity?,
        version: Int
    ) {
        if (ownedIdentity == null) {
            throw Exception()
        }

        val protocolInstanceUid = UID(prng)
        val coreProtocolMessage = CoreProtocolMessage(
            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
            ConcreteProtocol.IDENTITY_DETAILS_PUBLICATION_PROTOCOL_ID,
            protocolInstanceUid
        )
        val message: ChannelMessageToSend? =
            IdentityDetailsPublicationProtocol.InitialMessage(coreProtocolMessage, version)
                .generateChannelProtocolMessageToSend()
        channelDelegate!!.post(session, message, prng)
    }

    @Throws(Exception::class)
    override fun startGroupDetailsPublicationProtocol(
        session: Session,
        ownedIdentity: Identity?,
        groupUid: ByteArray?
    ) {
        if (ownedIdentity == null || groupUid == null) {
            throw Exception()
        }

        val groupInformation =
            identityDelegate!!.getGroupInformation(session, ownedIdentity, groupUid)
        if (groupInformation == null) {
            throw Exception()
        }
        val protocolInstanceUid = groupInformation.computeProtocolUid()
        val coreProtocolMessage = CoreProtocolMessage(
            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
            ConcreteProtocol.GROUP_MANAGEMENT_PROTOCOL_ID,
            protocolInstanceUid
        )
        val message: ChannelMessageToSend? = GroupMembersOrDetailsChangedTriggerMessage(
            coreProtocolMessage,
            groupInformation
        ).generateChannelProtocolMessageToSend()
        channelDelegate!!.post(session, message, prng)
    }

    @Throws(Exception::class)
    override fun startOneToOneInvitationProtocol(
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ) {
        if (ownedIdentity == null || contactIdentity == null) {
            throw Exception()
        }

        session.use { protocolManagerSession ->
            val protocolInstanceUid = UID(prng)
            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.ONE_TO_ONE_CONTACT_INVITATION_PROTOCOL_ID,
                protocolInstanceUid
            )
            val message: ChannelMessageToSend? = OneToOneContactInvitationProtocol.InitialMessage(
                coreProtocolMessage,
                contactIdentity
            ).generateChannelProtocolMessageToSend()
            channelDelegate!!.post(protocolManagerSession.session, message, prng)
            protocolManagerSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun inviteContactsToGroup(
        groupOwnerAndUid: ByteArray?,
        ownedIdentity: Identity?,
        newMembersIdentity: HashSet<Identity?>?
    ) {
        if (groupOwnerAndUid == null || ownedIdentity == null || newMembersIdentity == null || newMembersIdentity.isEmpty()) {
            throw Exception()
        }

        if (newMembersIdentity.contains(ownedIdentity)) {
            Logger.e("Error in inviteContactsToGroup: ownedIdentity contained in newMembersIdentity")
            throw Exception()
        }


        session.use { protocolManagerSession ->
            val group = identityDelegate!!.getGroup(
                protocolManagerSession.session,
                ownedIdentity,
                groupOwnerAndUid
            )
            val groupInformation = identityDelegate!!.getGroupInformation(
                protocolManagerSession.session,
                ownedIdentity,
                groupOwnerAndUid
            )
            if (group == null || groupInformation == null) {
                Logger.e("Error in inviteContactsToGroup: group not found")
                throw Exception()
            }

            for (pendingIdentity in group.getPendingGroupMembers()) {
                if (newMembersIdentity.contains(pendingIdentity.identity)) {
                    Logger.e("Error in inviteContactsToGroup: adding a member that is already pending")
                    throw Exception()
                }
            }

            for (memberIdentity in group.getGroupMembers()) {
                if (newMembersIdentity.contains(memberIdentity)) {
                    Logger.e("Error in inviteContactsToGroup: adding a member that is already in the group")
                    throw Exception()
                }
            }

            val protocolInstanceUid = groupInformation.computeProtocolUid()

            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.GROUP_MANAGEMENT_PROTOCOL_ID,
                protocolInstanceUid
            )

            val message: ChannelMessageToSend? = AddGroupMembersMessage(
                coreProtocolMessage,
                groupInformation,
                @Suppress("UNCHECKED_CAST") (newMembersIdentity as HashSet<Identity>)
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun reinvitePendingToGroup(
        groupOwnerAndUid: ByteArray?,
        ownedIdentity: Identity?,
        pendingMemberIdentity: Identity?
    ) {
        if (groupOwnerAndUid == null || ownedIdentity == null || pendingMemberIdentity == null) {
            throw Exception()
        }

        session.use { protocolManagerSession ->
            val group = identityDelegate!!.getGroup(
                protocolManagerSession.session,
                ownedIdentity,
                groupOwnerAndUid
            )
            val groupInformation = identityDelegate!!.getGroupInformation(
                protocolManagerSession.session,
                ownedIdentity,
                groupOwnerAndUid
            )
            if (group == null || groupInformation == null) {
                Logger.e("Error in reinvitePendingToGroup: group not found")
                throw Exception()
            }

            if (!group.isPendingMember(pendingMemberIdentity)) {
                Logger.e("Error in reinvitePendingToGroup: pendingMemberIdentity is not a PendingMember")
                throw Exception()
            }

            val protocolInstanceUid = groupInformation.computeProtocolUid()

            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.GROUP_MANAGEMENT_PROTOCOL_ID,
                protocolInstanceUid
            )

            val message: ChannelMessageToSend? = ReinvitePendingMemberMessage(
                coreProtocolMessage,
                groupInformation,
                pendingMemberIdentity
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }


    @Throws(Exception::class)
    override fun removeContactsFromGroup(
        groupOwnerAndUid: ByteArray?,
        ownedIdentity: Identity?,
        removedMemberIdentities: HashSet<Identity?>?
    ) {
        if (groupOwnerAndUid == null || ownedIdentity == null || removedMemberIdentities == null || removedMemberIdentities.isEmpty()) {
            throw Exception()
        }

        if (removedMemberIdentities.contains(ownedIdentity)) {
            Logger.e("Error in inviteContactsToGroup: ownedIdentity contained in removedMemberIdentities")
            throw Exception()
        }


        session.use { protocolManagerSession ->
            val group = identityDelegate!!.getGroup(
                protocolManagerSession.session,
                ownedIdentity,
                groupOwnerAndUid
            )
            val groupInformation = identityDelegate!!.getGroupInformation(
                protocolManagerSession.session,
                ownedIdentity,
                groupOwnerAndUid
            )
            if (group == null || groupInformation == null) {
                Logger.e("Error in inviteContactsToGroup: group not found")
                throw Exception()
            }

            for (removedMemberIdentity in removedMemberIdentities) {
                if (!group.isMember(removedMemberIdentity) && !group.isPendingMember(
                        removedMemberIdentity
                    )
                ) {
                    Logger.e("Error in removedMemberIdentities: removing a member that is neither member nor pending")
                    throw Exception()
                }
            }

            val protocolInstanceUid = groupInformation.computeProtocolUid()

            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.GROUP_MANAGEMENT_PROTOCOL_ID,
                protocolInstanceUid
            )

            val message: ChannelMessageToSend? = RemoveGroupMembersMessage(
                coreProtocolMessage,
                groupInformation,
                @Suppress("UNCHECKED_CAST") (removedMemberIdentities as HashSet<Identity>)
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun leaveGroup(groupOwnerAndUid: ByteArray?, ownedIdentity: Identity?) {
        if (groupOwnerAndUid == null || ownedIdentity == null) {
            throw Exception()
        }

        session.use { protocolManagerSession ->
            val group = identityDelegate!!.getGroup(
                protocolManagerSession.session,
                ownedIdentity,
                groupOwnerAndUid
            )
            val groupInformation = identityDelegate!!.getGroupInformation(
                protocolManagerSession.session,
                ownedIdentity,
                groupOwnerAndUid
            )
            if (group == null || groupInformation == null) {
                Logger.e("Error in leaveGroup: group not found")
                throw Exception()
            }

            if (group.getGroupOwner() == null) {
                Logger.e("Error in leaveGroup: trying to leave a group you own")
                throw Exception()
            }

            val protocolInstanceUid = groupInformation.computeProtocolUid()

            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.GROUP_MANAGEMENT_PROTOCOL_ID,
                protocolInstanceUid
            )

            val message: ChannelMessageToSend? = LeaveGroupMessage(
                coreProtocolMessage,
                groupInformation
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun disbandGroup(groupOwnerAndUid: ByteArray?, ownedIdentity: Identity?) {
        if (groupOwnerAndUid == null || ownedIdentity == null) {
            throw Exception()
        }

        session.use { protocolManagerSession ->
            val group = identityDelegate!!.getGroup(
                protocolManagerSession.session,
                ownedIdentity,
                groupOwnerAndUid
            )
            val groupInformation = identityDelegate!!.getGroupInformation(
                protocolManagerSession.session,
                ownedIdentity,
                groupOwnerAndUid
            )
            if (group == null || groupInformation == null) {
                Logger.e("Error in disbandGroup: group not found")
                throw Exception()
            }

            if (group.getGroupOwner() != null) {
                Logger.e("Error in disbandGroup: trying to disband a group you do not own")
                throw Exception()
            }

            val protocolInstanceUid = groupInformation.computeProtocolUid()

            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.GROUP_MANAGEMENT_PROTOCOL_ID,
                protocolInstanceUid
            )

            val message: ChannelMessageToSend? = DisbandGroupMessage(
                coreProtocolMessage,
                groupInformation
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun queryGroupMembers(groupOwnerAndUid: ByteArray?, ownedIdentity: Identity?) {
        if (groupOwnerAndUid == null || ownedIdentity == null) {
            throw Exception()
        }

        session.use { protocolManagerSession ->
            val group = identityDelegate!!.getGroup(
                protocolManagerSession.session,
                ownedIdentity,
                groupOwnerAndUid
            )
            val groupInformation = identityDelegate!!.getGroupInformation(
                protocolManagerSession.session,
                ownedIdentity,
                groupOwnerAndUid
            )
            if (group == null || groupInformation == null) {
                Logger.e("Error in queryGroupMembers: group not found")
                throw Exception()
            }

            if (group.getGroupOwner() == null) {
                throw Exception()
            }

            val protocolInstanceUid = groupInformation.computeProtocolUid()

            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.GROUP_MANAGEMENT_PROTOCOL_ID,
                protocolInstanceUid
            )

            val message: ChannelMessageToSend? = InitiateGroupMembersQueryMessage(
                coreProtocolMessage,
                groupInformation
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }


    @Throws(Exception::class)
    override fun reinviteAndPushMembersToContact(
        groupOwnerAndUid: ByteArray?,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ) {
        if (groupOwnerAndUid == null || ownedIdentity == null || contactIdentity == null) {
            throw Exception()
        }

        session.use { protocolManagerSession ->
            val group = identityDelegate!!.getGroup(
                protocolManagerSession.session,
                ownedIdentity,
                groupOwnerAndUid
            )
            val groupInformation = identityDelegate!!.getGroupInformation(
                protocolManagerSession.session,
                ownedIdentity,
                groupOwnerAndUid
            )
            if (group == null || groupInformation == null) {
                Logger.e("Error in reinviteAndPushMembersToContact: group not found")
                throw Exception()
            }

            if (group.getGroupOwner() != null) {
                Logger.e("Error in reinviteAndPushMembersToContact: trying to reinvite to a group you do not own")
                throw Exception()
            }

            val protocolInstanceUid = groupInformation.computeProtocolUid()

            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.GROUP_MANAGEMENT_PROTOCOL_ID,
                protocolInstanceUid
            )

            val message: ChannelMessageToSend? = TriggerReinviteMessage(
                coreProtocolMessage,
                groupInformation,
                contactIdentity
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }


    @Throws(Exception::class)
    override fun deleteContact(ownedIdentity: Identity?, contactIdentity: Identity?) {
        if (contactIdentity == null || ownedIdentity == null) {
            throw Exception()
        }

        session.use { protocolManagerSession ->
            if (!identityDelegate!!.isIdentityAContactOfOwnedIdentity(
                protocolManagerSession.session,
                ownedIdentity,
                contactIdentity
            )
            ) {
                Logger.e("Error in deleteContact: contact not found")
                throw Exception()
            }
            val protocolInstanceUid = UID(prng)

            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.CONTACT_MANAGEMENT_PROTOCOL_ID,
                protocolInstanceUid
            )

            val message: ChannelMessageToSend? = InitiateContactDeletionMessage(
                coreProtocolMessage,
                contactIdentity
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun downgradeOneToOneContact(ownedIdentity: Identity?, contactIdentity: Identity?) {
        if (contactIdentity == null || ownedIdentity == null) {
            throw Exception()
        }

        session.use { protocolManagerSession ->
            if (!identityDelegate!!.isIdentityAContactOfOwnedIdentity(
                protocolManagerSession.session,
                ownedIdentity,
                contactIdentity
            )
            ) {
                Logger.e("Error in downgradeContact: contact not found")
                throw Exception()
            }
            val protocolInstanceUid = UID(prng)

            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.CONTACT_MANAGEMENT_PROTOCOL_ID,
                protocolInstanceUid
            )

            val message: ChannelMessageToSend? = InitiateContactDowngradeMessage(
                coreProtocolMessage,
                contactIdentity
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun addKeycloakContact(
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        signedContactDetails: String?
    ) {
        if (contactIdentity == null || ownedIdentity == null || signedContactDetails == null) {
            throw Exception()
        }

        session.use { protocolManagerSession ->
            val protocolInstanceUid = UID(prng)
            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.KEYCLOAK_CONTACT_ADDITION_PROTOCOL_ID,
                protocolInstanceUid
            )

            val message: ChannelMessageToSend? = KeycloakContactAdditionProtocol.InitialMessage(
                coreProtocolMessage,
                contactIdentity,
                signedContactDetails
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun startProtocolForBindingOwnedIdentityToKeycloakWithinTransaction(
        session: Session,
        ownedIdentity: Identity?,
        keycloakState: ObvKeycloakState?,
        keycloakUserId: String?
    ) {
        if (ownedIdentity == null || keycloakState == null || keycloakUserId == null || keycloakState.keycloakServer == null || keycloakState.jwks == null) {
            throw Exception()
        }

        val protocolInstanceUid = UID(prng)

        val coreProtocolMessage = CoreProtocolMessage(
            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
            ConcreteProtocol.KEYCLOAK_BINDING_AND_UNBINDING_PROTOCOL_ID,
            protocolInstanceUid
        )

        val message: ChannelMessageToSend? = OwnedIdentityKeycloakBindingMessage(
            coreProtocolMessage,
            keycloakState,
            keycloakUserId
        ).generateChannelProtocolMessageToSend()
        channelDelegate!!.post(session, message, prng)
    }

    @Throws(Exception::class)
    override fun updateCurrentDeviceCapabilitiesForOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?,
        newOwnCapabilities: MutableList<ObvCapability>?
    ) {
        if (newOwnCapabilities == null) {
            return
        }

        val protocolInstanceUid = UID(prng)

        val coreProtocolMessage = CoreProtocolMessage(
            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
            ConcreteProtocol.DEVICE_CAPABILITIES_DISCOVERY_PROTOCOL_ID,
            protocolInstanceUid
        )

        val message: ChannelMessageToSend? = InitialForAddingOwnCapabilitiesMessage(
            coreProtocolMessage,
            newOwnCapabilities
        ).generateChannelProtocolMessageToSend()
        channelDelegate!!.post(session, message, prng)
    }

    @Throws(Exception::class)
    override fun startProtocolForUnbindingOwnedIdentityFromKeycloak(ownedIdentity: Identity?) {
        if (ownedIdentity == null) {
            throw Exception()
        }

        session.use { protocolManagerSession ->
            val protocolInstanceUid = UID(prng)
            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.KEYCLOAK_BINDING_AND_UNBINDING_PROTOCOL_ID,
                protocolInstanceUid
            )

            val message: ChannelMessageToSend? =
                OwnedIdentityKeycloakUnbindingMessage(coreProtocolMessage).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun startOwnedIdentityDeletionProtocol(
        session: Session,
        ownedIdentity: Identity?,
        deleteEverywhere: Boolean
    ) {
        if (ownedIdentity == null) {
            throw Exception()
        }
        try {
            val protocolInstanceUid = UID(prng)

            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.OWNED_IDENTITY_DELETION_PROTOCOL_ID,
                protocolInstanceUid
            )

            val message: ChannelMessageToSend? =
                OwnedIdentityDeletionProtocol.InitialMessage(coreProtocolMessage, deleteEverywhere)
                    .generateChannelProtocolMessageToSend()
            channelDelegate!!.post(session, message, prng)
        } catch (_: NoAcceptableChannelException) {
            Logger.w("Tried to delete an identity that is already deleted, ignoring message!")
        }
    }


    @Throws(Exception::class)
    override fun initiateSingleItemSync(
        session: Session,
        ownedIdentity: Identity?,
        obvSyncAtom: ObvSyncAtom?
    ) {
        if (ownedIdentity == null || obvSyncAtom == null) {
            throw Exception()
        }

        val protocolInstanceUid = UID(prng)

        val coreProtocolMessage = CoreProtocolMessage(
            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
            ConcreteProtocol.SYNCHRONIZATION_PROTOCOL_ID,
            protocolInstanceUid
        )

        val message: ChannelMessageToSend? = InitiateSingleItemSyncMessage(
            coreProtocolMessage,
            obvSyncAtom
        ).generateChannelProtocolMessageToSend()
        channelDelegate!!.post(session, message, prng)
    }

    //    @Override
    //    public void triggerOwnedDevicesSync(Session session, Identity ownedIdentity) {
    //        try {
    //            ProtocolManagerSession protocolManagerSession = wrapSession(session);
    //            for (ProtocolInstance protocolInstance : ProtocolInstance.getAllForOwnedIdentityProtocolId(protocolManagerSession, ownedIdentity, ConcreteProtocol.SYNCHRONIZATION_PROTOCOL_ID)) {
    //                CoreProtocolMessage coreProtocolMessage = new CoreProtocolMessage(SendChannelInfo.createLocalChannelInfo(ownedIdentity),
    //                        ConcreteProtocol.SYNCHRONIZATION_PROTOCOL_ID,
    //                        protocolInstance.getUid(),
    //                        false);
    //                ChannelMessageToSend message = new SynchronizationProtocol.TriggerSyncMessage(coreProtocolMessage, true).generateChannelProtocolMessageToSend();
    //                protocolManagerSession!!.channelDelegate!!.post(protocolManagerSession!!.session, message, prng);
    //            }
    //        } catch (Exception e) {
    //            Logger.x(e);
    //        }
    //    }
    @Throws(Exception::class)
    override fun initiateOwnedIdentityTransferProtocolOnSourceDevice(ownedIdentity: Identity?) {
        if (ownedIdentity == null) {
            throw Exception()
        }

        session.use { protocolManagerSession ->
            val protocolInstanceUid = UID(prng)
            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.OWNED_IDENTITY_TRANSFER_PROTOCOL_ID,
                protocolInstanceUid
            )

            val message: ChannelMessageToSend? =
                InitiateTransferOnSourceDeviceMessage(coreProtocolMessage).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun initiateOwnedIdentityTransferProtocolOnTargetDevice(deviceName: String?) {
        val serverAuthKeyPair = Suite.generateServerAuthenticationKeyPair(null, prng)
        val encryptionKeyPair = Suite.generateEncryptionKeyPair(null, prng)
        if (serverAuthKeyPair == null || encryptionKeyPair == null) {
            throw Exception()
        }
        val macKey = Suite.getDefaultMAC(0).generateKey(prng)
        val ephemeralIdentity = Identity(
            Constants.EPHEMERAL_IDENTITY_SERVER,
            serverAuthKeyPair.getPublicKey() as ServerAuthenticationPublicKey,
            encryptionKeyPair.getPublicKey() as EncryptionPublicKey
        )


        session.use { protocolManagerSession ->
            val protocolInstanceUid = UID(prng)
            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ephemeralIdentity),
                ConcreteProtocol.OWNED_IDENTITY_TRANSFER_PROTOCOL_ID,
                protocolInstanceUid
            )

            val message: ChannelMessageToSend? = InitiateTransferOnTargetDeviceMessage(
                coreProtocolMessage,
                deviceName!!,
                serverAuthKeyPair.getPrivateKey() as ServerAuthenticationPrivateKey,
                encryptionKeyPair.getPrivateKey() as EncryptionPrivateKey,
                macKey
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                message,
                prng
            )
            protocolManagerSession.session.commit()
        }
    }


    // endregion
    // region Implement FullRatchetProtocolStarterDelegate
    @Throws(Exception::class)
    override fun startFullRatchetProtocolForObliviousChannel(
        currentDeviceUid: UID?,
        remoteDeviceUid: UID?,
        remoteIdentity: Identity?
    ) {
        session.use { protocolManagerSession ->
            val ownedIdentity = identityDelegate!!.getOwnedIdentityForCurrentDeviceUid(
                protocolManagerSession.session,
                currentDeviceUid!!
            )
            if (ownedIdentity != null) {
                val protocolInstanceUid: UID = FullRatchetProtocol.computeProtocolUid(
                    ownedIdentity,
                    remoteIdentity!!,
                    currentDeviceUid,
                    remoteDeviceUid!!
                )

                val coreProtocolMessage = CoreProtocolMessage(
                    SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                    ConcreteProtocol.FULL_RATCHET_PROTOCOL_ID,
                    protocolInstanceUid,
                    false
                )

                val message: ChannelMessageToSend? = FullRatchetProtocol.InitialMessage(
                    coreProtocolMessage,
                    remoteIdentity,
                    remoteDeviceUid
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    message,
                    prng
                )
                protocolManagerSession.session.commit()
            }
        }
    } // endregion

    companion object {
        @JvmStatic
        @Throws(SQLException::class)
        fun upgradeTables(session: Session, oldVersion: Int, newVersion: Int) {
            ReceivedMessage.upgradeTable(session, oldVersion, newVersion)
            ProtocolInstance.upgradeTable(session, oldVersion, newVersion)
            LinkBetweenProtocolInstances.upgradeTable(session, oldVersion, newVersion)
            ChannelCreationProtocolInstance.upgradeTable(session, oldVersion, newVersion)
            WaitingForOneToOneContactProtocolInstance.upgradeTable(
                session,
                oldVersion,
                newVersion
            )
            ChannelCreationPingSignatureReceived.upgradeTable(
                session,
                oldVersion,
                newVersion
            )
            TrustEstablishmentCommitmentReceived.upgradeTable(
                session,
                oldVersion,
                newVersion
            )
            MutualScanSignatureReceived.upgradeTable(session, oldVersion, newVersion)
            GroupV2SignatureReceived.upgradeTable(session, oldVersion, newVersion)
            GroupV2PreShotVersionSeedReceived.upgradeTable(session, oldVersion, newVersion)
            IdentityDeletionSignatureReceived.upgradeTable(
                session,
                oldVersion,
                newVersion
            )
        }
    }
}
