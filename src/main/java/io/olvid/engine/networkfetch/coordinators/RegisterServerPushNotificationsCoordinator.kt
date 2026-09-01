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
package io.olvid.engine.networkfetch.coordinators

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.ExponentialBackoffRepeatingScheduler
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoDuplicateOperationQueue
import io.olvid.engine.datatypes.NotificationListener
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.Operation.OnCancelCallback
import io.olvid.engine.datatypes.Operation.OnFinishCallback
import io.olvid.engine.datatypes.PushNotificationTypeAndParameters
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.IdentityAndUid
import io.olvid.engine.datatypes.containers.OwnedIdentitySynchronizationStatus
import io.olvid.engine.datatypes.notifications.DownloadNotifications
import io.olvid.engine.metamanager.NotificationListeningDelegate
import io.olvid.engine.metamanager.NotificationPostingDelegate
import io.olvid.engine.networkfetch.databases.PushNotificationConfiguration
import io.olvid.engine.networkfetch.databases.PushNotificationConfiguration.NewPushNotificationConfigurationListener
import io.olvid.engine.networkfetch.datatypes.CreateServerSessionDelegate
import io.olvid.engine.networkfetch.datatypes.DownloadMessagesAndListAttachmentsDelegate
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import io.olvid.engine.networkfetch.datatypes.RegisterServerPushNotificationDelegate
import io.olvid.engine.networkfetch.operations.RegisterPushNotificationOperation
import io.olvid.engine.protocol.datatypes.ProtocolStarterDelegate
import javax.net.ssl.SSLSocketFactory


class RegisterServerPushNotificationsCoordinator(
    fetchManagerSessionFactory: FetchManagerSessionFactory,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?,
    createServerSessionDelegate: CreateServerSessionDelegate,
    downloadMessagesAndListAttachmentsDelegate: DownloadMessagesAndListAttachmentsDelegate
) : RegisterServerPushNotificationDelegate, NewPushNotificationConfigurationListener,
    OnCancelCallback, OnFinishCallback {
    private val fetchManagerSessionFactory: FetchManagerSessionFactory
    private val sslSocketFactory: SSLSocketFactory?
    private val userAgentOverride: String?
    private val createServerSessionDelegate: CreateServerSessionDelegate
    private val downloadMessagesAndListAttachmentsDelegate: DownloadMessagesAndListAttachmentsDelegate

    private val scheduler: ExponentialBackoffRepeatingScheduler<Identity?>
    private val registerPushNotificationOperationQueue: NoDuplicateOperationQueue

    private val serverSessionCreatedNotificationListener: ServerSessionCreatedNotificationListener

    private val androidIdentityMaskingUids: HashMap<UID?, IdentityAndUid?>
    private val ownedIdentitiesThatNeedAnOwnedDeviceDiscovery: HashSet<Identity?>

    private var notificationListeningDelegate: NotificationListeningDelegate? = null
    private var notificationPostingDelegate: NotificationPostingDelegate? = null
    private var protocolStarterDelegate: ProtocolStarterDelegate? = null

    init {
        this.fetchManagerSessionFactory = fetchManagerSessionFactory
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride
        this.createServerSessionDelegate = createServerSessionDelegate
        this.downloadMessagesAndListAttachmentsDelegate = downloadMessagesAndListAttachmentsDelegate

        registerPushNotificationOperationQueue = NoDuplicateOperationQueue()

        scheduler = ExponentialBackoffRepeatingScheduler<Identity?>()

        androidIdentityMaskingUids = HashMap<UID?, IdentityAndUid?>()
        ownedIdentitiesThatNeedAnOwnedDeviceDiscovery = HashSet<Identity?>()

        serverSessionCreatedNotificationListener = ServerSessionCreatedNotificationListener()
    }

    fun startProcessing() {
        registerPushNotificationOperationQueue.execute(
            1,
            "Engine-RegisterServerPushNotificationsCoordinator"
        )
    }

    fun setNotificationListeningDelegate(notificationListeningDelegate: NotificationListeningDelegate) {
        this.notificationListeningDelegate = notificationListeningDelegate
        // register to NotificationCenter for NOTIFICATION_SERVER_SESSION_CREATED
        this.notificationListeningDelegate!!.addListener(
            DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED,
            serverSessionCreatedNotificationListener
        )
    }

    fun setNotificationPostingDelegate(notificationPostingDelegate: NotificationPostingDelegate?) {
        this.notificationPostingDelegate = notificationPostingDelegate
    }

    fun setProtocolStarterDelegate(protocolStarterDelegate: ProtocolStarterDelegate?) {
        this.protocolStarterDelegate = protocolStarterDelegate
    }


    fun initialQueueing() {
        try {
            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                val pushNotificationConfigurations: Array<PushNotificationConfiguration?> =
                    PushNotificationConfiguration.getAll(fetchManagerSession)
                for (pushNotificationConfiguration in pushNotificationConfigurations) {
                    if (pushNotificationConfiguration == null) continue
                    // check that the corresponding owned Identity still exists --> delete otherwise
                    if (!fetchManagerSession.identityDelegate!!.isOwnedIdentity(
                            fetchManagerSession.session,
                            pushNotificationConfiguration.getOwnedIdentity(),
                            true
                        )
                    ) {
                        PushNotificationConfiguration.deleteForOwnedIdentity(
                            fetchManagerSession,
                            pushNotificationConfiguration.getOwnedIdentity()
                        )
                        fetchManagerSession.session.commit()
                        continue
                    }

                    when (pushNotificationConfiguration.pushNotificationType) {
                        PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_ANDROID -> {
                            storeAndroidIdentityMaskingUid(
                                pushNotificationConfiguration.getOwnedIdentity(),
                                pushNotificationConfiguration.deviceUid,
                                pushNotificationConfiguration.identityMaskingUid
                            )
                            registerServerPushNotification(
                                pushNotificationConfiguration.getOwnedIdentity(),
                                false
                            )
                        }

                        PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_WEBSOCKET_ANDROID, PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_WEBSOCKET_WINDOWS, PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_WEBSOCKET_LINUX, PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_WEBSOCKET_DAEMON -> registerServerPushNotification(
                            pushNotificationConfiguration.getOwnedIdentity(),
                            false
                        )
                    }
                }
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }


    private fun queueNewRegisterPushNotificationOperation(ownedIdentity: Identity) {
        val op = RegisterPushNotificationOperation(
            fetchManagerSessionFactory,
            sslSocketFactory,
            userAgentOverride,
            ownedIdentity,
            this,
            this
        )
        registerPushNotificationOperationQueue.queue(op)
    }

    private fun scheduleNewRegisterPushNotificationOperationQueueing(identity: Identity) {
        scheduler.schedule(
            identity,
            Runnable { queueNewRegisterPushNotificationOperation(identity) },
            "RegisterPushNotificationOperation"
        )
    }


    override fun onFinishCallback(operation: Operation) {
        val ownedIdentity = (operation as RegisterPushNotificationOperation).ownedIdentity
        scheduler.clearFailedCount(ownedIdentity)
        if (notificationPostingDelegate != null) {
            val userInfo = HashMap<String, Any>()
            userInfo[DownloadNotifications.NOTIFICATION_PUSH_NOTIFICATION_REGISTERED_OWNED_IDENTITY_KEY] = ownedIdentity
            notificationPostingDelegate?.postNotification(
                DownloadNotifications.NOTIFICATION_PUSH_NOTIFICATION_REGISTERED,
                userInfo
            )
        } else {
            Logger.e("NotificationPostingDelegate not set in RegisterServerPushNotificationsCoordinator")
        }
        synchronized(ownedIdentitiesThatNeedAnOwnedDeviceDiscovery) {
            if (protocolStarterDelegate != null && ownedIdentitiesThatNeedAnOwnedDeviceDiscovery.remove(
                    ownedIdentity
                )
            ) {
                try {
                    protocolStarterDelegate!!.startOwnedDeviceDiscoveryProtocol(ownedIdentity)
                } catch (_: Exception) {
                }
            }
        }
    }

    override fun onCancelCallback(operation: Operation) {
        val ownedIdentity = (operation as RegisterPushNotificationOperation).ownedIdentity
        var rfc = operation.reasonForCancel
        Logger.i("RegisterPushNotificationOperation cancelled for reason " + rfc)
        if (rfc == null) {
            rfc = Operation.RFC_NULL
        }
        when (rfc) {
            RegisterPushNotificationOperation.RFC_INVALID_SERVER_SESSION -> {
                createServerSessionDelegate.createServerSession(ownedIdentity)
            }

            RegisterPushNotificationOperation.RFC_ANOTHER_DEVICE_IS_ALREADY_REGISTERED, RegisterPushNotificationOperation.RFC_PUSH_NOTIFICATION_CONFIGURATION_NOT_FOUND -> {}
            RegisterPushNotificationOperation.RFC_DEVICE_UID_TO_REPLACE_NOT_FOUND -> {
                val userInfo = HashMap<String, Any>()
                userInfo[DownloadNotifications.NOTIFICATION_PUSH_REGISTER_FAILED_BAD_DEVICE_UID_TO_REPLACE_OWNED_IDENTITY_KEY] = ownedIdentity
                notificationPostingDelegate?.postNotification(
                    DownloadNotifications.NOTIFICATION_PUSH_REGISTER_FAILED_BAD_DEVICE_UID_TO_REPLACE,
                    userInfo
                )
            }

            else -> {
                scheduleNewRegisterPushNotificationOperationQueueing(ownedIdentity)
            }
        }
    }

    override fun registerServerPushNotification(
        identity: Identity?,
        triggerAnOwnedDeviceDiscoveryWhenFinished: Boolean
    ) {
        if (identity == null) return
        if (triggerAnOwnedDeviceDiscoveryWhenFinished) {
            synchronized(ownedIdentitiesThatNeedAnOwnedDeviceDiscovery) {
                ownedIdentitiesThatNeedAnOwnedDeviceDiscovery.add(identity)
            }
        }
        queueNewRegisterPushNotificationOperation(identity)
    }

    override fun newPushNotificationConfiguration(
        identity: Identity?,
        deviceUid: UID?,
        pushNotificationTypeAndParameters: PushNotificationTypeAndParameters?
    ) {
        if (identity == null || deviceUid == null || pushNotificationTypeAndParameters == null) return
        when (pushNotificationTypeAndParameters.pushNotificationType) {
            PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_ANDROID -> {
                storeAndroidIdentityMaskingUid(
                    identity,
                    deviceUid,
                    pushNotificationTypeAndParameters.identityMaskingUid
                )
                registerServerPushNotification(identity, false)
            }

            PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_WEBSOCKET_ANDROID, PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_WEBSOCKET_WINDOWS, PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_WEBSOCKET_LINUX, PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_WEBSOCKET_DAEMON -> registerServerPushNotification(
                identity,
                false
            )
        }
    }

    fun processAndroidPushNotification(androidMaskingUidString: String?) {
        if (androidMaskingUidString == null) {
            return
        }
        try {
            val androidIdentityMaskingUid = UID(androidMaskingUidString)
            val identityAndUid = androidIdentityMaskingUids.get(androidIdentityMaskingUid)
            if (identityAndUid != null) {
                fetchManagerSessionFactory.markOwnedIdentityAsNotUpToDate(
                    identityAndUid.identity,
                    OwnedIdentitySynchronizationStatus.OTHER_SYNC_IN_PROGRESS
                )
                downloadMessagesAndListAttachmentsDelegate.downloadMessagesAndListAttachments(
                    identityAndUid.identity,
                    identityAndUid.uid
                )
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    fun getOwnedIdentityFromMaskingUid(androidMaskingUidString: String?): Identity? {
        if (androidMaskingUidString != null) {
            try {
                val androidIdentityMaskingUid = UID(androidMaskingUidString)
                val identityAndUid = androidIdentityMaskingUids.get(androidIdentityMaskingUid)
                if (identityAndUid != null) {
                    return identityAndUid.identity
                }
            } catch (e: Exception) {
                Logger.x(e)
            }
        }
        return null
    }

    private fun storeAndroidIdentityMaskingUid(
        identity: Identity,
        deviceUid: UID,
        identityMaskingUid: UID?
    ) {
        androidIdentityMaskingUids.put(identityMaskingUid, IdentityAndUid(identity, deviceUid))
    }


    fun retryScheduledNetworkTasks() {
        scheduler.retryScheduledRunnables()
    }

    internal inner class ServerSessionCreatedNotificationListener : NotificationListener {
        override fun callback(notificationName: String?, userInfo: Map<String, Any>?) {
            if (notificationName != DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED) {
                return
            }
            val identityObject =
                userInfo?.get(DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED_IDENTITY_KEY)
            if (identityObject !is Identity) {
                return
            }

            // always do a register after a new client session, we no longer keep a list a awaiting identities
            queueNewRegisterPushNotificationOperation(identityObject)
        }
    }
}
