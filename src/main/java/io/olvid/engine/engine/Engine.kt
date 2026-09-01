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
package io.olvid.engine.engine

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.backup.BackupManager
import io.olvid.engine.channel.ChannelManager
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.crypto.Signature
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.BackupSeed
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.OperationQueue
import io.olvid.engine.datatypes.PushNotificationTypeAndParameters
import io.olvid.engine.datatypes.PushNotificationTypeAndParameters.Companion.createDaemon
import io.olvid.engine.datatypes.PushNotificationTypeAndParameters.Companion.createFirebaseAndroid
import io.olvid.engine.datatypes.PushNotificationTypeAndParameters.Companion.createLinux
import io.olvid.engine.datatypes.PushNotificationTypeAndParameters.Companion.createWebsocketOnlyAndroid
import io.olvid.engine.datatypes.PushNotificationTypeAndParameters.Companion.createWindows
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.SessionCommitListener
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelApplicationMessageToSend
import io.olvid.engine.datatypes.containers.ChannelDialogMessageToSend
import io.olvid.engine.datatypes.containers.ChannelDialogResponseMessageToSend
import io.olvid.engine.datatypes.containers.DialogType
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.containers.GroupV2.IdentityAndPermissions
import io.olvid.engine.datatypes.containers.IdentityWithSerializedDetails
import io.olvid.engine.datatypes.containers.ServerQuery
import io.olvid.engine.datatypes.containers.ServerQuery.BackupsV2DownloadProfilePictureQuery
import io.olvid.engine.datatypes.containers.ServerQuery.KeycloakIdBasedAuthGetSessionQuery
import io.olvid.engine.datatypes.containers.ServerQuery.KeycloakIdBasedAuthRequestChallengeQuery
import io.olvid.engine.datatypes.containers.ServerQuery.OwnedDeviceDiscoveryQuery
import io.olvid.engine.datatypes.containers.ServerQuery.RegisterApiKeyQuery
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesMDCKeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaMDCKeyPair
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.datatypes.notifications.BackupNotifications
import io.olvid.engine.datatypes.notifications.ProtocolNotifications
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.databases.EngineDbSchemaVersion
import io.olvid.engine.engine.databases.UserInterfaceDialog
import io.olvid.engine.engine.datatypes.EngineSession
import io.olvid.engine.engine.datatypes.EngineSessionFactory
import io.olvid.engine.engine.datatypes.UserInterfaceDialogListener
import io.olvid.engine.engine.types.EngineAPI
import io.olvid.engine.engine.types.EngineAPI.ListenerPriority
import io.olvid.engine.engine.types.EngineDbQueryStatisticsEntry
import io.olvid.engine.engine.types.EngineNotificationListener
import io.olvid.engine.engine.types.EngineNotifications
import io.olvid.engine.engine.types.JsonGroupDetails
import io.olvid.engine.engine.types.JsonGroupDetailsWithVersionAndPhoto
import io.olvid.engine.engine.types.JsonIdentityDetails
import io.olvid.engine.engine.types.JsonIdentityDetailsWithVersionAndPhoto
import io.olvid.engine.engine.types.JsonOsmStyle
import io.olvid.engine.engine.types.ObvAttachment
import io.olvid.engine.engine.types.ObvBackupKeyInformation
import io.olvid.engine.engine.types.ObvBackupKeyVerificationOutput
import io.olvid.engine.engine.types.ObvBytesKey
import io.olvid.engine.engine.types.ObvCapability
import io.olvid.engine.engine.types.ObvContactDeviceCount
import io.olvid.engine.engine.types.ObvContactInfo
import io.olvid.engine.engine.types.ObvDeviceBackupForRestore
import io.olvid.engine.engine.types.ObvDeviceList
import io.olvid.engine.engine.types.ObvDeviceManagementRequest
import io.olvid.engine.engine.types.ObvDialog
import io.olvid.engine.engine.types.ObvKeycloakIdBasedAuthResult
import io.olvid.engine.engine.types.ObvKeycloakIdBasedAuthResult.GetSessionResponse
import io.olvid.engine.engine.types.ObvMessage
import io.olvid.engine.engine.types.ObvOutboundAttachment
import io.olvid.engine.engine.types.ObvPostMessageOutput
import io.olvid.engine.engine.types.ObvProfileBackupsForRestore
import io.olvid.engine.engine.types.ObvPushNotificationType
import io.olvid.engine.engine.types.ObvReturnReceipt
import io.olvid.engine.engine.types.RegisterApiKeyResult
import io.olvid.engine.engine.types.identities.ObvContactActiveOrInactiveReason
import io.olvid.engine.engine.types.identities.ObvGroup
import io.olvid.engine.engine.types.identities.ObvGroupV2
import io.olvid.engine.engine.types.identities.ObvGroupV2.ObvGroupV2ChangeSet
import io.olvid.engine.engine.types.identities.ObvGroupV2.ObvGroupV2DetailsAndPhotos
import io.olvid.engine.engine.types.identities.ObvIdentity
import io.olvid.engine.engine.types.identities.ObvKeycloakAuthType
import io.olvid.engine.engine.types.identities.ObvKeycloakAuthType.IdBased
import io.olvid.engine.engine.types.identities.ObvKeycloakState
import io.olvid.engine.engine.types.identities.ObvMutualScanUrl
import io.olvid.engine.engine.types.identities.ObvOwnedDevice
import io.olvid.engine.engine.types.identities.ObvTrustOrigin
import io.olvid.engine.engine.types.sync.ObvBackupAndSyncDelegate
import io.olvid.engine.engine.types.sync.ObvBackupAndSyncDelegate.RestoreFinishedCallback
import io.olvid.engine.engine.types.sync.ObvSyncAtom
import io.olvid.engine.engine.types.sync.ObvSyncSnapshot
import io.olvid.engine.identity.IdentityManager
import io.olvid.engine.identity.databases.sync.IdentityManagerSyncSnapshot
import io.olvid.engine.metamanager.CreateSessionDelegate
import io.olvid.engine.metamanager.EngineOwnedIdentityCleanupDelegate
import io.olvid.engine.metamanager.MetaManager
import io.olvid.engine.networkfetch.FetchManager
import io.olvid.engine.networkfetch.datatypes.DownloadAttachmentPriorityCategory
import io.olvid.engine.networkfetch.operations.StandaloneServerQueryOperation
import io.olvid.engine.networksend.SendManager
import io.olvid.engine.notification.NotificationManager
import io.olvid.engine.protocol.ProtocolManager
import java.io.File
import java.io.IOException
import java.lang.ref.WeakReference
import java.nio.charset.StandardCharsets
import java.sql.SQLException
import java.util.EnumSet
import java.util.Map
import java.util.UUID
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingDeque
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SSLSocketFactory
import org.jose4j.jwk.JsonWebKey

class Engine(
    config: EngineConfiguration
) : UserInterfaceDialogListener, EngineSessionFactory, EngineAPI,
    EngineOwnedIdentityCleanupDelegate {

    // region fields
    private var instanceCounter: Long
    private val listeners: HashMap<String?, HashMap<Long?, ListenerAndPriority?>?>
    private val listenersLock: ReentrantLock
    private val notificationQueue: BlockingQueue<EngineNotification>

    private val prng: PRNGService
    @JvmField val jsonObjectMapper: ObjectMapper


    private val dbPath: String

    @Suppress("unused")
    private val dbKey: String?
    private val sslSocketFactory: SSLSocketFactory?
    private val userAgentOverride: String?
    private val createSessionDelegate: CreateSessionDelegate
    private val appBackupAndSyncDelegate: ObvBackupAndSyncDelegate?

    @JvmField val channelManager: ChannelManager
    @JvmField val identityManager: IdentityManager
    @JvmField val fetchManager: FetchManager
    @JvmField val sendManager: SendManager
    @JvmField val notificationManager: NotificationManager
    @JvmField val protocolManager: ProtocolManager
    @JvmField val backupManager: BackupManager
    @JvmField val notificationWorker: NotificationWorker

    override fun startProcessing() {
        fetchManager.startProcessing()
        sendManager.startProcessing()
        protocolManager.startProcessing()
    }

    private fun initializationComplete() {
        try {
            // clear all transfer protocol UserInterfaceDialog
            getSession().use { engineSession ->
                for (userInterfaceDialog in UserInterfaceDialog.getAll(engineSession)) {
                    try {
                        if (userInterfaceDialog.getObvDialog().getCategory()
                                .getId() == ObvDialog.Category.TRANSFER_DIALOG_CATEGORY
                        ) {
                            userInterfaceDialog.delete()
                        }
                    } catch (e: Exception) {
                        Logger.x(e)
                        try {
                            userInterfaceDialog.delete()
                        } catch (_: Exception) { }
                    }
                }
                engineSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    private fun deleteRecursive(fileOrDirectory: File?) {
        if (fileOrDirectory == null) {
            return
        }
        if (fileOrDirectory.isDirectory()) {
            val children = fileOrDirectory.listFiles()
            if (children != null) {
                for (child in children) {
                    deleteRecursive(child)
                }
            }
        }
        fileOrDirectory.delete()
    }


    // region External Notifications
    override fun addNotificationListener(
        notificationName: String?,
        engineNotificationListener: EngineNotificationListener?
    ) {
        addNotificationListener(
            notificationName,
            engineNotificationListener,
            ListenerPriority.NORMAL
        )
    }

    override fun addNotificationListener(
        notificationName: String?,
        engineNotificationListener: EngineNotificationListener?,
        priority: ListenerPriority?
    ) {
        listenersLock.lock()
        val listenerNumber: Long
        if (engineNotificationListener!!.hasEngineNotificationListenerRegistrationNumber()) {
            listenerNumber =
                engineNotificationListener.getEngineNotificationListenerRegistrationNumber()
        } else {
            listenerNumber = instanceCounter
            instanceCounter++
            engineNotificationListener.setEngineNotificationListenerRegistrationNumber(
                listenerNumber
            )
        }
        var notificationObservers = listeners.get(notificationName)
        if (notificationObservers == null) {
            notificationObservers = HashMap<Long?, ListenerAndPriority?>()
            listeners.put(notificationName, notificationObservers)
        }
        val weakReference = WeakReference<EngineNotificationListener?>(engineNotificationListener)
        notificationObservers.put(listenerNumber, ListenerAndPriority(weakReference, priority))
        listenersLock.unlock()
    }


    override fun removeNotificationListener(
        notificationName: String?,
        engineNotificationListener: EngineNotificationListener?
    ) {
        if (engineNotificationListener != null && engineNotificationListener.hasEngineNotificationListenerRegistrationNumber()) {
            removeNotificationListener(
                notificationName,
                engineNotificationListener.getEngineNotificationListenerRegistrationNumber()
            )
        }
    }

    override fun startSendingNotifications() {
        notificationWorker.start()
    }

    override fun stopSendingNotifications() {
        notificationWorker.stop()
    }

    override fun runTaskOnEngineNotificationQueue(runnable: Runnable?) {
        val userInfo = HashMap<String, Any?>()
        userInfo.put(SYNCHRONIZED_TASK, runnable)
        postEngineNotification(SYNCHRONIZED_TASK, userInfo)
    }

    private fun removeNotificationListener(
        notificationName: String?,
        notificationListenerRegistrationNumber: Long
    ) {
        listenersLock.lock()
        val notificationObservers = listeners.get(notificationName)
        if (notificationObservers != null) {
            notificationObservers.remove(notificationListenerRegistrationNumber)
        }
        listenersLock.unlock()
    }


    fun postEngineNotification(notificationName: String, userInfo: HashMap<String, Any?>) {
        Logger.d("Posting engine notification with name " + notificationName)
        try {
            notificationQueue.put(EngineNotification(notificationName, userInfo))
        } catch (e: InterruptedException) {
            Logger.x(e)
        }
    }

    inner class NotificationWorker {
        private var started = false
        private var thread: Thread? = null

        @Synchronized
        fun start() {
            if (started) {
                return
            }
            started = true
            thread = Thread {
                while (started) {
                    var engineNotification: EngineNotification? = null
                    try {
                        engineNotification = notificationQueue.take()
                    } catch (e: InterruptedException) {
                        Logger.x(e)
                    }
                    if (engineNotification == null) {
                        continue
                    }

                    if (engineNotification.notificationName == SYNCHRONIZED_TASK) {
                        try {
                            val task = engineNotification.userInfo.get(SYNCHRONIZED_TASK)
                            if (task is Runnable) {
                                task.run()
                            }
                        } catch (e: Exception) {
                            Logger.e("Exception while running App task on engine notification queue")
                            Logger.x(e)
                        }
                        continue
                    }
                    listenersLock.lock()
                    var notificationObservers = listeners.get(engineNotification.notificationName)
                    if (notificationObservers != null) {
                        notificationObservers =
                            HashMap<Long?, ListenerAndPriority?>(notificationObservers) // we clone the HashMap to make sure that, even outside the lock, we can iterate on the HashMap
                        listenersLock.unlock()

                        if (notificationObservers.size < 2) {
                            // if there is only one listener, do not bother with priorities!
                            for (entry in notificationObservers.entries) {
                                val listener = entry.value!!.listener.get()
                                if (listener == null) { // remove the listener
                                    removeNotificationListener(
                                        engineNotification.notificationName,
                                        entry.key!!
                                    )
                                } else { // call callback method
                                    try {
                                        listener.callback(
                                            engineNotification.notificationName,
                                            engineNotification.userInfo
                                        )
                                    } catch (e: Exception) {
                                        Logger.x(e)
                                    }
                                }
                            }
                        } else {
                            // first notify high priority listeners
                            for (priority in arrayOf<ListenerPriority>(
                                ListenerPriority.HIGH,
                                ListenerPriority.NORMAL,
                                ListenerPriority.LOW
                            )) {
                                for (entry in notificationObservers.entries) {
                                    if (entry.value!!.priority == priority) {
                                        val listener = entry.value!!.listener.get()
                                        if (listener == null) { // remove the listener
                                            removeNotificationListener(
                                                engineNotification.notificationName,
                                                entry.key!!
                                            )
                                        } else { // call callback method
                                            try {
                                                listener.callback(
                                                    engineNotification.notificationName,
                                                    engineNotification.userInfo
                                                )
                                            } catch (e: Exception) {
                                                Logger.x(e)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        listenersLock.unlock()
                    }
                }
            }
            thread!!.setName("Engine-EngineNotificationPosting")
            thread!!.start()
        }

        @Synchronized
        fun stop() {
            if (!started) {
                return
            }
            started = false
            if (thread != null) {
                thread!!.interrupt()
                thread = null
            }
        }

    }

    private class EngineNotification(notificationName: String, userInfo: HashMap<String, Any?>) {
        @JvmField val notificationName: String
        val userInfo: HashMap<String, Any?>

        init {
            this.notificationName = notificationName
            this.userInfo = userInfo
        }
    }


    private class ListenerAndPriority(
        listener: WeakReference<EngineNotificationListener?>,
        priority: ListenerPriority?
    ) {
        @JvmField val listener: WeakReference<EngineNotificationListener?>
        @JvmField val priority: ListenerPriority?

        init {
            this.listener = listener
            this.priority = priority
        }
    }

    // endregion
    // region Internal Notifications Listener
    private var notificationListenerChannelsAndProtocols: NotificationListenerChannelsAndProtocols? =
        null
    private var notificationListenerDownloads: NotificationListenerDownloads? = null
    private var notificationListenerIdentity: NotificationListenerIdentity? = null
    private var notificationListenerGroups: NotificationListenerGroups? = null
    private var notificationListenerGroupsV2: NotificationListenerGroupsV2? = null
    private var notificationListenerUploads: NotificationListenerUploads? = null
    private var notificationListenerBackups: NotificationListenerBackups? = null

    // endregion
    init {
        val baseDirectory = config.baseDirectory
        var dbKey = config.dbKey
        val appBackupAndSyncDelegate = config.appBackupAndSyncDelegate
        val sslSocketFactory = config.sslSocketFactory
        val userAgentOverride = config.userAgentOverride
        val logOutputter = config.logOutputter
        val logLevel = config.logLevel
        val sendMessageThreadCount = config.sendMessageThreadCount
        val sendReturnReceiptThreadCount = config.sendReturnReceiptThreadCount
        val fileIo = config.fileIo
        instanceCounter = 0
        listeners = HashMap<String?, HashMap<Long?, ListenerAndPriority?>?>()
        listenersLock = ReentrantLock()
        notificationQueue = LinkedBlockingDeque<EngineNotification>(100000)
        notificationWorker = NotificationWorker()

        Logger.setOutputter(logOutputter)
        Logger.setOutputLogLevel(logLevel)

        this.prng = Suite.getDefaultPRNGService(0)

        this.jsonObjectMapper = ObjectMapper()
        this.jsonObjectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL)

        val baseDirectoryPath = baseDirectory.getPath()

        this.dbPath = File(baseDirectory, Constants.ENGINE_DB_FILENAME).getPath()
        this.dbKey = dbKey
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride
        this.appBackupAndSyncDelegate = appBackupAndSyncDelegate

        val inboundAttachmentDirectory =
            File(baseDirectory, Constants.INBOUND_ATTACHMENTS_DIRECTORY)
        inboundAttachmentDirectory.mkdir()

        val identityPhotosDirectory = File(baseDirectory, Constants.IDENTITY_PHOTOS_DIRECTORY)
        identityPhotosDirectory.mkdir()

        val userDataDirectory = File(baseDirectory, Constants.DOWNLOADED_USER_DATA_DIRECTORY)
        userDataDirectory.mkdir()


        // check whether the database is already encrypted with dbKey
        if (dbKey != null && !Session.databaseIsReadable(dbPath, dbKey)) {
            // database may not yet be encrypted, try to encrypt it
            try {
                Logger.i("Engine database may need to be encrypted")
                val startTime = System.currentTimeMillis()

                val dbFile = File(baseDirectory, Constants.ENGINE_DB_FILENAME)
                val tmpEncryptedDbFile =
                    File(baseDirectory, Constants.TMP_ENGINE_ENCRYPTED_DB_FILENAME)
                if (tmpEncryptedDbFile.exists()) {
                    tmpEncryptedDbFile.delete()
                }

                Session.getUpgradeTablesSession(dbPath, null).use { session ->
                    session.createStatement().use { statement ->
                        statement.execute("ATTACH DATABASE '" + tmpEncryptedDbFile.getPath() + "' AS encrypted KEY \"" + dbKey + "\";")
                        statement.execute("SELECT sqlcipher_export('encrypted');")
                        statement.execute("DETACH DATABASE encrypted;")
                    }
                }
                val deleted = dbFile.delete()
                if (deleted) {
                    val renamed = tmpEncryptedDbFile.renameTo(dbFile)
                    if (renamed) {
                        Logger.i("Engine database encryption successful (took " + (System.currentTimeMillis() - startTime) + "ms)")
                    } else {
                        // If we reach this, data is probably lost...
                        Logger.e("Engine database encryption error: Unable to rename encrypted database!")
                    }
                } else {
                    throw RuntimeException("Engine database encryption error: unable to delete unencrypted database!")
                }
            } catch (_: Exception) {
                // database is encrypted but not with the provided dbKey, or database encryption failed --> try disabling encryption to use a plain database
                Logger.e("Engine database encryption failed, falling back to un-encrypted database")
                dbKey = null
            }
        }


        // check whether a database upgrade is required
        try {
            Session.getUpgradeTablesSession(dbPath, dbKey).use { session ->
                session.startTransaction()
                EngineDbSchemaVersion.createTable(session)
                session.commit()
                val engineDbSchemaVersion: EngineDbSchemaVersion? =
                    EngineDbSchemaVersion.get(wrapSession(session))
                if (engineDbSchemaVersion == null) {
                    throw SQLException()
                }
                if (engineDbSchemaVersion.getVersion() != Constants.CURRENT_ENGINE_DB_SCHEMA_VERSION) {
                    Logger.w("WARNING ENGINE DB SCHEMA VERSION CHANGED FROM " + engineDbSchemaVersion.getVersion() + " TO " + Constants.CURRENT_ENGINE_DB_SCHEMA_VERSION)
                    for (version in engineDbSchemaVersion.getVersion()..<Constants.CURRENT_ENGINE_DB_SCHEMA_VERSION) {
                        if (version == 15) { // the migration from 15 to 16 changes the path format of inboundAttachments, we delete them and reset their progress
                            deleteRecursive(inboundAttachmentDirectory)
                            inboundAttachmentDirectory.mkdir()
                        }
                        session.startTransaction()
                        Logger.w("WARNING    -  STEP VERSION " + version + " TO " + (version + 1))
                        upgradeTables(session, version, version + 1)
                        ChannelManager.upgradeTables(session, version, version + 1)
                        IdentityManager.upgradeTables(session, version, version + 1)
                        FetchManager.upgradeTables(session, version, version + 1)
                        SendManager.upgradeTables(session, version, version + 1)
                        ProtocolManager.upgradeTables(session, version, version + 1)
                        BackupManager.upgradeTables(session, version, version + 1)
                        engineDbSchemaVersion.update(version + 1)
                        session.commit()
                    }
                }
            }
        } catch (e: SQLException) {
            Logger.x(e)
            throw RuntimeException("Unable to check for tables upgrade", e)
        }


        val metaManager = MetaManager()
        val finalDbKey = dbKey
        this.createSessionDelegate = object : CreateSessionDelegate {
            override val session: Session
                get() = Session.getSession(dbPath, finalDbKey)
        }
        metaManager.registerImplementedDelegates(this.createSessionDelegate)
        metaManager.registerImplementedDelegates(this)

        try {
            getSession().use { engineSession ->
                UserInterfaceDialog.createTable(engineSession.session)
                engineSession.session.commit()
            }
        } catch (e: SQLException) {
            Logger.x(e)
            throw RuntimeException("Unable to create engine databases")
        }

        this.channelManager = ChannelManager(metaManager)
        this.identityManager =
            IdentityManager(metaManager, baseDirectoryPath, fileIo, jsonObjectMapper, prng)
        this.fetchManager = FetchManager(
            metaManager,
            sslSocketFactory,
            userAgentOverride,
            baseDirectoryPath,
            fileIo,
            prng,
            jsonObjectMapper
        )
        this.sendManager =
            SendManager(
                metaManager,
                sslSocketFactory,
                userAgentOverride,
                baseDirectoryPath,
                fileIo,
                prng,
                sendMessageThreadCount,
                sendReturnReceiptThreadCount
            )
        this.notificationManager = NotificationManager(metaManager)
        this.protocolManager = ProtocolManager(
            metaManager,
            appBackupAndSyncDelegate,
            baseDirectoryPath,
            fileIo,
            prng,
            jsonObjectMapper
        )
        this.backupManager = BackupManager(
            metaManager,
            appBackupAndSyncDelegate,
            sslSocketFactory,
            userAgentOverride,
            prng,
            jsonObjectMapper
        )

        registerToInternalNotifications()
        initializationComplete()
        metaManager.initializationComplete()
    }

    private fun registerToInternalNotifications() {
        notificationListenerChannelsAndProtocols = NotificationListenerChannelsAndProtocols(this)
        notificationListenerChannelsAndProtocols!!.registerToNotifications(this.notificationManager)

        notificationListenerDownloads = NotificationListenerDownloads(this)
        notificationListenerDownloads!!.registerToNotifications(this.notificationManager)

        notificationListenerIdentity = NotificationListenerIdentity(this)
        notificationListenerIdentity!!.registerToNotifications(this.notificationManager)

        notificationListenerIdentity = NotificationListenerIdentity(this)
        notificationListenerIdentity!!.registerToNotifications(this.notificationManager)

        notificationListenerGroups = NotificationListenerGroups(this)
        notificationListenerGroups!!.registerToNotifications(this.notificationManager)

        notificationListenerGroupsV2 = NotificationListenerGroupsV2(this)
        notificationListenerGroupsV2!!.registerToNotifications(this.notificationManager)

        notificationListenerUploads = NotificationListenerUploads(this)
        notificationListenerUploads!!.registerToNotifications(this.notificationManager)

        notificationListenerBackups = NotificationListenerBackups(this)
        notificationListenerBackups!!.registerToNotifications(this.notificationManager)
    }

    // endregion
    // region EngineSessionFactory
    @Throws(SQLException::class)
    override fun getSession(): EngineSession {
        return EngineSession(createSessionDelegate.session, this, jsonObjectMapper)
    }

    fun wrapSession(session: Session): EngineSession {
        return EngineSession(session, this, jsonObjectMapper)
    }

    // endregion
    // region UserInterfaceDialogListener
    override fun sendUserInterfaceDialogNotification(
        uuid: UUID?,
        dialog: ObvDialog?,
        creationTimestamp: Long
    ) {
        val userInfo = HashMap<String, Any?>()
        userInfo[EngineNotifications.UI_DIALOG_UUID_KEY] = uuid
        userInfo[EngineNotifications.UI_DIALOG_DIALOG_KEY] = dialog
        userInfo[EngineNotifications.UI_DIALOG_CREATION_TIMESTAMP_KEY] = creationTimestamp
        postEngineNotification(EngineNotifications.UI_DIALOG, userInfo)
    }

    override fun sendUserInterfaceDialogDeletionNotification(uuid: UUID?) {
        val userInfo = HashMap<String, Any?>()
        userInfo[EngineNotifications.UI_DIALOG_DELETED_UUID_KEY] = uuid
        postEngineNotification(EngineNotifications.UI_DIALOG_DELETED, userInfo)
    }

    fun createDialog(channelDialogMessageToSend: ChannelDialogMessageToSend): ObvDialog? {
        val category: ObvDialog.Category?
        val ownedIdentity = channelDialogMessageToSend.sendChannelInfo!!.getToIdentity()

        val dialogType = channelDialogMessageToSend.sendChannelInfo.getDialogType()
        when (dialogType!!.id) {
            DialogType.INVITE_SENT_DIALOG_ID -> {
                category = ObvDialog.Category.createInviteSent(
                    dialogType.contactIdentity!!.getBytes(),
                    dialogType.contactDisplayNameOrSerializedDetails
                )
            }

            DialogType.ACCEPT_INVITE_DIALOG_ID -> {
                category = ObvDialog.Category.createAcceptInvite(
                    dialogType.contactIdentity!!.getBytes(),
                    dialogType.contactDisplayNameOrSerializedDetails,
                    dialogType.serverTimestamp
                )
            }

            DialogType.SAS_EXCHANGE_DIALOG_ID -> {
                category = ObvDialog.Category.createSasExchange(
                    dialogType.contactIdentity!!.getBytes(),
                    dialogType.contactDisplayNameOrSerializedDetails,
                    dialogType.sasToDisplay,
                    dialogType.serverTimestamp
                )
            }

            DialogType.SAS_CONFIRMED_DIALOG_ID -> {
                category = ObvDialog.Category.createSasConfirmed(
                    dialogType.contactIdentity!!.getBytes(),
                    dialogType.contactDisplayNameOrSerializedDetails,
                    dialogType.sasToDisplay,
                    dialogType.sasEntered
                )
            }

            DialogType.INVITE_ACCEPTED_DIALOG_ID -> {
                category = ObvDialog.Category.createInviteAccepted(
                    dialogType.contactIdentity!!.getBytes(),
                    dialogType.contactDisplayNameOrSerializedDetails
                )
            }

            DialogType.ACCEPT_MEDIATOR_INVITE_DIALOG_ID -> {
                var bytesMediatorIdentity: ByteArray? = null
                if (dialogType.mediatorOrGroupOwnerIdentity != null) {
                    bytesMediatorIdentity = dialogType.mediatorOrGroupOwnerIdentity.getBytes()
                }
                category = ObvDialog.Category.createAcceptMediatorInvite(
                    dialogType.contactIdentity!!.getBytes(),
                    dialogType.contactDisplayNameOrSerializedDetails,
                    bytesMediatorIdentity,
                    dialogType.serverTimestamp
                )
            }

            DialogType.MEDIATOR_INVITE_ACCEPTED_DIALOG_ID -> {
                var bytesMediatorIdentity: ByteArray? = null
                if (dialogType.mediatorOrGroupOwnerIdentity != null) {
                    bytesMediatorIdentity = dialogType.mediatorOrGroupOwnerIdentity.getBytes()
                }
                category = ObvDialog.Category.createMediatorInviteAccepted(
                    dialogType.contactIdentity!!.getBytes(),
                    dialogType.contactDisplayNameOrSerializedDetails,
                    bytesMediatorIdentity
                )
            }

            DialogType.ACCEPT_GROUP_INVITE_DIALOG_ID -> {
                var bytesGroupOwnedIdentity: ByteArray? = null
                if (dialogType.mediatorOrGroupOwnerIdentity != null) {
                    bytesGroupOwnedIdentity = dialogType.mediatorOrGroupOwnerIdentity.getBytes()
                }
                val pendingGroupMemberIdentities =
                    arrayOfNulls<ObvIdentity>(dialogType.pendingGroupMemberIdentities!!.size)
                var i = 0
                while (i < pendingGroupMemberIdentities.size) {
                    try {
                        val identityDetails = jsonObjectMapper.readValue<JsonIdentityDetails?>(
                            dialogType.pendingGroupMemberSerializedDetails!![i],
                            JsonIdentityDetails::class.java
                        )
                        pendingGroupMemberIdentities[i] = ObvIdentity(
                            dialogType.pendingGroupMemberIdentities[i]!!,
                            identityDetails,
                            false,
                            true
                        )
                    } catch (_: Exception) {
                        break
                    }
                    i++
                }
                category = ObvDialog.Category.createAcceptGroupInvite(
                    dialogType.serializedGroupDetails,
                    dialogType.groupUid!!.bytes,
                    bytesGroupOwnedIdentity,
                    pendingGroupMemberIdentities,
                    dialogType.serverTimestamp
                )
            }

            DialogType.ONE_TO_ONE_INVITATION_SENT_DIALOG_ID -> {
                category =
                    ObvDialog.Category.createOneToOneInvitationSent(dialogType.contactIdentity!!.getBytes())
            }

            DialogType.ACCEPT_ONE_TO_ONE_INVITATION_DIALOG_ID -> {
                category = ObvDialog.Category.createAcceptOneToOneInvitation(
                    dialogType.contactIdentity!!.getBytes(),
                    dialogType.serverTimestamp
                )
            }

            DialogType.ACCEPT_GROUP_V2_INVITATION_DIALOG_ID -> {
                category = ObvDialog.Category.createGroupV2Invitation(
                    dialogType.mediatorOrGroupOwnerIdentity!!.getBytes(),
                    dialogType.obvGroupV2
                )
            }

            DialogType.GROUP_V2_FROZEN_INVITATION_DIALOG_ID -> {
                category = ObvDialog.Category.createGroupV2FrozenInvitation(
                    dialogType.mediatorOrGroupOwnerIdentity!!.getBytes(),
                    dialogType.obvGroupV2
                )
            }

            DialogType.SYNC_ITEM_TO_APPLY_DIALOG_ID -> {
                category =
                    ObvDialog.Category.createSyncItemToApply(dialogType.obvSyncAtom)
            }

            DialogType.TRANSFER_DIALOG_ID -> {
                category =
                    ObvDialog.Category.createTransferDialog(dialogType.obvTransferStep)
            }

            else -> {
                Logger.w("Unknown DialogType " + dialogType.id)
                return null
            }
        }
        return ObvDialog(
            channelDialogMessageToSend.getUuid(),
            channelDialogMessageToSend.getEncodedElements(),
            ownedIdentity!!.getBytes(),
            category
        )
    }

    // endregion
    // region EngineOwnedIdentityCleanupDelegate
    @Throws(Exception::class)
    override fun deleteOwnedIdentityFromInboxOutboxProtocolsAndDialogs(
        session: Session,
        ownedIdentity: Identity?,
        excludedProtocolInstanceUid: UID?
    ) {
        protocolManager.deleteOwnedIdentity(session, ownedIdentity!!, excludedProtocolInstanceUid)
        sendManager.deleteOwnedIdentity(session, ownedIdentity)
        // do not delete the server session if called with a non-null excludedProtocolInstanceUid
        //  --> this server session is used in the OwnedIdentityDeletionProtocol to run a server query
        fetchManager.deleteOwnedIdentity(
            session,
            ownedIdentity,
            excludedProtocolInstanceUid != null
        )

        for (userInterfaceDialog in UserInterfaceDialog.getAll(wrapSession(session))) {
            try {
                val obvDialog: ObvDialog = userInterfaceDialog.getObvDialog()
                if (obvDialog.getBytesOwnedIdentity().contentEquals(ownedIdentity.getBytes())) {
                    userInterfaceDialog.delete()
                }
            } catch (e: Exception) {
                Logger.x(e)
            }
        }
    }

    override fun deleteOwnedIdentityServerSession(session: Session, ownedIdentity: Identity?) {
        fetchManager.deleteExistingServerSession(session, ownedIdentity, false)
    }


    // endregion
    // region Public API
    // region Managing Owned Identities
    override fun getEngineDbQueryStatistics(): MutableMap<String, EngineDbQueryStatisticsEntry> {
        return Session.queryStatistics
    }

    override fun getServerOfIdentity(bytesIdentity: ByteArray?): String? {
        try {
            val identity = Identity.of(bytesIdentity!!)
            return identity.server
        } catch (_: DecodingException) {
            // nothing
        }
        return null
    }

    @Throws(Exception::class)
    override fun getOwnedIdentities(): Array<ObvIdentity> {
        getSession().use { engineSession ->
            val identities = identityManager.getOwnedIdentities(engineSession.session)
            return identities.map { ObvIdentity(engineSession.session, identityManager, it) }.toTypedArray()
        }
    }

    @Throws(Exception::class)
    override fun getOwnedIdentity(bytesOwnedIdentity: ByteArray?): ObvIdentity? {
        getSession().use { engineSession ->
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            val obvOwnedIdentity =
                ObvIdentity(engineSession.session, identityManager, ownedIdentity)
            if (obvOwnedIdentity.getIdentityDetails() != null) {
                return obvOwnedIdentity
            }
            return null
        }
    }

    override fun generateOwnedIdentity(
        server: String?,
        jsonIdentityDetails: JsonIdentityDetails?,
        keycloakState: ObvKeycloakState?,
        deviceDisplayName: String?
    ): ObvIdentity? {
        var server = server
        try {
            getSession().use { engineSession ->
                if (server == null) {
                    server = ""
                }
                val identity = identityManager.generateOwnedIdentity(
                    engineSession.session,
                    server,
                    jsonIdentityDetails,
                    keycloakState,
                    deviceDisplayName,
                    prng
                )
                if (identity == null) {
                    return null
                }

                val ownedIdentity =
                    ObvIdentity(identity, jsonIdentityDetails, keycloakState != null, true)
                engineSession.session.commit()
                return ownedIdentity
            }
        } catch (_: Exception) {
            return null
        }
    }


    override fun registerOwnedIdentityApiKeyOnServer(
        bytesOwnedIdentity: ByteArray?,
        apiKey: UUID?
    ): RegisterApiKeyResult {
        try {
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            val serverSessionToken = fetchManager.getServerAuthenticationToken(ownedIdentity)
            if (serverSessionToken == null) {
                fetchManager.createServerSession(ownedIdentity)
                return RegisterApiKeyResult.WAIT_FOR_SERVER_SESSION
            }

            val standaloneServerQueryOperation = StandaloneServerQueryOperation(
                ServerQuery(
                    null,
                    ownedIdentity,
                    RegisterApiKeyQuery(ownedIdentity, serverSessionToken, Logger.getUuidString(apiKey))
                ), sslSocketFactory, userAgentOverride
            )

            val queue = OperationQueue()
            queue.queue(standaloneServerQueryOperation)
            queue.execute(1, "Engine-registerOwnedIdentityApiKeyOnServer")
            queue.join()

            if (standaloneServerQueryOperation.isFinished) {
                recreateServerSession(bytesOwnedIdentity)
                return RegisterApiKeyResult.SUCCESS
            } else {
                if (standaloneServerQueryOperation.reasonForCancel != null) {
                    when (standaloneServerQueryOperation.reasonForCancel) {
                        StandaloneServerQueryOperation.RFC_INVALID_API_KEY -> {
                            return RegisterApiKeyResult.INVALID_KEY
                        }

                        StandaloneServerQueryOperation.RFC_INVALID_SERVER_SESSION -> {
                            recreateServerSession(bytesOwnedIdentity)
                            return RegisterApiKeyResult.WAIT_FOR_SERVER_SESSION
                        }

                        StandaloneServerQueryOperation.RFC_UNSUPPORTED_SERVER_QUERY_TYPE, StandaloneServerQueryOperation.RFC_NETWORK_ERROR -> {}
                        else -> {}
                    }
                }
                return RegisterApiKeyResult.FAILED
            }
        } catch (e: Exception) {
            Logger.x(e)
            return RegisterApiKeyResult.FAILED
        }
    }

    override fun updateKeycloakTransferRestrictedIfNeeded(
        bytesOwnedIdentity: ByteArray?,
        serverUrl: String?,
        transferRestricted: Boolean
    ) {
        try {
            getSession().use { engineSession ->
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                identityManager.updateKeycloakTransferRestrictedIfNeeded(
                    engineSession.session,
                    ownedIdentity,
                    serverUrl,
                    transferRestricted
                )
                engineSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    override fun updateKeycloakPushTopicsIfNeeded(
        bytesOwnedIdentity: ByteArray?,
        serverUrl: String?,
        pushTopics: MutableList<String?>?
    ) {
        try {
            getSession().use { engineSession ->
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                val updated = identityManager.updateKeycloakPushTopicsIfNeeded(
                    engineSession.session,
                    ownedIdentity,
                    serverUrl,
                    pushTopics
                )
                engineSession.session.commit()
                if (updated) {
                    fetchManager.forceRegisterPushNotification(ownedIdentity, false)
                }
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    override fun updateKeycloakRevocationList(
        bytesOwnedIdentity: ByteArray?,
        latestRevocationListTimestamp: Long,
        signedRevocations: MutableList<String?>?
    ) {
        try {
            getSession().use { engineSession ->
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                engineSession.session.startTransaction()
                identityManager.verifyAndAddRevocationList(
                    engineSession.session,
                    ownedIdentity,
                    signedRevocations
                )
                identityManager.setKeycloakLatestRevocationListTimestamp(
                    engineSession.session,
                    ownedIdentity,
                    latestRevocationListTimestamp
                )
                engineSession.session.commit()
                // commit once to get out of the transaction fast
                identityManager.unCertifyExpiredSignedContactDetails(
                    engineSession.session,
                    ownedIdentity,
                    latestRevocationListTimestamp
                )
                engineSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    override fun setOwnedIdentityKeycloakSelfRevocationTestNonce(
        bytesOwnedIdentity: ByteArray?,
        serverUrl: String?,
        nonce: String?
    ) {
        if (nonce == null) {
            return
        }
        try {
            getSession().use { engineSession ->
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                identityManager.setOwnedIdentityKeycloakSelfRevocationTestNonce(
                    engineSession.session,
                    ownedIdentity,
                    serverUrl,
                    nonce
                )
                engineSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    override fun getOwnedIdentityKeycloakSelfRevocationTestNonce(
        bytesOwnedIdentity: ByteArray?,
        serverUrl: String?
    ): String? {
        try {
            getSession().use { engineSession ->
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                return identityManager.getOwnedIdentityKeycloakSelfRevocationTestNonce(
                    engineSession.session,
                    ownedIdentity,
                    serverUrl
                )
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
        return null
    }

    // returns true if the update was successful
    override fun updateKeycloakGroups(
        bytesOwnedIdentity: ByteArray?,
        signedGroupBlobs: MutableList<String?>?,
        signedGroupDeletions: MutableList<String?>?,
        signedGroupKicks: MutableList<String?>?,
        keycloakCurrentTimestamp: Long
    ): Boolean {
        try {
            getSession().use { engineSession ->
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                var success = false
                try {
                    engineSession.session.startTransaction()
                    identityManager.updateKeycloakGroups(
                        engineSession.session,
                        ownedIdentity,
                        signedGroupBlobs,
                        signedGroupDeletions,
                        signedGroupKicks,
                        keycloakCurrentTimestamp
                    )
                    success = true
                } catch (e: Exception) {
                    Logger.x(e)
                } finally {
                    if (success) {
                        engineSession.session.commit()
                    } else {
                        engineSession.session.rollback()
                    }
                }
                return success
            }
        } catch (e: Exception) {
            Logger.x(e)
            return false
        }
    }

    override fun performKeycloakIdBasedAuth(bytesOwnedIdentity: ByteArray?): ObvKeycloakIdBasedAuthResult {
        try {
            getSession().use { engineSession ->
                Logger.i("Initiating Keycloak ID-based authentication")
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                val keycloakState = identityManager.getOwnedIdentityKeycloakState(
                    engineSession.session,
                    ownedIdentity
                )
                val keycloakUsedId = identityManager.getOwnedIdentityKeycloakUserId(
                    engineSession.session,
                    ownedIdentity
                )

                if (keycloakState == null || keycloakState.supportedAuthenticationMethods.stream()
                        .noneMatch { authType: ObvKeycloakAuthType? -> authType is IdBased }
                    || keycloakUsedId == null
                ) {
                    Logger.w("ID-based authentication failed: PERMANENT_ERROR")
                    return ObvKeycloakIdBasedAuthResult(ObvKeycloakIdBasedAuthResult.Status.PERMANENT_ERROR)
                }
                val nonce = prng.bytes(Constants.SERVER_SESSION_NONCE_LENGTH)
                var standaloneServerQueryOperation = StandaloneServerQueryOperation(
                    ServerQuery(
                        null,
                        ownedIdentity,
                        KeycloakIdBasedAuthRequestChallengeQuery(
                            keycloakState.keycloakServer,
                            keycloakUsedId,
                            nonce
                        )
                    ), sslSocketFactory, userAgentOverride
                )

                var queue = OperationQueue()
                queue.queue(standaloneServerQueryOperation)
                queue.execute(1, "Engine-queryKeycloakIdBasedAuthRequestChallengeQuery")
                queue.join()

                if (standaloneServerQueryOperation.isCancelled || standaloneServerQueryOperation.serverResponse == null) {
                    if (standaloneServerQueryOperation.reasonForCancel != null && standaloneServerQueryOperation.reasonForCancel == StandaloneServerQueryOperation.RFC_NETWORK_ERROR) {
                        Logger.w("ID-based authentication failed: NETWORK_ERROR")
                        return ObvKeycloakIdBasedAuthResult(ObvKeycloakIdBasedAuthResult.Status.NETWORK_ERROR)
                    }
                    Logger.w("ID-based authentication failed: ERROR")
                    return ObvKeycloakIdBasedAuthResult(ObvKeycloakIdBasedAuthResult.Status.ERROR)
                }

                val challenge = standaloneServerQueryOperation.serverResponse!!.decodeBytes()

                val challengeResponse = identityManager.signBlock(
                    engineSession.session,
                    Constants.SignatureContext.KEYCLOAK_ID_BASED_AUTH,
                    challenge,
                    ownedIdentity,
                    prng
                )

                standaloneServerQueryOperation = StandaloneServerQueryOperation(
                    ServerQuery(
                        null,
                        ownedIdentity,
                        KeycloakIdBasedAuthGetSessionQuery(
                            keycloakState.keycloakServer,
                            challengeResponse,
                            nonce
                        )
                    ), sslSocketFactory, userAgentOverride
                )

                queue = OperationQueue()
                queue.queue(standaloneServerQueryOperation)
                queue.execute(1, "Engine-queryKeycloakIdBasedAuthGetSessionQuery")
                queue.join()

                if (standaloneServerQueryOperation.isCancelled || standaloneServerQueryOperation.serverResponse == null) {
                    if (standaloneServerQueryOperation.reasonForCancel != null) {
                        when (standaloneServerQueryOperation.reasonForCancel) {
                            StandaloneServerQueryOperation.RFC_NETWORK_ERROR -> return ObvKeycloakIdBasedAuthResult(
                                ObvKeycloakIdBasedAuthResult.Status.NETWORK_ERROR
                            )

                            StandaloneServerQueryOperation.RFC_PERMISSION_DENIED -> return ObvKeycloakIdBasedAuthResult(
                                ObvKeycloakIdBasedAuthResult.Status.PERMANENT_ERROR
                            )

                            StandaloneServerQueryOperation.RFC_SERVER_PARSING_ERROR, StandaloneServerQueryOperation.RFC_INVALID_SERVER_SESSION -> {}
                        }
                    }
                    Logger.w("ID-based authentication failed: ERROR")
                    return ObvKeycloakIdBasedAuthResult(ObvKeycloakIdBasedAuthResult.Status.ERROR)
                }

                val serializedAuthSession =
                    standaloneServerQueryOperation.serverResponse!!.decodeBytes()
                val getSessionResponse = jsonObjectMapper.readValue<GetSessionResponse>(
                    serializedAuthSession,
                    GetSessionResponse::class.java
                )

                Logger.i("ID-based authentication success")
                return ObvKeycloakIdBasedAuthResult(
                    ObvKeycloakIdBasedAuthResult.Status.SUCCESS,
                    getSessionResponse.accessToken,
                    getSessionResponse.refreshToken,
                    getSessionResponse.clientId,
                    getSessionResponse.clientSecret
                )
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
        Logger.w("ID-based authentication failed: ERROR")
        return ObvKeycloakIdBasedAuthResult(ObvKeycloakIdBasedAuthResult.Status.ERROR)
    }

    override fun recreateServerSession(bytesOwnedIdentity: ByteArray?) {
        try {
            getSession().use { engineSession ->
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                fetchManager.deleteExistingServerSession(engineSession.session, ownedIdentity, true)
                engineSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    @Throws(Exception::class)
    override fun deleteOwnedIdentity(bytesOwnedIdentity: ByteArray?) {
        getSession().use { engineSession ->
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            engineSession.session.startTransaction()
            channelManager.deleteAllChannelsForOwnedIdentity(engineSession.session, ownedIdentity)
            identityManager.deleteOwnedIdentity(engineSession.session, ownedIdentity)

            deleteOwnedIdentityFromInboxOutboxProtocolsAndDialogs(
                engineSession.session,
                ownedIdentity,
                null
            )
            engineSession.session.commit()
        }
    }


    @Throws(Exception::class)
    override fun getOwnedIdentityPublishedAndLatestDetails(bytesOwnedIdentity: ByteArray?): Array<JsonIdentityDetailsWithVersionAndPhoto?>? {
        getSession().use { engineSession ->
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            return identityManager.getOwnedIdentityPublishedAndLatestDetails(
                engineSession.session,
                ownedIdentity
            )
        }
    }


    @Throws(Exception::class)
    override fun getOwnedIdentityKeycloakState(bytesOwnedIdentity: ByteArray?): ObvKeycloakState? {
        getSession().use { engineSession ->
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            return identityManager.getOwnedIdentityKeycloakState(
                engineSession.session,
                ownedIdentity
            )
        }
    }

    @Throws(Exception::class)
    override fun saveKeycloakAuthState(
        bytesOwnedIdentity: ByteArray?,
        serializedAuthState: String?
    ) {
        Logger.d("Saving keycloak authState in Engine")
        getSession().use { engineSession ->
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            identityManager.saveKeycloakAuthState(
                engineSession.session,
                ownedIdentity,
                serializedAuthState
            )
            engineSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun saveKeycloakJwks(bytesOwnedIdentity: ByteArray?, serializedJwks: String?) {
        getSession().use { engineSession ->
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            identityManager.saveKeycloakJwks(engineSession.session, ownedIdentity, serializedJwks)
            engineSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun saveKeycloakApiKey(bytesOwnedIdentity: ByteArray?, apiKey: String?) {
        getSession().use { engineSession ->
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            identityManager.saveKeycloakApiKey(engineSession.session, ownedIdentity, apiKey)
            engineSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun getOwnedIdentitiesWithKeycloakPushTopic(pushTopic: String?): MutableCollection<ObvIdentity> {
        getSession().use { engineSession ->
            return identityManager.getOwnedIdentitiesWithKeycloakPushTopic(
                engineSession.session,
                pushTopic
            )
        }
    }

    @Throws(Exception::class)
    override fun getOwnedIdentityKeycloakUserId(bytesOwnedIdentity: ByteArray?): String? {
        getSession().use { engineSession ->
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            return identityManager.getOwnedIdentityKeycloakUserId(
                engineSession.session,
                ownedIdentity
            )
        }
    }

    @Throws(Exception::class)
    override fun setOwnedIdentityKeycloakUserId(bytesOwnedIdentity: ByteArray?, userId: String?) {
        getSession().use { engineSession ->
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            identityManager.setOwnedIdentityKeycloakUserId(
                engineSession.session,
                ownedIdentity,
                userId
            )
            engineSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun getOwnedIdentityKeycloakSignatureKey(bytesOwnedIdentity: ByteArray?): JsonWebKey? {
        getSession().use { engineSession ->
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            return identityManager.getOwnedIdentityKeycloakSignatureKey(
                engineSession.session,
                ownedIdentity
            )
        }
    }

    @Throws(Exception::class)
    override fun setOwnedIdentityKeycloakSignatureKey(
        bytesOwnedIdentity: ByteArray?,
        signatureKey: JsonWebKey?
    ) {
        getSession().use { engineSession ->
            engineSession.session.startTransaction()
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            identityManager.setOwnedIdentityKeycloakSignatureKey(
                engineSession.session,
                ownedIdentity,
                signatureKey
            )
            identityManager.reCheckAllCertifiedByOwnKeycloakContacts(
                engineSession.session,
                ownedIdentity
            )
            engineSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun setOwnedIdentityKeycloakSupportsIdBasedAuth(
        bytesOwnedIdentity: ByteArray?,
        supportsIdBasedAuth: Boolean
    ) {
        getSession().use { engineSession ->
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            identityManager.setOwnedIdentityKeycloakSupportsIdBasedAuth(
                engineSession.session,
                ownedIdentity,
                supportsIdBasedAuth
            )
        }
    }

    override fun bindOwnedIdentityToKeycloak(
        bytesOwnedIdentity: ByteArray?,
        keycloakState: ObvKeycloakState?,
        keycloakUserId: String?
    ): ObvIdentity? {
        try {
            getSession().use { engineSession ->
                engineSession.session.startTransaction()
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                protocolManager.startProtocolForBindingOwnedIdentityToKeycloakWithinTransaction(
                    engineSession.session,
                    ownedIdentity,
                    keycloakState,
                    keycloakUserId
                )
                val obvIdentity = ObvIdentity(engineSession.session, identityManager, ownedIdentity)
                engineSession.session.commit()
                return obvIdentity
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
        return null
    }

    override fun unbindOwnedIdentityFromKeycloak(bytesOwnedIdentity: ByteArray?) {
        try {
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            protocolManager.startProtocolForUnbindingOwnedIdentityFromKeycloak(ownedIdentity)
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    @Throws(Exception::class)
    override fun registerToPushNotification(
        bytesOwnedIdentity: ByteArray?,
        pushNotificationType: ObvPushNotificationType?,
        reactivateCurrentDevice: Boolean,
        bytesDeviceUidToReplace: ByteArray?
    ) {
        getSession().use { engineSession ->
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            val currentDeviceUid = identityManager.getCurrentDeviceUidOfOwnedIdentity(
                engineSession.session,
                ownedIdentity
            )
            val deviceUidToReplace =
                if (bytesDeviceUidToReplace == null) null else UID(bytesDeviceUidToReplace)

            val pushNotificationTypeAndParameters: PushNotificationTypeAndParameters?
            when (pushNotificationType!!.platform) {
                ObvPushNotificationType.Platform.ANDROID -> {
                    if (pushNotificationType.firebaseToken == null) {
                        pushNotificationTypeAndParameters =
                            createWebsocketOnlyAndroid(reactivateCurrentDevice, deviceUidToReplace)
                    } else {
                        // We pick a random identityMaskingUid in case we need to register (only useful when configuration changed)
                        val identityMaskingUid = UID(prng)
                        val firebaseTokenBytes: ByteArray =
                            pushNotificationType.firebaseToken.toByteArray(
                                StandardCharsets.UTF_8
                            )
                        pushNotificationTypeAndParameters = createFirebaseAndroid(
                            firebaseTokenBytes,
                            identityMaskingUid,
                            reactivateCurrentDevice,
                            deviceUidToReplace
                        )
                    }
                }

                ObvPushNotificationType.Platform.WINDOWS -> {
                    pushNotificationTypeAndParameters =
                        createWindows(reactivateCurrentDevice, deviceUidToReplace)
                }

                ObvPushNotificationType.Platform.LINUX -> {
                    pushNotificationTypeAndParameters =
                        createLinux(reactivateCurrentDevice, deviceUidToReplace)
                }

                ObvPushNotificationType.Platform.DAEMON -> {
                    pushNotificationTypeAndParameters =
                        createDaemon(reactivateCurrentDevice, deviceUidToReplace)
                }

                else -> {
                    Logger.e("Engine.registerToPushNotification: unknown pushNotificationType.platform")
                    throw Exception()
                }
            }
            engineSession.session.startTransaction()
            fetchManager.registerPushNotificationIfConfigurationChanged(
                engineSession.session,
                ownedIdentity,
                currentDeviceUid,
                pushNotificationTypeAndParameters
            )
            engineSession.session.commit()
        }
    }


    override fun processAndroidPushNotification(maskingUidString: String?) {
        fetchManager.processAndroidPushNotification(maskingUidString)
    }

    override fun getOwnedIdentityFromMaskingUid(maskingUidString: String?): ByteArray? {
        val ownedIdentity = fetchManager.getOwnedIdentityFromMaskingUid(maskingUidString)
        if (ownedIdentity != null) {
            return ownedIdentity.getBytes()
        }
        return null
    }

    @Throws(Exception::class)
    override fun processDeviceManagementRequest(
        bytesOwnedIdentity: ByteArray?,
        deviceManagementRequest: ObvDeviceManagementRequest?
    ) {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        getSession().use { engineSession ->
            protocolManager.processDeviceManagementRequest(
                engineSession.session,
                ownedIdentity,
                deviceManagementRequest
            )
            engineSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun updateLatestIdentityDetails(
        bytesOwnedIdentity: ByteArray?,
        jsonIdentityDetails: JsonIdentityDetails?
    ) {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        getSession().use { engineSession ->
            engineSession.session.startTransaction()
            identityManager.updateLatestIdentityDetails(
                engineSession.session,
                ownedIdentity,
                jsonIdentityDetails
            )
            engineSession.session.commit()
        }
    }

    override fun discardLatestIdentityDetails(bytesOwnedIdentity: ByteArray?) {
        try {
            getSession().use { engineSession ->
                engineSession.session.startTransaction()
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                identityManager.discardLatestIdentityDetails(engineSession.session, ownedIdentity)
                engineSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    override fun publishLatestIdentityDetails(bytesOwnedIdentity: ByteArray?) {
        try {
            getSession().use { engineSession ->
                engineSession.session.startTransaction()
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                val version = identityManager.publishLatestIdentityDetails(
                    engineSession.session,
                    ownedIdentity
                )
                if (version != -1) {
                    protocolManager.startIdentityDetailsPublicationProtocol(
                        engineSession.session,
                        ownedIdentity,
                        version
                    )
                }
                engineSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    @Throws(Exception::class)
    override fun updateOwnedIdentityPhoto(
        bytesOwnedIdentity: ByteArray?,
        absolutePhotoUrl: String?
    ) {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        getSession().use { engineSession ->
            engineSession.session.startTransaction()
            identityManager.updateOwnedIdentityPhoto(
                engineSession.session,
                ownedIdentity,
                absolutePhotoUrl
            )
            engineSession.session.commit()
        }
    }

    override fun getServerAuthenticationToken(bytesOwnedIdentity: ByteArray?): ByteArray? {
        try {
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            return fetchManager.getServerAuthenticationToken(ownedIdentity)
        } catch (e: DecodingException) {
            Logger.x(e)
            return null
        }
    }

    // returns null in case of error, empty list if there are no capabilities
    override fun getOwnCapabilities(bytesOwnedIdentity: ByteArray?): MutableList<ObvCapability>? {
        try {
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            return identityManager.getOwnCapabilities(ownedIdentity)
        } catch (e: Exception) {
            Logger.x(e)
            return null
        }
    }

    override fun getOwnedDevices(bytesOwnedIdentity: ByteArray?): MutableList<ObvOwnedDevice>? {
        try {
            getSession().use { engineSession ->
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                return identityManager.getDevicesOfOwnedIdentity(
                    engineSession.session,
                    ownedIdentity
                )
            }
        } catch (e: Exception) {
            Logger.x(e)
            return null
        }
    }

    override fun queryRegisteredOwnedDevicesFromServer(bytesOwnedIdentity: ByteArray?): ObvDeviceList? {
        try {
            getSession().use { engineSession ->
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                val standaloneServerQueryOperation = StandaloneServerQueryOperation(
                    ServerQuery(
                        null,
                        ownedIdentity,
                        OwnedDeviceDiscoveryQuery(ownedIdentity)
                    ), sslSocketFactory, userAgentOverride
                )

                val queue = OperationQueue()
                queue.queue(standaloneServerQueryOperation)
                queue.execute(1, "Engine-queryRegisterOwnedDevicesFromServer")
                queue.join()
                if (standaloneServerQueryOperation.isFinished && standaloneServerQueryOperation.serverResponse != null) {
                    return ObvDeviceList.of(
                        standaloneServerQueryOperation.serverResponse!!.decodeEncryptedData(),
                        identityManager.getOwnedIdentityEncryptionPrivateKey(
                            engineSession.session,
                            ownedIdentity
                        )
                    )
                }
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
        return null
    }

    override fun refreshOwnedDeviceList(bytesOwnedIdentity: ByteArray?) {
        try {
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            protocolManager.startOwnedDeviceDiscoveryProtocol(ownedIdentity)
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    override fun recreateOwnedDeviceChannel(
        bytesOwnedIdentity: ByteArray?,
        bytesDeviceUid: ByteArray?
    ) {
        try {
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            val deviceUid = UID(bytesDeviceUid!!)
            // simply start the channel creation protocol: this deletes any channel and aborts any ongoing instance
            protocolManager.startChannelCreationWithOwnedDeviceProtocol(ownedIdentity, deviceUid)
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    //    @Override
    //    public void resynchronizeAllOwnedDevices(byte[] bytesOwnedIdentity) {
    //        try (EngineSession engineSession = getSession()) {
    //            Identity ownedIdentity = Identity.of(bytesOwnedIdentity);
    //            protocolManager.triggerOwnedDevicesSync(engineSession.session, ownedIdentity);
    //            engineSession.session.commit();
    //        } catch (Exception e) {
    //            Logger.x(e);
    //        }
    //    }
    // endregion
    // region Managing Contact Identities
    @Throws(Exception::class)
    override fun getContactsOfOwnedIdentity(bytesOwnedIdentity: ByteArray?): Array<ObvIdentity> {
        getSession().use { engineSession ->
            if (bytesOwnedIdentity == null) return emptyArray()

            val ownedIdentity = Identity.of(bytesOwnedIdentity)
            val identities = identityManager.getContactsOfOwnedIdentity(engineSession.session, ownedIdentity) ?: return emptyArray()
            return identities.map {
                ObvIdentity(
                    engineSession.session,
                    identityManager,
                    it,
                    ownedIdentity
                )
            }.toTypedArray()
        }
    }

    @Throws(Exception::class)
    override fun getContactsInfoOfOwnedIdentity(bytesOwnedIdentity: ByteArray?): MutableList<ObvContactInfo> {
        getSession().use { engineSession ->
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            return identityManager.getContactsInfoOfOwnedIdentity(
                engineSession.session,
                ownedIdentity
            )
        }
    }


    override fun getContactActiveOrInactiveReasons(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ): EnumSet<ObvContactActiveOrInactiveReason>? {
        try {
            getSession().use { engineSession ->
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                val contactIdentity = Identity.of(bytesContactIdentity!!)
                return identityManager.getContactActiveOrInactiveReasons(
                    engineSession.session,
                    ownedIdentity,
                    contactIdentity
                )
            }
        } catch (e: Exception) {
            Logger.x(e)
            return null
        }
    }

    override fun forcefullyUnblockContact(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ): Boolean {
        try {
            getSession().use { engineSession ->
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                val contactIdentity = Identity.of(bytesContactIdentity!!)
                val success = identityManager.forcefullyUnblockContact(
                    engineSession.session,
                    ownedIdentity,
                    contactIdentity
                )
                engineSession.session.commit()
                return success
            }
        } catch (e: Exception) {
            Logger.x(e)
            return false
        }
    }

    override fun reBlockForcefullyUnblockedContact(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ): Boolean {
        try {
            getSession().use { engineSession ->
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                val contactIdentity = Identity.of(bytesContactIdentity!!)
                val success = identityManager.reBlockForcefullyUnblockedContact(
                    engineSession.session,
                    ownedIdentity,
                    contactIdentity
                )
                engineSession.session.commit()
                return success
            }
        } catch (e: Exception) {
            Logger.x(e)
            return false
        }
    }

    @Throws(Exception::class)
    override fun isContactOneToOne(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ): Boolean {
        getSession().use { engineSession ->
            val contactIdentity = Identity.of(bytesContactIdentity!!)
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            return identityManager.isIdentityAOneToOneContactOfOwnedIdentity(
                engineSession.session,
                ownedIdentity,
                contactIdentity
            )
        }
    }

    @Throws(Exception::class)
    override fun getContactDeviceCounts(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ): ObvContactDeviceCount {
        getSession().use { engineSession ->
            return identityManager.getContactDeviceCounts(
                engineSession.session,
                Identity.of(bytesOwnedIdentity!!),
                Identity.of(bytesContactIdentity!!)
            )
        }
    }

    override fun forceContactDeviceDiscovery(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ) {
        try {
            val contactIdentity = Identity.of(bytesContactIdentity!!)
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            protocolManager.startDeviceDiscoveryProtocol(ownedIdentity, contactIdentity)
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    @Throws(Exception::class)
    override fun getContactTrustedDetailsPhotoUrl(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ): String? {
        getSession().use { engineSession ->
            val contactIdentity = Identity.of(bytesContactIdentity!!)
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            return identityManager.getContactTrustedDetailsPhotoUrl(
                engineSession.session,
                ownedIdentity,
                contactIdentity
            )
        }
    }

    @Throws(Exception::class)
    override fun getContactPublishedAndTrustedDetails(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ): Array<JsonIdentityDetailsWithVersionAndPhoto?>? {
        getSession().use { engineSession ->
            val contactIdentity = Identity.of(bytesContactIdentity!!)
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            return identityManager.getContactPublishedAndTrustedDetails(
                engineSession.session,
                ownedIdentity,
                contactIdentity
            )
        }
    }

    override fun trustPublishedContactDetails(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ) {
        try {
            getSession().use { engineSession ->
                val contactIdentity = Identity.of(bytesContactIdentity!!)
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                val details = identityManager.trustPublishedContactDetails(
                    engineSession.session,
                    contactIdentity,
                    ownedIdentity
                )
                if (details != null) {
                    propagateEngineSyncAtomToOtherDevicesIfNeeded(
                        engineSession.session,
                        ownedIdentity,
                        ObvSyncAtom.createTrustContactDetails(
                            contactIdentity,
                            jsonObjectMapper.writeValueAsString(details)
                        )
                    )
                }
                engineSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    @Throws(Exception::class)
    override fun getContactTrustOrigins(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ): Array<ObvTrustOrigin?> {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        val contactIdentity = Identity.of(bytesContactIdentity!!)
        val obvTrustOrigins: Array<ObvTrustOrigin?>
        getSession().use { engineSession ->
            val trustOrigins = identityManager.getTrustOriginsOfContactIdentity(
                engineSession.session,
                ownedIdentity,
                contactIdentity
            )
            obvTrustOrigins = arrayOfNulls<ObvTrustOrigin>(trustOrigins.size)
            for (i in trustOrigins.indices) {
                obvTrustOrigins[i] = ObvTrustOrigin(
                    engineSession.session,
                    identityManager,
                    trustOrigins[i]!!,
                    ownedIdentity
                )
            }
        }
        return obvTrustOrigins
    }

    @Throws(Exception::class)
    override fun getContactTrustLevel(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ): Int {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        val contactIdentity = Identity.of(bytesContactIdentity!!)

        getSession().use { engineSession ->
            val contactTrustLevel = identityManager.getContactTrustLevel(
                engineSession.session,
                ownedIdentity,
                contactIdentity
            )
            if (contactTrustLevel != null) {
                return contactTrustLevel.major
            } else {
                return 0
            }
        }
    }

    // returns null in case of error, empty list if there are no capabilities
    override fun getContactCapabilities(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ): MutableList<ObvCapability>? {
        try {
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            val contactIdentity = Identity.of(bytesContactIdentity!!)
            return identityManager.getContactCapabilities(ownedIdentity, contactIdentity)
        } catch (e: Exception) {
            Logger.x(e)
            return null
        }
    }


    // endregion
    // region ObvGroup
    @Throws(Exception::class)
    override fun getGroupsOfOwnedIdentity(bytesOwnedIdentity: ByteArray?): Array<ObvGroup> {
        getSession().use { engineSession ->
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            val groups =
                identityManager.getGroupsForOwnedIdentity(engineSession.session, ownedIdentity)
            return groups.map { group ->
                val byteContactIdentities =
                    arrayOfNulls<ByteArray>(group.getGroupMembers().size)
                for (j in byteContactIdentities.indices) {
                    byteContactIdentities[j] = group.getGroupMembers()[j].getBytes()
                }
                val pendingMembers =
                    arrayOfNulls<ObvIdentity>(group.getPendingGroupMembers().size)
                for (j in pendingMembers.indices) {
                    try {
                        val identityDetails =
                            identityManager.jsonObjectMapper.readValue<JsonIdentityDetails?>(
                                group.getPendingGroupMembers()[j].serializedDetails,
                                JsonIdentityDetails::class.java
                            )
                        pendingMembers[j] = ObvIdentity(
                            group.getPendingGroupMembers()[j].identity,
                            identityDetails,
                            false,
                            true
                        )
                    } catch (_: IOException) {
                        pendingMembers[j] = ObvIdentity(
                            group.getPendingGroupMembers()[j].identity,
                            null,
                            false,
                            true
                        )
                    }
                }
                val bytesDeclinesPendingMembers =
                    arrayOfNulls<ByteArray>(group.getDeclinedPendingMembers().size)
                for (j in bytesDeclinesPendingMembers.indices) {
                    bytesDeclinesPendingMembers[j] =
                        group.getDeclinedPendingMembers()[j].getBytes()
                }
                return@map if (group.getGroupOwner() == null) {
                    ObvGroup(
                        group.getGroupOwnerAndUid(),
                        group.getPublishedGroupDetails(),
                        ownedIdentity.getBytes(),
                        byteContactIdentities,
                        pendingMembers,
                        bytesDeclinesPendingMembers,
                        null
                    )
                } else {
                     ObvGroup(
                        group.getGroupOwnerAndUid(),
                        group.getLatestOrTrustedGroupDetails(),
                        ownedIdentity.getBytes(),
                        byteContactIdentities,
                        pendingMembers,
                        bytesDeclinesPendingMembers,
                        group.getGroupOwner()!!.getBytes()
                    )
                }
            }.toTypedArray()
        }
    }

    @Throws(Exception::class)
    override fun getGroupPublishedAndLatestOrTrustedDetails(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupOwnerAndUid: ByteArray?
    ): Array<JsonGroupDetailsWithVersionAndPhoto?>? {
        getSession().use { engineSession ->
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            return identityManager.getGroupPublishedAndLatestOrTrustedDetails(
                engineSession.session,
                ownedIdentity,
                bytesGroupOwnerAndUid
            )
        }
    }

    @Throws(Exception::class)
    override fun getGroupTrustedDetailsPhotoUrl(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupOwnerAndUid: ByteArray?
    ): String? {
        getSession().use { engineSession ->
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            return identityManager.getGroupPhotoUrl(
                engineSession.session,
                ownedIdentity,
                bytesGroupOwnerAndUid
            )
        }
    }

    override fun trustPublishedGroupDetails(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupOwnerAndUid: ByteArray?
    ) {
        try {
            getSession().use { engineSession ->
                engineSession.session.startTransaction()
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                val details = identityManager.trustPublishedGroupDetails(
                    engineSession.session,
                    ownedIdentity,
                    bytesGroupOwnerAndUid
                )
                if (details != null) {
                    propagateEngineSyncAtomToOtherDevicesIfNeeded(
                        engineSession.session,
                        ownedIdentity,
                        ObvSyncAtom.createTrustGroupV1Details(
                            bytesGroupOwnerAndUid!!,
                            jsonObjectMapper.writeValueAsString(details)
                        )
                    )
                }
                engineSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    @Throws(Exception::class)
    override fun updateLatestGroupDetails(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupOwnerAndUid: ByteArray?,
        jsonGroupDetails: JsonGroupDetails?
    ) {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        getSession().use { engineSession ->
            engineSession.session.startTransaction()
            identityManager.updateLatestGroupDetails(
                engineSession.session,
                ownedIdentity,
                bytesGroupOwnerAndUid,
                jsonGroupDetails
            )
            engineSession.session.commit()
        }
    }

    override fun discardLatestGroupDetails(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupOwnerAndUid: ByteArray?
    ) {
        try {
            getSession().use { engineSession ->
                engineSession.session.startTransaction()
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                identityManager.discardLatestGroupDetails(
                    engineSession.session,
                    ownedIdentity,
                    bytesGroupOwnerAndUid
                )
                engineSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    override fun publishLatestGroupDetails(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupOwnerAndUid: ByteArray?
    ) {
        try {
            getSession().use { engineSession ->
                engineSession.session.startTransaction()
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                val version = identityManager.publishLatestGroupDetails(
                    engineSession.session,
                    ownedIdentity,
                    bytesGroupOwnerAndUid
                )
                if (version != -1) {
                    protocolManager.startGroupDetailsPublicationProtocol(
                        engineSession.session,
                        ownedIdentity,
                        bytesGroupOwnerAndUid
                    )
                }
                engineSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    @Throws(Exception::class)
    override fun updateOwnedGroupPhoto(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupOwnerAndUid: ByteArray?,
        absolutePhotoUrl: String?
    ) {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        getSession().use { engineSession ->
            engineSession.session.startTransaction()
            identityManager.updateOwnedGroupPhoto(
                engineSession.session,
                ownedIdentity,
                bytesGroupOwnerAndUid,
                absolutePhotoUrl,
                false
            )
            engineSession.session.commit()
        }
    }


    // endregion
    // region Groups V2
    @Throws(Exception::class)
    override fun getGroupsV2OfOwnedIdentity(bytesOwnedIdentity: ByteArray?): MutableList<ObvGroupV2> {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        getSession().use { engineSession ->
            return identityManager.getObvGroupsV2ForOwnedIdentity(
                engineSession.session,
                ownedIdentity
            )
        }
    }

    @Throws(Exception::class)
    override fun trustGroupV2PublishedDetails(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupIdentifier: ByteArray?
    ) {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        val groupIdentifier = GroupV2.Identifier.of(bytesGroupIdentifier!!)
        getSession().use { engineSession ->
            val version = identityManager.trustGroupV2PublishedDetails(
                engineSession.session,
                ownedIdentity,
                groupIdentifier
            )
            if (version != -1) {
                propagateEngineSyncAtomToOtherDevicesIfNeeded(
                    engineSession.session,
                    ownedIdentity,
                    ObvSyncAtom.createTrustGroupV2Details(groupIdentifier, version)
                )
            }
            engineSession.session.commit()
        }
    }

    override fun getGroupV2JsonType(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupIdentifier: ByteArray?
    ): String? {
        if (bytesOwnedIdentity == null || bytesGroupIdentifier == null) {
            return null
        }

        try {
            val ownedIdentity = Identity.of(bytesOwnedIdentity)
            val groupIdentifier = GroupV2.Identifier.of(bytesGroupIdentifier)

            getSession().use { engineSession ->
                return identityManager.getGroupV2JsonGroupType(
                    engineSession.session,
                    ownedIdentity,
                    groupIdentifier
                )
            }
        } catch (e: Exception) {
            Logger.x(e)
            return null
        }
    }

    override fun getGroupV2DetailsAndPhotos(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupIdentifier: ByteArray?
    ): ObvGroupV2DetailsAndPhotos? {
        if (bytesOwnedIdentity == null || bytesGroupIdentifier == null) {
            return null
        }

        try {
            val ownedIdentity = Identity.of(bytesOwnedIdentity)
            val groupIdentifier = GroupV2.Identifier.of(bytesGroupIdentifier)

            getSession().use { engineSession ->
                return identityManager.getGroupV2DetailsAndPhotos(
                    engineSession.session,
                    ownedIdentity,
                    groupIdentifier
                )
            }
        } catch (e: Exception) {
            Logger.x(e)
            return null
        }
    }


    @Throws(Exception::class)
    override fun initiateGroupV2Update(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupIdentifier: ByteArray?,
        changeSet: ObvGroupV2ChangeSet?
    ) {
        if (bytesOwnedIdentity == null || bytesGroupIdentifier == null) {
            throw Exception()
        }
        val ownedIdentity = Identity.of(bytesOwnedIdentity)
        val groupIdentifier = GroupV2.Identifier.of(bytesGroupIdentifier)

        protocolManager.initiateGroupV2Update(ownedIdentity, groupIdentifier, changeSet)
    }

    @Throws(Exception::class)
    override fun leaveGroupV2(bytesOwnedIdentity: ByteArray?, bytesGroupIdentifier: ByteArray?) {
        if (bytesOwnedIdentity == null || bytesGroupIdentifier == null) {
            throw Exception()
        }
        val ownedIdentity = Identity.of(bytesOwnedIdentity)
        val groupIdentifier = GroupV2.Identifier.of(bytesGroupIdentifier)
        if (groupIdentifier.category == GroupV2.Identifier.CATEGORY_KEYCLOAK) {
            // it is not possible to leave a keycloak group
            return
        }

        protocolManager.initiateGroupV2Leave(ownedIdentity, groupIdentifier)
    }

    @Throws(Exception::class)
    override fun disbandGroupV2(bytesOwnedIdentity: ByteArray?, bytesGroupIdentifier: ByteArray?) {
        if (bytesOwnedIdentity == null || bytesGroupIdentifier == null) {
            throw Exception()
        }
        val ownedIdentity = Identity.of(bytesOwnedIdentity)
        val groupIdentifier = GroupV2.Identifier.of(bytesGroupIdentifier)
        if (groupIdentifier.category == GroupV2.Identifier.CATEGORY_KEYCLOAK) {
            // it is not possible to leave a keycloak group
            return
        }

        protocolManager.initiateGroupV2Disband(ownedIdentity, groupIdentifier)
    }

    @Throws(Exception::class)
    override fun reDownloadGroupV2(bytesOwnedIdentity: ByteArray?, bytesGroupIdentifier: ByteArray?) {
        if (bytesOwnedIdentity == null || bytesGroupIdentifier == null) {
            throw Exception()
        }
        val ownedIdentity = Identity.of(bytesOwnedIdentity)
        val groupIdentifier = GroupV2.Identifier.of(bytesGroupIdentifier)

        protocolManager.initiateGroupV2ReDownload(ownedIdentity, groupIdentifier)
    }

    @Throws(Exception::class)
    override fun getGroupV2Version(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupIdentifier: ByteArray?
    ): Int? {
        if (bytesOwnedIdentity == null || bytesGroupIdentifier == null) {
            throw Exception()
        }
        val ownedIdentity = Identity.of(bytesOwnedIdentity)
        val groupIdentifier = GroupV2.Identifier.of(bytesGroupIdentifier)

        getSession().use { engineSession ->
            return identityManager.getGroupV2Version(
                engineSession.session,
                ownedIdentity,
                groupIdentifier
            )
        }
    }

    @Throws(Exception::class)
    override fun isGroupV2UpdateInProgress(
        bytesOwnedIdentity: ByteArray?,
        groupIdentifier: GroupV2.Identifier?
    ): Boolean {
        if (bytesOwnedIdentity == null || groupIdentifier == null) {
            throw Exception()
        }
        val ownedIdentity = Identity.of(bytesOwnedIdentity)

        getSession().use { engineSession ->
            return identityManager.isGroupV2Frozen(
                engineSession.session,
                ownedIdentity,
                groupIdentifier
            )
        }
    }

    // endregion
    // region ObvDialog
    @Throws(Exception::class)
    override fun deletePersistedDialog(uuid: UUID?) {
        getSession().use { engineSession ->
            val dialog: UserInterfaceDialog? =
                UserInterfaceDialog.get(engineSession, uuid)
            if (dialog != null) {
                dialog.delete()
                engineSession.session.commit()
            }
        }
    }

    @Throws(Exception::class)
    override fun getAllPersistedDialogUuids(): MutableSet<UUID> {
        getSession().use { engineSession ->
            val dialogs: Array<UserInterfaceDialog> = UserInterfaceDialog.getAll(engineSession)
            val obvDialogUuids: MutableSet<UUID> = HashSet()
            for (dialog in dialogs) {
                obvDialogUuids.add(dialog.getUuid())
            }
            return obvDialogUuids
        }
    }

    @Throws(Exception::class)
    override fun resendAllPersistedDialogs() {
        getSession().use { engineSession ->
            for (dialog in UserInterfaceDialog.getAll(engineSession)) {
                dialog.resend()
            }
        }
    }

    @Throws(Exception::class)
    override fun respondToDialog(dialog: ObvDialog?) {
        getSession().use { engineSession ->
            val ownedIdentity = Identity.of(dialog!!.getBytesOwnedIdentity())
            val responseMessageToSend = ChannelDialogResponseMessageToSend(
                dialog.getUuid(),
                ownedIdentity,
                dialog.getEncodedResponse(),
                dialog.getEncodedElements(),
                dialog.getVersion()
            )

            engineSession.session.startTransaction()
            channelManager.post(engineSession.session, responseMessageToSend, prng)
            engineSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun abortProtocol(dialog: ObvDialog?) {
        getSession().use { engineSession ->
            val userInterfaceDialog: UserInterfaceDialog? =
                UserInterfaceDialog.get(engineSession, dialog!!.getUuid())
            val protocolInstanceUid = dialog.getEncodedElements()!!.decodeList()[1].decodeUid()
            val ownedIdentity = Identity.of(dialog.getBytesOwnedIdentity())

            engineSession.session.startTransaction()
            userInterfaceDialog!!.delete()
            protocolManager.abortProtocol(engineSession.session, protocolInstanceUid, ownedIdentity)
            engineSession.session.commit()
        }
    }


    // endregion
    // region Start protocols
    @Throws(Exception::class)
    override fun startTrustEstablishmentProtocol(
        bytesRemoteIdentity: ByteArray?,
        contactDisplayName: String?,
        bytesOwnedIdentity: ByteArray?
    ) {
        val remoteIdentity = Identity.of(bytesRemoteIdentity!!)
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        protocolManager.startTrustEstablishmentProtocol(
            ownedIdentity,
            remoteIdentity,
            contactDisplayName
        )
    }

    @Throws(Exception::class)
    override fun computeMutualScanSignedNonceUrl(
        bytesRemoteIdentity: ByteArray?,
        bytesOwnedIdentity: ByteArray?,
        ownDisplayName: String?
    ): ObvMutualScanUrl {
        val contactIdentity = Identity.of(bytesRemoteIdentity!!)
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)

        getSession().use { engineSession ->
            val signature = identityManager.signIdentities(
                engineSession.session,
                Constants.SignatureContext.MUTUAL_SCAN,
                arrayOf(contactIdentity, ownedIdentity),
                ownedIdentity,
                prng
            )
            return ObvMutualScanUrl(ownedIdentity, ownDisplayName!!, signature!!)
        }
    }

    override fun verifyMutualScanSignedNonceUrl(
        bytesOwnedIdentity: ByteArray?,
        mutualScanUrl: ObvMutualScanUrl?
    ): Boolean {
        try {
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)

            return Signature.verify(
                Constants.SignatureContext.MUTUAL_SCAN,
                arrayOf<Identity?>(ownedIdentity, mutualScanUrl!!.identity),
                mutualScanUrl.identity,
                mutualScanUrl.signature
            )
        } catch (_: Exception) {
            return false
        }
    }


    @Throws(Exception::class)
    override fun startMutualScanTrustEstablishmentProtocol(
        bytesOwnedIdentity: ByteArray?,
        bytesRemoteIdentity: ByteArray?,
        signature: ByteArray?
    ) {
        val contactIdentity = Identity.of(bytesRemoteIdentity!!)
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        protocolManager.startMutualScanTrustEstablishmentProtocol(
            ownedIdentity,
            contactIdentity,
            signature
        )
    }

    @Throws(Exception::class)
    override fun startContactMutualIntroductionProtocol(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentityA: ByteArray?,
        bytesContactIdentities: Array<ByteArray?>?
    ) {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        val contactIdentityA = Identity.of(bytesContactIdentityA!!)
        val contactIdentities = arrayOfNulls<Identity>(bytesContactIdentities!!.size)
        for (i in bytesContactIdentities.indices) {
            contactIdentities[i] = Identity.of(bytesContactIdentities[i]!!)
            if (contactIdentityA.equals(contactIdentities[i])) {
                throw Exception()
            }
        }
        protocolManager.startContactMutualIntroductionProtocol(
            ownedIdentity,
            contactIdentityA,
            contactIdentities
        )
    }

    @Throws(Exception::class)
    override fun startGroupCreationProtocol(
        serializedGroupDetailsWithVersionAndPhoto: String?,
        absolutePhotoUrl: String?,
        bytesOwnedIdentity: ByteArray?,
        bytesRemoteIdentities: Array<ByteArray?>?
    ) {
        if (bytesOwnedIdentity == null || bytesRemoteIdentities == null) {
            throw Exception()
        }

        val groupMemberIdentitiesAndDisplayNames = HashSet<IdentityWithSerializedDetails?>()
        val ownedIdentity = Identity.of(bytesOwnedIdentity)

        getSession().use { engineSession ->
            for (bytesRemoteIdentity in bytesRemoteIdentities) {
                val remoteIdentity = Identity.of(bytesRemoteIdentity!!)
                val serializedDetails =
                    identityManager.getSerializedPublishedDetailsOfContactIdentity(
                        engineSession.session,
                        ownedIdentity,
                        remoteIdentity
                    )
                groupMemberIdentitiesAndDisplayNames.add(
                    IdentityWithSerializedDetails(
                        remoteIdentity,
                        serializedDetails!!
                    )
                )
            }
        }
        protocolManager.startGroupCreationProtocol(
            ownedIdentity,
            serializedGroupDetailsWithVersionAndPhoto,
            absolutePhotoUrl,
            groupMemberIdentitiesAndDisplayNames
        )
    }


    @Throws(Exception::class)
    override fun startGroupV2CreationProtocol(
        serializedGroupDetails: String?,
        absolutePhotoUrl: String?,
        bytesOwnedIdentity: ByteArray?,
        ownPermissions: HashSet<GroupV2.Permission?>?,
        otherGroupMembers: HashMap<ObvBytesKey?, HashSet<GroupV2.Permission?>?>?,
        serializedGroupType: String?
    ) {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)

        val otherGroupMembersSet = HashSet<IdentityAndPermissions?>()
        for (entry in otherGroupMembers!!.entries) {
            val remoteIdentity = Identity.of(entry.key!!.getBytes())
            @Suppress("UNCHECKED_CAST")
            otherGroupMembersSet.add(IdentityAndPermissions(remoteIdentity, entry.value as HashSet<GroupV2.Permission>))
        }

        protocolManager.startGroupV2CreationProtocol(
            ownedIdentity,
            serializedGroupDetails,
            absolutePhotoUrl,
            ownPermissions,
            otherGroupMembersSet,
            serializedGroupType
        )
    }

    @Throws(Exception::class)
    override fun restartAllOngoingChannelEstablishmentProtocols(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ) {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        val contactIdentity = Identity.of(bytesContactIdentity!!)
        getSession().use { engineSession ->
            engineSession.session.startTransaction()
            val deviceUids = identityManager.getDeviceUidsOfContactIdentity(
                engineSession.session,
                ownedIdentity,
                contactIdentity
            )
            val confirmedDeviceUids = HashSet(
                channelManager.getConfirmedObliviousChannelDeviceUids(
                        engineSession.session,
                        ownedIdentity,
                        contactIdentity
                    ).toList()
            )

            for (deviceUid in deviceUids) {
                if (!confirmedDeviceUids.contains(deviceUid)) {
                    identityManager.removeDeviceForContactIdentity(
                        engineSession.session,
                        ownedIdentity,
                        contactIdentity,
                        deviceUid
                    )
                }
            }
            protocolManager.startDeviceDiscoveryProtocolWithinTransaction(
                engineSession.session,
                ownedIdentity,
                contactIdentity
            )
            engineSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun recreateAllChannels(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ) {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        val contactIdentity = Identity.of(bytesContactIdentity!!)
        getSession().use { engineSession ->
            engineSession.session.startTransaction()
            channelManager.deleteObliviousChannelsWithContact(
                engineSession.session,
                ownedIdentity,
                contactIdentity
            )
            identityManager.removeAllDevicesForContactIdentity(
                engineSession.session,
                ownedIdentity,
                contactIdentity
            )
            protocolManager.startDeviceDiscoveryProtocolWithinTransaction(
                engineSession.session,
                ownedIdentity,
                contactIdentity
            )
            engineSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun recreateAllChannels(bytesOwnedIdentity: ByteArray?) {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        getSession().use { engineSession ->
            engineSession.session.startTransaction()
            val contactIdentities =
                identityManager.getContactsOfOwnedIdentity(engineSession.session, ownedIdentity)
            for (contactIdentity in contactIdentities!!) {
                channelManager.deleteObliviousChannelsWithContact(
                    engineSession.session,
                    ownedIdentity,
                    contactIdentity
                )
                identityManager.removeAllDevicesForContactIdentity(
                    engineSession.session,
                    ownedIdentity,
                    contactIdentity
                )
                protocolManager.startDeviceDiscoveryProtocolWithinTransaction(
                    engineSession.session,
                    ownedIdentity,
                    contactIdentity
                )
            }
            engineSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun inviteContactsToGroup(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupOwnerAndUid: ByteArray?,
        bytesNewMemberIdentities: Array<ByteArray?>?
    ) {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        val newMembersIdentity = HashSet<Identity?>()
        for (bytesNewMemberIdentity in bytesNewMemberIdentities!!) {
            newMembersIdentity.add(Identity.of(bytesNewMemberIdentity!!))
        }
        protocolManager.inviteContactsToGroup(
            bytesGroupOwnerAndUid,
            ownedIdentity,
            newMembersIdentity
        )
    }

    @Throws(Exception::class)
    override fun removeContactsFromGroup(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupOwnerAndUid: ByteArray?,
        bytesRemovedMemberIdentities: Array<ByteArray?>?
    ) {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        val removedMemberIdentities = HashSet<Identity?>()
        for (bytesNewMemberIdentity in bytesRemovedMemberIdentities!!) {
            removedMemberIdentities.add(Identity.of(bytesNewMemberIdentity!!))
        }
        protocolManager.removeContactsFromGroup(
            bytesGroupOwnerAndUid,
            ownedIdentity,
            removedMemberIdentities
        )
    }

    @Throws(Exception::class)
    override fun reinvitePendingToGroup(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupOwnerAndUid: ByteArray?,
        bytesPendingMemberIdentity: ByteArray?
    ) {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        val pendingMemberIdentity = Identity.of(bytesPendingMemberIdentity!!)
        protocolManager.reinvitePendingToGroup(
            bytesGroupOwnerAndUid,
            ownedIdentity,
            pendingMemberIdentity
        )
    }

    @Throws(Exception::class)
    override fun leaveGroup(bytesOwnedIdentity: ByteArray?, bytesGroupOwnerAndUid: ByteArray?) {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        protocolManager.leaveGroup(bytesGroupOwnerAndUid, ownedIdentity)
    }

    @Throws(Exception::class)
    override fun disbandGroup(bytesOwnedIdentity: ByteArray?, bytesGroupOwnerAndUid: ByteArray?) {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        protocolManager.disbandGroup(bytesGroupOwnerAndUid, ownedIdentity)
    }

    @Throws(Exception::class)
    override fun deleteContact(bytesOwnedIdentity: ByteArray?, bytesContactIdentity: ByteArray?) {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        val contactIdentity = Identity.of(bytesContactIdentity!!)
        protocolManager.deleteContact(ownedIdentity, contactIdentity)
    }

    @Throws(Exception::class)
    override fun downgradeOneToOneContact(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ) {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        val contactIdentity = Identity.of(bytesContactIdentity!!)
        protocolManager.downgradeOneToOneContact(ownedIdentity, contactIdentity)
    }

    @Throws(Exception::class)
    override fun startOneToOneInvitationProtocol(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ) {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        val contactIdentity = Identity.of(bytesContactIdentity!!)
        protocolManager.startOneToOneInvitationProtocol(ownedIdentity, contactIdentity)
    }

    @Throws(Exception::class)
    override fun deleteOwnedIdentityAndNotifyContacts(
        bytesOwnedIdentity: ByteArray?,
        deleteEverywhere: Boolean
    ) {
        getSession().use { engineSession ->
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            // now delete contacts and leave/disband groups
            // the protocol will also delete all channels (once they are no longer used) and actually delete the owned identity
            protocolManager.startOwnedIdentityDeletionProtocol(
                engineSession.session,
                ownedIdentity,
                deleteEverywhere
            )
            engineSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun queryGroupOwnerForLatestGroupMembers(
        bytesGroupOwnerAndUid: ByteArray?,
        bytesOwnedIdentity: ByteArray?
    ) {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        protocolManager.queryGroupMembers(bytesGroupOwnerAndUid, ownedIdentity)
    }

    @Throws(Exception::class)
    override fun addKeycloakContact(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?,
        signedContactDetails: String?
    ) {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        val contactIdentity = Identity.of(bytesContactIdentity!!)
        protocolManager.addKeycloakContact(ownedIdentity, contactIdentity, signedContactDetails)
    }

    @Throws(Exception::class)
    override fun initiateOwnedIdentityTransferProtocolOnSourceDevice(bytesOwnedIdentity: ByteArray?) {
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        protocolManager.initiateOwnedIdentityTransferProtocolOnSourceDevice(ownedIdentity)
    }

    @Throws(Exception::class)
    override fun initiateOwnedIdentityTransferProtocolOnTargetDevice(deviceName: String?) {
        protocolManager.initiateOwnedIdentityTransferProtocolOnTargetDevice(deviceName)
    }


    // endregion
    // region Post/receive messages
    override fun getReturnReceiptNonce(): ByteArray {
        return prng.bytes(Constants.RETURN_RECEIPT_NONCE_LENGTH)
    }

    override fun getReturnReceiptKey(): ByteArray? {
        val authEncKey = Suite.getDefaultAuthEnc(Suite.LATEST_VERSION).generateKey(prng) ?: return null
        return Encoded.of(authEncKey).bytes
    }

    override fun deleteReturnReceipt(bytesOwnedIdentity: ByteArray?, serverUid: ByteArray?) {
        try {
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            fetchManager.deleteReturnReceipt(ownedIdentity, serverUid)
        } catch (e: DecodingException) {
            Logger.w("DecodingException while reconstructing the ownedIdentity in deleteReturnReceipt")
            Logger.x(e)
        }
    }

    override fun decryptReturnReceipt(
        returnReceiptKey: ByteArray?,
        encryptedPayload: ByteArray?
    ): ObvReturnReceipt? {
        try {
            val authEncKey = Encoded(returnReceiptKey!!).decodeSymmetricKey() as AuthEncKey?
            val authEnc = Suite.getAuthEnc(authEncKey)
            if (authEnc != null) {
                val decryptedPayload = authEnc.decrypt(authEncKey, EncryptedBytes(encryptedPayload!!))
                if (decryptedPayload != null) {
                    val list: Array<Encoded> = Encoded(decryptedPayload).decodeList()
                    if (list.size == 2) {
                        // this is for a message
                        return ObvReturnReceipt(
                            list[0].decodeBytes(),
                            list[1].decodeLong().toInt()
                        )
                    } else if (list.size == 3) {
                        // this is for an attachment
                        return ObvReturnReceipt(
                            list[0].decodeBytes(),
                            list[1].decodeLong().toInt(),
                            list[2].decodeLong().toInt()
                        )
                    }
                }
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
        return null
    }

    override fun post(
        messagePayload: ByteArray?,
        extendedMessagePayload: ByteArray?,
        outboundAttachments: Array<ObvOutboundAttachment?>?,
        bytesContactIdentities: MutableList<ByteArray?>?,
        bytesOwnedIdentity: ByteArray?,
        hasUserContent: Boolean,
        isVoipMessage: Boolean
    ): ObvPostMessageOutput {
        if (messagePayload == null || outboundAttachments == null || bytesContactIdentities == null || bytesOwnedIdentity == null) {
            Logger.e("Unexpected null arguments to Engine.post()", Exception())
            return ObvPostMessageOutput(false, HashMap())
        }

        // compute contact groups by server
        val contactServersHashMap = HashMap<String?, HashSet<Identity>?>()
        for (bytesContactIdentity in bytesContactIdentities) {
            try {
                val contactIdentity = Identity.of(bytesContactIdentity!!)
                var list: HashSet<Identity>? = contactServersHashMap[contactIdentity.server]
                if (list == null) {
                    list = HashSet()
                    contactServersHashMap[contactIdentity.server] = list
                }
                list.add(contactIdentity)
            } catch (e: DecodingException) {
                Logger.x(e)
                Logger.w("Error decoding a bytesContactIdentity while posting a message!")
            }
        }

        val messageIdentifierByContactIdentity = HashMap<ObvBytesKey?, ByteArray?>()
        var messageSent = false

        for (server in contactServersHashMap.keys) {
            val contactIdentities = contactServersHashMap[server] ?: continue
            try {
                val attachments =
                    arrayOfNulls<ChannelApplicationMessageToSend.Attachment>(outboundAttachments.size)

                for (i in outboundAttachments.indices) {
                    attachments[i] = ChannelApplicationMessageToSend.Attachment(
                        outboundAttachments[i]!!.getPath(),
                        false,
                        outboundAttachments[i]!!.getAttachmentLength(),
                        outboundAttachments[i]!!.getMetadata()
                    )
                }

                val ownedIdentity = Identity.of(bytesOwnedIdentity)


                val message = ChannelApplicationMessageToSend(
                    contactIdentities.toTypedArray<Identity>(),
                    ownedIdentity,
                    messagePayload,
                    extendedMessagePayload,
                    attachments,
                    hasUserContent,
                    isVoipMessage
                )


                var messageUid: UID? = null
                getSession().use { engineSession ->
                    try {
                        engineSession.session.startTransaction()
                        messageUid = channelManager.post(engineSession.session, message, prng)
                        engineSession.session.commit()
                    } catch (_: Exception) {
                        engineSession.session.rollback()
                    }
                }
                if (messageUid != null) {
                    for (contactIdentity in contactIdentities) {
                        messageIdentifierByContactIdentity[ObvBytesKey(contactIdentity.getBytes())] = messageUid.bytes
                    }
                } else {
                    for (contactIdentity in contactIdentities) {
                        messageIdentifierByContactIdentity[ObvBytesKey(contactIdentity.getBytes())] = null
                    }
                    continue
                }

                // message is considered SENT even if a single recipient receives it.
                messageSent = true
            } catch (e: Exception) {
                for (contactIdentity in contactIdentities) {
                    messageIdentifierByContactIdentity[ObvBytesKey(contactIdentity.getBytes())] = null
                }
                Logger.x(e)
            }
        }

        return ObvPostMessageOutput(messageSent, messageIdentifierByContactIdentity)
    }

    // some bytesContactDeviceUids may be null: send to all devices for this contact in that case
    override fun postToSpecificDevices(
        messagePayload: ByteArray?,
        bytesContactIdentities: MutableList<ByteArray?>?,
        bytesContactDeviceUids: MutableList<ByteArray?>?,
        bytesOwnedIdentity: ByteArray?,
        hasUserContent: Boolean,
        isVoipMessage: Boolean
    ): ObvPostMessageOutput {
        if (messagePayload == null || bytesContactIdentities == null || bytesContactDeviceUids == null || bytesOwnedIdentity == null) {
            Logger.e("Unexpected null arguments to Engine.postToSpecificDevices()", Exception())
            return ObvPostMessageOutput(false, HashMap())
        }

        if (bytesContactIdentities.size != bytesContactDeviceUids.size) {
            return ObvPostMessageOutput(false, HashMap<ObvBytesKey?, ByteArray?>())
        }
        val contactServersHashMap = HashMap<String, HashSet<Identity>>()
        val contactDeviceUids = HashMap<Identity?, UID?>()
        for (i in bytesContactIdentities.indices) {
            try {
                val contactIdentity = Identity.of(bytesContactIdentities[i]!!)
                var list: HashSet<Identity>? = contactServersHashMap[contactIdentity.server]
                if (list == null) {
                    list = HashSet()
                    contactServersHashMap[contactIdentity.server] = list
                }
                list.add(contactIdentity)

                val bytesContactDeviceUid = bytesContactDeviceUids[i]
                if (bytesContactDeviceUid != null) {
                    contactDeviceUids[contactIdentity] = UID(bytesContactDeviceUid)
                }
            } catch (e: DecodingException) {
                Logger.x(e)
                Logger.w("Error decoding a bytesContactIdentity while postingToSpecificDevices a message!")
            }
        }

        val messageIdentifierByContactIdentity = HashMap<ObvBytesKey?, ByteArray?>()
        var messageSent = false

        for (server in contactServersHashMap.keys) {
            val contactIdentities = contactServersHashMap[server] ?: continue
            try {
                val ownedIdentity = Identity.of(bytesOwnedIdentity)

                val contactIdentityArray = contactIdentities.toTypedArray()
                val contactDeviceUidArray = contactIdentities.map { contactDeviceUids[it] }.toTypedArray()

                val message = ChannelApplicationMessageToSend(
                    contactIdentityArray,
                    contactDeviceUidArray,
                    ownedIdentity,
                    messagePayload,
                    null,
                    arrayOfNulls(0),
                    hasUserContent,
                    isVoipMessage
                )


                var messageUid: UID? = null
                getSession().use { engineSession ->
                    try {
                        engineSession.session.startTransaction()
                        messageUid = channelManager.post(engineSession.session, message, prng)
                        engineSession.session.commit()
                    } catch (_: Exception) {
                        engineSession.session.rollback()
                    }
                }
                if (messageUid != null) {
                    for (contactIdentity in contactIdentities) {
                        messageIdentifierByContactIdentity[ObvBytesKey(contactIdentity.getBytes())] = messageUid.bytes
                    }
                } else {
                    for (contactIdentity in contactIdentities) {
                        messageIdentifierByContactIdentity[ObvBytesKey(contactIdentity.getBytes())] = null
                    }
                    continue
                }

                // message is considered SENT even if a single recipient receives it.
                messageSent = true
            } catch (e: Exception) {
                for (contactIdentity in contactIdentities) {
                    messageIdentifierByContactIdentity[ObvBytesKey(contactIdentity.getBytes())] = null
                }
                Logger.x(e)
            }
        }

        return ObvPostMessageOutput(messageSent, messageIdentifierByContactIdentity)
    }

    override fun sendReturnReceipt(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?,
        status: Int,
        returnReceiptNonce: ByteArray?,
        returnReceiptKeyBytes: ByteArray?,
        attachmentNumber: Int?
    ) {
        try {
            getSession().use { engineSession ->
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                val contactIdentity = Identity.of(bytesContactIdentity!!)
                val returnReceiptKey =
                    Encoded(returnReceiptKeyBytes!!).decodeSymmetricKey() as AuthEncKey?
                // fetch contact deviceUids
                val deviceUids: Array<UID?>?
                // To improve: maybe find a way to send the return receipt only to the device that actually sent the message?
                if (bytesOwnedIdentity.contentEquals(bytesContactIdentity)) {
                    deviceUids = identityManager.getOtherDeviceUidsOfOwnedIdentity(
                        engineSession.session,
                        ownedIdentity
                    )
                } else {
                    deviceUids = identityManager.getDeviceUidsOfContactIdentity(
                        engineSession.session,
                        ownedIdentity,
                        contactIdentity
                    )
                }
                if (deviceUids!!.size != 0) {
                    sendManager.sendReturnReceipt(
                        engineSession.session,
                        ownedIdentity,
                        contactIdentity,
                        deviceUids,
                        status,
                        returnReceiptNonce,
                        returnReceiptKey,
                        attachmentNumber
                    )
                }
                engineSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    override fun isOutboxAttachmentSent(
        bytesOwnedIdentity: ByteArray?,
        engineMessageIdentifier: ByteArray?,
        engineNumber: Int
    ): Boolean {
        try {
            getSession().use { engineSession ->
                return sendManager.isOutboxAttachmentSent(
                    engineSession.session,
                    Identity.of(bytesOwnedIdentity!!),
                    UID(engineMessageIdentifier!!),
                    engineNumber
                )
            }
        } catch (e: Exception) {
            Logger.x(e)
            return false
        }
    }

    override fun isOutboxMessageSent(
        bytesOwnedIdentity: ByteArray?,
        engineMessageIdentifier: ByteArray?
    ): Boolean {
        try {
            getSession().use { engineSession ->
                return sendManager.isOutboxMessageSent(
                    engineSession.session,
                    Identity.of(bytesOwnedIdentity!!),
                    UID(engineMessageIdentifier!!)
                )
            }
        } catch (e: Exception) {
            Logger.x(e)
            return false
        }
    }

    override fun cancelMessageSending(
        bytesOwnedIdentity: ByteArray?,
        engineMessageIdentifier: ByteArray?
    ) {
        try {
            getSession().use { engineSession ->
                engineSession.session.startTransaction()
                sendManager.cancelMessageSending(
                    engineSession.session,
                    Identity.of(bytesOwnedIdentity!!),
                    UID(engineMessageIdentifier!!)
                )
                engineSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    override fun isInboxAttachmentReceived(
        bytesOwnedIdentity: ByteArray?,
        engineMessageIdentifier: ByteArray?,
        attachmentNumber: Int
    ): Boolean {
        try {
            getSession().use { engineSession ->
                return fetchManager.isInboxAttachmentReceived(
                    engineSession.session,
                    Identity.of(bytesOwnedIdentity!!),
                    UID(engineMessageIdentifier!!),
                    attachmentNumber
                )
            }
        } catch (e: Exception) {
            Logger.x(e)
            return false
        }
    }

    override fun downloadMessages(bytesOwnedIdentity: ByteArray?) {
        try {
            getSession().use { engineSession ->
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                val currentDeviceUid = identityManager.getCurrentDeviceUidOfOwnedIdentity(
                    engineSession.session,
                    ownedIdentity
                )
                fetchManager.downloadMessages(ownedIdentity, currentDeviceUid)
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    override fun downloadSmallAttachment(
        bytesOwnedIdentity: ByteArray?,
        messageIdentifier: ByteArray?,
        attachmentNumber: Int
    ) {
        try {
            fetchManager.downloadAttachment(
                Identity.of(bytesOwnedIdentity!!),
                UID(messageIdentifier!!),
                attachmentNumber,
                DownloadAttachmentPriorityCategory.WEIGHT
            )
        } catch (e: DecodingException) {
            Logger.e("Error parsing bytesOwnedIdentity in Engine.downloadSmallAttachment")
            Logger.x(e)
        }
    }

    override fun downloadLargeAttachment(
        bytesOwnedIdentity: ByteArray?,
        messageIdentifier: ByteArray?,
        attachmentNumber: Int
    ) {
        try {
            fetchManager.downloadAttachment(
                Identity.of(bytesOwnedIdentity!!),
                UID(messageIdentifier!!),
                attachmentNumber,
                DownloadAttachmentPriorityCategory.TIMESTAMP
            )
        } catch (e: DecodingException) {
            Logger.e("Error parsing bytesOwnedIdentity in Engine.downloadLargeAttachment")
            Logger.x(e)
        }
    }

    override fun pauseAttachmentDownload(
        bytesOwnedIdentity: ByteArray?,
        messageIdentifier: ByteArray?,
        attachmentNumber: Int
    ) {
        try {
            fetchManager.pauseDownloadAttachment(
                Identity.of(bytesOwnedIdentity!!),
                UID(messageIdentifier!!),
                attachmentNumber
            )
        } catch (e: DecodingException) {
            Logger.e("Error parsing bytesOwnedIdentity in Engine.pauseAttachmentDownload")
            Logger.x(e)
        }
    }

    override fun markAttachmentForDeletion(attachment: ObvAttachment?) {
        markAttachmentForDeletion(
            attachment!!.getOwnedIdentity(),
            attachment.getMessageUid(),
            attachment.getNumber()
        )
    }

    override fun markAttachmentForDeletion(
        bytesOwnedIdentity: ByteArray?,
        messageIdentifier: ByteArray?,
        attachmentNumber: Int
    ) {
        try {
            markAttachmentForDeletion(
                Identity.of(bytesOwnedIdentity!!),
                UID(messageIdentifier!!),
                attachmentNumber
            )
        } catch (e: DecodingException) {
            Logger.e("Error parsing bytesOwnedIdentity in Engine.deleteAttachment")
            Logger.x(e)
        }
    }

    override fun deleteMessageAndAttachments(
        bytesOwnedIdentity: ByteArray?,
        messageIdentifier: ByteArray?
    ) {
        val messageUid = UID(messageIdentifier!!)
        val ownedIdentity: Identity?
        try {
            ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        } catch (e: DecodingException) {
            Logger.e("Error parsing bytesOwnedIdentity in Engine.deleteMessage")
            Logger.x(e)
            return
        }
        try {
            getSession().use { engineSession ->
                fetchManager.deleteMessageAndAttachments(
                    engineSession.session,
                    ownedIdentity,
                    messageUid
                )
                engineSession.session.commit()
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    override fun markMessageForDeletion(
        bytesOwnedIdentity: ByteArray?,
        messageIdentifier: ByteArray?
    ) {
        val messageUid = UID(messageIdentifier!!)
        val ownedIdentity: Identity?
        try {
            ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        } catch (e: DecodingException) {
            Logger.e("Error parsing bytesOwnedIdentity in Engine.deleteMessage")
            Logger.x(e)
            return
        }
        try {
            getSession().use { engineSession ->
                fetchManager.deleteMessage(engineSession.session, ownedIdentity, messageUid)
                engineSession.session.commit()
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    override fun markMessageAsOnHold(bytesOwnedIdentity: ByteArray?, messageIdentifier: ByteArray?) {
        val messageUid = UID(messageIdentifier!!)
        val ownedIdentity: Identity?
        try {
            ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        } catch (e: DecodingException) {
            Logger.e("Error parsing bytesOwnedIdentity in Engine.markMessageAsOnHold")
            Logger.x(e)
            return
        }
        try {
            getSession().use { engineSession ->
                fetchManager.markMessageAsOnHold(engineSession.session, ownedIdentity, messageUid)
                engineSession.session.commit()
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    private fun markAttachmentForDeletion(
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int
    ) {
        if (ownedIdentity == null || messageUid == null) {
            return
        }
        try {
            getSession().use { engineSession ->
                fetchManager.deleteAttachment(
                    engineSession.session,
                    ownedIdentity,
                    messageUid,
                    attachmentNumber
                )
                engineSession.session.commit()
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    override fun cancelAttachmentUpload(
        bytesOwnedIdentity: ByteArray?,
        messageIdentifier: ByteArray?,
        attachmentNumber: Int
    ) {
        if (bytesOwnedIdentity == null || messageIdentifier == null) {
            return
        }
        try {
            getSession().use { engineSession ->
                sendManager.cancelAttachmentUpload(
                    engineSession.session,
                    Identity.of(bytesOwnedIdentity),
                    UID(messageIdentifier),
                    attachmentNumber
                )
                engineSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    @Throws(Exception::class)
    override fun resendAllAttachmentNotifications() {
        fetchManager.resendAllDownloadedAttachmentNotifications()
    }

    override fun connectWebsocket(
        relyOnWebsocketForNetworkDetection: Boolean,
        os: String?,
        osVersion: String?,
        appBuild: Int,
        appVersion: String?
    ) {
        fetchManager.connectWebsockets(
            relyOnWebsocketForNetworkDetection,
            os,
            osVersion,
            appBuild,
            appVersion
        )
    }

    override fun disconnectWebsocket() {
        fetchManager.disconnectWebsockets()
    }

    override fun pingWebsocket(bytesOwnedIdentity: ByteArray?) {
        try {
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            fetchManager.pingWebsocket(ownedIdentity)
        } catch (_: Exception) {
        }
    }

    override fun retryScheduledNetworkTasks() {
        fetchManager.retryScheduledNetworkTasks()
        sendManager.retryScheduledNetworkTasks()
        backupManager.retryScheduledNetworkTasks()
    }

    @Throws(Exception::class)
    override fun getOnHoldMessage(
        bytesOwnedIdentity: ByteArray?,
        messageIdentifier: ByteArray?
    ): ObvMessage? {
        val messageUid = UID(messageIdentifier!!)
        val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
        getSession().use { engineSession ->
            return fetchManager.getOnHoldMessage(engineSession.session, ownedIdentity, messageUid)
        }
    }

    // endregion
    // region Backup
    override fun initiateBackup(forExport: Boolean) {
        backupManager.initiateBackup(forExport)
    }


    override fun generateDeviceBackupSeed(server: String?): String? {
        try {
            return backupManager.generateDeviceBackupSeed(server)
        } catch (e: Exception) {
            Logger.x(e)
            return null
        }
    }

    @Throws(Exception::class)
    override fun getDeviceBackupSeed(): String? {
        return backupManager.currentDeviceBackupSeed
    }

    override fun deleteDeviceBackupSeed(deviceBackupSeed: String?) {
        try {
            val backupSeed = BackupSeed(deviceBackupSeed!!)
            backupManager.deleteDeviceBackupSeed(backupSeed)
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    override fun backupDeviceAndProfilesNow(): Boolean {
        try {
            return backupManager.backupDeviceAndProfilesNow()
        } catch (e: Exception) {
            Logger.x(e)
            return false
        }
    }

    override fun deviceBackupNeeded() {
        notificationManager.postNotification(
            BackupNotifications.NOTIFICATION_DEVICE_BACKUP_NEEDED,
            HashMap<String, Any>()
        )
    }

    override fun profileBackupNeeded(bytesOwnedIdentity: ByteArray?) {
        try {
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            notificationManager.postNotification(
                BackupNotifications.NOTIFICATION_PROFILE_BACKUP_NEEDED, Map.of<String, Any>(
                    BackupNotifications.NOTIFICATION_PROFILE_BACKUP_NEEDED_OWNED_IDENTITY,
                    ownedIdentity
                )
            )
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    override fun fetchDeviceBackup(
        server: String?,
        deviceBackupSeed: String?
    ): ObvDeviceBackupForRestore? {
        try {
            val backupSeed = BackupSeed(deviceBackupSeed!!)
            return backupManager.fetchDeviceBackup(server, backupSeed)
        } catch (e: Exception) {
            Logger.x(e)
            return ObvDeviceBackupForRestore(
                ObvDeviceBackupForRestore.Status.PERMANENT_ERROR,
                null,
                null
            )
        }
    }

    override fun fetchProfileBackups(
        bytesIdentity: ByteArray?,
        profileBackupSeed: String?
    ): ObvProfileBackupsForRestore? {
        try {
            val backupSeed = BackupSeed(profileBackupSeed!!)
            val identity = Identity.of(bytesIdentity!!)
            return backupManager.fetchProfileBackups(identity.server, backupSeed)
        } catch (e: Exception) {
            Logger.x(e)
            return ObvProfileBackupsForRestore(
                ObvProfileBackupsForRestore.Status.PERMANENT_ERROR,
                null,
                null
            )
        }
    }

    override fun deleteProfileBackupSnapshot(
        bytesIdentity: ByteArray?,
        profileBackupSeed: String?,
        threadId: ByteArray?,
        version: Long
    ): Boolean {
        try {
            val backupSeed = BackupSeed(profileBackupSeed!!)
            val identity = Identity.of(bytesIdentity!!)
            val backupThreadId = UID(threadId!!)
            return backupManager.deleteProfileBackupSnapshot(
                identity.server,
                backupSeed,
                backupThreadId,
                version
            )
        } catch (e: Exception) {
            Logger.x(e)
            return false
        }
    }

    @Throws(Exception::class)
    override fun downloadProfilePicture(
        bytesIdentity: ByteArray?,
        photoLabel: ByteArray?,
        photoKey: ByteArray?
    ): ByteArray? {
        val identity = Identity.of(bytesIdentity!!)
        val label = UID(photoLabel!!)
        val authEncKey = Encoded(photoKey!!).decodeSymmetricKey() as AuthEncKey?

        val standaloneServerQueryOperation = StandaloneServerQueryOperation(
            ServerQuery(
                null,
                null,
                BackupsV2DownloadProfilePictureQuery(identity, label, authEncKey)
            ), sslSocketFactory, userAgentOverride
        )

        val queue = OperationQueue()
        queue.queue(standaloneServerQueryOperation)
        queue.execute(1, "Engine-downloadProfilePicture")
        queue.join()

        if (standaloneServerQueryOperation.isFinished) {
            return standaloneServerQueryOperation.serverResponse!!.decodeBytes()
        }

        return null
    }

    override fun restoreProfile(
        snapshot: ObvSyncSnapshot?,
        deviceName: String?,
        serializedKeycloakAuthState: String?
    ): Boolean {
        var success = false
        try {
            getSession().use { engineSession ->
                engineSession.session.startTransaction()
                try {
                    val wrappedIdentityDelegate =
                        identityManager.getSyncDelegateWithinTransaction(engineSession.session)

                    val commitCallbackList: MutableList<RestoreFinishedCallback> = ArrayList()
                    engineSession.session.addSessionCommitListener {
                        for (callback in commitCallbackList) {
                            callback.onRestoreSuccess()
                        }
                    }

                    try {
                        // create the owned identity (and associated stuff) at engine level
                        val node = snapshot!!.getSnapshotNode(wrappedIdentityDelegate.tag)
                        val obvOwnedIdentity: ObvIdentity?
                        if (node is IdentityManagerSyncSnapshot) {
                            obvOwnedIdentity = identityManager.restoreTransferredOwnedIdentity(
                                engineSession.session,
                                deviceName,
                                node
                            )
                            if (serializedKeycloakAuthState != null) {
                                identityManager.saveKeycloakAuthState(
                                    engineSession.session,
                                    obvOwnedIdentity.getIdentity(),
                                    serializedKeycloakAuthState
                                )
                            }
                        } else {
                            throw Exception()
                        }

                        // give a chance for all delegates to create an owned identity based on what the engine just created
                        val callbacksOwnedIdentity = snapshot.restoreOwnedIdentity(
                            obvOwnedIdentity,
                            wrappedIdentityDelegate,
                            appBackupAndSyncDelegate!!
                        )
                        if (callbacksOwnedIdentity.isNotEmpty()) {
                            commitCallbackList.addAll(callbacksOwnedIdentity)
                        }


                        // actually restore the snapshot
                        val callbacks =
                            snapshot.restore(wrappedIdentityDelegate, appBackupAndSyncDelegate)

                        if (callbacks.isNotEmpty()) {
                            commitCallbackList.addAll(callbacks)
                        }
                    } catch (e: Exception) {
                        // if an exception occurs, always call the failure of any already added callback
                        for (callback in commitCallbackList) {
                            callback.onRestoreFailure()
                        }
                        throw e
                    }

                    try {
                        // trigger a download of all user data (including other identities, but we do not really care...)
                        identityManager.downloadAllUserData(engineSession.session)
                    } catch (_: Exception) {
                    }

                    // at the very end, add a final session commit listener that will be called after all engine notifications are sent
                    engineSession.session.addSessionCommitListener {
                        notificationManager.postNotification(
                            ProtocolNotifications.NOTIFICATION_SNAPSHOT_RESTORATION_FINISHED,
                            HashMap()
                        )
                    }

                    success = true
                } catch (e: Exception) {
                    Logger.x(e)
                } finally {
                    if (success) {
                        engineSession.session.commit()
                    } else {
                        engineSession.session.rollback()
                    }
                }
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
        return success
    }

    // legacy methods
    @Throws(Exception::class)
    override fun getBackupKeyInformation(): ObvBackupKeyInformation? {
        return backupManager.backupKeyInformation
    }

    override fun stopLegacyBackups() {
        backupManager.stopLegacyBackups()
    }

    override fun setAutoBackupEnabled(enabled: Boolean, initiateBackupNowIfNeeded: Boolean) {
        backupManager.setAutoBackupEnabled(enabled, initiateBackupNowIfNeeded)
    }

    override fun markBackupExported(backupKeyUid: ByteArray?, version: Int) {
        backupManager.markBackupExported(UID(backupKeyUid!!), version)
    }

    override fun markBackupUploaded(backupKeyUid: ByteArray?, version: Int) {
        backupManager.markBackupUploaded(UID(backupKeyUid!!), version)
    }

    override fun discardBackup(backupKeyUid: ByteArray?, version: Int) {
        backupManager.discardBackup(UID(backupKeyUid!!), version)
    }

    override fun validateBackupSeed(
        backupSeedString: String?,
        backupContent: ByteArray?
    ): ObvBackupKeyVerificationOutput {
        val status = backupManager.validateBackupSeed(backupSeedString, backupContent)
        when (status) {
            BackupManager.BACKUP_SEED_VERIFICATION_STATUS_SUCCESS -> return ObvBackupKeyVerificationOutput(
                ObvBackupKeyVerificationOutput.STATUS_SUCCESS
            )

            BackupManager.BACKUP_SEED_VERIFICATION_STATUS_TOO_SHORT -> return ObvBackupKeyVerificationOutput(
                ObvBackupKeyVerificationOutput.STATUS_TOO_SHORT
            )

            BackupManager.BACKUP_SEED_VERIFICATION_STATUS_TOO_LONG -> return ObvBackupKeyVerificationOutput(
                ObvBackupKeyVerificationOutput.STATUS_TOO_LONG
            )

            BackupManager.BACKUP_SEED_VERIFICATION_STATUS_BAD_KEY -> return ObvBackupKeyVerificationOutput(
                ObvBackupKeyVerificationOutput.STATUS_BAD_KEY
            )

            else -> return ObvBackupKeyVerificationOutput(ObvBackupKeyVerificationOutput.STATUS_BAD_KEY)
        }
    }

    override fun restoreOwnedIdentitiesFromBackup(
        backupSeed: String?,
        backupContent: ByteArray?,
        deviceDisplayName: String?
    ): Array<ObvIdentity?>? {
        return backupManager.restoreOwnedIdentitiesFromBackup(
            backupSeed,
            backupContent,
            deviceDisplayName
        )
    }

    override fun restoreContactsAndGroupsFromBackup(
        backupSeed: String?,
        backupContent: ByteArray?,
        restoredOwnedIdentities: Array<ObvIdentity?>?
    ) {
        backupManager.restoreContactsAndGroupsFromBackup(
            backupSeed,
            backupContent,
            restoredOwnedIdentities
        )
    }

    override fun decryptAppDataBackup(backupSeed: String?, backupContent: ByteArray?): String? {
        return backupManager.decryptAppDataBackup(backupSeed!!, backupContent!!)
    }

    override fun appBackupSuccess(
        bytesBackupKeyUid: ByteArray?,
        version: Int,
        appBackupContent: String?
    ) {
        backupManager.backupSuccess(
            BackupManager.APP_BACKUP_TAG,
            UID(bytesBackupKeyUid!!),
            version,
            appBackupContent
        )
    }

    override fun appBackupFailed(bytesBackupKeyUid: ByteArray?, version: Int) {
        backupManager.backupFailed(BackupManager.APP_BACKUP_TAG, UID(bytesBackupKeyUid!!), version)
    }


    // endregion
    // region Upgrade procedures and various DB stuff
    override fun getTurnCredentials(
        bytesOwnedIdentity: ByteArray?,
        callUuid: UUID?,
        callerUsername: String?,
        recipientUsername: String?
    ) {
        try {
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            fetchManager.getTurnCredentials(
                ownedIdentity,
                callUuid,
                callerUsername,
                recipientUsername
            )
        } catch (e: DecodingException) {
            Logger.x(e)
        }
    }

    override fun getWellKnownTurnServers(bytesOwnedIdentity: ByteArray?): MutableList<String>? {
        try {
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            return fetchManager.getWellKnownTurnServers(ownedIdentity)
        } catch (e: DecodingException) {
            Logger.x(e)
        }
        return null
    }

    override fun getWellKnownAltTurnServers(bytesOwnedIdentity: ByteArray?): MutableList<String>? {
        try {
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            return fetchManager.getWellKnownAltTurnServers(ownedIdentity)
        } catch (e: DecodingException) {
            Logger.x(e)
        }
        return null
    }

    override fun queryApiKeyStatus(bytesOwnedIdentity: ByteArray?, apiKey: UUID?) {
        try {
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            fetchManager.queryApiKeyStatus(ownedIdentity, apiKey)
        } catch (e: DecodingException) {
            Logger.x(e)
        }
    }

    override fun queryApiKeyStatus(server: String?, apiKey: UUID?) {
        // generate a dummy identity to query the server
        val anonAuthKeyPair = EncryptionEciesMDCKeyPair.generate(prng)
        val serverAuthKeyPair = ServerAuthenticationECSdsaMDCKeyPair.generate(prng)
        if (anonAuthKeyPair != null && serverAuthKeyPair != null) {
            val dummyIdentity =
                Identity(server!!, serverAuthKeyPair.getPublicKey(), anonAuthKeyPair.getPublicKey())
            fetchManager.queryApiKeyStatus(dummyIdentity, apiKey)
        }
    }

    override fun queryFreeTrial(bytesOwnedIdentity: ByteArray?) {
        try {
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            fetchManager.queryFreeTrial(ownedIdentity)
        } catch (e: DecodingException) {
            Logger.x(e)
        }
    }

    override fun startFreeTrial(bytesOwnedIdentity: ByteArray?) {
        try {
            getSession().use { engineSession ->
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                // do not allow free trial start for keycloak managed identities
                if (!identityManager.isOwnedIdentityKeycloakManaged(
                        engineSession.session,
                        ownedIdentity
                    )
                ) {
                    fetchManager.startFreeTrial(ownedIdentity)
                }
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    override fun verifyReceipt(bytesOwnedIdentity: ByteArray?, storeToken: String?) {
        try {
            getSession().use { engineSession ->
                val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
                // do not allow in-app purchases for keycloak managed identities
                if (!identityManager.isOwnedIdentityKeycloakManaged(
                        engineSession.session,
                        ownedIdentity
                    )
                ) {
                    fetchManager.verifyReceipt(ownedIdentity, storeToken)
                }
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    override fun queryServerWellKnown(server: String?) {
        fetchManager.queryServerWellKnown(server)
    }

    override fun getOsmStyles(bytesOwnedIdentity: ByteArray?): MutableList<JsonOsmStyle>? {
        try {
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            return fetchManager.getOsmStyles(ownedIdentity.server)
        } catch (_: Exception) {
            return null
        }
    }

    override fun getAddressServerUrl(bytesOwnedIdentity: ByteArray?): String? {
        try {
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            return fetchManager.getAddressServerUrl(ownedIdentity.server)
        } catch (_: Exception) {
            return null
        }
    }


    @Throws(Exception::class)
    override fun propagateAppSyncAtomToAllOwnedIdentitiesOtherDevicesIfNeeded(obvSyncAtom: ObvSyncAtom) {
        // the App should never be sending a non-app sync item
        if (!obvSyncAtom.isAppSyncItem) {
            throw Exception()
        }

        getSession().use { engineSession ->
            for (ownedIdentity in identityManager.getOwnedIdentities(engineSession.session)) {
                if (identityManager.getOtherDeviceUidsOfOwnedIdentity(
                        engineSession.session,
                        ownedIdentity
                    )?.isNotEmpty() == true
                ) {
                    protocolManager.initiateSingleItemSync(
                        engineSession.session,
                        ownedIdentity,
                        obvSyncAtom
                    )
                }
            }
            engineSession.session.commit()
        }
    }

    @Throws(Exception::class)
    override fun propagateAppSyncAtomToOtherDevicesIfNeeded(
        bytesOwnedIdentity: ByteArray?,
        obvSyncAtom: ObvSyncAtom
    ) {
        // the App should never be sending a non-app sync item
        if (!obvSyncAtom.isAppSyncItem) {
            throw Exception()
        }

        getSession().use { engineSession ->
            val ownedIdentity = Identity.of(bytesOwnedIdentity!!)
            if (identityManager.getOtherDeviceUidsOfOwnedIdentity(
                    engineSession.session,
                    ownedIdentity
                )?.isNotEmpty() == true
            ) {
                protocolManager.initiateSingleItemSync(
                    engineSession.session,
                    ownedIdentity,
                    obvSyncAtom
                )
                engineSession.session.commit()
            }
        }
    }

    @Throws(Exception::class)
    private fun propagateEngineSyncAtomToOtherDevicesIfNeeded(
        session: Session,
        ownedIdentity: Identity?,
        obvSyncAtom: ObvSyncAtom
    ): Boolean {
        // the App should never be sending a non-app sync item
        if (obvSyncAtom.isAppSyncItem) {
            throw Exception()
        }

        if (identityManager.getOtherDeviceUidsOfOwnedIdentity(
                session,
                ownedIdentity
            )?.isNotEmpty() == true
        ) {
            protocolManager.initiateSingleItemSync(session, ownedIdentity, obvSyncAtom)
            return true
        }
        return false
    }


    // Run once after you upgrade from a version not handling Contact and ContactGroup UserData to a version able to do so
    // Also run after a backup restore
    @Throws(Exception::class)
    override fun downloadAllUserData() {
        getSession().use { engineSession ->
            engineSession.session.startTransaction()
            identityManager.downloadAllUserData(engineSession.session)
            engineSession.session.commit()
        }
    }

    // Run once after the first introduction of device names for multi-device
    override fun setAllOwnedDeviceNames(deviceName: String?) {
        try {
            getSession().use { engineSession ->
                for (ownedIdentity in identityManager.getOwnedIdentities(engineSession.session)) {
                    val currentDeviceUid = identityManager.getCurrentDeviceUidOfOwnedIdentity(
                        engineSession.session,
                        ownedIdentity
                    )
                    protocolManager.processDeviceManagementRequest(
                        engineSession.session,
                        ownedIdentity,
                        ObvDeviceManagementRequest.createSetNicknameRequest(
                            currentDeviceUid!!.bytes,
                            deviceName
                        )
                    )
                }
                engineSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    @Throws(Exception::class)
    override fun vacuumDatabase() {
        getSession().use { engineSession ->
            engineSession.session.createStatement("Engine.vacuumDatabase").use { statement ->
                statement.execute("VACUUM")
                statement.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                engineSession.session.commit()
            }
        }
    } // endregion
    // endregion

    companion object {
        const val SYNCHRONIZED_TASK: String = "synchronized_task"

        @Throws(SQLException::class)
        private fun upgradeTables(session: Session, oldVersion: Int, newVersion: Int) {
            UserInterfaceDialog.upgradeTable(session, oldVersion, newVersion)
        }
    }
}
