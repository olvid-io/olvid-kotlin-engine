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
package io.olvid.engine.backup

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.backup.databases.Backup
import io.olvid.engine.backup.databases.BackupKey
import io.olvid.engine.backup.databases.DeviceBackupSeed
import io.olvid.engine.backup.databases.ProfileBackupThreadId
import io.olvid.engine.backup.datatypes.BackupManagerSession
import io.olvid.engine.backup.datatypes.BackupManagerSessionFactory
import io.olvid.engine.backup.datatypes.BackupTaskStatus
import io.olvid.engine.backup.tasks.DeviceBackupDeleteTask
import io.olvid.engine.backup.tasks.DeviceBackupFetchTask
import io.olvid.engine.backup.tasks.DeviceBackupUploadTask
import io.olvid.engine.backup.tasks.ProfileBackupSnapshotDeleteTask
import io.olvid.engine.backup.tasks.ProfileBackupUploadTask
import io.olvid.engine.backup.tasks.ProfileBackupsFetchTask
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.BackupSeed
import io.olvid.engine.datatypes.BackupSeed.DerivedKeys
import io.olvid.engine.datatypes.BackupSeed.SeedTooLongException
import io.olvid.engine.datatypes.BackupSeed.SeedTooShortException
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoExceptionSingleThreadExecutor
import io.olvid.engine.datatypes.NotificationListener
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.notifications.BackupNotifications
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.engine.types.ObvBackupKeyInformation
import io.olvid.engine.engine.types.ObvDeviceBackupForRestore
import io.olvid.engine.engine.types.ObvProfileBackupsForRestore
import io.olvid.engine.engine.types.identities.ObvIdentity
import io.olvid.engine.engine.types.sync.ObvBackupAndSyncDelegate
import io.olvid.engine.metamanager.BackupDelegate
import io.olvid.engine.metamanager.BackupV2Delegate
import io.olvid.engine.metamanager.CreateSessionDelegate
import io.olvid.engine.metamanager.IdentityDelegate
import io.olvid.engine.metamanager.MetaManager
import io.olvid.engine.metamanager.NotificationListeningDelegate
import io.olvid.engine.metamanager.NotificationPostingDelegate
import io.olvid.engine.metamanager.ObvManager
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.sql.SQLException
import java.util.Random
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.zip.Inflater
import java.util.zip.InflaterInputStream
import javax.net.ssl.SSLSocketFactory
import kotlin.math.min


class BackupManager(
    metaManager: MetaManager,
    private val appBackupAndSyncDelegates: ObvBackupAndSyncDelegate?,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?,
    private val prng: PRNGService,
    @JvmField val jsonObjectMapper: ObjectMapper
) : BackupDelegate, BackupV2Delegate, BackupManagerSessionFactory, ObvManager,
    NotificationListener {
    private var createSessionDelegate: CreateSessionDelegate? = null
    private var identityDelegate: IdentityDelegate? = null
    private var notificationPostingDelegate: NotificationPostingDelegate? = null

    private val executor: NoExceptionSingleThreadExecutor
    private val autoBackupScheduler: ScheduledExecutorService

    // for legacy backups
    private var autoBackupEnabled: Boolean
    private var autoBackupIsScheduled: Boolean
    private var scheduledAutoBackupTask: ScheduledFuture<*>? = null
    private val autoBackupSchedulerLock: Any
    private val ongoingBackupMap: MutableMap<UidAndVersion?, MutableMap<String?, String?>?>
    private val ongoingBackupTimeoutMap: MutableMap<UidAndVersion?, ScheduledFuture<*>?>

    // for backup v2
    private var deviceBackupsActive: Boolean
    private val scheduledBackups: MutableSet<ScheduledBackup>
    private var nextScheduledBackupTimestamp: Long?

    init {
        this.executor = NoExceptionSingleThreadExecutor("BackupManager executor")
        this.autoBackupScheduler = Executors.newScheduledThreadPool(1)
        this.autoBackupEnabled = false
        this.autoBackupIsScheduled = false
        this.autoBackupSchedulerLock = Any()
        this.ongoingBackupMap = HashMap()
        this.ongoingBackupTimeoutMap = HashMap()

        this.deviceBackupsActive = false
        this.scheduledBackups = HashSet()
        this.nextScheduledBackupTimestamp = null

        metaManager.requestDelegate(this, CreateSessionDelegate::class.java)
        metaManager.requestDelegate(this, IdentityDelegate::class.java)
        metaManager.requestDelegate(this, NotificationPostingDelegate::class.java)
        metaManager.requestDelegate(this, NotificationListeningDelegate::class.java)
        metaManager.registerImplementedDelegates(this)
    }

    override fun initialQueueingPriority(): Int {
        return 40
    }

    override fun initialisationComplete() {
        // clear obsolete backups
        try {
            session.use { backupManagerSession ->
                for (backupKey in BackupKey.getAll(backupManagerSession)) {
                    Backup.cleanup(
                        backupManagerSession,
                        backupKey.uid,
                        backupKey.uploadedBackupVersion,
                        backupKey.exportedBackupVersion,
                        backupKey.latestBackupVersion
                    )
                }
                backupManagerSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }

        // backups v2
        try {
            session.use { backupManagerSession ->
                val deviceBackupSeed: DeviceBackupSeed? =
                    DeviceBackupSeed.getActive(backupManagerSession)
                if (deviceBackupSeed != null) {
                    scheduleDeviceAndAllProfilesBackup(backupManagerSession, deviceBackupSeed)
                }
                for (inactiveDeviceBackupSeed in DeviceBackupSeed.getAllInactive(
                    backupManagerSession
                )) {
                    cleanUpDeviceBackups(inactiveDeviceBackupSeed!!.backupSeed)
                }
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    fun setDelegate(createSessionDelegate: CreateSessionDelegate) {
        this.createSessionDelegate = createSessionDelegate

        try {
            session.use { backupManagerSession ->
                Backup.createTable(backupManagerSession.session)
                BackupKey.createTable(backupManagerSession.session)
                DeviceBackupSeed.createTable(backupManagerSession.session)
                ProfileBackupThreadId.createTable(backupManagerSession.session)
                backupManagerSession.session.commit()
            }
        } catch (e: SQLException) {
            Logger.x(e)
            throw RuntimeException("Unable to create backup databases")
        }
    }

    fun setDelegate(identityDelegate: IdentityDelegate) {
        this.identityDelegate = identityDelegate
    }

    fun setDelegate(notificationPostingDelegate: NotificationPostingDelegate) {
        this.notificationPostingDelegate = notificationPostingDelegate
    }

    fun setDelegate(notificationListeningDelegate: NotificationListeningDelegate) {
        notificationListeningDelegate.addListener(
            IdentityNotifications.NOTIFICATION_DATABASE_CONTENT_CHANGED,
            this
        )
        notificationListeningDelegate.addListener(
            BackupNotifications.NOTIFICATION_DEVICE_BACKUP_NEEDED,
            this
        )
        notificationListeningDelegate.addListener(
            BackupNotifications.NOTIFICATION_PROFILE_BACKUP_NEEDED,
            this
        )
    }

    @get:Throws(SQLException::class)
    override val session: BackupManagerSession
        get() {
            if (createSessionDelegate == null) {
                throw SQLException("No CreateSessionDelegate was set in BackupManager.")
            }
            return BackupManagerSession(
                createSessionDelegate!!.session,
                notificationPostingDelegate,
                identityDelegate,
                appBackupAndSyncDelegates,
                jsonObjectMapper,
                prng
            )
        }


    // region backup v2 scheduling
    fun retryScheduledNetworkTasks() {
        synchronized(scheduledBackups) {
            for (scheduledBackup in scheduledBackups) {
                scheduledBackup.clearFailedAttemptCounts()
            }
            executeScheduledBackupsThatReachedTheirTimestamp()
        }
    }

    @Throws(SQLException::class)
    private fun scheduleDeviceAndAllProfilesBackup(
        backupManagerSession: BackupManagerSession,
        deviceBackupSeed: DeviceBackupSeed
    ) {
        deviceBackupsActive = true
        scheduleDeviceBackup(deviceBackupSeed.nextBackupTimestamp)

        var commitNeeded = false
        // first make sure all owned identities have a ProfileBackupThreadId
        val profileBackupThreadIds: MutableList<ProfileBackupThreadId> =
            ProfileBackupThreadId.getAll(backupManagerSession)
        val ownedIdentities = HashSet(
            identityDelegate!!.getOwnedIdentities(backupManagerSession.session).toList()
        )
        for (profileBackupThreadId in profileBackupThreadIds) {
            if (!ownedIdentities.remove(profileBackupThreadId.ownedIdentity)) {
                Logger.w("Found a ProfileBackupThreadId for an unknown OwnedIdentity --> cleaning it up!")
                profileBackupThreadId.delete()
                commitNeeded = true
            }
        }

        // left over ownedIdentities are missing ProfileBackupThreadId --> create them
        for (ownedIdentity in ownedIdentities) {
            Logger.i("Found an ownedIdentity without a ProfileBackupThreadId --> creating one!")
            val profileBackupThreadId: ProfileBackupThreadId? =
                ProfileBackupThreadId.create(backupManagerSession, ownedIdentity, prng)
            if (profileBackupThreadId != null) {
                profileBackupThreadIds.add(profileBackupThreadId)
                commitNeeded = true
            }
        }

        if (commitNeeded) {
            backupManagerSession.session.commit()
        }

        for (profileBackupThreadId in profileBackupThreadIds) {
            scheduleProfileBackup(
                profileBackupThreadId.ownedIdentity,
                profileBackupThreadId.nextBackupTimestamp
            )
        }
    }


    private fun scheduleDeviceBackup(timestamp: Long) {
        synchronized(scheduledBackups) {
            for (scheduledBackup in scheduledBackups) {
                if (scheduledBackup.ownedIdentity == null) {
                    if (scheduledBackup.timestamp < timestamp) {
                        // we already planned a backup sooner --> nothing to do
                        return
                    } else {
                        // the new timestamp comes sooner --> remove old ScheduledBackup
                        scheduledBackups.remove(scheduledBackup)
                        break
                    }
                }
            }
            // insert the ScheduledBackup
            insertScheduledBackup(ScheduledBackup(null, timestamp))
        }
    }

    private fun scheduleProfileBackup(ownedIdentity: Identity?, timestamp: Long) {
        synchronized(scheduledBackups) {
            for (scheduledBackup in scheduledBackups) {
                if (scheduledBackup.ownedIdentity == ownedIdentity) {
                    if (scheduledBackup.timestamp < timestamp) {
                        // we already planned a backup sooner --> nothing to do
                        return
                    } else {
                        // the new timestamp comes sooner --> remove old ScheduledBackup
                        scheduledBackups.remove(scheduledBackup)
                        break
                    }
                }
            }
            // insert the ScheduledBackup
            insertScheduledBackup(ScheduledBackup(ownedIdentity, timestamp))
        }
    }

    private fun cancelScheduledDeviceAndProfileBackups() {
        synchronized(scheduledBackups) {
            scheduledBackups.clear()
        }
    }

    private fun insertScheduledBackup(scheduledBackup: ScheduledBackup) {
        synchronized(scheduledBackups) {
            scheduledBackups.add(scheduledBackup)
            if (scheduledBackup.scheduledTimestamp > System.currentTimeMillis()) {
                // this backup should be scheduled in the future
                if (nextScheduledBackupTimestamp == null || scheduledBackup.scheduledTimestamp < nextScheduledBackupTimestamp!!) {
                    // this will be the next backup --> schedule a task
                    nextScheduledBackupTimestamp = scheduledBackup.scheduledTimestamp
                    autoBackupScheduler.schedule(
                        { this.executeScheduledBackupsThatReachedTheirTimestamp() },
                        scheduledBackup.scheduledTimestamp - System.currentTimeMillis(),
                        TimeUnit.MILLISECONDS
                    )
                }
            } else {
                executeScheduledBackupsThatReachedTheirTimestamp()
            }
        }
    }

    private fun executeScheduledBackupsThatReachedTheirTimestamp() {
        synchronized(scheduledBackups) {
            val now = System.currentTimeMillis()
            var nextTimestamp: Long? = null
            for (scheduledBackup in ArrayList<ScheduledBackup>(scheduledBackups)) {
                if (scheduledBackup.scheduledTimestamp < now) {
                    scheduledBackups.remove(scheduledBackup)
                    initiateBackup(scheduledBackup)
                } else {
                    if (nextTimestamp == null || scheduledBackup.scheduledTimestamp < nextTimestamp) {
                        nextTimestamp = scheduledBackup.scheduledTimestamp
                    }
                }
            }
            if (nextTimestamp != null) {
                nextScheduledBackupTimestamp = nextTimestamp
                autoBackupScheduler.schedule(
                    { this.executeScheduledBackupsThatReachedTheirTimestamp() },
                    nextTimestamp - System.currentTimeMillis(),
                    TimeUnit.MILLISECONDS
                )
            }
        }
    }

    private fun initiateBackup(scheduledBackup: ScheduledBackup) {
        executor.execute {
            if (scheduledBackup.ownedIdentity == null) {
                val deviceBackupUploadTask =
                    DeviceBackupUploadTask(this, sslSocketFactory, userAgentOverride)
                when (deviceBackupUploadTask.execute()) {
                    BackupTaskStatus.SUCCESS -> {
                        // backup successful --> update nextBackupTimestamp and reschedule
                        try {
                            session.use { backupManagerSession ->
                                val deviceBackupSeed: DeviceBackupSeed? =
                                    DeviceBackupSeed.getActive(backupManagerSession)
                                if (deviceBackupSeed != null) {
                                    val nextBackupTimestamp =
                                        System.currentTimeMillis() + Constants.DEVICE_BACKUP_INTERVAL
                                    deviceBackupSeed.updateNextBackupTimestamp(nextBackupTimestamp)
                                    backupManagerSession.session.commit()
                                    scheduleDeviceBackup(nextBackupTimestamp)
                                }
                            }
                        } catch (e: Exception) {
                            Logger.x(e)
                        }
                    }

                    BackupTaskStatus.RETRIABLE_FAILURE -> {
                        synchronized(scheduledBackups) {
                            scheduledBackup.rescheduleAfterRetriableFailure()
                            insertScheduledBackup(scheduledBackup)
                        }
                    }

                    BackupTaskStatus.PERMANENT_FAILURE -> {
                        // nothing to do, but this should only happen if the device backupSeed was cleared
                    }
                }
            } else {
                val profileBackupUploadTask = ProfileBackupUploadTask(
                    this,
                    sslSocketFactory,
                    userAgentOverride,
                    scheduledBackup.ownedIdentity
                )
                when (profileBackupUploadTask.execute()) {
                    BackupTaskStatus.SUCCESS -> {
                        // backup successful --> update nextBackupTimestamp and reschedule
                        try {
                            session.use { backupManagerSession ->
                                val profileBackupThreadId: ProfileBackupThreadId? =
                                    ProfileBackupThreadId.get(
                                        backupManagerSession,
                                        scheduledBackup.ownedIdentity
                                    )
                                if (profileBackupThreadId != null) {
                                    val nextBackupTimestamp =
                                        System.currentTimeMillis() + Constants.PROFILE_BACKUP_INTERVAL
                                    profileBackupThreadId.updateNextBackupTimestamp(
                                        nextBackupTimestamp
                                    )
                                    backupManagerSession.session.commit()
                                    scheduleProfileBackup(
                                        scheduledBackup.ownedIdentity,
                                        nextBackupTimestamp
                                    )
                                }
                            }
                        } catch (e: Exception) {
                            Logger.x(e)
                        }
                    }

                    BackupTaskStatus.RETRIABLE_FAILURE -> {
                        synchronized(scheduledBackups) {
                            scheduledBackup.rescheduleAfterRetriableFailure()
                            insertScheduledBackup(scheduledBackup)
                        }
                    }

                    BackupTaskStatus.PERMANENT_FAILURE -> {
                        // nothing to do, but this should only happen if the profile no longer exists on the device or if the device backupSeed was cleared
                    }
                }
            }
        }
    }


    private fun cleanUpDeviceBackups(backupSeed: BackupSeed) {
        executor.execute {
            val deviceBackupDeleteTask =
                DeviceBackupDeleteTask(this, sslSocketFactory, userAgentOverride, backupSeed)
            when (deviceBackupDeleteTask.execute()) {
                BackupTaskStatus.SUCCESS -> {
                    // delete successful --> delete the DeviceBackupSeed (if indeed inactive !)
                    try {
                        session.use { backupManagerSession ->
                            val deviceBackupSeed: DeviceBackupSeed? =
                                DeviceBackupSeed.get(backupManagerSession, backupSeed)
                            if (deviceBackupSeed != null && !deviceBackupSeed.isActive) {
                                deviceBackupSeed.delete()
                                backupManagerSession.session.commit()
                            }
                        }
                    } catch (e: Exception) {
                        Logger.x(e)
                    }
                }

                BackupTaskStatus.RETRIABLE_FAILURE -> autoBackupScheduler.schedule({
                    cleanUpDeviceBackups(
                        backupSeed
                    )
                }, 5, TimeUnit.MINUTES)

                BackupTaskStatus.PERMANENT_FAILURE -> {
                    // nothing to do
                }
            }
        }
    }


    // endregion
    // region implement BackupV2Delegate
    @Throws(Exception::class)
    override fun generateDeviceBackupSeed(server: String?): String? {
        session.use { backupManagerSession ->
            synchronized(this) {
                var deviceBackupSeed: DeviceBackupSeed? =
                    DeviceBackupSeed.getActive(backupManagerSession)
                if (deviceBackupSeed != null) {
                    throw Exception("A DeviceBackupSeed already exists")
                }
                deviceBackupSeed =
                    DeviceBackupSeed.create(backupManagerSession, BackupSeed.generate(prng), server)
                if (deviceBackupSeed != null) {
                    // also reset the nextBackupTimestamp of all ProfileBackupThreadId
                    for (profileBackupThreadId in ProfileBackupThreadId.getAll(
                        backupManagerSession
                    )) {
                        profileBackupThreadId.updateNextBackupTimestamp(0L)
                    }
                    backupManagerSession.session.commit()
                    scheduleDeviceAndAllProfilesBackup(backupManagerSession, deviceBackupSeed)
                    return deviceBackupSeed.backupSeed.toString()
                }
            }
        }
        return null
    }

    @get:Throws(Exception::class)
    override val currentDeviceBackupSeed: String?
        get() {
            session.use { backupManagerSession ->
                val deviceBackupSeed: DeviceBackupSeed? =
                    DeviceBackupSeed.getActive(backupManagerSession)
                if (deviceBackupSeed != null) {
                    return deviceBackupSeed.backupSeed.toString()
                }
            }
            return null
        }

    @Throws(Exception::class)
    override fun deleteDeviceBackupSeed(backupSeed: BackupSeed?) {
        session.use { backupManagerSession ->
            val deviceBackupSeed: DeviceBackupSeed? =
                DeviceBackupSeed.getActive(backupManagerSession)
            if (deviceBackupSeed != null && deviceBackupSeed.backupSeed == backupSeed) {
                deviceBackupSeed.markBackupKeyInactive()
                backupManagerSession.session.commit()
                cancelScheduledDeviceAndProfileBackups()
                cleanUpDeviceBackups(deviceBackupSeed.backupSeed)
            }
        }
    }

    override fun backupDeviceAndProfilesNow(): Boolean {
        try {
            session.use { backupManagerSession ->
                if (DeviceBackupSeed.getActive(backupManagerSession) != null) {
                    scheduleDeviceBackup(0L)

                    val ownedIdentities = HashSet<Identity?>()
                    for (ownedIdentity in backupManagerSession.identityDelegate!!.getOwnedIdentities(
                        backupManagerSession.session
                    )) {
                        scheduleProfileBackup(ownedIdentity, 0L)
                        ownedIdentities.add(ownedIdentity)
                    }

                    val lock = Any()
                    val success = AtomicBoolean(false)
                    // we post this on the executor so it is executed once all backups are finished
                    // if no backup was re-queued with a failed attempt count, everything went as expected
                    executor.execute {
                        try {
                            var allGood = true
                            synchronized(scheduledBackups) {
                                for (scheduledBackup in scheduledBackups) {
                                    if (scheduledBackup.failedAttemptCounts != 0
                                        && (scheduledBackup.ownedIdentity == null || ownedIdentities.contains(
                                            scheduledBackup.ownedIdentity
                                        ))
                                    ) {
                                        allGood = false
                                        break
                                    }
                                }
                            }
                            success.set(allGood)
                        } finally {
                            synchronized(lock) {
                                (lock as Object).notify()
                            }
                        }
                    }
                    // wait for the check to execute
                    synchronized(lock) {
                        try {
                            (lock as Object).wait()
                        } catch (_: InterruptedException) {
                        }
                    }
                    return success.get()
                }
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
        return false
    }

    override fun fetchDeviceBackup(
        server: String?,
        backupSeed: BackupSeed?
    ): ObvDeviceBackupForRestore? {
        val deviceBackupFetchTask =
            DeviceBackupFetchTask(server, backupSeed!!, this, sslSocketFactory, userAgentOverride)
        when (deviceBackupFetchTask.execute()) {
            BackupTaskStatus.SUCCESS -> {
                // download successful
                return deviceBackupFetchTask.obvDeviceBackupForRestore
            }

            BackupTaskStatus.RETRIABLE_FAILURE -> {
                if (deviceBackupFetchTask.obvDeviceBackupForRestore != null) {
                    return deviceBackupFetchTask.obvDeviceBackupForRestore
                }
            }

            BackupTaskStatus.PERMANENT_FAILURE -> {
                if (deviceBackupFetchTask.obvDeviceBackupForRestore != null) {
                    return deviceBackupFetchTask.obvDeviceBackupForRestore
                }
                return ObvDeviceBackupForRestore(
                    ObvDeviceBackupForRestore.Status.PERMANENT_ERROR,
                    null,
                    null
                )
            }
        }
        return ObvDeviceBackupForRestore(ObvDeviceBackupForRestore.Status.ERROR, null, null)
    }

    override fun fetchProfileBackups(
        server: String?,
        backupSeed: BackupSeed?
    ): ObvProfileBackupsForRestore? {
        val profileBackupsFetchTask =
            ProfileBackupsFetchTask(server, backupSeed!!, this, sslSocketFactory, userAgentOverride)
        when (profileBackupsFetchTask.execute()) {
            BackupTaskStatus.SUCCESS -> {
                // download successful
                return profileBackupsFetchTask.obvProfileBackupsForRestore
            }

            BackupTaskStatus.RETRIABLE_FAILURE -> {
                if (profileBackupsFetchTask.obvProfileBackupsForRestore != null) {
                    return profileBackupsFetchTask.obvProfileBackupsForRestore
                }
            }

            BackupTaskStatus.PERMANENT_FAILURE -> {
                if (profileBackupsFetchTask.obvProfileBackupsForRestore != null) {
                    return profileBackupsFetchTask.obvProfileBackupsForRestore
                }
                return ObvProfileBackupsForRestore(
                    ObvProfileBackupsForRestore.Status.PERMANENT_ERROR,
                    null,
                    null
                )
            }
        }
        return ObvProfileBackupsForRestore(ObvProfileBackupsForRestore.Status.ERROR, null, null)
    }

    override fun deleteProfileBackupSnapshot(
        server: String?,
        backupSeed: BackupSeed?,
        backupThreadId: UID?,
        version: Long
    ): Boolean {
        val profileBackupSnapshotDeleteTask = ProfileBackupSnapshotDeleteTask(
            server,
            backupSeed!!,
            backupThreadId!!,
            version,
            prng,
            sslSocketFactory,
            userAgentOverride
        )
        return when (profileBackupSnapshotDeleteTask.execute()) {
            BackupTaskStatus.SUCCESS -> {
                true
            }

            BackupTaskStatus.RETRIABLE_FAILURE, BackupTaskStatus.PERMANENT_FAILURE -> {
                false
            }
        }
    }


    // endregion
    // region implement BackupDelegate
    //    @Override
    //    public void generateNewBackupKey() {
    //        try {
    //            BackupSeed backupSeed = BackupSeed.generate(prng);
    //            if (backupSeed == null) {
    //                throw new Exception("Failed to generate BackupSeed");
    //            }
    //            BackupSeed.DerivedKeys derivedKeys = backupSeed.deriveKeys();
    //            if (derivedKeys == null) {
    //                throw new Exception("Failed to derive keys from BackupSeed");
    //            }
    //            try (BackupManagerSession backupManagerSession = getSession()) {
    //                backupManagerSession.session.startTransaction();
    //                BackupKey.deleteAll(backupManagerSession);
    //                BackupKey.create(backupManagerSession, derivedKeys.backupKeyUid, derivedKeys.encryptionKeyPair.getPublicKey(), derivedKeys.macKey);
    //                backupManagerSession.session.commit();
    //
    //                // if autobackup is active --> immediately backup
    //                if (autoBackupEnabled) {
    //                    initiateBackup(false);
    //                }
    //
    //                HashMap<String, Object> userInfo = new HashMap<>();
    //                userInfo.put(BackupNotifications.NOTIFICATION_NEW_BACKUP_SEED_GENERATED_SEED_KEY, backupSeed.toString());
    //                notificationPostingDelegate.postNotification(BackupNotifications.NOTIFICATION_NEW_BACKUP_SEED_GENERATED, userInfo);
    //            } catch (SQLException e) {
    //                Logger.x(e);
    //                throw new Exception("Failed to save new BackupKey to database");
    //            }
    //        } catch (Exception e) {
    //            Logger.x(e);
    //            notificationPostingDelegate.postNotification(BackupNotifications.NOTIFICATION_BACKUP_SEED_GENERATION_FAILED, new HashMap<>());
    //        }
    //    }
    //    @Override
    //    public int verifyBackupKey(String seedString) {
    //        try (BackupManagerSession backupManagerSession = getSession()) {
    //            BackupKey[] backupKeys = BackupKey.getAll(backupManagerSession);
    //            if (backupKeys.length == 0) {
    //                throw new Exception("No BackupKey generated!");
    //            } else if (backupKeys.length > 1) {
    //                throw new Exception("Multiple BackupKey generated, this should never occur!");
    //            }
    //            BackupKey backupKey = backupKeys[0];
    //
    //            BackupSeed backupSeed = new BackupSeed(seedString);
    //            BackupSeed.DerivedKeys derivedKeys = backupSeed.deriveKeys();
    //
    //            if (derivedKeys.macKey.equals(backupKey.getMacKey()) &&
    //                    derivedKeys.encryptionKeyPair.getPublicKey().equals(backupKey.getEncryptionPublicKey())) {
    //                // we have the same keys, everything is fine
    //                backupKey.addSuccessfulVerification();
    //
    //                notificationPostingDelegate.postNotification(BackupNotifications.NOTIFICATION_BACKUP_VERIFICATION_SUCCESSFUL, Collections.emptyMap());
    //                return BACKUP_SEED_VERIFICATION_STATUS_SUCCESS;
    //            }
    //            return BACKUP_SEED_VERIFICATION_STATUS_BAD_KEY;
    //        } catch (BackupSeed.SeedTooShortException e) {
    //            return BACKUP_SEED_VERIFICATION_STATUS_TOO_SHORT;
    //        } catch (BackupSeed.SeedTooLongException e) {
    //            return BACKUP_SEED_VERIFICATION_STATUS_TOO_LONG;
    //        } catch (Exception e) {
    //            return BACKUP_SEED_VERIFICATION_STATUS_BAD_KEY;
    //        }
    //    }
    override fun stopLegacyBackups() {
        autoBackupEnabled = false
        try {
            session.use { backupManagerSession ->
                BackupKey.deleteAll(backupManagerSession)
                backupManagerSession.session.commit()
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    override fun setAutoBackupEnabled(enabled: Boolean, initiateBackupNowIfNeeded: Boolean) {
        autoBackupEnabled = enabled
        if (!enabled || !initiateBackupNowIfNeeded) {
            return
        }

        // check the last time a backup was uploaded and initiate one if this was long ago
        try {
            session.use { backupManagerSession ->
                val backupKeys: Array<BackupKey> = BackupKey.getAll(backupManagerSession)
                if (backupKeys.size == 1) {
                    val backupKey = backupKeys[0]
                    val lastUploadedBackup = backupKey.uploadedBackup
                    if (lastUploadedBackup == null || (backupKey.latestBackupVersion != null && backupKey.latestBackupVersion!! > lastUploadedBackup.version)
                        || ((System.currentTimeMillis() - lastUploadedBackup.statusChangeTimestamp) > Constants.AUTOBACKUP_MAX_INTERVAL)
                        || lastUploadedBackup.backupJsonVersion != Constants.CURRENT_BACKUP_JSON_VERSION
                    ) {
                        scheduleBackupForUploadIfNeeded(true)
                    }
                }
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    override fun initiateBackup(forExpert: Boolean) {
        executor.execute {
            try {
                session.use { backupManagerSession ->
                    val backupKeys: Array<BackupKey> =
                        BackupKey.getAll(backupManagerSession)
                    if (backupKeys.isEmpty()) {
                        throw Exception("No BackupKey generated!")
                    } else if (backupKeys.size > 1) {
                        throw Exception("Multiple BackupKey generated, this should never occur!")
                    }
                    val backupKey = backupKeys[0]

                    Logger.d("Initiating a backup")
                    backupManagerSession.session.startTransaction()
                    var newVersion = backupKey.latestBackupVersion
                    if (newVersion == null) {
                        newVersion = 0
                    } else {
                        newVersion++
                    }
                    val backup: Backup = Backup.createOngoingBackup(
                        backupManagerSession,
                        backupKey.uid,
                        newVersion,
                        forExpert
                    ) ?: throw Exception("BackupManager failed to create ongoing backup in DB")
                    backupKey.setLatestBackupVersion(newVersion)
                    backupManagerSession.session.commit()

                    val uidAndVersion = UidAndVersion(backupKey.uid, newVersion)
                    ongoingBackupMap.remove(uidAndVersion)
                    ongoingBackupMap[uidAndVersion] = HashMap()

                    val previousTimeout = ongoingBackupTimeoutMap.remove(uidAndVersion)
                    previousTimeout?.cancel(false)

                    val finalNewVersion = newVersion
                    ongoingBackupTimeoutMap[uidAndVersion] = autoBackupScheduler.schedule({
                        backupFailed(
                            "TIMEOUT",
                            backupKey.uid,
                            finalNewVersion
                        )
                    }, 30000, TimeUnit.MILLISECONDS)

                    // request backup from identityManager
                    identityDelegate!!.initiateBackup(
                        this,
                        IDENTITY_BACKUP_TAG,
                        backupKey.uid,
                        newVersion
                    )

                    // request backup from App (through notification)
                    val userInfo = HashMap<String, Any>()
                    userInfo[BackupNotifications.NOTIFICATION_APP_BACKUP_INITIATION_REQUEST_BACKUP_KEY_UID_KEY] =
                        backupKey.uid
                    userInfo[BackupNotifications.NOTIFICATION_APP_BACKUP_INITIATION_REQUEST_VERSION_KEY] =
                        newVersion
                    notificationPostingDelegate?.postNotification(
                        BackupNotifications.NOTIFICATION_APP_BACKUP_INITIATION_REQUEST,
                        userInfo
                    )
                }
            } catch (e: Exception) {
                Logger.x(e)
                // nothing to do...
            }
        }
    }

    override fun backupFailed(tag: String?, backupKeyUid: UID, version: Int) {
        executor.execute {
            Logger.w("Backup failed for tag: $tag")
            val uidAndVersion = UidAndVersion(backupKeyUid, version)
            ongoingBackupMap.remove(uidAndVersion)
            val timeout = ongoingBackupTimeoutMap.remove(uidAndVersion)
            timeout?.cancel(false)

            try {
                session.use { backupManagerSession ->
                    val backup: Backup? =
                        Backup.get(backupManagerSession, backupKeyUid, version)
                    if (backup != null && backup.status == Backup.STATUS_ONGOING) {
                        backup.setFailed()
                        if (backup.isForExport) {
                            notificationPostingDelegate?.postNotification(
                                BackupNotifications.NOTIFICATION_BACKUP_FOR_EXPORT_FAILED,
                                mutableMapOf()
                            )
                        }
                    }
                }
            } catch (_: SQLException) {
                // nothing to do
            }
        }
    }

    override fun backupSuccess(
        tag: String?,
        backupKeyUid: UID,
        version: Int,
        backupContent: String?
    ) {
        executor.execute {
            try {
                session.use { backupManagerSession ->
                    val backupKey: BackupKey =
                        BackupKey.get(backupManagerSession, backupKeyUid)
                            ?: throw Exception("BackupKey not found")
                    val backup: Backup? =
                        Backup.get(backupManagerSession, backupKeyUid, version)
                    if (backup == null || backup.status != Backup.STATUS_ONGOING) {
                        throw Exception("Ongoing Backup not found")
                    }

                    val uidAndVersion = UidAndVersion(backupKeyUid, version)
                    val backupParts =
                        ongoingBackupMap[uidAndVersion] ?: // this should never happen!
                        throw Exception("Unable to find ongoing backup parts map")

                    if (backupParts.containsKey(tag)) {
                        // this should never happen!
                        throw Exception("Received 2 backups for the same tag!")
                    }

                    // store the backup content in memory
                    backupParts[tag] = backupContent

                    // check if all parts of the backup have been received
                    var complete = true
                    for (backupTag in ALL_BACKUP_TAGS) {
                        if (!backupParts.containsKey(backupTag)) {
                            complete = false
                            break
                        }
                    }
                    if (complete) {
                        // all parts of the backup have been received --> finalize the backup
                        val pojo = Pojo_0()

                        val enginePojo = EnginePojo_0()
                        enginePojo.identity_manager = backupParts[IDENTITY_BACKUP_TAG]
                        pojo.engine = enginePojo

                        pojo.app = backupParts[APP_BACKUP_TAG]

                        pojo.backup_json_version = backup.backupJsonVersion
                        pojo.backup_timestamp = System.currentTimeMillis()
                        val fullBackupContent = jsonObjectMapper.writeValueAsString(pojo)

                        val encryptionPublicKey = backupKey.encryptionPublicKey
                        val macKey = backupKey.macKey

                        val encryptedBackup =
                            Suite.getPublicKeyEncryption(encryptionPublicKey)!!.encrypt(
                                encryptionPublicKey, fullBackupContent.toByteArray(
                                    StandardCharsets.UTF_8
                                ), prng
                            )!!
                        val mac =
                            Suite.getMAC(macKey)!!.digest(macKey, encryptedBackup.getBytes())!!

                        val macedEncryptedBackup =
                            ByteArray(encryptedBackup.getBytes().size + mac.size)
                        System.arraycopy(
                            encryptedBackup.getBytes(),
                            0,
                            macedEncryptedBackup,
                            0,
                            encryptedBackup.getBytes().size
                        )
                        System.arraycopy(
                            mac,
                            0,
                            macedEncryptedBackup,
                            encryptedBackup.getBytes().size,
                            mac.size
                        )

                        backup.setReady(macedEncryptedBackup)

                        // cleanup the maps
                        ongoingBackupMap.remove(uidAndVersion)
                        val timeout = ongoingBackupTimeoutMap.remove(uidAndVersion)
                        timeout?.cancel(false)

                        if (backup.isForExport) {
                            val userInfo = HashMap<String, Any>()
                            userInfo[BackupNotifications.NOTIFICATION_BACKUP_FOR_EXPORT_FINISHED_BACKUP_KEY_UID_KEY] =
                                backupKeyUid
                            userInfo[BackupNotifications.NOTIFICATION_BACKUP_FOR_EXPORT_FINISHED_VERSION_KEY] =
                                version
                            userInfo[BackupNotifications.NOTIFICATION_BACKUP_FOR_EXPORT_FINISHED_ENCRYPTED_CONTENT_KEY] =
                                macedEncryptedBackup
                            notificationPostingDelegate?.postNotification(
                                BackupNotifications.NOTIFICATION_BACKUP_FOR_EXPORT_FINISHED,
                                userInfo
                            )
                        }

                        val userInfo = HashMap<String, Any>()
                        userInfo[BackupNotifications.NOTIFICATION_BACKUP_FINISHED_BACKUP_KEY_UID_KEY] =
                            backupKeyUid
                        userInfo[BackupNotifications.NOTIFICATION_BACKUP_FINISHED_VERSION_KEY] =
                            version
                        userInfo[BackupNotifications.NOTIFICATION_BACKUP_FINISHED_ENCRYPTED_CONTENT_KEY] =
                            macedEncryptedBackup
                        notificationPostingDelegate?.postNotification(
                            BackupNotifications.NOTIFICATION_BACKUP_FINISHED,
                            userInfo
                        )
                    }
                }
            } catch (e: Exception) {
                Logger.x(e)
                backupFailed(tag, backupKeyUid, version)
            }
        }
    }

    @get:Throws(Exception::class)
    override val backupKeyInformation: ObvBackupKeyInformation?
        get() {
            session.use { backupManagerSession ->
                val backupKeys: Array<BackupKey> =
                    BackupKey.getAll(backupManagerSession)
                if (backupKeys.isEmpty()) {
                    Logger.d("No BackupKey generated!")
                    return null
                } else if (backupKeys.size > 1) {
                    Logger.e("Multiple BackupKey generated, this should never occur!")
                    return null
                }
                val backupKey = backupKeys[0]

                val exportedBackup = backupKey.exportedBackup
                val uploadedBackup = backupKey.uploadedBackup
                return ObvBackupKeyInformation(
                    backupKey.keyGenerationTimestamp,
                    backupKey.lastSuccessfulKeyVerificationTimestamp,
                    backupKey.successfulVerificationCount,
                    exportedBackup?.statusChangeTimestamp ?: 0L,
                    uploadedBackup?.statusChangeTimestamp ?: 0L
                )
            }
        }

    override fun markBackupExported(backupKeyUid: UID, version: Int) {
        try {
            session.use { backupManagerSession ->
                val backupKey: BackupKey =
                    BackupKey.get(backupManagerSession, backupKeyUid) ?: return
                val backup: Backup? =
                    Backup.get(backupManagerSession, backupKeyUid, version)
                if (backup == null || backup.status != Backup.STATUS_READY || !backup.isForExport) {
                    return
                }
                backupManagerSession.session.startTransaction()
                backup.setUploadedOrExported()
                if (backupKey.exportedBackupVersion == null || backupKey.exportedBackupVersion!! < version) {
                    backupKey.setExportedBackupVersion(version)
                }
                backupManagerSession.session.commit()
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    override fun markBackupUploaded(backupKeyUid: UID, version: Int) {
        try {
            session.use { backupManagerSession ->
                val backupKey: BackupKey =
                    BackupKey.get(backupManagerSession, backupKeyUid) ?: return
                val backup: Backup? =
                    Backup.get(backupManagerSession, backupKeyUid, version)
                if (backup == null || (backup.status != Backup.STATUS_READY && backup.status != Backup.STATUS_UPLOADED_OR_EXPORTED)) {
                    return
                }
                backupManagerSession.session.startTransaction()
                backup.setUploadedOrExported()
                if (backupKey.uploadedBackupVersion == null || backupKey.uploadedBackupVersion!! < version) {
                    backupKey.setUploadedBackupVersion(version)
                }
                backupManagerSession.session.commit()
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    override fun discardBackup(backupKeyUid: UID, version: Int) {
        try {
            session.use { backupManagerSession ->
                val backupKey: BackupKey =
                    BackupKey.get(backupManagerSession, backupKeyUid) ?: return
                val backup: Backup? =
                    Backup.get(backupManagerSession, backupKeyUid, version)
                if (backup == null || backup.status != Backup.STATUS_READY) {
                    return
                }
                backup.setFailed()
                Logger.d("Backup discarded.")
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    override fun validateBackupSeed(seedString: String?, backupContent: ByteArray?): Int {
        try {
            val backupSeed = BackupSeed(seedString!!)
            val derivedKeys = backupSeed.deriveKeys()
            val mac = Suite.getMAC(derivedKeys.macKey)!!
            val ciphertext =
                backupContent!!.copyOfRange(0, backupContent.size - mac.outputLength())
            val expectedMacOutput = backupContent.copyOfRange(backupContent.size - mac.outputLength(), backupContent.size)
            if (!mac.verify(derivedKeys.macKey, ciphertext, expectedMacOutput)) {
                return BACKUP_SEED_VERIFICATION_STATUS_BAD_KEY
            }
            val publicKeyEncryption =
                Suite.getPublicKeyEncryption(derivedKeys.encryptionKeyPair.getPrivateKey())!!
            publicKeyEncryption.decrypt(
                derivedKeys.encryptionKeyPair.getPrivateKey(),
                EncryptedBytes(ciphertext)
            )
            return BACKUP_SEED_VERIFICATION_STATUS_SUCCESS
        } catch (_: SeedTooShortException) {
            return BACKUP_SEED_VERIFICATION_STATUS_TOO_SHORT
        } catch (_: SeedTooLongException) {
            return BACKUP_SEED_VERIFICATION_STATUS_TOO_LONG
        } catch (_: Exception) {
            return BACKUP_SEED_VERIFICATION_STATUS_BAD_KEY
        }
    }

    private class BackupContentAndDerivedKeys(
        val pojo: Pojo_0?,
        val derivedKeys: DerivedKeys
    )

    @Throws(Exception::class)
    private fun decryptBackupContent(
        seedString: String,
        backupContent: ByteArray,
        jsonObjectMapper: ObjectMapper
    ): BackupContentAndDerivedKeys? {
        val backupSeed = BackupSeed(seedString)
        val derivedKeys = backupSeed.deriveKeys()
        val mac = Suite.getMAC(derivedKeys.macKey)!!
        val ciphertext = backupContent.copyOfRange(0, backupContent.size - mac.outputLength())
        val expectedMacOutput = backupContent.copyOfRange(backupContent.size - mac.outputLength(), backupContent.size)
        if (!mac.verify(derivedKeys.macKey, ciphertext, expectedMacOutput)) {
            return null
        }
        val publicKeyEncryption =
            Suite.getPublicKeyEncryption(derivedKeys.encryptionKeyPair.getPrivateKey())!!
        val plaintext = publicKeyEncryption.decrypt(
            derivedKeys.encryptionKeyPair.getPrivateKey(),
            EncryptedBytes(ciphertext)
        )

        // If we reach this point, decryption was successful --> we need to distinguish between a compressed backup (legacy) and an uncompressed backup
        try {
            // first, try to directly parse our pojo (will fail for compressed backups
            val pojo = jsonObjectMapper.readValue(plaintext, Pojo_0::class.java)
            return BackupContentAndDerivedKeys(pojo, derivedKeys)
        } catch (_: Exception) {
        }

        ByteArrayInputStream(plaintext).use { bais ->
            InflaterInputStream(bais, Inflater(true)).use { inflater ->
                ByteArrayOutputStream().use { baos ->
                    val buffer = ByteArray(8192)
                    var c: Int
                    while ((inflater.read(buffer).also { c = it }) != -1) {
                        baos.write(buffer, 0, c)
                    }

                    val pojo =
                        jsonObjectMapper.readValue(baos.toByteArray(), Pojo_0::class.java)
                    return BackupContentAndDerivedKeys(pojo, derivedKeys)
                }
            }
        }
    }

    override fun restoreOwnedIdentitiesFromBackup(
        seedString: String?,
        backupContent: ByteArray?,
        deviceDisplayName: String?
    ): Array<ObvIdentity?>? {
        try {
            val backupContentAndDerivedKeys =
                decryptBackupContent(seedString!!, backupContent!!, jsonObjectMapper) ?: return null

            if (backupContentAndDerivedKeys.pojo!!.backup_json_version != Constants.CURRENT_BACKUP_JSON_VERSION) {
                // do an upgrade when needed
                Logger.e("Restoring ownedIdentity with a different backup JSON version:" + backupContentAndDerivedKeys.pojo.backup_json_version + " (expecting " + Constants.CURRENT_BACKUP_JSON_VERSION + ").")
                return null
            }

            session.use { backupManagerSession ->
                if (BackupKey.getAll(backupManagerSession).isEmpty()) {
                    val backupKey: BackupKey = BackupKey.create(
                        backupManagerSession,
                        backupContentAndDerivedKeys.derivedKeys.backupKeyUid,
                        backupContentAndDerivedKeys.derivedKeys.encryptionKeyPair.getPublicKey(),
                        backupContentAndDerivedKeys.derivedKeys.macKey
                    )!!
                    backupKey.addSuccessfulVerification()
                    backupManagerSession.session.commit()
                }
            }
            return identityDelegate!!.restoreOwnedIdentitiesFromBackup(
                backupContentAndDerivedKeys.pojo.engine!!.identity_manager,
                deviceDisplayName,
                prng
            )
        } catch (e: Exception) {
            Logger.x(e)
            return null
        }
    }


    override fun restoreContactsAndGroupsFromBackup(
        seedString: String?,
        backupContent: ByteArray?,
        restoredOwnedIdentities: Array<ObvIdentity?>?
    ) {
        try {
            val backupContentAndDerivedKeys =
                decryptBackupContent(seedString!!, backupContent!!, jsonObjectMapper) ?: return

            if (backupContentAndDerivedKeys.pojo!!.backup_json_version != Constants.CURRENT_BACKUP_JSON_VERSION) {
                // do an upgrade when needed
                Logger.e("Restoring contacts and groups with a different backup JSON version:" + backupContentAndDerivedKeys.pojo.backup_json_version + " (expecting " + Constants.CURRENT_BACKUP_JSON_VERSION + ").")
                return
            }

            identityDelegate!!.restoreContactsAndGroupsFromBackup(
                backupContentAndDerivedKeys.pojo.engine!!.identity_manager,
                restoredOwnedIdentities,
                backupContentAndDerivedKeys.pojo.backup_timestamp
            )

            notificationPostingDelegate?.postNotification(
                BackupNotifications.NOTIFICATION_BACKUP_RESTORATION_FINISHED,
                mutableMapOf()
            )
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    fun decryptAppDataBackup(seedString: String, backupContent: ByteArray): String? {
        try {
            val backupContentAndDerivedKeys =
                decryptBackupContent(seedString, backupContent, jsonObjectMapper) ?: return null

            if (backupContentAndDerivedKeys.pojo != null) {
                return backupContentAndDerivedKeys.pojo.app
            }
            return null
        } catch (_: Exception) {
            return null
        }
    }

    // endregion
    // region NotificationListener
    override fun callback(notificationName: String?, userInfo: Map<String, Any>?) {
        when (notificationName) {
            IdentityNotifications.NOTIFICATION_DATABASE_CONTENT_CHANGED -> {
                if (autoBackupEnabled) {
                    scheduleBackupForUploadIfNeeded(false)
                }
            }

            BackupNotifications.NOTIFICATION_DEVICE_BACKUP_NEEDED -> {
                if (deviceBackupsActive) {
                    val targetTimestamp = System.currentTimeMillis() + Constants.BACKUP_START_DELAY
                    synchronized(scheduledBackups) {
                        var doBackup = true
                        for (scheduledBackup in scheduledBackups) {
                            if (scheduledBackup.ownedIdentity == null) {
                                if (scheduledBackup.timestamp < targetTimestamp) {
                                    doBackup = false
                                }
                                break
                            }
                        }
                        if (doBackup) {
                            try {
                                session.use { backupManagerSession ->
                                    val deviceBackupSeed: DeviceBackupSeed? =
                                        DeviceBackupSeed.getActive(backupManagerSession)
                                    if (deviceBackupSeed != null && deviceBackupSeed.nextBackupTimestamp > targetTimestamp) {
                                        deviceBackupSeed.updateNextBackupTimestamp(targetTimestamp)
                                        backupManagerSession.session.commit()
                                        scheduleDeviceBackup(targetTimestamp)
                                    }
                                }
                            } catch (e: Exception) {
                                Logger.x(e)
                            }
                        }
                    }
                }
            }

            BackupNotifications.NOTIFICATION_PROFILE_BACKUP_NEEDED -> {
                if (deviceBackupsActive) {
                    val ownedIdentity =
                        userInfo?.get(BackupNotifications.NOTIFICATION_PROFILE_BACKUP_NEEDED_OWNED_IDENTITY) as? Identity?
                            ?: return
                    val targetTimestamp = System.currentTimeMillis() + Constants.BACKUP_START_DELAY
                    synchronized(scheduledBackups) {
                        var doBackup = true
                        for (scheduledBackup in scheduledBackups) {
                            if (ownedIdentity == scheduledBackup.ownedIdentity) {
                                if (scheduledBackup.timestamp < targetTimestamp) {
                                    doBackup = false
                                }
                                break
                            }
                        }
                        if (doBackup) {
                            try {
                                session.use { backupManagerSession ->
                                    val profileBackupThreadId: ProfileBackupThreadId? =
                                        ProfileBackupThreadId.get(
                                            backupManagerSession,
                                            ownedIdentity
                                        )
                                    if (profileBackupThreadId == null || profileBackupThreadId.nextBackupTimestamp > targetTimestamp) {
                                        if (profileBackupThreadId != null) {
                                            profileBackupThreadId.updateNextBackupTimestamp(
                                                targetTimestamp
                                            )
                                            backupManagerSession.session.commit()
                                        }
                                        scheduleProfileBackup(ownedIdentity, targetTimestamp)
                                    }
                                }
                            } catch (e: Exception) {
                                Logger.x(e)
                            }
                        }
                    }
                }
            }
        }
    }

    // Public entry point used by the desktop daemon to trigger a backup when storage changes.
    fun scheduleBackupIfNeeded() {
        scheduleBackupForUploadIfNeeded(false)
    }

    private fun scheduleBackupForUploadIfNeeded(immediately: Boolean) {
        synchronized(autoBackupSchedulerLock) {
            if (immediately) {
                if (autoBackupIsScheduled && scheduledAutoBackupTask != null) {
                    scheduledAutoBackupTask!!.cancel(true)
                    scheduledAutoBackupTask = null
                }
                Logger.d("Immediately running a backup upload to the cloud")
                autoBackupScheduler.submit { initiateBackup(false) }
            } else {
                if (autoBackupIsScheduled) {
                    return
                }
                Logger.d("Scheduling a backup upload to the cloud")
                autoBackupIsScheduled = true
                scheduledAutoBackupTask = autoBackupScheduler.schedule({
                    synchronized(autoBackupSchedulerLock) {
                        autoBackupIsScheduled = false
                        scheduledAutoBackupTask = null
                    }
                    initiateBackup(false)
                }, Constants.AUTOBACKUP_START_DELAY, TimeUnit.MILLISECONDS)
            }
        }
    }

    // endregion
    @JsonIgnoreProperties(ignoreUnknown = true)
    private class Pojo_0 {
        @JvmField var engine: EnginePojo_0? = null
        @JvmField var app: String? = null
        @JvmField var backup_json_version: Int = 0
        @JvmField var backup_timestamp: Long = 0
    }


    @JsonIgnoreProperties(ignoreUnknown = true)
    private class EnginePojo_0 {
        @JvmField var identity_manager: String? = null
    }


    private class UidAndVersion(@JvmField val uid: UID, @JvmField val version: Int) {
        override fun hashCode(): Int {
            return uid.hashCode() * 31 + version
        }

        override fun equals(other: Any?): Boolean {
            if (other !is UidAndVersion) {
                return false
            }
            return uid == other.uid && version == other.version
        }
    }

    private class ScheduledBackup(// null for device backups
        val ownedIdentity: Identity?, val timestamp: Long
    ) {
        @JvmField var failedAttemptCounts: Int = 0
        @JvmField var scheduledTimestamp: Long

        init {
            this.scheduledTimestamp = timestamp
        }

        fun rescheduleAfterRetriableFailure() {
            failedAttemptCounts++
            val base = Constants.BASE_RESCHEDULING_TIME shl min(failedAttemptCounts, 32)
            scheduledTimestamp =
                System.currentTimeMillis() + (base * (1 + Random().nextFloat())).toLong()
        }

        fun clearFailedAttemptCounts() {
            failedAttemptCounts = 0
            scheduledTimestamp = timestamp
        }

        override fun equals(other: Any?): Boolean {
            if (other !is ScheduledBackup) {
                return false
            }
            return timestamp == other.timestamp && ownedIdentity == other.ownedIdentity
        }

        override fun hashCode(): Int {
            if (ownedIdentity == null) {
                return timestamp.hashCode()
            }
            return ownedIdentity.hashCode() * 31 + timestamp.hashCode()
        }
    }

    companion object {
        const val IDENTITY_BACKUP_TAG: String = "identity"
        const val APP_BACKUP_TAG: String = "app"

        val ALL_BACKUP_TAGS: Array<String> = arrayOf(IDENTITY_BACKUP_TAG, APP_BACKUP_TAG)

        const val BACKUP_SEED_VERIFICATION_STATUS_SUCCESS: Int = 0
        const val BACKUP_SEED_VERIFICATION_STATUS_TOO_SHORT: Int = 1
        const val BACKUP_SEED_VERIFICATION_STATUS_TOO_LONG: Int = 2
        const val BACKUP_SEED_VERIFICATION_STATUS_BAD_KEY: Int = 3

        @JvmStatic
        @Throws(SQLException::class)
        fun upgradeTables(session: Session, oldVersion: Int, newVersion: Int) {
            Backup.upgradeTable(session, oldVersion, newVersion)
            BackupKey.upgradeTable(session, oldVersion, newVersion)
            DeviceBackupSeed.upgradeTable(session, oldVersion, newVersion)
            ProfileBackupThreadId.upgradeTable(session, oldVersion, newVersion)
        }
    }
}
