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
package io.olvid.engine.channel

import io.olvid.engine.Logger
import io.olvid.engine.channel.coordinators.ChannelCoordinator
import io.olvid.engine.channel.databases.ObliviousChannel
import io.olvid.engine.channel.databases.Provision
import io.olvid.engine.channel.databases.ProvisionedKeyMaterial
import io.olvid.engine.channel.datatypes.Channel
import io.olvid.engine.channel.datatypes.ChannelManagerSession
import io.olvid.engine.channel.datatypes.ChannelManagerSessionFactory
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.NetworkReceivedMessage
import io.olvid.engine.datatypes.containers.OwnedDeviceAndPreKey
import io.olvid.engine.datatypes.containers.UidAndPreKey
import io.olvid.engine.metamanager.ChannelDelegate
import io.olvid.engine.metamanager.CreateSessionDelegate
import io.olvid.engine.metamanager.EncryptionForIdentityDelegate
import io.olvid.engine.metamanager.FullRatchetProtocolStarterDelegate
import io.olvid.engine.metamanager.IdentityDelegate
import io.olvid.engine.metamanager.MetaManager
import io.olvid.engine.metamanager.NetworkFetchDelegate
import io.olvid.engine.metamanager.NetworkSendDelegate
import io.olvid.engine.metamanager.NotificationPostingDelegate
import io.olvid.engine.metamanager.ObvManager
import io.olvid.engine.metamanager.PreKeyEncryptionDelegate
import io.olvid.engine.metamanager.ProcessDownloadedMessageDelegate
import io.olvid.engine.metamanager.ProtocolDelegate
import io.olvid.engine.protocol.datatypes.ProtocolStarterDelegate
import java.sql.SQLException
import java.util.Arrays


class ChannelManager(metaManager: MetaManager) : ChannelDelegate, ProcessDownloadedMessageDelegate,
    ChannelManagerSessionFactory, ObvManager {
    private val channelCoordinator: ChannelCoordinator


    private var createSessionDelegate: CreateSessionDelegate? = null
    private var networkSendDelegate: NetworkSendDelegate? = null
    private var networkFetchDelegate: NetworkFetchDelegate? = null
    private var fullRatchetProtocolStarterDelegate: FullRatchetProtocolStarterDelegate? = null
    private var protocolDelegate: ProtocolDelegate? = null
    private var protocolStarterDelegate: ProtocolStarterDelegate? = null
    private var identityDelegate: IdentityDelegate? = null
    private var encryptionForIdentityDelegate: EncryptionForIdentityDelegate? = null
    private var preKeyEncryptionDelegate: PreKeyEncryptionDelegate? = null
    private var notificationPostingDelegate: NotificationPostingDelegate? = null

    init {
        this.channelCoordinator = ChannelCoordinator(this)

        metaManager.requestDelegate(this, CreateSessionDelegate::class.java)
        metaManager.requestDelegate(this, FullRatchetProtocolStarterDelegate::class.java)
        metaManager.requestDelegate(this, NetworkFetchDelegate::class.java)
        metaManager.requestDelegate(this, NetworkSendDelegate::class.java)
        metaManager.requestDelegate(this, ProtocolDelegate::class.java)
        metaManager.requestDelegate(this, ProtocolStarterDelegate::class.java)
        metaManager.requestDelegate(this, IdentityDelegate::class.java)
        metaManager.requestDelegate(this, EncryptionForIdentityDelegate::class.java)
        metaManager.requestDelegate(this, PreKeyEncryptionDelegate::class.java)
        metaManager.requestDelegate(this, NotificationPostingDelegate::class.java)
        metaManager.registerImplementedDelegates(this)
    }

    override fun initialQueueingPriority(): Int {
        return 30
    }

    override fun initialisationComplete() {
        try {
            session.use { channelManagerSession ->
                // clean expired provisions
                ObliviousChannel.clean(channelManagerSession)
                channelManagerSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }

        try {
            session.use { channelManagerSession ->
                val ownedIdentityFromDeviceUid = HashMap<UID?, Identity?>()
                // clear all channels with deviceUids of contacts that do not exist
                // at the same time, try to detect contact devices without a channel
                val obliviousChannels: Array<ObliviousChannel?> =
                    ObliviousChannel.getAll(channelManagerSession)
                val deviceUidsMap: MutableMap<Identity?, MutableMap<Identity?, MutableSet<UID?>?>?> =
                    identityDelegate!!.getAllDeviceUidsOfAllContactsOfAllOwnedIdentities(
                        channelManagerSession.session
                    )
                for (ownedIdentity in identityDelegate!!.getOwnedIdentities(channelManagerSession.session)) {
                    val ownedDeviceUids = identityDelegate!!.getDeviceUidsOfOwnedIdentity(
                        channelManagerSession.session,
                        ownedIdentity
                    )
                    if (!deviceUidsMap.containsKey(ownedIdentity)) {
                        deviceUidsMap[ownedIdentity] = HashMap()
                    }
                    val ownedIdentityMap: MutableMap<Identity?, MutableSet<UID?>?>? =
                        deviceUidsMap[ownedIdentity]
                    ownedIdentityMap!![ownedIdentity] = HashSet(ownedDeviceUids!!.toList())
                }

                for (obliviousChannel in obliviousChannels) {
                    if (obliviousChannel == null) continue
                    var ownedIdentity =
                        ownedIdentityFromDeviceUid.get(obliviousChannel.currentDeviceUid)
                    if (ownedIdentity == null) {
                        ownedIdentity = identityDelegate!!.getOwnedIdentityForCurrentDeviceUid(
                            channelManagerSession.session,
                            obliviousChannel.currentDeviceUid
                        )
                        if (ownedIdentity == null) {
                            continue
                        }
                        ownedIdentityFromDeviceUid[obliviousChannel.currentDeviceUid] = ownedIdentity
                    }
                    var found = false
                    val ownedIdentityMap: MutableMap<Identity?, MutableSet<UID?>?>? =
                        deviceUidsMap.get(ownedIdentity)
                    if (ownedIdentityMap != null) {
                        val deviceUids = ownedIdentityMap.get(obliviousChannel.remoteIdentity)
                        if (deviceUids != null) {
                            found = deviceUids.remove(obliviousChannel.remoteDeviceUid)
                        }
                    }
                    if (!found) {
                        // the device this channel is connected to no longer exists! Delete the channel
                        Logger.i("Found an orphan oblivious channel -> deleting it!")
                        obliviousChannel.delete()
                    }
                }

                // now that we have removed (from the HashMap) all devices for which we have a channel, we walk through the deviceUidsMap to check for channel-less deviceUids
                for (ownedIdentity in deviceUidsMap.keys) {
                    // first check if some channels with owned devices should be restarted
                    if (identityDelegate!!.isActiveOwnedIdentity(
                            channelManagerSession.session,
                            ownedIdentity
                        )
                    ) {
                        for (ownedDeviceUid in identityDelegate!!.getOtherDeviceUidsOfOwnedIdentity(
                            channelManagerSession.session,
                            ownedIdentity
                        )!!) {
                            try {
                                val channelExists = checkIfObliviousChannelExists(
                                    channelManagerSession.session,
                                    ownedIdentity,
                                    ownedDeviceUid,
                                    ownedIdentity
                                )
                                val channelCreationInProgress =
                                    protocolDelegate!!.isChannelCreationInProgress(
                                        channelManagerSession.session,
                                        ownedIdentity,
                                        ownedIdentity,
                                        ownedDeviceUid
                                    )
                                if (!channelExists && !channelCreationInProgress) {
                                    // we found a device without a channel and no channel creation is in progress
                                    //  --> we start a channel creation
                                    val latestPing =
                                        identityDelegate!!.getLatestChannelCreationPingTimestampForOwnedDevice(
                                            channelManagerSession.session,
                                            ownedIdentity,
                                            ownedDeviceUid
                                        )
                                    if (latestPing != -1L && latestPing < System.currentTimeMillis() - Constants.CHANNEL_CREATION_PING_INTERVAL) {
                                        Logger.i("Found an owned device with no channel and no channel creation. Restarting channel creation.")
                                        protocolStarterDelegate!!.startChannelCreationProtocolWithOwnedDevice(
                                            channelManagerSession.session,
                                            ownedIdentity,
                                            ownedDeviceUid
                                        )
                                    }
                                }
                            } catch (_: Exception) {
                                // nothing to do
                            }
                        }
                    }


                    val ownedIdentityMap = deviceUidsMap.get(ownedIdentity)
                    if (ownedIdentityMap == null) {
                        continue
                    }
                    for (contactIdentity in ownedIdentityMap.keys) {
                        if (contactIdentity?.equals(ownedIdentity) == true) {
                            continue
                        }
                        val deviceUidSet = ownedIdentityMap.get(contactIdentity)
                        if (deviceUidSet == null) {
                            continue
                        }
                        for (contactDeviceUid in deviceUidSet) {
                            // check if a ChannelCreationProtocolInstance exists for this device
                            try {
                                if (!protocolDelegate!!.isChannelCreationInProgress(
                                        channelManagerSession.session,
                                        ownedIdentity,
                                        contactIdentity,
                                        contactDeviceUid
                                    )
                                ) {
                                    // we found a device without a channel and no channel creation is in progress
                                    //  --> restart a channel creation
                                    val latestPing =
                                        identityDelegate!!.getLatestChannelCreationPingTimestampForContactDevice(
                                            channelManagerSession.session,
                                            ownedIdentity,
                                            contactIdentity,
                                            contactDeviceUid
                                        )
                                    if (latestPing != -1L && latestPing < System.currentTimeMillis() - Constants.CHANNEL_CREATION_PING_INTERVAL) {
                                        Logger.i("Found a contact device with no channel and no channel creation. Restarting channel creation.")
                                        protocolStarterDelegate!!.startChannelCreationProtocolWithContactDevice(
                                            channelManagerSession.session,
                                            ownedIdentity,
                                            contactIdentity,
                                            contactDeviceUid
                                        )
                                    }
                                    break
                                }
                            } catch (_: Exception) {
                                // nothing to do
                            }
                        }
                    }
                }
                channelManagerSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    fun setDelegate(createSessionDelegate: CreateSessionDelegate) {
        this.createSessionDelegate = createSessionDelegate

        try {
            session.use { channelManagerSession ->
                ObliviousChannel.createTable(channelManagerSession.session)
                Provision.createTable(channelManagerSession.session)
                ProvisionedKeyMaterial.createTable(channelManagerSession.session)
                channelManagerSession.session.commit()
            }
        } catch (e: SQLException) {
            Logger.x(e)
            throw RuntimeException("Unable to create channel databases")
        }
    }

    fun setDelegate(fullRatchetProtocolStarterDelegate: FullRatchetProtocolStarterDelegate?) {
        this.fullRatchetProtocolStarterDelegate = fullRatchetProtocolStarterDelegate
    }

    fun setDelegate(networkSendDelegate: NetworkSendDelegate?) {
        this.networkSendDelegate = networkSendDelegate
    }

    fun setDelegate(networkFetchDelegate: NetworkFetchDelegate?) {
        this.networkFetchDelegate = networkFetchDelegate
    }

    fun setDelegate(protocolDelegate: ProtocolDelegate) {
        this.protocolDelegate = protocolDelegate
    }

    fun setDelegate(protocolStarterDelegate: ProtocolStarterDelegate) {
        this.protocolStarterDelegate = protocolStarterDelegate
    }

    fun setDelegate(identityDelegate: IdentityDelegate?) {
        this.identityDelegate = identityDelegate
    }

    fun setDelegate(encryptionForIdentityDelegate: EncryptionForIdentityDelegate?) {
        this.encryptionForIdentityDelegate = encryptionForIdentityDelegate
    }

    fun setDelegate(preKeyEncryptionDelegate: PreKeyEncryptionDelegate?) {
        this.preKeyEncryptionDelegate = preKeyEncryptionDelegate
    }

    fun setDelegate(notificationPostingDelegate: NotificationPostingDelegate?) {
        this.notificationPostingDelegate = notificationPostingDelegate
    }


    // region Implementing ProcessDownloadedMessageDelegate
    override fun processDownloadedMessage(networkReceivedMessage: NetworkReceivedMessage?) {
        if (networkReceivedMessage == null) {
            Logger.i("Could not process null NetworkReceivedMessage")
            return
        }
        channelCoordinator.decryptAndProcess(networkReceivedMessage)
    }

    // endregion
    // region Implementing ChannelDelegate
    @Throws(Exception::class)
    override fun post(session: Session, channelMessageToSend: ChannelMessageToSend?, prng: PRNGService?): UID? {
        return Channel.post(wrapSession(session), channelMessageToSend!!, prng)
    }

    @Throws(Exception::class)
    override fun createObliviousChannel(
        session: Session,
        ownedIdentity: Identity?,
        remoteDeviceUid: UID?,
        remoteIdentity: Identity?,
        seed: Seed?,
        obliviousEngineVersion: Int
    ) {
        if (identityDelegate == null) {
            Logger.w("Calling createObliviousChannel while the IdentityDelegate is not yet set")
            throw Exception()
        }
        val currentDeviceUid =
            identityDelegate!!.getCurrentDeviceUidOfOwnedIdentity(session, ownedIdentity)
        ObliviousChannel.create(
            wrapSession(session),
            currentDeviceUid,
            remoteDeviceUid,
            remoteIdentity,
            seed,
            obliviousEngineVersion
        )
    }

    @Throws(Exception::class)
    override fun confirmObliviousChannel(
        session: Session,
        ownedIdentity: Identity?,
        remoteDeviceUid: UID?,
        remoteIdentity: Identity?
    ) {
        val channel = getObliviousChannel(session, ownedIdentity, remoteDeviceUid, remoteIdentity)
        channel?.confirm()
    }

    @Throws(Exception::class)
    override fun updateObliviousChannelSendSeed(
        session: Session,
        ownedIdentity: Identity?,
        remoteDeviceUid: UID?,
        remoteIdentity: Identity?,
        seed: Seed?,
        obliviousEngineVersion: Int
    ) {
        val channel = getObliviousChannel(session, ownedIdentity, remoteDeviceUid, remoteIdentity)
        channel?.updateSendSeed(seed!!, obliviousEngineVersion)
    }

    @Throws(Exception::class)
    override fun updateObliviousChannelReceiveSeed(
        session: Session,
        ownedIdentity: Identity?,
        remoteDeviceUid: UID?,
        remoteIdentity: Identity?,
        seed: Seed?,
        obliviousEngineVersion: Int
    ) {
        val channel = getObliviousChannel(session, ownedIdentity, remoteDeviceUid, remoteIdentity)
        channel?.createNewProvision(seed!!, obliviousEngineVersion)
    }

    @Throws(Exception::class)
    private fun getObliviousChannel(
        session: Session,
        ownedIdentity: Identity?,
        remoteDeviceUid: UID?,
        remoteIdentity: Identity?
    ): ObliviousChannel? {
        if (identityDelegate == null) {
            Logger.w("Calling getObliviousChannel while the IdentityDelegate is not yet set")
            return null
        }
        val currentDeviceUid =
            identityDelegate!!.getCurrentDeviceUidOfOwnedIdentity(session, ownedIdentity)
        return ObliviousChannel.get(
            wrapSession(session),
            currentDeviceUid,
            remoteDeviceUid,
            remoteIdentity,
            false
        )
    }

    @Throws(Exception::class)
    override fun getConfirmedObliviousChannelDeviceUids(
        session: Session,
        ownedIdentity: Identity?,
        remoteIdentity: Identity?
    ): Array<UID?> {
        val remoteUids: Array<UID?>?
        if (ownedIdentity == remoteIdentity) { // channels with owned devices
            remoteUids =
                identityDelegate!!.getOtherDeviceUidsOfOwnedIdentity(session, ownedIdentity)
        } else {
            remoteUids = identityDelegate!!.getDeviceUidsOfContactIdentity(
                session,
                ownedIdentity,
                remoteIdentity
            )
        }
        if ((remoteUids == null) || (remoteUids.size == 0)) {
            return arrayOfNulls<UID>(0)
        }
        val currentDeviceUid =
            identityDelegate!!.getCurrentDeviceUidOfOwnedIdentity(session, ownedIdentity)
        val obliviousChannels: Array<ObliviousChannel>? = ObliviousChannel.getMany(
            wrapSession(session),
            currentDeviceUid,
            remoteUids,
            remoteIdentity,
            true
        )
        val uids = arrayOfNulls<UID>(obliviousChannels?.size ?: 0)
        if (obliviousChannels != null) {
            for (i in obliviousChannels.indices) {
                uids[i] = obliviousChannels[i].remoteDeviceUid
            }
        }
        return uids
    }

    @Throws(Exception::class)
    override fun getConfirmedObliviousChannelOrPreKeyDeviceUids(
        session: Session,
        ownedIdentity: Identity?,
        remoteIdentity: Identity?
    ): Array<UID?> {
        if (ownedIdentity == remoteIdentity) { // channels with owned devices
            var currentDeviceUid: UID? = null
            val ownedDeviceAndPreKeys: MutableList<OwnedDeviceAndPreKey?>? =
                identityDelegate!!.getDevicesAndPreKeysOfOwnedIdentity(session, ownedIdentity)
            val deviceWithoutPreKey: MutableList<UID?> = ArrayList()
            val uids: MutableList<UID?> = ArrayList()
            for (ownedDeviceAndPreKey in ownedDeviceAndPreKeys!!) {
                if (ownedDeviceAndPreKey == null) continue
                if (ownedDeviceAndPreKey.currentDevice) {
                    currentDeviceUid = ownedDeviceAndPreKey.deviceUid
                } else if (ownedDeviceAndPreKey.preKey == null) {
                    deviceWithoutPreKey.add(ownedDeviceAndPreKey.deviceUid)
                } else {
                    uids.add(ownedDeviceAndPreKey.deviceUid)
                }
            }

            if (currentDeviceUid != null && !deviceWithoutPreKey.isEmpty()) {
                val obliviousChannels: Array<ObliviousChannel>? = ObliviousChannel.getMany(
                    wrapSession(session),
                    currentDeviceUid,
                    deviceWithoutPreKey.toTypedArray<UID?>(),
                    remoteIdentity,
                    true
                )
                if (obliviousChannels != null) {
                    for (obliviousChannel in obliviousChannels) {
                        uids.add(obliviousChannel.remoteDeviceUid)
                    }
                }
            }
            return uids.toTypedArray<UID?>()
        } else {
            val uidAndPreKeys: MutableList<UidAndPreKey?>? =
                identityDelegate!!.getDeviceUidsAndPreKeysOfContactIdentity(
                    session,
                    ownedIdentity,
                    remoteIdentity
                )
            val deviceWithoutPreKey: MutableList<UID?> = ArrayList()
            val uids: MutableList<UID?> = ArrayList()
            for (uidAndPreKey in uidAndPreKeys!!) {
                if (uidAndPreKey == null) continue
                if (uidAndPreKey.preKey == null) {
                    deviceWithoutPreKey.add(uidAndPreKey.uid)
                } else {
                    uids.add(uidAndPreKey.uid)
                }
            }

            if (!deviceWithoutPreKey.isEmpty()) {
                val currentDeviceUid =
                    identityDelegate!!.getCurrentDeviceUidOfOwnedIdentity(session, ownedIdentity)
                val obliviousChannels: Array<ObliviousChannel>? = ObliviousChannel.getMany(
                    wrapSession(session),
                    currentDeviceUid,
                    deviceWithoutPreKey.toTypedArray<UID?>(),
                    remoteIdentity,
                    true
                )
                if (obliviousChannels != null) {
                    for (obliviousChannel in obliviousChannels) {
                        uids.add(obliviousChannel.remoteDeviceUid)
                    }
                }
            }
            return uids.toTypedArray<UID?>()
        }
    }

    @Throws(Exception::class)
    override fun deleteObliviousChannelsWithContact(
        session: Session,
        ownedIdentity: Identity?,
        remoteIdentity: Identity?
    ) {
        val remoteUids = identityDelegate!!.getDeviceUidsOfContactIdentity(
            session,
            ownedIdentity,
            remoteIdentity
        )
        if ((remoteUids == null) || (remoteUids.size == 0)) {
            return
        }
        val currentDeviceUid =
            identityDelegate!!.getCurrentDeviceUidOfOwnedIdentity(session, ownedIdentity)
        ObliviousChannel.deleteMany(
            wrapSession(session),
            currentDeviceUid,
            remoteUids,
            remoteIdentity
        )
    }

    @Throws(Exception::class)
    override fun deleteObliviousChannelIfItExists(
        session: Session,
        ownedIdentity: Identity?,
        remoteDeviceUid: UID?,
        remoteIdentity: Identity?
    ) {
        val currentDeviceUid =
            identityDelegate!!.getCurrentDeviceUidOfOwnedIdentity(session, ownedIdentity)
        val obliviousChannel: ObliviousChannel? = ObliviousChannel.get(
            wrapSession(session),
            currentDeviceUid,
            remoteDeviceUid,
            remoteIdentity,
            false
        )
        if (obliviousChannel != null) {
            // delete the channel
            obliviousChannel.delete()
        }
    }

    @Throws(SQLException::class)
    override fun deleteAllChannelsForOwnedIdentity(session: Session, ownedIdentity: Identity?) {
        val currentDeviceUid =
            identityDelegate!!.getCurrentDeviceUidOfOwnedIdentity(session, ownedIdentity)
        ObliviousChannel.deleteAll(wrapSession(session), currentDeviceUid)
    }

    @Throws(SQLException::class)
    override fun checkIfObliviousChannelExists(
        session: Session,
        ownedIdentity: Identity?,
        remoteDeviceUid: UID?,
        remoteIdentity: Identity?
    ): Boolean {
        val currentDeviceUid =
            identityDelegate!!.getCurrentDeviceUidOfOwnedIdentity(session, ownedIdentity)
        val obliviousChannel: ObliviousChannel? = ObliviousChannel.get(
            wrapSession(session),
            currentDeviceUid,
            remoteDeviceUid,
            remoteIdentity,
            false
        )
        return obliviousChannel != null
    }

    @Throws(SQLException::class)
    override fun checkIfObliviousChannelIsConfirmed(
        session: Session,
        ownedIdentity: Identity?,
        remoteDeviceUid: UID?,
        remoteIdentity: Identity?
    ): Boolean {
        val currentDeviceUid =
            identityDelegate!!.getCurrentDeviceUidOfOwnedIdentity(session, ownedIdentity)
        val obliviousChannel: ObliviousChannel? = ObliviousChannel.get(
            wrapSession(session),
            currentDeviceUid,
            remoteDeviceUid,
            remoteIdentity,
            true
        )
        return obliviousChannel != null
    }

    // endregion
    // region Implementing ChannelManagerSessionFactory methods
    @get:Throws(SQLException::class)
    override val session: ChannelManagerSession
        get() {
            if (createSessionDelegate == null) {
                throw SQLException("No CreateSessionDelegate was set in ChannelManager.")
            }
            return ChannelManagerSession(
                createSessionDelegate!!.session,
                fullRatchetProtocolStarterDelegate,
                networkFetchDelegate,
                networkSendDelegate,
                protocolDelegate,
                encryptionForIdentityDelegate,
                preKeyEncryptionDelegate,
                identityDelegate,
                notificationPostingDelegate,
                protocolStarterDelegate
            )
        }

    private fun wrapSession(session: Session): ChannelManagerSession {
        return ChannelManagerSession(
            session,
            fullRatchetProtocolStarterDelegate,
            networkFetchDelegate,
            networkSendDelegate,
            protocolDelegate,
            encryptionForIdentityDelegate,
            preKeyEncryptionDelegate,
            identityDelegate,
            notificationPostingDelegate,
            protocolStarterDelegate
        )
    } // endregion

    companion object {
        @JvmStatic
        @Throws(SQLException::class)
        fun upgradeTables(session: Session, oldVersion: Int, newVersion: Int) {
            ObliviousChannel.upgradeTable(session, oldVersion, newVersion)
            Provision.upgradeTable(session, oldVersion, newVersion)
            ProvisionedKeyMaterial.upgradeTable(session, oldVersion, newVersion)
        }
    }
}
