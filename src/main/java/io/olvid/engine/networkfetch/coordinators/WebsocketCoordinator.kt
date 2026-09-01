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

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.crypto.Hash
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.ExponentialBackoffRepeatingScheduler
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoDuplicateOperationQueue
import io.olvid.engine.datatypes.NotificationListener
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.Operation.OnCancelCallback
import io.olvid.engine.datatypes.ServerMethod
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.OwnedIdentitySynchronizationStatus
import io.olvid.engine.datatypes.notifications.DownloadNotifications
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.engine.types.HttpHelper
import io.olvid.engine.metamanager.NotificationListeningDelegate
import io.olvid.engine.metamanager.NotificationPostingDelegate
import io.olvid.engine.networkfetch.coordinators.WellKnownCoordinator.NotCachedException
import io.olvid.engine.networkfetch.databases.ServerSession
import io.olvid.engine.networkfetch.datatypes.CreateServerSessionDelegate
import io.olvid.engine.networkfetch.datatypes.DownloadMessagesAndListAttachmentsDelegate
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import io.olvid.engine.networkfetch.datatypes.WellKnownCacheDelegate
import io.olvid.engine.protocol.datatypes.ProtocolStarterDelegate
import java.io.IOException
import java.lang.ref.WeakReference
import java.security.KeyStore
import java.sql.SQLException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlin.collections.ArrayList
import kotlin.collections.HashMap
import kotlin.collections.HashSet
import kotlin.collections.MutableList
import kotlin.collections.MutableMap
import kotlin.collections.contentToString
import kotlin.math.min
import net.iharder.Base64
import okhttp3.Authenticator
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.Route
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString


class WebsocketCoordinator(
    fetchManagerSessionFactory: FetchManagerSessionFactory,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?,
    createServerSessionDelegate: CreateServerSessionDelegate,
    downloadMessagesAndListAttachmentsDelegate: DownloadMessagesAndListAttachmentsDelegate,
    wellKnownCacheDelegate: WellKnownCacheDelegate,
    jsonObjectMapper: ObjectMapper
) : OnCancelCallback {
    private val fetchManagerSessionFactory: FetchManagerSessionFactory
    private val createServerSessionDelegate: CreateServerSessionDelegate
    private val downloadMessagesAndListAttachmentsDelegate: DownloadMessagesAndListAttachmentsDelegate
    private val wellKnownCacheDelegate: WellKnownCacheDelegate
    private val jsonObjectMapper: ObjectMapper

    private val ownedIdentityAndUidsByServer: MutableMap<String, MutableList<IdentityAndUid>?>
    private val ownedIdentityFirstRegisterSuccessful: HashSet<Identity?>
    private val ownedIdentityCurrentDeviceUids: MutableMap<Identity?, UID?>
    private val ownedIdentityServerSessionTokens: MutableMap<Identity?, ByteArray?>
    private val ownedIdentityAndUidsLock = Any()

    private val existingWebsockets: MutableMap<String?, WebSocketClient?>

    private val scheduler: ExponentialBackoffRepeatingScheduler<String?>
    private val websocketCreationOperationQueue: NoDuplicateOperationQueue
    private val identityRegistrationOperationQueue: NoDuplicateOperationQueue

    private val awaitingServerSessionIdentities: HashSet<Identity?>
    private val awaitingServerSessionIdentitiesLock: Any
    private val serverSessionCreatedNotificationListener: ServerSessionCreatedNotificationListener
    private val ownedIdentityListUpdatedNotificationListener: OwnedIdentityListUpdatedNotificationListener
    private val wellKnownCacheNotificationListener: WellKnownCacheNotificationListener

    private var notificationListeningDelegate: NotificationListeningDelegate? = null
    private var notificationPostingDelegate: NotificationPostingDelegate? = null
    private var protocolStarterDelegate: ProtocolStarterDelegate? = null

    private val okHttpClient: OkHttpClient

    private var doConnect = false
    private var relyOnWebsocketForNetworkDetection = false

    private var os: String? = null
    private var osVersion: String? = null
    private var appBuild = 0
    private var appVersion: String? = null

    @JvmField var lastSleepDetectorTaskTimestamp: Long = 0
    @JvmField var sleepDetectorTask: Runnable = Runnable {
        val timestamp = System.currentTimeMillis()
        if (lastSleepDetectorTaskTimestamp != 0L) {
            if (timestamp - lastSleepDetectorTaskTimestamp > Constants.WEBSOCKET_SLEEP_DETECTION_THRESHOLD_MILLIS) {
                Logger.w("💤 Sleep detected: " + (timestamp - lastSleepDetectorTaskTimestamp) + " -> reconnecting WebSockets.")
                resetWebsockets()
            }
        }
        lastSleepDetectorTaskTimestamp = timestamp
    }

    init {
        this.fetchManagerSessionFactory = fetchManagerSessionFactory
        this.createServerSessionDelegate = createServerSessionDelegate
        this.downloadMessagesAndListAttachmentsDelegate = downloadMessagesAndListAttachmentsDelegate
        this.wellKnownCacheDelegate = wellKnownCacheDelegate
        this.jsonObjectMapper = jsonObjectMapper

        websocketCreationOperationQueue = NoDuplicateOperationQueue()

        identityRegistrationOperationQueue = NoDuplicateOperationQueue()

        scheduler = object : ExponentialBackoffRepeatingScheduler<String?>() {
            override fun computeReschedulingDelay(failedAttemptCount: Int): Long {
                // if in aggressive mode (for Desktop), never reschedule too far in the future
                if (relyOnWebsocketForNetworkDetection) {
                    return min(
                        super.computeReschedulingDelay(failedAttemptCount),
                        Constants.WEBSOCKET_PING_INTERVAL_MILLIS
                    )
                }
                return super.computeReschedulingDelay(failedAttemptCount)
            }
        }
        awaitingServerSessionIdentities = HashSet<Identity?>()
        awaitingServerSessionIdentitiesLock = Any()

        serverSessionCreatedNotificationListener =
            ServerSessionCreatedNotificationListener()
        ownedIdentityListUpdatedNotificationListener =
            OwnedIdentityListUpdatedNotificationListener()
        wellKnownCacheNotificationListener = WellKnownCacheNotificationListener()

        ownedIdentityAndUidsByServer = HashMap<String, MutableList<IdentityAndUid>?>()
        ownedIdentityFirstRegisterSuccessful = HashSet<Identity?>()
        ownedIdentityCurrentDeviceUids = HashMap<Identity?, UID?>()
        ownedIdentityServerSessionTokens = HashMap<Identity?, ByteArray?>()
        existingWebsockets = HashMap<String?, WebSocketClient?>()

        okHttpClient = initializeOkHttpClientForWebSocket(sslSocketFactory, userAgentOverride)
    }

    fun startProcessing() {
        websocketCreationOperationQueue.execute(1, "Engine-WebsocketCoordinator-create")
        identityRegistrationOperationQueue.execute(1, "Engine-WebsocketCoordinator-register")

        scheduler.schedulePeriodically(
            "💤 sleep detection",
            sleepDetectorTask,
            "timer task",
            Constants.WEBSOCKET_SLEEP_DETECTION_INTERVAL_MILLIS
        )
    }

    fun setNotificationListeningDelegate(notificationListeningDelegate: NotificationListeningDelegate) {
        this.notificationListeningDelegate = notificationListeningDelegate
        // register to NotificationCenter for NOTIFICATION_SERVER_SESSION_CREATED
        this.notificationListeningDelegate!!.addListener(
            DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED,
            serverSessionCreatedNotificationListener
        )
        // register to NotificationCenter for NOTIFICATION_OWNED_IDENTITY_LIST_UPDATED and NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS
        this.notificationListeningDelegate!!.addListener(
            IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_LIST_UPDATED,
            ownedIdentityListUpdatedNotificationListener
        )
        this.notificationListeningDelegate!!.addListener(
            IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS,
            ownedIdentityListUpdatedNotificationListener
        )

        this.notificationListeningDelegate!!.addListener(
            DownloadNotifications.NOTIFICATION_WELL_KNOWN_CACHE_INITIALIZED,
            wellKnownCacheNotificationListener
        )
        this.notificationListeningDelegate!!.addListener(
            DownloadNotifications.NOTIFICATION_WELL_KNOWN_UPDATED,
            wellKnownCacheNotificationListener
        )
    }

    fun setNotificationPostingDelegate(notificationPostingDelegate: NotificationPostingDelegate?) {
        this.notificationPostingDelegate = notificationPostingDelegate
    }


    fun setProtocolStarterDelegate(protocolStarterDelegate: ProtocolStarterDelegate?) {
        this.protocolStarterDelegate = protocolStarterDelegate
    }

    fun initialQueueing() {
        synchronized(ownedIdentityAndUidsLock) {
            try {
                fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                    ownedIdentityAndUidsByServer.clear()
                    ownedIdentityCurrentDeviceUids.clear()
                    val ownedIdentities: Array<Identity> =
                        fetchManagerSession.identityDelegate!!.getOwnedIdentities(fetchManagerSession.session)
                    for (ownedIdentity in ownedIdentities) {
                        if (!fetchManagerSession.identityDelegate.isActiveOwnedIdentity(
                                fetchManagerSession.session,
                                ownedIdentity
                            )
                        ) {
                            continue
                        }
                        val deviceUid =
                            fetchManagerSession.identityDelegate.getCurrentDeviceUidOfOwnedIdentity(
                                fetchManagerSession.session,
                                ownedIdentity
                            )
                        ownedIdentityCurrentDeviceUids.put(ownedIdentity, deviceUid)
                        val server = ownedIdentity.server
                        var identityAndUids = ownedIdentityAndUidsByServer.get(server)
                        if (identityAndUids == null) {
                            identityAndUids = ArrayList()
                            ownedIdentityAndUidsByServer[server] = identityAndUids
                        }
                        identityAndUids.add(
                            IdentityAndUid(
                                ownedIdentity,
                                deviceUid!!
                            )
                        )
                    }
                }
            } catch (e: Exception) {
                Logger.x(e)
            }
        }
        resetWebsockets()
    }

    fun connectWebsockets(
        relyOnWebsocketForNetworkDetection: Boolean,
        os: String?,
        osVersion: String?,
        appBuild: Int,
        appVersion: String?
    ) {
        this.doConnect = true
        this.relyOnWebsocketForNetworkDetection = relyOnWebsocketForNetworkDetection
        this.os = os
        this.osVersion = osVersion
        this.appBuild = appBuild
        this.appVersion = appVersion

        internalConnectWebsockets()
    }

    fun disconnectWebsockets() {
        this.doConnect = false
        this.relyOnWebsocketForNetworkDetection = false
        internalDisconnectWebsockets()
    }

    // this sends a ping for the current ownedIdentity websocket and returns a ping latency inside a notification
    fun pingWebsocket(ownedIdentity: Identity) {
        val server = ownedIdentity.server
        val webSocketClient = existingWebsockets.get(server)
        if (webSocketClient != null && webSocketClient.websocketConnected) {
            webSocketClient.sendPing()
        }
    }

    private fun resetWebsockets() {
        internalDisconnectWebsockets()
        internalConnectWebsockets()
    }

    private fun internalDisconnectWebsockets() {
        val webSocketClients: MutableList<WebSocketClient?>
        synchronized(existingWebsockets) {
            webSocketClients = ArrayList<WebSocketClient?>(existingWebsockets.values)
        }
        for (webSocketClient in webSocketClients) {
            webSocketClient?.close(true)
        }
    }

    private fun internalConnectWebsockets() {
        if (!doConnect) {
            return
        }
        synchronized(ownedIdentityAndUidsLock) {
            for (server in ownedIdentityAndUidsByServer.keys) {
                queueWebsocketCreationOperation(server)
            }
        }
    }

    private fun queueWebsocketCreationOperation(server: String) {
        websocketCreationOperationQueue.queue(WebsocketCreationOperation(server, this))
    }

    private fun queueIdentityRegistrationOperation(identity: Identity, deviceUid: UID) {
        identityRegistrationOperationQueue.queue(
            IdentityRegistrationOperation(
                identity,
                deviceUid,
                this
            )
        )
    }

    private fun scheduleNewWebsocketCreationQueueing(server: String) {
        scheduler.schedule(
            server,
            Runnable { queueWebsocketCreationOperation(server) },
            "Websocket Connection"
        )
    }

    fun retryScheduledNetworkTasks() {
        scheduler.retryScheduledRunnables()
    }


    override fun onCancelCallback(operation: Operation) {
        if (operation is WebsocketCreationOperation) {
            val server: String = operation.server
            var rfc = operation.reasonForCancel
            Logger.i("WebsocketCreationOperation cancelled for reason " + rfc)
            if (rfc == null) {
                rfc = Operation.RFC_NULL
            }
            when (rfc) {
                RFC_WEBSOCKET_ALREADY_EXISTS, RFC_NO_KNOWN_WS_SERVER_FOR_SERVER -> {}
                RFC_SSL_HOSTNAME_VERIFICATION_ERROR, RFC_WELL_KNOWN_NOT_CACHED_YET -> scheduleNewWebsocketCreationQueueing(
                    server
                )

                else -> scheduleNewWebsocketCreationQueueing(server)
            }
        } else if (operation is IdentityRegistrationOperation) {
            val identity: Identity =
                operation.identity
            var rfc = operation.reasonForCancel
            Logger.i("IdentityRegistrationOperation cancelled for reason " + rfc)
            if (rfc == null) {
                rfc = Operation.RFC_NULL
            }
            when (rfc) {
                RFC_WEBSOCKET_NOT_FOUND -> {
                    resetWebsockets()
                }

                RFC_NO_VALID_SERVER_SESSION -> {
                    synchronized(awaitingServerSessionIdentitiesLock) {
                        awaitingServerSessionIdentities.add(identity)
                    }
                    createServerSessionDelegate.createServerSession(identity)
                }

                RFC_WEBSOCKET_NOT_CONNECTED -> {}
                else -> {}
            }
        }
    }

    private inner class ServerSessionCreatedNotificationListener : NotificationListener {
        override fun callback(notificationName: String?, userInfo: Map<String, Any>?) {
            if (notificationName != DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED) {
                return
            }
            val identityObject =
                userInfo?.get(DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED_IDENTITY_KEY)
            if (identityObject !is Identity) {
                return
            }
            val identity = identityObject
            synchronized(awaitingServerSessionIdentitiesLock) {
                if (awaitingServerSessionIdentities.contains(identity)) {
                    val deviceUid = ownedIdentityCurrentDeviceUids.get(identity)
                    if (deviceUid != null) {
                        queueIdentityRegistrationOperation(identity, deviceUid)
                    }
                    awaitingServerSessionIdentities.remove(identity)
                }
            }
        }
    }

    private inner class OwnedIdentityListUpdatedNotificationListener : NotificationListener {
        override fun callback(notificationName: String?, userInfo: Map<String, Any>?) {
            synchronized(ownedIdentityAndUidsLock) {
                try {
                    fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                        ownedIdentityAndUidsByServer.clear()
                        ownedIdentityCurrentDeviceUids.clear()
                        val ownedIdentities: Array<Identity> =
                            fetchManagerSession.identityDelegate!!.getOwnedIdentities(
                                fetchManagerSession.session
                            )
                        for (ownedIdentity in ownedIdentities) {
                            if (!fetchManagerSession.identityDelegate.isActiveOwnedIdentity(
                                    fetchManagerSession.session,
                                    ownedIdentity
                                )
                            ) {
                                continue
                            }
                            val deviceUid =
                                fetchManagerSession.identityDelegate.getCurrentDeviceUidOfOwnedIdentity(
                                    fetchManagerSession.session,
                                    ownedIdentity
                                )
                            ownedIdentityCurrentDeviceUids.put(ownedIdentity, deviceUid)
                            val server = ownedIdentity.server
                            var identityAndUids = ownedIdentityAndUidsByServer.get(server)
                            if (identityAndUids == null) {
                                identityAndUids = ArrayList<IdentityAndUid>()
                                ownedIdentityAndUidsByServer.put(server, identityAndUids)
                            }
                            identityAndUids.add(
                                IdentityAndUid(
                                    ownedIdentity,
                                    deviceUid!!
                                )
                            )
                        }
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }
            resetWebsockets()
        }
    }

    private inner class WellKnownCacheNotificationListener : NotificationListener {
        override fun callback(notificationName: String?, userInfo: Map<String, Any>?) {
            when (notificationName) {
                DownloadNotifications.NOTIFICATION_WELL_KNOWN_CACHE_INITIALIZED, DownloadNotifications.NOTIFICATION_WELL_KNOWN_UPDATED -> {
                    // maybe one day we can do something more subtle, but for now, we simply reconnect all websockets when an url might have changed
                    resetWebsockets()
                }
            }
        }
    }

    private class IdentityAndUid(identity: Identity, deviceUid: UID) {
        @JvmField val identity: Identity
        @JvmField val deviceUid: UID

        init {
            this.identity = identity
            this.deviceUid = deviceUid
        }
    }

    private inner class WebsocketCreationOperation(
        server: String,
        onCancelCallback: OnCancelCallback?
    ) : Operation(
        UID(Suite.getHash(Hash.SHA256).digest(server.toByteArray())), null, onCancelCallback
    ) {
        @JvmField val server: String

        init {
            this.server = server
        }

        override fun doCancel() {
            // nothing to do
        }

        override fun doExecute() {
            var finished = false
            try {
                if (!doConnect) {
                    finished = true
                    return
                }
                if (existingWebsockets.containsKey(server)) {
                    cancel(RFC_WEBSOCKET_ALREADY_EXISTS)
                    return
                }
                // create the websocket connection
                val wsUrl: String?
                try {
                    wsUrl = wellKnownCacheDelegate.getWsUrl(server)
                } catch (_: NotCachedException) {
                    cancel(RFC_WELL_KNOWN_NOT_CACHED_YET)
                    return
                }
                if (wsUrl == null) {
                    cancel(RFC_NO_KNOWN_WS_SERVER_FOR_SERVER)
                    return
                }

                WebSocketClient(server, wsUrl)
                finished = true
            } catch (e: Exception) {
                Logger.x(e)
            } finally {
                if (finished) {
                    setFinished()
                } else {
                    if (hasNoReasonForCancel()) {
                        cancel(null)
                    }
                    processCancel()
                }
            }
        }
    }

    private inner class IdentityRegistrationOperation(
        identity: Identity,
        deviceUid: UID,
        onCancelCallback: OnCancelCallback?
    ) : Operation(identity.computeUniqueUid(), null, onCancelCallback) {
        @JvmField val identity: Identity
        @JvmField val deviceUid: UID

        init {
            this.identity = identity
            this.deviceUid = deviceUid
        }

        override fun doCancel() {
            // nothing to do
        }

        override fun doExecute() {
            var finished = false
            try {
                fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                    try {
                        val webSocketClient = existingWebsockets.get(identity.server)
                        if (webSocketClient == null) {
                            cancel(RFC_WEBSOCKET_NOT_FOUND)
                            return
                        }
                        if (!webSocketClient.websocketConnected) {
                            cancel(RFC_WEBSOCKET_NOT_CONNECTED)
                            return
                        }

                        val serverSessionToken: ByteArray? =
                            ServerSession.getToken(fetchManagerSession, identity)
                        if (serverSessionToken == null) {
                            cancel(RFC_NO_VALID_SERVER_SESSION)
                            return
                        }
                        ownedIdentityServerSessionTokens.put(identity, serverSessionToken)

                        val messageMap: MutableMap<String, Any> = HashMap<String, Any>()
                        messageMap["action"] = "register"
                        messageMap["identity"] = Base64.encodeBytes(identity.getBytes())
                        messageMap["deviceUid"] = Base64.encodeBytes(deviceUid.bytes)
                        messageMap["token"] = Base64.encodeBytes(serverSessionToken)
                        val osValue = os
                        val osVersionValue = osVersion
                        val appVersionValue = appVersion
                        if (osValue != null && osVersionValue != null && appBuild != 0 && appVersionValue != null) {
                            messageMap["os"] = osValue
                            messageMap["osVersion"] = osVersionValue
                            messageMap["appBuild"] = appBuild
                            messageMap["appVersion"] = appVersionValue
                        }

                        webSocketClient.send(jsonObjectMapper.writeValueAsString(messageMap))
                        finished = true
                    } catch (e: Exception) {
                        Logger.x(e)
                    } finally {
                        if (finished) {
                            setFinished()
                        } else {
                            if (hasNoReasonForCancel()) {
                                cancel(null)
                            }
                            processCancel()
                        }
                    }
                }
            } catch (e: SQLException) {
                Logger.x(e)
                cancel(null)
                processCancel()
            }
        }
    }

    fun deleteReturnReceipt(ownedIdentity: Identity, serverUid: ByteArray?) {
        val server = ownedIdentity.server
        val webSocketClient = existingWebsockets.get(server)
        if (webSocketClient != null) {
            try {
                val messageMap: MutableMap<String, Any> = HashMap<String, Any>()
                messageMap["action"] = "delete_return_receipt"
                messageMap["serverUid"] = Base64.encodeBytes(serverUid)
                webSocketClient.send(jsonObjectMapper.writeValueAsString(messageMap))
            } catch (e: Exception) {
                Logger.x(e)
            }
        }
    }


    private inner class WebSocketClient(server: String, wsUrl: String) : WebSocketListener() {
        private val wsUrl: String?
        private val server: String
        private val webSocket: WebSocket?

        internal var websocketConnected = false
        private var remotelyInitiatedClosing = false
        private var reconnectAlreadyTakenCareOf = false

        private val pingCounter = AtomicLong(0)
        private var lastPingCounter: Long = -1
        private var lastPingTimestamp: Long = -1

        private var currentConnectionState: Int

        init {
            this.wsUrl = wsUrl
            this.server = server
            this.currentConnectionState = 0
            synchronized(existingWebsockets) {
                existingWebsockets.put(server, this)
            }
            this.webSocket = okHttpClient.newWebSocket(Request.Builder().url(wsUrl).build(), this)
        }

        fun send(message: String) {
            webSocket!!.send(message)
        }


        override fun onOpen(webSocket: WebSocket, response: Response) {
            websocketConnected = true
            Logger.d("Websocket connected to " + wsUrl)
            if (notificationPostingDelegate != null) {
                if (currentConnectionState != 1) {
                    currentConnectionState = 1
                    val userInfo = HashMap<String, Any>()
                    userInfo[DownloadNotifications.NOTIFICATION_WEBSOCKET_CONNECTION_STATE_CHANGED_STATE_KEY] = 1
                    notificationPostingDelegate?.postNotification(
                        DownloadNotifications.NOTIFICATION_WEBSOCKET_CONNECTION_STATE_CHANGED,
                        userInfo
                    )
                }
                if (relyOnWebsocketForNetworkDetection) {
                    notificationPostingDelegate?.postNotification(
                        DownloadNotifications.NOTIFICATION_WEBSOCKET_DETECTED_SOME_NETWORK,
                        HashMap<String, Any>()
                    )
                }
            }

            val identityAndUids = ownedIdentityAndUidsByServer.get(server)
            if (identityAndUids != null) {
                for (identityAndUid in identityAndUids) {
                    queueIdentityRegistrationOperation(
                        identityAndUid.identity,
                        identityAndUid.deviceUid
                    )
                }
            }
            sendPing()

            // schedule a reconnect after less than 2 hours to avoid dirty disconnections from the server
            scheduler.schedule(
                server,
                ReconnectTask(WeakReference<WebSocketClient?>(this), server),
                "WebSocket automatic reconnection",
                Constants.WEBSOCKET_RECONNECT_INTERVAL_MILLIS
            )
        }

        override fun onMessage(webSocket: WebSocket, text: String) {
            // we received a message, so the connection is functioning properly, we can reset the connection failed count
            scheduler.clearFailedCount(server)

            if (notificationPostingDelegate != null && currentConnectionState != 2) {
                currentConnectionState = 2
                val userInfo = HashMap<String, Any>()
                userInfo[DownloadNotifications.NOTIFICATION_WEBSOCKET_CONNECTION_STATE_CHANGED_STATE_KEY] = 2
                notificationPostingDelegate?.postNotification(
                    DownloadNotifications.NOTIFICATION_WEBSOCKET_CONNECTION_STATE_CHANGED,
                    userInfo
                )
            }

            //            Logger.d("Websocket received message " + message);
            val receivedMessage: MutableMap<String?, Any?>
            val action: String?
            try {
                receivedMessage = jsonObjectMapper.readValue<MutableMap<String?, Any?>>(
                    text,
                    object : TypeReference<MutableMap<String?, Any?>?>() {})
                action = receivedMessage.get("action") as String?
            } catch (_: Exception) {
                Logger.i("Unable to parse websocket JSON message $text")
                return
            }
            if (action != null) {
                when (action) {
                    "register" -> {
                        val identityObject = receivedMessage.get("identity")
                        if (identityObject !is String) {
                            return
                        }
                        try {
                            val identity = Identity.of(Base64.decode(identityObject))
                            if (!ownedIdentityCurrentDeviceUids.containsKey(identity)) {
                                // server sent an unknown identity!
                                return
                            }
                            if (!receivedMessage.containsKey("err")) {
                                Logger.d("Successfully registered identity on websocket")
                                synchronized(ownedIdentityFirstRegisterSuccessful) {
                                    ownedIdentityFirstRegisterSuccessful.add(identity)
                                }
                                return
                            }

                            val errObject = receivedMessage.get("err")
                            var err = 255
                            if (errObject is Int) {
                                err = errObject
                            }
                            when (err.toByte()) {
                                ServerMethod.INVALID_SESSION -> {
                                    if (ownedIdentityServerSessionTokens.get(identity) != null) {
                                        try {
                                            fetchManagerSessionFactory.session!!
                                                .use { fetchManagerSession ->
                                                    ServerSession.deleteCurrentTokenIfEqualTo(
                                                        fetchManagerSession,
                                                        ownedIdentityServerSessionTokens.get(
                                                            identity
                                                        ),
                                                        identity
                                                    )
                                                    fetchManagerSession.session.commit()
                                                }
                                        } catch (e: SQLException) {
                                            Logger.x(e)
                                        }
                                    }
                                    synchronized(awaitingServerSessionIdentitiesLock) {
                                        awaitingServerSessionIdentities.add(identity)
                                    }
                                    createServerSessionDelegate.createServerSession(identity)
                                }

                                else -> {}
                            }
                        } catch (e: IOException) {
                            Logger.d("Error decoding identity")
                            Logger.x(e)
                        } catch (e: DecodingException) {
                            Logger.d("Error decoding identity")
                            Logger.x(e)
                        }
                    }

                    "message" -> {
                        val identityObject = receivedMessage.get("identity")
                        if (identityObject !is String) {
                            return
                        }
                        try {
                            val identity = Identity.of(Base64.decode(identityObject))
                            val deviceUid = ownedIdentityCurrentDeviceUids.get(identity)
                            if (deviceUid == null) {
                                // server sent an unknown identity!
                                return
                            }
                            val messageObject = receivedMessage.get("message")
                            if (messageObject is String) {
                                try {
                                    val messagePayload = Base64.decode(messageObject)
                                    downloadMessagesAndListAttachmentsDelegate.processWebsocketDownloadedMessage(
                                        identity,
                                        deviceUid,
                                        messagePayload
                                    )
                                    // we break, no listing required
                                    return
                                } catch (_: Exception) {
                                    // if base64 decoding fails, revert to usual list
                                }
                            }
                            // uf we receive this notification, we might have many pending messages on the server --> mark own identity as not up to date
                            synchronized(ownedIdentityFirstRegisterSuccessful) {
                                if (ownedIdentityFirstRegisterSuccessful.contains(identity)) {
                                    fetchManagerSessionFactory.markOwnedIdentityAsNotUpToDate(
                                        identity,
                                        OwnedIdentitySynchronizationStatus.OTHER_SYNC_IN_PROGRESS
                                    )
                                } else {
                                    fetchManagerSessionFactory.markOwnedIdentityAsNotUpToDate(
                                        identity,
                                        OwnedIdentitySynchronizationStatus.INITIAL_SYNC_IN_PROGRESS
                                    )
                                }
                            }
                            downloadMessagesAndListAttachmentsDelegate.downloadMessagesAndListAttachments(
                                identity,
                                deviceUid
                            )
                        } catch (e: IOException) {
                            Logger.d("Error decoding identity")
                            Logger.x(e)
                        } catch (e: DecodingException) {
                            Logger.d("Error decoding identity")
                            Logger.x(e)
                        }
                    }

                    "return_receipt" -> {
                        val identityObject = receivedMessage.get("identity")
                        val serverUidObject = receivedMessage.get("serverUid")
                        val nonceObject = receivedMessage.get("nonce")
                        val encryptedPayloadObject = receivedMessage.get("encryptedPayload")
                        val timestampObject = receivedMessage.get("timestamp")
                        if (identityObject != null && serverUidObject != null && nonceObject != null && encryptedPayloadObject != null && timestampObject != null) {
                            try {
                                val identity = Identity.of(Base64.decode(identityObject as String))
                                val serverUid = Base64.decode(serverUidObject as String)
                                val nonce = Base64.decode(nonceObject as String)
                                val encryptedPayload =
                                    Base64.decode(encryptedPayloadObject as String)
                                val timestamp = timestampObject as Long

                                if (notificationPostingDelegate != null) {
                                    val userInfo = HashMap<String, Any>()
                                    userInfo[DownloadNotifications.NOTIFICATION_RETURN_RECEIPT_RECEIVED_OWNED_IDENTITY_KEY] = identity
                                    userInfo[DownloadNotifications.NOTIFICATION_RETURN_RECEIPT_RECEIVED_SERVER_UID_KEY] = serverUid
                                    userInfo[DownloadNotifications.NOTIFICATION_RETURN_RECEIPT_RECEIVED_NONCE_KEY] = nonce
                                    userInfo[DownloadNotifications.NOTIFICATION_RETURN_RECEIPT_RECEIVED_ENCRYPTED_PAYLOAD_KEY] = encryptedPayload
                                    userInfo[DownloadNotifications.NOTIFICATION_RETURN_RECEIPT_RECEIVED_TIMESTAMP_KEY] = timestamp

                                    notificationPostingDelegate?.postNotification(
                                        DownloadNotifications.NOTIFICATION_RETURN_RECEIPT_RECEIVED,
                                        userInfo
                                    )
                                }
                            } catch (e: Exception) {
                                Logger.d("Error parsing return receipt")
                                Logger.x(e)
                            }
                        }
                    }

                    "push_topic" -> {
                        val pushTopicObject = receivedMessage.get("topic")
                        if (pushTopicObject != null) {
                            try {
                                val pushTopic = pushTopicObject as String
                                if (notificationPostingDelegate != null) {
                                    val userInfo = HashMap<String, Any>()
                                    userInfo[DownloadNotifications.NOTIFICATION_PUSH_TOPIC_NOTIFIED_TOPIC_KEY] = pushTopic

                                    notificationPostingDelegate?.postNotification(
                                        DownloadNotifications.NOTIFICATION_PUSH_TOPIC_NOTIFIED,
                                        userInfo
                                    )
                                }
                            } catch (e: Exception) {
                                Logger.d("Error parsing push topic")
                                Logger.x(e)
                            }
                        }
                    }

                    "pong" -> {
                        val counterObj = receivedMessage.get("cnt")
                        val timestampObj = receivedMessage.get("timestamp")
                        if (counterObj != null && timestampObj != null) {
                            var counter = -1L
                            var timestamp = -1L
                            try {
                                if (counterObj is Int) {
                                    counter = counterObj.toLong()
                                } else {
                                    counter = counterObj as Long
                                }
                                if (timestampObj is Int) {
                                    timestamp = timestampObj.toLong()
                                } else {
                                    timestamp = timestampObj as Long
                                }
                            } catch (e: Exception) {
                                Logger.x(e)
                                // this is treated after
                            }
                            if (notificationPostingDelegate != null) {
                                if (counter == lastPingCounter && timestamp != -1L) {
                                    lastPingCounter = -1
                                    val delay = System.currentTimeMillis() - timestamp
                                    val userInfo = HashMap<String, Any>()
                                    userInfo[DownloadNotifications.NOTIFICATION_PING_RECEIVED_DELAY_KEY] = delay
                                    notificationPostingDelegate?.postNotification(
                                        DownloadNotifications.NOTIFICATION_PING_RECEIVED,
                                        userInfo
                                    )
                                }
                            }
                        }
                    }

                    "keycloak" -> {
                        val identityObject = receivedMessage.get("identity")
                        if (identityObject !is String) {
                            return
                        }
                        try {
                            val identity = Identity.of(Base64.decode(identityObject))

                            val userInfo = HashMap<String, Any>()
                            userInfo[DownloadNotifications.NOTIFICATION_PUSH_KEYCLOAK_UPDATE_REQUIRED_OWNED_IDENTITY_KEY] = identity
                            notificationPostingDelegate?.postNotification(
                                DownloadNotifications.NOTIFICATION_PUSH_KEYCLOAK_UPDATE_REQUIRED,
                                userInfo
                            )
                        } catch (e: IOException) {
                            Logger.d("Error decoding identity in keycloak websocket notification")
                            Logger.x(e)
                        } catch (e: DecodingException) {
                            Logger.d("Error decoding identity in keycloak websocket notification")
                            Logger.x(e)
                        }
                    }

                    "ownedDevices" -> {
                        val identityObject = receivedMessage.get("identity")
                        if (identityObject !is String) {
                            return
                        }
                        try {
                            val identity = Identity.of(Base64.decode(identityObject))

                            if (protocolStarterDelegate != null) {
                                try {
                                    protocolStarterDelegate!!.startOwnedDeviceDiscoveryProtocol(
                                        identity
                                    )
                                } catch (e: Exception) {
                                    Logger.x(e)
                                }
                            }
                        } catch (e: IOException) {
                            Logger.d("Error decoding identity in ownedDevices websocket notification")
                            Logger.x(e)
                        } catch (e: DecodingException) {
                            Logger.d("Error decoding identity in ownedDevices websocket notification")
                            Logger.x(e)
                        }
                    }
                }
            }
        }

        override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
            Logger.e("Received a binary message on websocket!")
        }


        fun sendPing() {
            val counter = pingCounter.incrementAndGet()
            val timestamp = System.currentTimeMillis()
            if (lastPingCounter != -1L) {
                if (timestamp - lastPingTimestamp > 5000 && notificationPostingDelegate != null) {
                    notificationPostingDelegate?.postNotification(
                        DownloadNotifications.NOTIFICATION_PING_LOST,
                        HashMap<String, Any>()
                    )
                }
            }
            lastPingCounter = counter
            lastPingTimestamp = timestamp

            try {
                val messageMap: MutableMap<String, Any> = HashMap<String, Any>()
                messageMap["action"] = "ping"
                messageMap["cnt"] = counter
                messageMap["timestamp"] = timestamp

                this.webSocket!!.send(jsonObjectMapper.writeValueAsString(messageMap))
            } catch (e: Exception) {
                Logger.x(e)
            }
        }


        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            if (websocketConnected) {
                if (remotelyInitiatedClosing) {
                    Logger.d("Websocket remotely disconnected from " + wsUrl)
                } else {
                    Logger.d("Websocket locally disconnected from " + wsUrl)
                }
            }
            if (doConnect && !reconnectAlreadyTakenCareOf) {
                scheduleNewWebsocketCreationQueueing(server)
            }
            close(false)
        }

        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            remotelyInitiatedClosing = INTERNAL_CLOSING_CODE != code
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            if (websocketConnected) {
                Logger.w("Websocket exception")
                Logger.x(t)
            }
            close(false)
            if (doConnect) {
                scheduleNewWebsocketCreationQueueing(server)
            }
        }

        fun close(reconnectAlreadyTakenCareOf: Boolean) {
            if (notificationPostingDelegate != null && currentConnectionState != 0) {
                currentConnectionState = 0
                val userInfo = HashMap<String, Any>()
                userInfo[DownloadNotifications.NOTIFICATION_WEBSOCKET_CONNECTION_STATE_CHANGED_STATE_KEY] = 0
                notificationPostingDelegate?.postNotification(
                    DownloadNotifications.NOTIFICATION_WEBSOCKET_CONNECTION_STATE_CHANGED,
                    userInfo
                )
            }
            this.reconnectAlreadyTakenCareOf = reconnectAlreadyTakenCareOf

            synchronized(existingWebsockets) {
                if (existingWebsockets.get(server) === this) {
                    existingWebsockets.remove(server)
                }
            }
            if (webSocket != null && webSocket.close(INTERNAL_CLOSING_CODE, null)) {
                // if we initiated a graceful close, also schedule a cancel to make sure resources are properly released
                scheduler.schedule(
                    server,
                    Runnable { webSocket.cancel() },
                    "Websocket cancel()",
                    500
                )
            }
        }

    }


    private inner class ReconnectTask(
        webSocketClientWeakReference: WeakReference<WebSocketClient?>,
        server: String
    ) : Runnable {
        private val webSocketClientWeakReference: WeakReference<WebSocketClient?>
        private val server: String

        init {
            this.webSocketClientWeakReference = webSocketClientWeakReference
            this.server = server
        }

        override fun run() {
            val webSocketClient = webSocketClientWeakReference.get()
            if (webSocketClient != null) {
                var doReconnect = false

                // check if the weak reference is still the current WebSocketClient for this server
                synchronized(existingWebsockets) {
                    if (existingWebsockets.get(server) === webSocketClient) {
                        doReconnect =
                            doConnect // only do something if we are indeed willing to connect
                    }
                }

                if (doReconnect) {
                    // gracefully close the connection and immediately reconnect
                    webSocketClient.close(true)
                    queueWebsocketCreationOperation(server)
                }
            }
        }
    }

    companion object {
        // WebsocketCreationOperation reason for cancel codes
        private const val RFC_WEBSOCKET_ALREADY_EXISTS: Int = 1
        private const val RFC_NO_KNOWN_WS_SERVER_FOR_SERVER: Int = 2
        private const val RFC_SSL_HOSTNAME_VERIFICATION_ERROR: Int = 3
        private const val RFC_WELL_KNOWN_NOT_CACHED_YET: Int = 4
        // IdentityRegistrationOperation reason for cancel codes
        private const val RFC_WEBSOCKET_NOT_FOUND: Int = 1
        private const val RFC_WEBSOCKET_NOT_CONNECTED: Int = 2
        private const val RFC_NO_VALID_SERVER_SESSION: Int = 3
        // WebSocketClient internal closing code
        private const val INTERNAL_CLOSING_CODE = 4547

        fun initializeOkHttpClientForWebSocket(
            sslSocketFactory: SSLSocketFactory?,
            userAgentOverride: String?
        ): OkHttpClient {
            val builder = OkHttpClient.Builder()
            if (sslSocketFactory != null) {
                try {
                    val trustManagerFactory = TrustManagerFactory.getInstance(
                        TrustManagerFactory.getDefaultAlgorithm()
                    )
                    trustManagerFactory.init(null as KeyStore?)
                    val trustManagers = trustManagerFactory.getTrustManagers()
                    check(!(trustManagers.size != 1 || trustManagers[0] !is X509TrustManager)) {
                        ("Unexpected default trust managers:"
                                + trustManagers.contentToString())
                    }
                    val trustManager = trustManagers[0] as X509TrustManager
                    builder.sslSocketFactory(sslSocketFactory, trustManager)
                } catch (e: Exception) {
                    Logger.e("Error initializing websocket okHttpClient trustManager")
                    Logger.x(e)
                }
            }

            val userAgentProperty =
                if (userAgentOverride != null) userAgentOverride else System.getProperty("http.agent")
            if (userAgentProperty != null) {
                builder.addInterceptor(
                    Interceptor { chain: Interceptor.Chain ->
                        chain.proceed(
                            chain.request().newBuilder().header("User-Agent", userAgentProperty)
                                .build()
                        )
                    }
                )
                builder.proxyAuthenticator(Authenticator authenticator@{ route: Route?, response: Response ->
                    val request =
                        Authenticator.JAVA_NET_AUTHENTICATOR.authenticate(route, response)
                    if (request == null) {
                        if (route == null) {
                            return@authenticator null
                        }
                        return@authenticator Request.Builder()
                            .url(route.address.url)
                            .method("CONNECT", null)
                            .header("Host", HttpHelper.toHostHeader(route.address.url))
                            .header("Proxy-Connection", "Keep-Alive")
                            .header("User-Agent", userAgentProperty)
                            .build()
                    } else {
                        return@authenticator request.newBuilder()
                            .header("User-Agent", userAgentProperty).build()
                    }
                })
            }
            builder.pingInterval(Constants.WEBSOCKET_PING_INTERVAL_MILLIS, TimeUnit.MILLISECONDS)
            return builder.build()
        }
    }
}
