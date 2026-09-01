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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoDuplicateOperationQueue
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.Operation.OnCancelCallback
import io.olvid.engine.datatypes.Operation.OnFinishCallback
import io.olvid.engine.datatypes.notifications.DownloadNotifications
import io.olvid.engine.engine.types.JsonOsmStyle
import io.olvid.engine.metamanager.NotificationPostingDelegate
import io.olvid.engine.networkfetch.databases.CachedWellKnown
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import io.olvid.engine.networkfetch.datatypes.WellKnownCacheDelegate
import io.olvid.engine.networkfetch.operations.WellKnownDownloadOperation
import java.util.Timer
import java.util.TimerTask
import javax.net.ssl.SSLSocketFactory


class WellKnownCoordinator(
    fetchManagerSessionFactory: FetchManagerSessionFactory,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?,
    jsonObjectMapper: ObjectMapper
) : OnFinishCallback, OnCancelCallback, WellKnownCacheDelegate {
    private val fetchManagerSessionFactory: FetchManagerSessionFactory
    private val sslSocketFactory: SSLSocketFactory?
    private val userAgentOverride: String?
    private var notificationPostingDelegate: NotificationPostingDelegate? = null
    private val jsonObjectMapper: ObjectMapper

    private var cacheInitialized: Boolean
    private val wellKnownCache: HashMap<String?, JsonWellKnown?>

    private val wellKnownDownloadOperationQueue: NoDuplicateOperationQueue
    private val wellKnownDownloadTimer: Timer

    init {
        this.fetchManagerSessionFactory = fetchManagerSessionFactory
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride
        this.jsonObjectMapper = jsonObjectMapper

        this.cacheInitialized = false
        this.wellKnownCache = HashMap<String?, JsonWellKnown?>()

        this.wellKnownDownloadOperationQueue = NoDuplicateOperationQueue()

        this.wellKnownDownloadTimer = Timer("Engine-WellKnownDownloadTimer")
    }

    fun startProcessing() {
        this.wellKnownDownloadOperationQueue.execute(1, "Engine-WellKnownDownloadCoordinator")
    }

    fun setNotificationPostingDelegate(notificationPostingDelegate: NotificationPostingDelegate?) {
        this.notificationPostingDelegate = notificationPostingDelegate
    }

    fun initialQueueing() {
        try {
            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                val cachedWellKnowns: MutableList<CachedWellKnown?> =
                    CachedWellKnown.getAll(fetchManagerSession)
                val ownedIdentities: Array<Identity> =
                    fetchManagerSession.identityDelegate!!.getOwnedIdentities(fetchManagerSession.session)

                val servers: MutableSet<String?> = HashSet()
                for (ownedIdentity in ownedIdentities) {
                    servers.add(ownedIdentity.server)
                }

                for (server in servers) {
                    queueNewWellKnownDownloadOperation(server)
                }

                // check for obsolete cache elements
                for (cachedWellKnown in cachedWellKnowns) {
                    if (cachedWellKnown == null) continue
                    if (servers.contains(cachedWellKnown.server)) {
                        try {
                            wellKnownCache[cachedWellKnown.server] = jsonObjectMapper.readValue(
                                cachedWellKnown.serializedWellKnown,
                                JsonWellKnown::class.java
                            )
                        } catch (_: Exception) {
                            // do nothing
                        }
                    } else {
                        cachedWellKnown.delete()
                    }
                }
                this.cacheInitialized = true

                notificationPostingDelegate?.postNotification(
                    DownloadNotifications.NOTIFICATION_WELL_KNOWN_CACHE_INITIALIZED,
                    HashMap<String, Any>()
                )
                wellKnownDownloadTimer.schedule(object : TimerTask() {
                    override fun run() {
                        try {
                            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                                val ownedIdentities: Array<Identity> =
                                    fetchManagerSession.identityDelegate!!.getOwnedIdentities(
                                        fetchManagerSession.session
                                    )
                                val servers: MutableSet<String?> = HashSet()
                                for (ownedIdentity in ownedIdentities) {
                                    servers.add(ownedIdentity.server)
                                }
                                for (server in servers) {
                                    queueNewWellKnownDownloadOperation(server)
                                }
                            }
                        } catch (e: Exception) {
                            Logger.x(e)
                        }
                    }
                }, Constants.WELL_KNOWN_REFRESH_INTERVAL, Constants.WELL_KNOWN_REFRESH_INTERVAL)
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }


    fun queueNewWellKnownDownloadOperation(server: String?) {
        if (server == null) return
        Logger.d("Requesting .well-known fetch for " + server)
        wellKnownDownloadOperationQueue.queue(
            WellKnownDownloadOperation(
                fetchManagerSessionFactory,
                sslSocketFactory,
                userAgentOverride,
                server,
                jsonObjectMapper,
                this,
                this
            )
        )
    }


    override fun onFinishCallback(operation: Operation) {
        if (operation !is WellKnownDownloadOperation) {
            return
        }
        val wellKnownDownloadOperation = operation

        val server = wellKnownDownloadOperation.server
        val jsonWellKnown = wellKnownDownloadOperation.downloadedWellKnown
        val updated = wellKnownDownloadOperation.isUpdated
        wellKnownCache.put(server, jsonWellKnown)

        if (updated) {
            val userInfo = HashMap<String, Any>()
            userInfo[DownloadNotifications.NOTIFICATION_WELL_KNOWN_UPDATED_SERVER_KEY] = server
            jsonWellKnown?.serverConfig?.let {
                userInfo[DownloadNotifications.NOTIFICATION_WELL_KNOWN_UPDATED_SERVER_CONFIG_KEY] = it
            }
            jsonWellKnown?.appInfo?.let {
                userInfo[DownloadNotifications.NOTIFICATION_WELL_KNOWN_UPDATED_APP_INFO_KEY] = it
            }
            notificationPostingDelegate?.postNotification(
                DownloadNotifications.NOTIFICATION_WELL_KNOWN_UPDATED,
                userInfo
            )
        } else {
            val userInfo = HashMap<String, Any>()
            userInfo[DownloadNotifications.NOTIFICATION_WELL_KNOWN_DOWNLOAD_SUCCESS_SERVER_KEY] = wellKnownDownloadOperation.server
            jsonWellKnown?.appInfo?.let {
                userInfo[DownloadNotifications.NOTIFICATION_WELL_KNOWN_DOWNLOAD_SUCCESS_APP_INFO_KEY] = it
            }
            notificationPostingDelegate?.postNotification(
                DownloadNotifications.NOTIFICATION_WELL_KNOWN_DOWNLOAD_SUCCESS,
                userInfo
            )
        }
    }

    override fun onCancelCallback(operation: Operation) {
        if (operation !is WellKnownDownloadOperation) {
            return
        }
        val wellKnownDownloadOperation = operation

        val userInfo = HashMap<String, Any>()
        userInfo[DownloadNotifications.NOTIFICATION_WELL_KNOWN_DOWNLOAD_FAILED_SERVER_KEY] = wellKnownDownloadOperation.server
        notificationPostingDelegate?.postNotification(
            DownloadNotifications.NOTIFICATION_WELL_KNOWN_DOWNLOAD_FAILED,
            userInfo
        )
    }

    class NotCachedException : Exception()

    @Throws(NotCachedException::class)
    override fun getWsUrl(server: String?): String? {
        if (!cacheInitialized) {
            throw NotCachedException()
        }
        val jsonWellKnown = wellKnownCache.get(server)
        if (jsonWellKnown == null) {
            queueNewWellKnownDownloadOperation(server)
            throw NotCachedException()
        }
        if (jsonWellKnown.serverConfig == null) {
            return null
        }
        return jsonWellKnown.serverConfig!!.webSocketUrl
    }

    @Throws(NotCachedException::class)
    override fun getTurnUrls(server: String?): MutableList<String>? {
        if (!cacheInitialized) {
            throw NotCachedException()
        }
        val jsonWellKnown = wellKnownCache.get(server)
        if (jsonWellKnown == null) {
            queueNewWellKnownDownloadOperation(server)
            throw NotCachedException()
        }
        if (jsonWellKnown.serverConfig == null) {
            return null
        }
        return jsonWellKnown.serverConfig!!.turnServerUrls
    }

    @Throws(NotCachedException::class)
    override fun getAltTurnUrls(server: String?): MutableList<String>? {
        if (!cacheInitialized) {
            throw NotCachedException()
        }
        val jsonWellKnown = wellKnownCache.get(server)
        if (jsonWellKnown == null) {
            queueNewWellKnownDownloadOperation(server)
            throw NotCachedException()
        }
        if (jsonWellKnown.serverConfig == null) {
            return null
        }
        return jsonWellKnown.serverConfig!!.altTurnServerUrls
    }

    @Throws(NotCachedException::class)
    override fun getOsmStyles(server: String?): MutableList<JsonOsmStyle>? {
        if (!cacheInitialized) {
            throw NotCachedException()
        }
        val jsonWellKnown = wellKnownCache.get(server)
        if (jsonWellKnown == null) {
            queueNewWellKnownDownloadOperation(server)
            throw NotCachedException()
        }
        if (jsonWellKnown.serverConfig == null) {
            return null
        }
        return jsonWellKnown.serverConfig!!.osmStyles
    }

    @Throws(NotCachedException::class)
    override fun getAddressUrl(server: String?): String? {
        if (!cacheInitialized) {
            throw NotCachedException()
        }
        val jsonWellKnown = wellKnownCache.get(server)
        if (jsonWellKnown == null) {
            queueNewWellKnownDownloadOperation(server)
            throw NotCachedException()
        }
        if (jsonWellKnown.serverConfig == null) {
            return null
        }
        return jsonWellKnown.serverConfig!!.addressServerUrl
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class JsonWellKnown {
        @JsonProperty("server")
        @JvmField var serverConfig: JsonWellKnownServerConfig? = null

        @JsonProperty("app")
        var appInfo: MutableMap<String?, Int?>? = null
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class JsonWellKnownServerConfig {
        @JsonProperty("ws_server")
        @JvmField var webSocketUrl: String? = null

        @JsonProperty("turn_servers")
        @JvmField var turnServerUrls: MutableList<String>? = null

        @JsonProperty("alt_turn_servers")
        @JvmField var altTurnServerUrls: MutableList<String>? = null

        // no longer used since we have osmStyles
        //        @JsonProperty("osm_server")
        //        public String osmServerUrl;
        @JsonProperty("address_server")
        @JvmField var addressServerUrl: String? = null

        @JsonProperty("osm_styles")
        @JvmField var osmStyles: MutableList<JsonOsmStyle>? = null
    }
}
