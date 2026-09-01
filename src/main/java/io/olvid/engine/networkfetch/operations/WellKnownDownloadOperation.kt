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
package io.olvid.engine.networkfetch.operations

import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.crypto.Hash
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.UID
import io.olvid.engine.networkfetch.coordinators.WellKnownCoordinator.JsonWellKnown
import io.olvid.engine.networkfetch.databases.CachedWellKnown
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.sql.SQLException
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocketFactory


class WellKnownDownloadOperation(
    private val fetchManagerSessionFactory: FetchManagerSessionFactory,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?,
    @JvmField val server: String,
    private val objectMapper: ObjectMapper,
    onFinishCallback: OnFinishCallback?,
    onCancelCallback: OnCancelCallback?
) : Operation(
    computeUniqueUid(
        server
    ), onFinishCallback, onCancelCallback
) {
    var isUpdated: Boolean = false
        private set
    var downloadedWellKnown: JsonWellKnown? = null
        private set


    override fun doCancel() {
        // do nothing
    }

    override fun doExecute() {
        var finished = false
        try {
            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                try {
                    val cachedWellKnown: CachedWellKnown? =
                        CachedWellKnown.get(fetchManagerSession, server)

                    val url = URL(server + WELL_KNOWN_PATH)

                    val connection = url.openConnection() as HttpURLConnection
                    if (connection is HttpsURLConnection && sslSocketFactory != null) {
                        connection.setSSLSocketFactory(sslSocketFactory)
                    }
                    val userAgentProperty =
                        if (userAgentOverride != null) userAgentOverride else System.getProperty("http.agent")
                    if (userAgentProperty != null) {
                        connection.setRequestProperty("User-Agent", userAgentProperty)
                    }
                    try {
                        // Timeout after 5 seconds
                        connection.setConnectTimeout(5000)
                        connection.setRequestProperty("Cache-Control", "no-store")
                        connection.setRequestMethod("GET")
                        connection.setDoOutput(false)

                        val serverResponse = connection.getResponseCode()

                        if (serverResponse == 200) {
                            val responseData: ByteArray?
                            connection.getInputStream().use { `is` ->
                                BufferedInputStream(`is`).use { bis ->
                                    ByteArrayOutputStream().use { byteArrayOutputStream ->
                                        var numberOfBytesRead: Int
                                        val buffer = ByteArray(32768)

                                        while ((bis.read(buffer)
                                                .also { numberOfBytesRead = it }) != -1
                                        ) {
                                            byteArrayOutputStream.write(
                                                buffer,
                                                0,
                                                numberOfBytesRead
                                            )
                                        }
                                        byteArrayOutputStream.flush()
                                        responseData = byteArrayOutputStream.toByteArray()
                                    }
                                }
                            }
                            try {
                                downloadedWellKnown = objectMapper.readValue<JsonWellKnown?>(
                                    responseData,
                                    JsonWellKnown::class.java
                                )
                            } catch (e: Exception) {
                                Logger.x(e)
                                cancel(RFC_MALFORMED_WELL_KNOWN)
                                return
                            }

                            val newSerializedWellKnown =
                                kotlin.text.String(responseData!!, StandardCharsets.UTF_8)

                            // check if something changed
                            if (cachedWellKnown == null) {
                                CachedWellKnown.create(
                                    fetchManagerSession,
                                    server,
                                    newSerializedWellKnown
                                )
                                this.isUpdated = true
                            } else if (cachedWellKnown.serializedWellKnown != newSerializedWellKnown) {
                                cachedWellKnown.update(newSerializedWellKnown)
                                this.isUpdated = true
                            } else {
                                this.isUpdated = false
                            }
                        } else {
                            cancel(RFC_NOT_FOUND)
                            return
                        }
                    } finally {
                        connection.disconnect()
                    }

                    finished = true
                } catch (e: Exception) {
                    Logger.x(e)
                } finally {
                    if (finished) {
                        fetchManagerSession.session.commit()
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

    companion object {
        const val RFC_NOT_FOUND: Int = 1
        const val RFC_MALFORMED_WELL_KNOWN: Int = 2

        const val WELL_KNOWN_PATH: String = "/.well-known/server-config.json"

        fun computeUniqueUid(server: String): UID {
            val sha256 = Suite.getHash(Hash.SHA256)
            return UID(sha256.digest(server.toByteArray(StandardCharsets.UTF_8)))
        }
    }
}
