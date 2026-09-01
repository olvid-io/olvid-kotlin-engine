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
package io.olvid.engine.datatypes

import io.olvid.engine.Logger
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.MalformedURLException
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocketFactory
import kotlin.math.min


abstract class ServerMethodForS3 {
    private var sslSocketFactory: SSLSocketFactory? = null
    private var userAgentOverride: String? = null
    private var progressListener: ServerMethodForS3ProgressListener? = null
    private var progressListenerIntervalMs: Long = 0

    protected abstract fun getUrl(): String?

    // only called for PUT methods
    protected abstract fun getDataToSend(): ByteArray

    // only called for GET methods
    protected abstract fun handleReceivedData(receivedData: ByteArray?)
    protected abstract fun getMethod(): String?
    protected abstract fun isActiveIdentityRequired(): Boolean

    protected var returnStatus: Byte = 0

    fun setProgressListener(
        intervalMs: Long,
        progressListener: ServerMethodForS3ProgressListener?
    ) {
        this.progressListenerIntervalMs = intervalMs
        this.progressListener = progressListener
    }

    fun setSslSocketFactory(sslSocketFactory: SSLSocketFactory?, userAgentOverride: String?) {
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride
    }

    fun execute(ownedIdentityIsActive: Boolean): Byte {
        if (isActiveIdentityRequired() && !ownedIdentityIsActive) {
            returnStatus = IDENTITY_IS_NOT_ACTIVE
            return returnStatus
        }
        val url = getUrl()
        val dataToSend = getDataToSend()
        val method = getMethod()

        try {
            val requestUrl = URL(url)
            val connection = requestUrl.openConnection() as HttpURLConnection
            if (connection is HttpsURLConnection && sslSocketFactory != null) {
                connection.sslSocketFactory = sslSocketFactory
            }
            val userAgentProperty =
                if (userAgentOverride != null) userAgentOverride else System.getProperty("http.agent")
            if (userAgentProperty != null) {
                connection.setRequestProperty("User-Agent", userAgentProperty)
            }
            try {
                // Timeout after 5 seconds
                connection.connectTimeout = 5000
                connection.setRequestProperty("Cache-Control", "no-store")
                connection.requestMethod = method
                val responseData: ByteArray?
                if (METHOD_GET == getMethod()) {
                    connection.setDoOutput(false)
                } else {
                    connection.setDoOutput(true)
                    connection.setFixedLengthStreamingMode(dataToSend.size)
                    connection.getOutputStream().use { os ->
                        if (progressListener != null) {
                            var nextReport = System.currentTimeMillis() + progressListenerIntervalMs

                            var offset = 0
                            while (offset < dataToSend.size) {
                                if (System.currentTimeMillis() > nextReport) {
                                    progressListener!!.onProgress(offset.toLong())
                                    nextReport =
                                        System.currentTimeMillis() + progressListenerIntervalMs
                                }
                                os.write(
                                    dataToSend,
                                    offset,
                                    min(BLOCK_SIZE, dataToSend.size - offset)
                                )
                                offset += BLOCK_SIZE
                            }
                            progressListener!!.onProgress(dataToSend.size.toLong())
                        } else {
                            os.write(dataToSend)
                        }
                    }
                }

                val serverResponse = connection.getResponseCode()

                when (serverResponse) {
                    200 -> {
                        returnStatus = OK
                        if (METHOD_GET == getMethod()) {
                            connection.getInputStream().use { `is` ->
                                BufferedInputStream(`is`).use { bis ->
                                    ByteArrayOutputStream().use { byteArrayOutputStream ->
                                        var numberOfBytesRead: Int
                                        val buffer = ByteArray(BLOCK_SIZE)

                                        if (progressListener != null) {
                                            var nextReport =
                                                System.currentTimeMillis() + progressListenerIntervalMs
                                            var progress = 0
                                            while ((bis.read(buffer)
                                                    .also { numberOfBytesRead = it }) != -1
                                            ) {
                                                byteArrayOutputStream.write(
                                                    buffer,
                                                    0,
                                                    numberOfBytesRead
                                                )
                                                progress += numberOfBytesRead
                                                if (System.currentTimeMillis() > nextReport) {
                                                    progressListener!!.onProgress(progress.toLong())
                                                    nextReport =
                                                        System.currentTimeMillis() + progressListenerIntervalMs
                                                }
                                            }
                                            progressListener!!.onProgress(progress.toLong())
                                        } else {
                                            while ((bis.read(buffer)
                                                    .also { numberOfBytesRead = it }) != -1
                                            ) {
                                                byteArrayOutputStream.write(
                                                    buffer,
                                                    0,
                                                    numberOfBytesRead
                                                )
                                            }
                                        }
                                        byteArrayOutputStream.flush()

                                        responseData = byteArrayOutputStream.toByteArray()
                                        handleReceivedData(responseData)
                                    }
                                }
                            }
                        }
                    }

                    403 -> {
                        returnStatus = INVALID_SIGNED_URL
                    }

                    404 -> {
                        returnStatus = NOT_FOUND
                    }

                    else -> {
                        Logger.w("Unexpected HTTP response code: " + serverResponse + " for attachment download")
                        returnStatus = GENERAL_ERROR
                    }
                }
            } finally {
                connection.disconnect()
            }
        } catch (e: MalformedURLException) {
            Logger.x(e)
            returnStatus = MALFORMED_URL
        } catch (e: IOException) {
            Logger.x(e)
            returnStatus = SERVER_CONNECTION_ERROR
        }
        return returnStatus
    }

    interface ServerMethodForS3ProgressListener {
        fun onProgress(byteCount: Long)
    }

    companion object {
        const val OK: Byte = 0x00
        const val NOT_FOUND: Byte = 0x01
        const val INVALID_SIGNED_URL: Byte = 0x02
        val GENERAL_ERROR: Byte = 0xff.toByte()

        const val METHOD_PUT: String = "PUT"
        const val METHOD_GET: String = "GET"

        val MALFORMED_URL: Byte = 0x80.toByte()
        val SERVER_CONNECTION_ERROR: Byte = 0x81.toByte()
        val IDENTITY_IS_NOT_ACTIVE: Byte = 0x8e.toByte()

        private const val BLOCK_SIZE = 32768
    }
}
