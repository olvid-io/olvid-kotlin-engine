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
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.MalformedURLException
import java.net.URL
import java.util.Arrays
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocketFactory


abstract class ServerMethod {
    protected abstract fun getServer(): String?
    protected abstract fun getServerMethod(): String?
    protected abstract fun getDataToSend(): ByteArray?
    protected abstract fun parseReceivedData(receivedData: Array<Encoded?>?)
    protected abstract fun isActiveIdentityRequired(): Boolean

    protected var returnStatus: Byte = 0

    private var sslSocketFactory: SSLSocketFactory? = null
    private var userAgentOverride: String? = null

    fun setSslSocketFactory(sslSocketFactory: SSLSocketFactory?, userAgentOverride: String?) {
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride
    }

    fun execute(ownedIdentityIsActive: Boolean): Byte {
        if (isActiveIdentityRequired() && !ownedIdentityIsActive) {
            returnStatus = IDENTITY_IS_NOT_ACTIVE
            return returnStatus
        }
        var server = getServer()
        val parts: Array<String?> =
            server!!.split("://".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        var proto: String? = "https"
        if (parts.size == 2) {
            proto = parts[0]
            server = parts[1]
        } else {
            server = parts[0]
        }
        var pathPrefix: String? = null
        val pathPos = server!!.indexOf('/')
        if (pathPos != -1) {
            pathPrefix = server.substring(pathPos)
            server = server.substring(0, pathPos)

            // remove any trailing / from pathPrefix
            while (pathPrefix!!.endsWith("/")) {
                pathPrefix = pathPrefix.substring(0, pathPrefix.length - 1)
            }
        }
        var port = -1
        val portPos = server.indexOf(':')
        if (portPos != -1) {
            port = server.substring(portPos + 1).toInt()
            server = server.substring(0, portPos)
        }
        var path = getServerMethod()
        if (pathPrefix != null && !pathPrefix.isEmpty()) {
            path = pathPrefix + path
        }
        val dataToSend = getDataToSend()

        try {
            val requestUrl = URL(proto, server, port, path)
            val connection = requestUrl.openConnection() as HttpURLConnection
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
                connection.setReadTimeout(20000)
                connection.setDoOutput(true)
                connection.setFixedLengthStreamingMode(dataToSend!!.size)
                connection.setRequestProperty("Cache-Control", "no-store")
                connection.setRequestProperty("Content-Type", "application/bytes")
                connection.setRequestProperty(
                    "Olvid-API-Version",
                    "" + Constants.SERVER_API_VERSION
                )
                connection.getOutputStream().use { os ->
                    os.write(dataToSend)
                    val serverResponse = connection.getResponseCode()
                    when (serverResponse) {
                        200 -> {
                            connection.getInputStream().use { `is` ->
                                BufferedInputStream(`is`).use { bis ->
                                    ByteArrayOutputStream().use { byteArrayOutputStream ->
                                        var numberOfBytesRead: Int
                                        val buffer = ByteArray(8192)

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

                                        val responseData = byteArrayOutputStream.toByteArray()

                                        val encodedResponse = Encoded(responseData)

                                        val responseList: Array<Encoded> =
                                            encodedResponse.decodeList()
                                        if (responseList.size == 0) {
                                            throw DecodingException()
                                        }
                                        val returnStatusBytes = responseList[0].decodeBytes()
                                        if (returnStatusBytes.size != 1) {
                                            throw DecodingException()
                                        }

                                        // Parse the received data and return the server status code
                                        returnStatus = returnStatusBytes[0]
                                        parseReceivedData(
                                            Arrays.copyOfRange<Encoded?>(
                                                responseList,
                                                1,
                                                responseList.size
                                            )
                                        )
                                    }
                                }
                            }
                        }

                        413 -> {
                            // payload too large
                            returnStatus = PAYLOAD_TOO_LARGE
                        }

                        else -> {
                            // unknown server response
                            Logger.w("Unexpected HTTP response code: " + serverResponse + " for query " + path)
                            returnStatus = SERVER_CONNECTION_ERROR
                        }
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
        } catch (e: DecodingException) {
            Logger.x(e)
            returnStatus = MALFORMED_SERVER_RESPONSE
        }
        return returnStatus
    }

    companion object {
        const val OK: Byte = 0x00

        //    public static final byte PROOF_OF_WORK_REQUIRED = 0x01;
        //    public static final byte QUOTA_EXCEEDED = 0x02;
        //    public static final byte EXCEEDING_EXPECTED_BYTE_LENGTH = 0x03;
        const val INVALID_SESSION: Byte = 0x04

        //    public static final byte NOT_YET_AVAILABLE = 0x05;
        //    public static final byte MESSAGE_NOT_COMPLETE_YET = 0x06;
        //    public static final byte UNKNOWN_API_KEY = 0x07;
        //    public static final byte API_KEY_LICENSES_EXHAUSTED = 0x08;
        const val DELETED_FROM_SERVER: Byte = 0x09
        const val ANOTHER_DEVICE_IS_ALREADY_REGISTERED: Byte = 0x0a
        const val DEVICE_IS_NOT_REGISTERED: Byte = 0x0b
        const val INVALID_NONCE: Byte = 0x0c
        const val UPLOAD_CANCELLED: Byte = 0x0d
        const val PERMISSION_DENIED: Byte = 0x0e
        const val FREE_TRIAL_ALREADY_USED: Byte = 0x0f

        //    public static final byte STATUS_RECEIPT_IS_EXPIRED = 0x10; // used on iOS only
        const val EXTENDED_PAYLOAD_UNAVAILABLE: Byte = 0x11
        const val GROUP_UID_ALREADY_USED: Byte = 0x12
        const val GROUP_IS_LOCKED: Byte = 0x13
        const val INVALID_SIGNATURE: Byte = 0x14
        const val GROUP_NOT_LOCKED: Byte = 0x15
        const val INVALID_API_KEY: Byte = 0x16
        const val LISTING_TRUNCATED: Byte = 0x17
        val PAYLOAD_TOO_LARGE: Byte = 0x18.toByte()
        val BACKUP_UID_ALREADY_USED: Byte = 0x19.toByte()
        val BACKUP_VERSION_TOO_SMALL: Byte = 0x1a.toByte()
        val UNKNOWN_BACKUP_UID: Byte = 0x1b.toByte()
        val UNKNOWN_BACKUP_THREAD_ID: Byte = 0x1c.toByte()
        val UNKNOWN_BACKUP_VERSION: Byte = 0x1d.toByte()


        val PARSING_ERROR: Byte = 0xfe.toByte()
        val GENERAL_ERROR: Byte = 0xff.toByte()

        val MALFORMED_URL: Byte = 0x80.toByte()
        val SERVER_CONNECTION_ERROR: Byte = 0x81.toByte()
        val MALFORMED_SERVER_RESPONSE: Byte = 0x82.toByte()
        val OK_WITH_MALFORMED_SERVER_RESPONSE: Byte = 0x83.toByte()
        val IDENTITY_IS_NOT_ACTIVE: Byte = 0x8e.toByte()
    }
}

