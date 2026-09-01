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
import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.NoExceptionSingleThreadExecutor
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelServerResponseMessageToSend
import io.olvid.engine.datatypes.containers.ServerQuery
import io.olvid.engine.datatypes.containers.ServerQuery.TransferCloseQuery
import io.olvid.engine.datatypes.containers.ServerQuery.TransferRelayQuery
import io.olvid.engine.datatypes.containers.ServerQuery.TransferTargetQuery
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.metamanager.ChannelDelegate
import io.olvid.engine.networkfetch.databases.PendingServerQuery
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import java.util.Arrays
import javax.net.ssl.SSLSocketFactory
import kotlin.math.min
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener

class ServerQueryCoordinatorWebSocketModule(
    fetchManagerSessionFactory: FetchManagerSessionFactory,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?,
    jsonObjectMapper: ObjectMapper?,
    prng: PRNGService
) {
    private val fetchManagerSessionFactory: FetchManagerSessionFactory
    private val sslSocketFactory: SSLSocketFactory?
    private val userAgentOverride: String?
    private val jsonObjectMapper: ObjectMapper?
    private val prng: PRNGService
    private val webSocketsMap: HashMap<UID?, WebSocketClientAndServerQuery?>
    private val executor: NoExceptionSingleThreadExecutor
    private var channelDelegate: ChannelDelegate? = null


    init {
        this.fetchManagerSessionFactory = fetchManagerSessionFactory
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride
        this.jsonObjectMapper = jsonObjectMapper
        this.prng = prng
        this.webSocketsMap = HashMap<UID?, WebSocketClientAndServerQuery?>()
        this.executor =
            NoExceptionSingleThreadExecutor("ServerQueryCoordinatorWebSocketModule executor")
    }

    fun setChannelDelegate(channelDelegate: ChannelDelegate) {
        this.channelDelegate = channelDelegate
    }

    fun handleServerQuery(pendingServerQuery: PendingServerQuery, calledFromOnOpen: Boolean) {
        executor.execute(Runnable handleServerQueryRunnable@{
            val serverQuery: ServerQuery?
            try {
                serverQuery = ServerQuery.of(pendingServerQuery.encodedQuery)
            } catch (e: DecodingException) {
                Logger.x(e)
                return@handleServerQueryRunnable
            }

            val protocolInstanceUid: UID
            try {
                val listOfEncoded: Array<Encoded> = serverQuery.getEncodedElements()!!.decodeList()
                protocolInstanceUid = listOfEncoded[1].decodeUid()
                /*
            int protocolId = (int) listOfEncoded[0].decodeLong();
            protocolInstanceUid = listOfEncoded[1].decodeUid();
            int protocolMessageId = (int) listOfEncoded[2].decodeLong();
            Encoded[] inputs = listOfEncoded[3].decodeList();
*/
            } catch (e: ArrayIndexOutOfBoundsException) {
                // we cannot respond to the protocol for a proper fail, so we simply ignore the message
                Logger.e("ServerQueryCoordinatorWebSocketModule.handlePendingServerQuery() failed to decode received serverQuery")
                return@handleServerQueryRunnable
            } catch (e: DecodingException) {
                Logger.e("ServerQueryCoordinatorWebSocketModule.handlePendingServerQuery() failed to decode received serverQuery")
                return@handleServerQueryRunnable
            }
            try {
                var webSocketClientAndQuery = webSocketsMap.get(protocolInstanceUid)
                if (webSocketClientAndQuery == null) {
                    // only the source and target message can trigger a websocket connection
                    if (serverQuery.getType().id != ServerQuery.TypeId.TRANSFER_SOURCE_QUERY_ID
                        && serverQuery.getType().id != ServerQuery.TypeId.TRANSFER_TARGET_QUERY_ID
                    ) {
                        sendFailedServerQueryResponse(pendingServerQuery)
                        return@handleServerQueryRunnable
                    }

                    // we do not handle the message yet, once the websocket is connected, it will be automatically handled
                    val webSocketClient: WebSocketClient =
                        WebSocketClient(protocolInstanceUid)
                    webSocketClientAndQuery =
                        WebSocketClientAndServerQuery(webSocketClient, pendingServerQuery)
                    webSocketsMap.put(protocolInstanceUid, webSocketClientAndQuery)
                    webSocketClientAndQuery.webSocketClient.connect()
                    return@handleServerQueryRunnable
                }

                if (!calledFromOnOpen) {
                    if (webSocketClientAndQuery.pendingServerQuery != null) {
                        try {
                            // check if the existing pendingServerQuery is a noResponseExpected relay message
                            val previousServerQuery =
                                ServerQuery.of(webSocketClientAndQuery.pendingServerQuery!!.encodedQuery)
                            if (previousServerQuery.getType().id == ServerQuery.TypeId.TRANSFER_RELAY_QUERY_ID
                                && (previousServerQuery.getType() as TransferRelayQuery).noResponseExpected
                            ) {
                                // in that case, delete the previous pendingServerQuery
                                fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                                    val rePendingServerQuery: PendingServerQuery? =
                                        PendingServerQuery.get(
                                            fetchManagerSession,
                                            webSocketClientAndQuery.pendingServerQuery!!.uid
                                        )
                                    if (rePendingServerQuery != null) {
                                        rePendingServerQuery.delete()
                                        fetchManagerSession.session.commit()
                                    }
                                }
                            } else {
                                // we have a message to send but never responded to the previous message --> this should never happen!
                                failProtocol(protocolInstanceUid)
                                return@handleServerQueryRunnable
                            }
                        } catch (_: Exception) {
                        }
                    }

                    webSocketClientAndQuery.pendingServerQuery = pendingServerQuery
                }

                if (webSocketClientAndQuery.webSocketClient.connectionStatus != ConnectionStatus.CONNECTED) {
                    // we received a message to send before the websocket ever got a chance to connect --> this should never happen!
                    failProtocol(protocolInstanceUid)
                    return@handleServerQueryRunnable
                }

                when (serverQuery.getType().id) {
                    ServerQuery.TypeId.TRANSFER_SOURCE_QUERY_ID -> {
                        val request = JsonRequestSource()
                        request.action = "source"

                        webSocketClientAndQuery.webSocketClient.send(
                            jsonObjectMapper!!.writeValueAsString(
                                request
                            )
                        )
                    }

                    ServerQuery.TypeId.TRANSFER_TARGET_QUERY_ID -> {
                        val transferTargetQuery = serverQuery.getType() as TransferTargetQuery
                        val request = JsonRequestTarget()
                        request.action = "target"
                        request.sessionNumber = transferTargetQuery.sessionNumber
                        request.payload = transferTargetQuery.payload

                        webSocketClientAndQuery.webSocketClient.send(
                            jsonObjectMapper!!.writeValueAsString(
                                request
                            )
                        )
                    }

                    ServerQuery.TypeId.TRANSFER_RELAY_QUERY_ID -> {
                        val transferRelayQuery = serverQuery.getType() as TransferRelayQuery
                        val request = JsonRequestRelay()
                        request.action = "relay"
                        request.relayConnectionId = transferRelayQuery.connectionIdentifier
                        request.payload = transferRelayQuery.payload

                        if (request.payload!!.size > Constants.TRANSFER_MAX_PAYLOAD_SIZE) {
                            val totalFragments =
                                ((transferRelayQuery.payload.size - 1) / Constants.TRANSFER_MAX_PAYLOAD_SIZE) + 1
                            request.totalFragments = totalFragments
                            var i = 0
                            while (i < totalFragments) {
                                request.fragmentNumber = i
                                request.payload = Arrays.copyOfRange(
                                    transferRelayQuery.payload,
                                    i * Constants.TRANSFER_MAX_PAYLOAD_SIZE,
                                    min(
                                        (i + 1) * Constants.TRANSFER_MAX_PAYLOAD_SIZE,
                                        transferRelayQuery.payload.size
                                    )
                                )
                                webSocketClientAndQuery.webSocketClient.send(
                                    jsonObjectMapper!!.writeValueAsString(
                                        request
                                    )
                                )
                                i++
                            }
                        } else {
                            webSocketClientAndQuery.webSocketClient.send(
                                jsonObjectMapper!!.writeValueAsString(
                                    request
                                )
                            )
                        }
                    }

                    ServerQuery.TypeId.TRANSFER_WAIT_QUERY_ID -> {
                        val pendingMessage =
                            webSocketClientAndQuery.webSocketClient.messageWaitingForWait
                        if (pendingMessage != null) {
                            webSocketClientAndQuery.webSocketClient.messageWaitingForWait = null
                            webSocketClientAndQuery.webSocketClient.dispatchMessage(pendingMessage)
                        }
                    }

                    ServerQuery.TypeId.TRANSFER_CLOSE_QUERY_ID -> {
                        val transferCloseQuery = serverQuery.getType() as TransferCloseQuery

                        // close the websocket
                        if (transferCloseQuery.abort) {
                            webSocketClientAndQuery.webSocketClient.webSocket!!.cancel()
                        } else {
                            webSocketClientAndQuery.webSocketClient.webSocket!!.close(1000, "")
                        }
                        webSocketsMap.remove(protocolInstanceUid)
                    }

                    ServerQuery.TypeId.DEVICE_DISCOVERY_QUERY_ID, ServerQuery.TypeId.PUT_USER_DATA_QUERY_ID, ServerQuery.TypeId.GET_USER_DATA_QUERY_ID, ServerQuery.TypeId.CHECK_KEYCLOAK_REVOCATION_QUERY_ID, ServerQuery.TypeId.CREATE_GROUP_BLOB_QUERY_ID, ServerQuery.TypeId.GET_GROUP_BLOB_QUERY_ID, ServerQuery.TypeId.LOCK_GROUP_BLOB_QUERY_ID, ServerQuery.TypeId.UPDATE_GROUP_BLOB_QUERY_ID, ServerQuery.TypeId.PUT_GROUP_LOG_QUERY_ID, ServerQuery.TypeId.DELETE_GROUP_BLOB_QUERY_ID, ServerQuery.TypeId.GET_KEYCLOAK_DATA_QUERY_ID, ServerQuery.TypeId.OWNED_DEVICE_DISCOVERY_QUERY_ID, ServerQuery.TypeId.DEVICE_MANAGEMENT_SET_NICKNAME_QUERY_ID, ServerQuery.TypeId.DEVICE_MANAGEMENT_DEACTIVATE_DEVICE_QUERY_ID, ServerQuery.TypeId.DEVICE_MANAGEMENT_SET_UNEXPIRING_DEVICE_QUERY_ID, ServerQuery.TypeId.REGISTER_API_KEY_QUERY_ID, ServerQuery.TypeId.UPLOAD_PRE_KEY_QUERY_ID, ServerQuery.TypeId.BACKUPS_V2_CREATE_BACKUP_QUERY_ID, ServerQuery.TypeId.BACKUPS_V2_UPLOAD_BACKUP_QUERY_ID, ServerQuery.TypeId.BACKUPS_V2_DELETE_BACKUP_QUERY_ID, ServerQuery.TypeId.BACKUPS_V2_LIST_BACKUPS_QUERY_ID, ServerQuery.TypeId.BACKUPS_V2_DOWNLOAD_PROFILE_PICTURE_QUERY_ID, ServerQuery.TypeId.KEYCLOAK_ID_BASED_AUTH_REQUEST_CHALLENGE, ServerQuery.TypeId.KEYCLOAK_ID_BASED_AUTH_GET_SESSION -> {
                        Logger.e("ServerQueryCoordinatorWebSocketModule.handlePendingServerQuery() received serverQuery with type " + serverQuery.getType().id)
                        failProtocol(protocolInstanceUid)
                    }

                    else -> {
                        Logger.e("ServerQueryCoordinatorWebSocketModule.handlePendingServerQuery() received serverQuery with type " + serverQuery.getType().id)
                        failProtocol(protocolInstanceUid)
                    }
                }
            } catch (e: Exception) {
                Logger.x(e)
                failProtocol(protocolInstanceUid)
            }
        })
    }


    private fun failProtocol(protocolInstanceUid: UID?) {
        Logger.i("ServerQueryCoordinatorWebSocketModule.failProtocol called")
        val clientAndQuery = webSocketsMap.get(protocolInstanceUid)
        if (clientAndQuery != null) {
            webSocketsMap.remove(protocolInstanceUid)
            if (clientAndQuery.webSocketClient.connectionStatus != ConnectionStatus.DISCONNECTED && clientAndQuery.webSocketClient.webSocket != null) {
                clientAndQuery.webSocketClient.webSocket!!.cancel()
            }
            if (clientAndQuery.pendingServerQuery != null) {
                sendFailedServerQueryResponse(clientAndQuery.pendingServerQuery!!)
            }
        }
    }

    private fun sendFailedServerQueryResponse(pendingServerQuery: PendingServerQuery) {
        // we notify the protocol the request failed by sending a null response
        sendServerQueryResponse(pendingServerQuery, null)
    }

    private fun sendServerQueryResponse(pendingServerQuery: PendingServerQuery, response: String?) {
        try {
            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                var success = false
                try {
                    val serverQuery = ServerQuery.of(pendingServerQuery.encodedQuery)
                    fetchManagerSession.session.startTransaction()
                    if (serverQuery.getType().id != ServerQuery.TypeId.TRANSFER_CLOSE_QUERY_ID) {
                        val channelServerResponseMessageToSend = ChannelServerResponseMessageToSend(
                            serverQuery.getOwnedIdentity(),
                            if (response == null) null else Encoded.of(response),
                            serverQuery.getEncodedElements()
                        )
                        channelDelegate!!.post(
                            fetchManagerSession.session,
                            channelServerResponseMessageToSend,
                            prng
                        )
                    }
                    val rePendingServerQuery: PendingServerQuery? =
                        PendingServerQuery.get(
                            fetchManagerSession,
                            pendingServerQuery.uid
                        )
                    if (rePendingServerQuery != null) {
                        rePendingServerQuery.delete()
                    }
                    success = true
                } catch (e: Exception) {
                    Logger.x(e)
                } finally {
                    if (success) {
                        fetchManagerSession.session.commit()
                    } else {
                        fetchManagerSession.session.rollback()
                    }
                }
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    inner class WebSocketClient internal constructor(protocolInstanceUid: UID?) :
        WebSocketListener() {
        var okHttpClient: OkHttpClient
        internal var webSocket: WebSocket?
        internal var connectionStatus: ConnectionStatus?
        private val protocolInstanceUid: UID?

        internal var messageWaitingForWait: String? = null

        init {
            this.okHttpClient = WebsocketCoordinator.initializeOkHttpClientForWebSocket(
                sslSocketFactory,
                userAgentOverride
            )
            this.protocolInstanceUid = protocolInstanceUid
            this.connectionStatus = ConnectionStatus.INITIALIZING
            this.webSocket = null
        }

        fun connect() {
            this.webSocket = okHttpClient.newWebSocket(
                Request.Builder().url(Constants.TRANSFER_WS_SERVER_URL).build(), this
            )
        }

        fun send(message: String) {
            webSocket!!.send(message)
        }

        fun dispatchMessage(text: String) {
            onMessage(text)
        }

        override fun onOpen(webSocket: WebSocket, response: Response) {
            executor.execute(Runnable {
                // once connected, process the pending message
                connectionStatus = ConnectionStatus.CONNECTED
                val clientAndQuery = webSocketsMap.get(protocolInstanceUid)
                if (clientAndQuery != null && clientAndQuery.pendingServerQuery != null) {
                    try {
                        handleServerQuery(clientAndQuery.pendingServerQuery!!, true)
                    } catch (e: Exception) {
                        Logger.x(e)
                    }
                }
            })
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            if (code != 1000) {
                executor.execute(Runnable { this.closeAndAbort() })
            }
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            Logger.x(t)
            executor.execute(Runnable { this.closeAndAbort() })
        }

        override fun onMessage(webSocket: WebSocket, text: String) {
            onMessage(text)
        }

        private fun onMessage(text: String?) {
            // ignore empty messages
            if (text == null || text.trim { it <= ' ' }.isEmpty()) {
                return
            }
            executor.execute(Runnable onMessageRunnable@{
                // first, try to parse error messages
                try {
                    val fail = jsonObjectMapper!!.readValue<JsonResponseFail>(
                        text,
                        JsonResponseFail::class.java
                    )
                    when (fail.errorCode) {
                        ERROR_CODE_UNKNOWN_SESSION_NUMBER, ERROR_CODE_OTHER_DISCONNECTED, ERROR_CODE_PAYLOAD_TOO_LARGE, ERROR_CODE_GENERAL_ERROR -> {
                            // for now we do not care what type of error we receive, but in the future we may want
                            // to inform the user about what went wrong and then need to differentiate based on error code
                            failProtocol(protocolInstanceUid)
                            return@onMessageRunnable
                        }
                    }
                } catch (_: Exception) {
                }

                val clientAndQuery = webSocketsMap.get(protocolInstanceUid)

                if (clientAndQuery == null) {
                    // protocol ended, we can ignore the message
                    return@onMessageRunnable
                }
                val pendingServerQuery = clientAndQuery.pendingServerQuery
                if (pendingServerQuery == null) {
                    // we don't have a server query to respond to yet, put the message on hold
                    messageWaitingForWait = text
                    return@onMessageRunnable
                }

                // check if the message was truncated or not
                try {
                    val fragmentedResponse =
                        jsonObjectMapper!!.readValue<JsonResponse>(text, JsonResponse::class.java)
                    if (fragmentedResponse.totalFragments != null && fragmentedResponse.fragmentNumber != null && fragmentedResponse.fragmentNumber!! >= 0 && fragmentedResponse.fragmentNumber!! < fragmentedResponse.totalFragments!!) {
                        // we have a fragmented response --> store it in the clientAndQuery
                        if (clientAndQuery.fragmentedResponse == null) {
                            clientAndQuery.fragmentedResponse = HashMap<Int?, JsonResponse?>()
                        }
                        clientAndQuery.fragmentedResponse!!.put(
                            fragmentedResponse.fragmentNumber,
                            fragmentedResponse
                        )
                        if (clientAndQuery.fragmentedResponse!!.size == fragmentedResponse.totalFragments) {
                            // we have all the fragments, reconstruct them
                            val reconstructedResponse = JsonResponse()
                            var payloadSize = 0
                            for (i in 0..<fragmentedResponse.totalFragments!!) {
                                payloadSize += clientAndQuery.fragmentedResponse!!.get(i)!!.payload.size
                            }
                            reconstructedResponse.otherConnectionId =
                                clientAndQuery.fragmentedResponse!!.get(0)!!.otherConnectionId
                            reconstructedResponse.payload = ByteArray(payloadSize)
                            var offset = 0
                            for (i in 0..<fragmentedResponse.totalFragments!!) {
                                val fragment = clientAndQuery.fragmentedResponse!!.get(i)
                                if (reconstructedResponse.otherConnectionId != fragment!!.otherConnectionId) {
                                    throw Exception("otherConnectionId mismatch")
                                }
                                System.arraycopy(
                                    fragment.payload,
                                    0,
                                    reconstructedResponse.payload,
                                    offset,
                                    fragment.payload.size
                                )
                                offset += fragment.payload.size
                            }
                            clientAndQuery.fragmentedResponse = null
                            clientAndQuery.pendingServerQuery = null
                            sendServerQueryResponse(
                                pendingServerQuery,
                                jsonObjectMapper.writeValueAsString(reconstructedResponse)
                            )
                        }
                        return@onMessageRunnable
                    }
                } catch (e: Exception) {
                    // in case of exception when parsing, ignore it and simply forward the response to the protocol
                    Logger.x(e)
                }

                // remove the pendingServerQuery
                clientAndQuery.pendingServerQuery = null

                // We do not parse the response here, the protocol will take care of this
                sendServerQueryResponse(pendingServerQuery, text)
            })
        }

        private fun closeAndAbort() {
            connectionStatus = ConnectionStatus.DISCONNECTED
            failProtocol(protocolInstanceUid)
        }
    }

    enum class ConnectionStatus {
        INITIALIZING,
        CONNECTED,
        DISCONNECTED,
    }

    class WebSocketClientAndServerQuery(
        webSocketClient: WebSocketClient,
        pendingServerQuery: PendingServerQuery?
    ) {
        @JvmField val webSocketClient: WebSocketClient
        @JvmField var pendingServerQuery: PendingServerQuery? // null after we have replied to a message
        var fragmentedResponse: HashMap<Int?, JsonResponse?>?

        init {
            this.webSocketClient = webSocketClient
            this.pendingServerQuery = pendingServerQuery
            this.fragmentedResponse = null
        }
    }


    @JsonIgnoreProperties(ignoreUnknown = true)
    class JsonResponseFail {
        @JvmField var errorCode: Int = 0
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class JsonRequestSource {
        @JvmField var action: String? = null
    }


    @JsonIgnoreProperties(ignoreUnknown = true)
    class JsonRequestTarget {
        @JvmField var action: String? = null
        @JvmField var sessionNumber: Long = 0
        @JvmField var payload: ByteArray? = null
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class JsonRequestRelay {
        @JvmField var action: String? = null
        @JvmField var relayConnectionId: String? = null
        @JvmField var payload: ByteArray? = null
        @JvmField var fragmentNumber: Int? = null
        @JvmField var totalFragments: Int? = null
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class JsonResponse {
        @JvmField var otherConnectionId: String? = null
        @JvmField var payload: ByteArray = ByteArray(0)
        @JvmField var fragmentNumber: Int? = null
        @JvmField var totalFragments: Int? = null
    }

    companion object {
        private val ERROR_CODE_GENERAL_ERROR = -1
        private const val ERROR_CODE_UNKNOWN_SESSION_NUMBER = 1
        private const val ERROR_CODE_OTHER_DISCONNECTED = 2
        private const val ERROR_CODE_PAYLOAD_TOO_LARGE = 3
    }
}
