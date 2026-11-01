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

package io.olvid.engine.engine.types

import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okhttp3.tls.decodeCertificatePem
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.X509TrustManager

// Same fixtures as OkHttp's CompromisedIntermediateTest: the emSign root, and one of its compromised
// intermediates, whose private key is 4.
class BlocklistedCertificatesTrustManagerTest {
    private val emsignRootTlsCaG3 = """
        -----BEGIN CERTIFICATE-----
        MIICKTCCAa+gAwIBAgIQDnYGcvFDRZ/I/gqwvAXjlDAKBggqhkjOPQQDAzBWMQsw
        CQYDVQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRl
        ZDEgMB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwHhcNMjQwMjA4MDgx
        OTMyWhcNNDkwMjA3MDgxOTMyWjBWMQswCQYDVQQGEwJJTjElMCMGA1UECgwcZU11
        ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAwwXZW1TaWduIFJvb3Qg
        VExTIENBIC0gRzMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARfD9w/q1cWxL6D9bMG
        H6CQ4u+gAV6GN9s+PwQx9Bl4hC+0iU8QOk8mWO/RwXQy10DCSxT8vSIJClHKp+Ao
        4qJKdYeV0SwZ7LMQziyLfxIUOY6Grja/sQFwLKYf8EdDXAyjQjBAMB0GA1UdDgQW
        BBThOqshfPHjTVSu1HK3/YtZQiCQVDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/
        BAUwAwEB/zAKBggqhkjOPQQDAwNoADBlAjBhCFTkly7Yl7+s4hiw+k6ZJTXT2AiI
        rvmsmfqPr5E7ecwXb6kXA5LTFd6rjwTuV3sCMQC9w6ZSbVq1mveMO6dKFziOzClT
        KCT2RFT6yXtq6nzgRICgBmiXbJAXsmZ8yAwjyWc=
        -----END CERTIFICATE-----
        """.trimIndent().decodeCertificatePem()

    private val emOvTlsCaG3c = """
        -----BEGIN CERTIFICATE-----
        MIIDaDCCAu6gAwIBAgIPKWkmwiejoVJjkrGUgqUEMAoGCCqGSM49BAMDMFYxCzAJ
        BgNVBAYTAklOMSUwIwYDVQQKDBxlTXVkaHJhIFRlY2hub2xvZ2llcyBMaW1pdGVk
        MSAwHgYDVQQDDBdlbVNpZ24gUm9vdCBUTFMgQ0EgLSBHMzAeFw0yNTA0MzAxNTM3
        NDFaFw00MDA0MjgxODMwMDBaMEAxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVk
        aHJhIEluYzEbMBkGA1UEAwwSRU0gT1YgVExTIENBIC0gRzNDMHYwEAYHKoZIzj0C
        AQYFK4EEACIDYgAEE4JRzVKskpjByKrZdzId65fnCb0LTKCspV3IrVHc/J0ViaFZ
        fjpRIOHv1jHGPhg1ysrimGmmLhYx6KKBgatWYW3EXZGKvAnzqw5jz3kqpNztc4e+
        N7ulaVSfHAKycO1no4IBljCCAZIwHwYDVR0jBBgwFoAU4TqrIXzx401UrtRyt/2L
        WUIgkFQwHQYDVR0OBBYEFDTq6gzryQra+dDF4u2beMmHnhtsMB0GA1UdJQQWMBQG
        CCsGAQUFBwMBBggrBgEFBQcDAjBdBgNVHSAEVjBUMDkGCysGAQQBg44hAQABMCow
        KAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDQYLKwYB
        BAGDjiEBAm4wCAYGZ4EMAQICMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYY
        aHR0cDovL29jc3AtYy5lbXNpZ24uY29tMD8GCCsGAQUFBzAChjNodHRwOi8vcmVw
        b3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL0VNT1ZUTFNDQUczQy5wN2MwNwYDVR0f
        BDAwLjAsoCqgKIYmaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290dGxzY2FnMy5j
        cmwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0E
        AwMDaAAwZQIxAMSZt2xsPeumRdeSMSQ3CbzIZeQ/q7GDCWfeE1Pq+mhgA6gRM44c
        NVF3xJ+wsxJk+wIwFJbaDMokD8Ei6eNOiA8yUMYvfzQyngmrhZQMdPCK1SewrR79
        4rSb9vGqxZzelQth
        -----END CERTIFICATE-----
        """.trimIndent().decodeCertificatePem()

    private val emOvTlsCaG3cPrivateKey = KeyFactory.getInstance("EC").run {
        val secp384r1 = AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp384r1"))
            getParameterSpec(ECParameterSpec::class.java)
        }
        generatePrivate(ECPrivateKeySpec(BigInteger("4"), secp384r1))
    }

    private val server = MockWebServer()

    // a platform that still trusts the emSign root
    private val platformTrustManager: X509TrustManager = HandshakeCertificates.Builder()
        .addTrustedCertificate(emsignRootTlsCaG3)
        .build()
        .trustManager

    @Before
    fun setUp() {
        val serverCertificate = HeldCertificate.Builder()
            .signedBy(HeldCertificate(KeyPair(emOvTlsCaG3c.publicKey, emOvTlsCaG3cPrivateKey), emOvTlsCaG3c))
            .addSubjectAlternativeName("localhost")
            .build()
        server.useHttps(
            HandshakeCertificates.Builder()
                .heldCertificate(serverCertificate, emOvTlsCaG3c)
                .build()
                .sslSocketFactory()
        )
        server.enqueue(MockResponse(body = "hello"))
        server.start()
    }

    @After
    fun tearDown() {
        server.close()
    }

    @Test
    fun platformAloneAcceptsTheCompromisedChain() {
        val connection = openConnection(platformTrustManager)

        assertEquals("hello", connection.inputStream.bufferedReader().readText())
        assertNotNull(server.takeRequest(1, TimeUnit.SECONDS))
    }

    @Test
    fun blocklistRejectsTheCompromisedChainBeforeAnyRequestIsSent() {
        val connection = openConnection(BlocklistedCertificatesTrustManager(platformTrustManager))
        connection.setRequestProperty("Authorization", "Bearer secret-token")

        assertThrows(SSLHandshakeException::class.java) { connection.inputStream }
        assertNull(server.takeRequest(100, TimeUnit.MILLISECONDS))
    }

    private fun openConnection(trustManager: X509TrustManager): HttpsURLConnection {
        val sslContext = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustManager), null) }
        return (server.url("/").newBuilder().host("localhost").build().toUrl().openConnection() as HttpsURLConnection).apply {
            sslSocketFactory = sslContext.socketFactory
        }
    }
}
