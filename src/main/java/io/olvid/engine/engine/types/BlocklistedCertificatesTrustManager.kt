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

import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString
import java.net.Socket
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedTrustManager
import javax.net.ssl.X509TrustManager

/**
 * Rejects server chains containing a certificate whose key is known to be compromised, for platforms
 * whose root store still trusts its issuer. The check runs during the handshake, so no request byte
 * is sent, whatever HTTP client uses the resulting socket factory.
 */
class BlocklistedCertificatesTrustManager(private val delegate: X509TrustManager) : X509ExtendedTrustManager() {

    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
        delegate.checkServerTrusted(chain, authType)
        rejectBlocklisted(chain)
    }

    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, socket: Socket?) {
        if (delegate is X509ExtendedTrustManager) {
            delegate.checkServerTrusted(chain, authType, socket)
        } else {
            delegate.checkServerTrusted(chain, authType)
        }
        rejectBlocklisted(chain)
    }

    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, engine: SSLEngine?) {
        if (delegate is X509ExtendedTrustManager) {
            delegate.checkServerTrusted(chain, authType, engine)
        } else {
            delegate.checkServerTrusted(chain, authType)
        }
        rejectBlocklisted(chain)
    }

    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
        delegate.checkClientTrusted(chain, authType)
    }

    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String, socket: Socket?) {
        if (delegate is X509ExtendedTrustManager) {
            delegate.checkClientTrusted(chain, authType, socket)
        } else {
            delegate.checkClientTrusted(chain, authType)
        }
    }

    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String, engine: SSLEngine?) {
        if (delegate is X509ExtendedTrustManager) {
            delegate.checkClientTrusted(chain, authType, engine)
        } else {
            delegate.checkClientTrusted(chain, authType)
        }
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers

    private fun rejectBlocklisted(chain: Array<X509Certificate>) {
        chain.firstOrNull { it.publicKey.encoded.toByteString().sha256() in BLOCKED_SPKI_SHA256 }?.let {
            throw CertificateException("Blocklisted certificate in chain: ${it.subjectX500Principal}")
        }
    }

    companion object {
        // CVE-2026-111943: compromised eMudhra intermediates under "emSign Root TLS CA - G3" (same list as OkHttp 5.5.1 and Go 1.27.3)
        private val BLOCKED_SPKI_SHA256 = setOf(
            "43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b".decodeHex(),
            "49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f".decodeHex(),
            "5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0".decodeHex(),
            "63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8".decodeHex(),
            "92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30".decodeHex(),
            "e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41".decodeHex(),
            "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105".decodeHex(),
            "ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6".decodeHex(),
        )

        /** The platform's default TLS context, with the blocklist applied. */
        @JvmStatic
        fun createSslContext(): SSLContext {
            val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            trustManagerFactory.init(null as KeyStore?)
            val platformTrustManager = trustManagerFactory.trustManagers.single() as X509TrustManager
            return SSLContext.getInstance("TLS").apply {
                init(null, arrayOf(BlocklistedCertificatesTrustManager(platformTrustManager)), null)
            }
        }
    }
}
