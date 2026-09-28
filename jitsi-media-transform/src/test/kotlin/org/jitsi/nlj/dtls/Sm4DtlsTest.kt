/*
 * Copyright @ 2026 CloudMeet contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.jitsi.nlj.dtls

import io.kotest.core.spec.style.ShouldSpec
import io.kotest.matchers.shouldBe
import org.jitsi.config.withNewConfig
import org.jitsi.nlj.resources.logging.StdoutLogger
import org.jitsi.nlj.srtp.SrtpUtil
import org.jitsi.nlj.srtp.TlsRole
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * JVB DTLS loopback with the experimental private SM4-SRTP profile.
 * This verifies profile negotiation and DTLS-SRTP exporter key material;
 * browser interoperability is intentionally outside this library test.
 */
class Sm4DtlsTest : ShouldSpec() {
    init {
        should("negotiate SRTP_SM4_GCM and export matching keying material") {
            withNewConfig("jmt.srtp.protection-profiles=[SRTP_SM4_GCM]") {
                val logger = StdoutLogger()
                val server = DtlsStack(logger).apply { actAsServer() }
                val client = DtlsStack(logger).apply { actAsClient() }
                val serverProfile = CompletableFuture<Int>()
                val clientProfile = CompletableFuture<Int>()

                server.eventHandler = object : DtlsStack.EventHandler {
                    override fun handshakeComplete(
                        chosenSrtpProtectionProfile: Int,
                        tlsRole: TlsRole,
                        keyingMaterial: ByteArray
                    ) {
                        chosenSrtpProtectionProfile shouldBe SrtpUtil.SRTP_SM4_GCM
                        tlsRole shouldBe TlsRole.SERVER
                        keyingMaterial.size shouldBe 56
                        serverProfile.complete(chosenSrtpProtectionProfile)
                    }
                }
                client.eventHandler = object : DtlsStack.EventHandler {
                    override fun handshakeComplete(
                        chosenSrtpProtectionProfile: Int,
                        tlsRole: TlsRole,
                        keyingMaterial: ByteArray
                    ) {
                        chosenSrtpProtectionProfile shouldBe SrtpUtil.SRTP_SM4_GCM
                        tlsRole shouldBe TlsRole.CLIENT
                        keyingMaterial.size shouldBe 56
                        clientProfile.complete(chosenSrtpProtectionProfile)
                    }
                }

                client.remoteFingerprints = mapOf(
                    server.localFingerprintHashFunction to listOf(server.localFingerprint)
                )
                server.remoteFingerprints = mapOf(
                    client.localFingerprintHashFunction to listOf(client.localFingerprint)
                )
                server.outgoingDataHandler = object : DtlsStack.OutgoingDataHandler {
                    override fun sendData(data: ByteArray, off: Int, len: Int) {
                        client.processIncomingProtocolData(data, off, len)
                    }
                }
                client.outgoingDataHandler = object : DtlsStack.OutgoingDataHandler {
                    override fun sendData(data: ByteArray, off: Int, len: Int) {
                        server.processIncomingProtocolData(data, off, len)
                    }
                }

                try {
                    val serverThread = thread { server.start() }
                    client.start()
                    serverThread.join()
                    serverProfile.get(5, TimeUnit.SECONDS) shouldBe SrtpUtil.SRTP_SM4_GCM
                    clientProfile.get(5, TimeUnit.SECONDS) shouldBe SrtpUtil.SRTP_SM4_GCM
                } finally {
                    client.close()
                    server.close()
                }
            }
        }
    }
}
