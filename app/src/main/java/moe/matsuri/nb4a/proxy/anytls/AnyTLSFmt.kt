package moe.matsuri.nb4a.proxy.anytls

import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.ktx.blankAsNull
import io.nekohasekai.sagernet.ktx.linkBuilder
import io.nekohasekai.sagernet.ktx.toLink
import io.nekohasekai.sagernet.ktx.urlSafe
import moe.matsuri.nb4a.SingBoxOptions
import moe.matsuri.nb4a.utils.listByLineOrComma
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

fun buildSingBoxOutboundAnyTLSBean(bean: AnyTLSBean): SingBoxOptions.Outbound_AnyTLSOptions {
    return SingBoxOptions.Outbound_AnyTLSOptions().apply {
        type = "anytls"
        server = bean.serverAddress
        server_port = bean.serverPort
        password = bean.password
        applyAnyTLSSessionTuning()

        tls = SingBoxOptions.OutboundTLSOptions().apply {
            enabled = true
            server_name = bean.sni.blankAsNull()
            if (bean.allowInsecure) insecure = true
            alpn = bean.alpn.blankAsNull()?.listByLineOrComma()
            bean.certificates.blankAsNull()?.let {
                certificate = it
            }
            bean.utlsFingerprint.blankAsNull()?.let {
                utls = SingBoxOptions.OutboundUTLSOptions().apply {
                    enabled = true
                    fingerprint = it
                }
            }
            bean.echConfig.blankAsNull()?.let {
                // In new version, some complex options will be deprecated, so we just do this.
                ech = SingBoxOptions.OutboundECHOptions().apply {
                    enabled = true
                    config = listOf(it)
                }
            }
        }
    }
}

/** Global AnyTLS session pool options from Settings (sing-box-nekobox). */
fun SingBoxOptions.Outbound_AnyTLSOptions.applyAnyTLSSessionTuning() {
    if (!DataStore.anytlsSessionTuning) return
    fun duration(v: String) = v.trim().blankAsNull()
    fun count(v: Int) = v.takeIf { it > 0 }
    idle_session_check_interval = duration(DataStore.anytlsIdleSessionCheckInterval)
    idle_session_timeout = duration(DataStore.anytlsIdleSessionTimeout)
    min_idle_session = count(DataStore.anytlsMinIdleSession)
    ensure_idle_session = count(DataStore.anytlsEnsureIdleSession)
    ensure_idle_session_create_rate = count(DataStore.anytlsEnsureIdleSessionCreateRate)
    heartbeat = duration(DataStore.anytlsHeartbeat)
    min_idle_session_for_age = count(DataStore.anytlsMinIdleSessionForAge)
    max_connection_lifetime = duration(DataStore.anytlsMaxConnectionLifetime)
    connection_lifetime_jitter = duration(DataStore.anytlsConnectionLifetimeJitter)
    close_after_idle = duration(DataStore.anytlsCloseAfterIdle)
    close_after_lifetime = duration(DataStore.anytlsCloseAfterLifetime)
}

fun AnyTLSBean.toUri(): String {
    val builder = linkBuilder()
        .host(serverAddress)
        .port(serverPort)
        .username(password)
    if (!name.isNullOrBlank()) {
        builder.encodedFragment(name.urlSafe())
    }
    if (allowInsecure) {
        builder.addQueryParameter("insecure", "1")
    }
    if (!sni.isNullOrBlank()) {
        builder.addQueryParameter("sni", sni)
    }
    if (!utlsFingerprint.isNullOrBlank()) {
        builder.addQueryParameter("fp", utlsFingerprint)
    }
    return builder.toLink("anytls")
}

fun parseAnytls(url: String): AnyTLSBean {
    // https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md
    val link = url.replace("anytls://", "https://").toHttpUrlOrNull() ?: error(
        "invalid anytls link $url"
    )
    return AnyTLSBean().apply {
        serverAddress = link.host
        serverPort = link.port
        name = link.fragment
        password = link.username
        sni = link.queryParameter("sni") ?: ""
        link.queryParameter("insecure")?.also {
            allowInsecure = it == "1" || it == "true"
        }
        link.queryParameter("fp")?.let {
            utlsFingerprint = it
        }
    }
}
