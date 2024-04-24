package com.icure.kryptom.expo

import com.icure.kryptom.crypto.PrivateRsaKeyJwk
import com.icure.kryptom.crypto.PublicRsaKeyJwk
import expo.modules.kotlin.records.Field
import expo.modules.kotlin.records.Record as ExpoRecord

class ExportPrivateRsaKeyJwk(
    @Field val alg: String,
    @Field val d: String,
    @Field val dp: String,
    @Field val dq: String,
    @Field val e: String,
    @Field val ext: Boolean,
    @Field val key_ops: Array<String>,
    @Field val n: String,
    @Field val p: String,
    @Field val q: String,
    @Field val qi: String,
): ExpoRecord {

    companion object {
        fun PrivateRsaKeyJwk.toExport() = ExportPrivateRsaKeyJwk(
            alg= alg,
            d= d,
            dp= dp,
            dq= dq,
            e= e,
            ext= ext,
            key_ops = key_ops.toTypedArray(),
            n= n,
            p= p,
            q= q,
            qi= qi
        )
    }

    fun toPrivateRsaKeyJwk(): PrivateRsaKeyJwk {
        return PrivateRsaKeyJwk(
            alg= alg,
            d= d,
            dp= dp,
            dq= dq,
            e= e,
            ext= ext,
            key_ops= key_ops.toSet(),
            n= n,
            p= p,
            q= q,
            qi= qi
        )
    }
}

class ExportPublicRsaKeyJwk(
    @Field val alg: String,
    @Field val e: String,
    @Field val ext: Boolean,
    @Field val key_ops: Array<String>,
    @Field val n: String,
): ExpoRecord {

    companion object {
        fun PublicRsaKeyJwk.toExport() = ExportPublicRsaKeyJwk(
            alg = alg,
            e = e,
            ext = ext,
            key_ops = key_ops.toTypedArray(),
            n = n,
        )
    }
    fun toPublicRsaKeyJwk(): PublicRsaKeyJwk {
        return PublicRsaKeyJwk(
            alg = alg,
            e = e,
            ext = ext,
            key_ops = key_ops.toSet().also {
               println(it)
            },
            n = n
        )
    }
}