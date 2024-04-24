//
//  Keys.swift
//  ExpoKryptom
//
//  Created by Clément Vandendaelen on 22/04/2024.
//

import Kryptom
import ExpoModulesCore

struct ExportPrivateRsaKeyJwk: Record {
    
    @Field
    var alg: String
    
    @Field
    var d: String
    
    @Field
    var dp: String
    
    @Field
    var dq: String
    
    @Field
    var e: String
    
    @Field
    var ext: Bool
    
    @Field
    var key_ops: [String]
    
    @Field
    var n: String
    
    @Field
    var p: String
    
    @Field
    var q: String
    
    @Field
    var qi: String
    
    func toPrivateRsaKeyJwk() -> PrivateRsaKeyJwk {
        return PrivateRsaKeyJwk(alg: alg, d: d, dp: dp, dq: dq, e: e, ext: ext, key_ops: Set(key_ops), n: n, p: p, q: q, qi: qi)
    }
    
    static func fromPrivateRsaKeyJwk(privateKey: PrivateRsaKeyJwk) -> ExportPrivateRsaKeyJwk {
        return ExportPrivateRsaKeyJwk(
            alg: Field(wrappedValue: privateKey.alg),
            d: Field(wrappedValue: privateKey.d),
            dp: Field(wrappedValue: privateKey.dp),
            dq: Field(wrappedValue: privateKey.dq),
            e: Field(wrappedValue: privateKey.e),
            ext: Field(wrappedValue: privateKey.ext),
            key_ops: Field(wrappedValue: Array(privateKey.key_ops)),
            n: Field(wrappedValue: privateKey.n),
            p: Field(wrappedValue: privateKey.p),
            q: Field(wrappedValue: privateKey.q),
            qi: Field(wrappedValue: privateKey.qi)
        )
    }
}

struct ExportPublicRsaKeyJwk: Record {
    
    @Field
    var alg: String
    
    @Field
    var e: String
    
    @Field
    var ext: Bool
    
    @Field
    var key_ops: [String]
    
    @Field
    var n: String
    
    func toPublicRsaKeyJwk() -> PublicRsaKeyJwk {
        return PublicRsaKeyJwk(alg: alg, e: e, ext: ext, key_ops: Set(key_ops), n: n)
    }
    
    static func fromPublicKeyRsaKeyJwk(publicKey: PublicRsaKeyJwk) -> ExportPublicRsaKeyJwk {
        ExportPublicRsaKeyJwk(
            alg: Field(wrappedValue: publicKey.alg),
            e: Field(wrappedValue: publicKey.e),
            ext: Field(wrappedValue: publicKey.ext),
            key_ops: Field(wrappedValue: Array(publicKey.key_ops)),
            n: Field(wrappedValue: publicKey.n)
        )
    }
}
