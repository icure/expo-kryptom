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
}
