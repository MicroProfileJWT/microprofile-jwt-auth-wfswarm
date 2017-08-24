package org.eclipse.microprofile.jwt.wfswarm.cdi;

import java.util.Optional;

import javax.annotation.PostConstruct;
import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.spi.InjectionPoint;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;

import static org.eclipse.microprofile.jwt.wfswarm.cdi.MPJWTProducer.getJWTPrincpal;

/**
 * A collection of producer methods for injection points with Provider&lt;...&gt; types.
 * The GenerateClaimsProviderMethods test code generates these methods from the Claims enum values.
 * Note: this means that one cannot injection non-standard claims using a Provider wrapper.
 */
@RequestScoped
public class ClaimsProviderProducer {
    JsonWebToken jwt;

    @PostConstruct
    void init() {
        jwt = getJWTPrincpal();
    }

    // +++ Begin iss
    @Produces
    @Claim(standard= Claims.iss)
    java.lang.String getRawValueISS() {
        Optional<java.lang.String> value = jwt.claim(Claims.iss.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.iss)
    Optional<java.lang.String> getOptionalValueISS(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.iss.name());
        return value;
    }
// +++ End iss

    // +++ Begin sub
    @Produces
    @Claim(standard= Claims.sub)
    java.lang.String getRawValueSUB() {
        Optional<java.lang.String> value = jwt.claim(Claims.sub.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.sub)
    Optional<java.lang.String> getOptionalValueSUB(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.sub.name());
        return value;
    }
// +++ End sub

    // +++ Begin aud
    @Produces
    @Claim(standard= Claims.aud)
    java.util.Set<String> getRawValueAUD() {
        Optional<java.util.Set<String>> value = jwt.claim(Claims.aud.name());
        return value.orElse(java.util.Collections.emptySet());
    }
    @Produces
    @Claim(standard=Claims.aud)
    Optional<java.util.Set<String>> getOptionalValueAUD(InjectionPoint ip) {
        Optional<java.util.Set<String>> value = jwt.claim(Claims.aud.name());
        return value;
    }
// +++ End aud

    // +++ Begin exp
    @Produces
    @Claim(standard= Claims.exp)
    java.lang.Long getRawValueEXP() {
        Optional<java.lang.Long> value = jwt.claim(Claims.exp.name());
        return value.orElse(0l);
    }
    @Produces
    @Claim(standard=Claims.exp)
    Optional<java.lang.Long> getOptionalValueEXP(InjectionPoint ip) {
        Optional<java.lang.Long> value = jwt.claim(Claims.exp.name());
        return value;
    }
// +++ End exp

    // +++ Begin iat
    @Produces
    @Claim(standard= Claims.iat)
    java.lang.Long getRawValueIAT() {
        Optional<java.lang.Long> value = jwt.claim(Claims.iat.name());
        return value.orElse(0l);
    }
    @Produces
    @Claim(standard=Claims.iat)
    Optional<java.lang.Long> getOptionalValueIAT(InjectionPoint ip) {
        Optional<java.lang.Long> value = jwt.claim(Claims.iat.name());
        return value;
    }
// +++ End iat

    // +++ Begin jti
    @Produces
    @Claim(standard= Claims.jti)
    java.lang.String getRawValueJTI() {
        Optional<java.lang.String> value = jwt.claim(Claims.jti.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.jti)
    Optional<java.lang.String> getOptionalValueJTI(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.jti.name());
        return value;
    }
// +++ End jti

    // +++ Begin upn
    @Produces
    @Claim(standard= Claims.upn)
    java.lang.String getRawValueUPN() {
        Optional<java.lang.String> value = jwt.claim(Claims.upn.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.upn)
    Optional<java.lang.String> getOptionalValueUPN(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.upn.name());
        return value;
    }
// +++ End upn

    // +++ Begin groups
    @Produces
    @Claim(standard= Claims.groups)
    java.util.Set<String> getRawValueGROUPS() {
        Optional<java.util.Set<String>> value = jwt.claim(Claims.groups.name());
        return value.orElse(java.util.Collections.emptySet());
    }
    @Produces
    @Claim(standard=Claims.groups)
    Optional<java.util.Set<String>> getOptionalValueGROUPS(InjectionPoint ip) {
        Optional<java.util.Set<String>> value = jwt.claim(Claims.groups.name());
        return value;
    }
// +++ End groups

    // +++ Begin raw_token
    @Produces
    @Claim(standard= Claims.raw_token)
    java.lang.String getRawValueRAW_TOKEN() {
        Optional<java.lang.String> value = jwt.claim(Claims.raw_token.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.raw_token)
    Optional<java.lang.String> getOptionalValueRAW_TOKEN(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.raw_token.name());
        return value;
    }
// +++ End raw_token

    // +++ Begin nbf
    @Produces
    @Claim(standard= Claims.nbf)
    java.lang.Long getRawValueNBF() {
        Optional<java.lang.Long> value = jwt.claim(Claims.nbf.name());
        return value.orElse(0l);
    }
    @Produces
    @Claim(standard=Claims.nbf)
    Optional<java.lang.Long> getOptionalValueNBF(InjectionPoint ip) {
        Optional<java.lang.Long> value = jwt.claim(Claims.nbf.name());
        return value;
    }
// +++ End nbf

    // +++ Begin auth_time
    @Produces
    @Claim(standard= Claims.auth_time)
    java.lang.Long getRawValueAUTH_TIME() {
        Optional<java.lang.Long> value = jwt.claim(Claims.auth_time.name());
        return value.orElse(0l);
    }
    @Produces
    @Claim(standard=Claims.auth_time)
    Optional<java.lang.Long> getOptionalValueAUTH_TIME(InjectionPoint ip) {
        Optional<java.lang.Long> value = jwt.claim(Claims.auth_time.name());
        return value;
    }
// +++ End auth_time

    // +++ Begin updated_at
    @Produces
    @Claim(standard= Claims.updated_at)
    java.lang.Long getRawValueUPDATED_AT() {
        Optional<java.lang.Long> value = jwt.claim(Claims.updated_at.name());
        return value.orElse(0l);
    }
    @Produces
    @Claim(standard=Claims.updated_at)
    Optional<java.lang.Long> getOptionalValueUPDATED_AT(InjectionPoint ip) {
        Optional<java.lang.Long> value = jwt.claim(Claims.updated_at.name());
        return value;
    }
// +++ End updated_at

    // +++ Begin azp
    @Produces
    @Claim(standard= Claims.azp)
    java.lang.String getRawValueAZP() {
        Optional<java.lang.String> value = jwt.claim(Claims.azp.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.azp)
    Optional<java.lang.String> getOptionalValueAZP(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.azp.name());
        return value;
    }
// +++ End azp

    // +++ Begin nonce
    @Produces
    @Claim(standard= Claims.nonce)
    java.lang.String getRawValueNONCE() {
        Optional<java.lang.String> value = jwt.claim(Claims.nonce.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.nonce)
    Optional<java.lang.String> getOptionalValueNONCE(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.nonce.name());
        return value;
    }
// +++ End nonce

    // +++ Begin at_hash
    @Produces
    @Claim(standard= Claims.at_hash)
    java.lang.Long getRawValueAT_HASH() {
        Optional<java.lang.Long> value = jwt.claim(Claims.at_hash.name());
        return value.orElse(0l);
    }
    @Produces
    @Claim(standard=Claims.at_hash)
    Optional<java.lang.Long> getOptionalValueAT_HASH(InjectionPoint ip) {
        Optional<java.lang.Long> value = jwt.claim(Claims.at_hash.name());
        return value;
    }
// +++ End at_hash

    // +++ Begin c_hash
    @Produces
    @Claim(standard= Claims.c_hash)
    java.lang.Long getRawValueC_HASH() {
        Optional<java.lang.Long> value = jwt.claim(Claims.c_hash.name());
        return value.orElse(0l);
    }
    @Produces
    @Claim(standard=Claims.c_hash)
    Optional<java.lang.Long> getOptionalValueC_HASH(InjectionPoint ip) {
        Optional<java.lang.Long> value = jwt.claim(Claims.c_hash.name());
        return value;
    }
// +++ End c_hash

    // +++ Begin full_name
    @Produces
    @Claim(standard= Claims.full_name)
    java.lang.String getRawValueFULL_NAME() {
        Optional<java.lang.String> value = jwt.claim(Claims.full_name.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.full_name)
    Optional<java.lang.String> getOptionalValueFULL_NAME(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.full_name.name());
        return value;
    }
// +++ End full_name

    // +++ Begin family_name
    @Produces
    @Claim(standard= Claims.family_name)
    java.lang.String getRawValueFAMILY_NAME() {
        Optional<java.lang.String> value = jwt.claim(Claims.family_name.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.family_name)
    Optional<java.lang.String> getOptionalValueFAMILY_NAME(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.family_name.name());
        return value;
    }
// +++ End family_name

    // +++ Begin middle_name
    @Produces
    @Claim(standard= Claims.middle_name)
    java.lang.String getRawValueMIDDLE_NAME() {
        Optional<java.lang.String> value = jwt.claim(Claims.middle_name.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.middle_name)
    Optional<java.lang.String> getOptionalValueMIDDLE_NAME(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.middle_name.name());
        return value;
    }
// +++ End middle_name

    // +++ Begin nickname
    @Produces
    @Claim(standard= Claims.nickname)
    java.lang.String getRawValueNICKNAME() {
        Optional<java.lang.String> value = jwt.claim(Claims.nickname.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.nickname)
    Optional<java.lang.String> getOptionalValueNICKNAME(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.nickname.name());
        return value;
    }
// +++ End nickname

    // +++ Begin given_name
    @Produces
    @Claim(standard= Claims.given_name)
    java.lang.String getRawValueGIVEN_NAME() {
        Optional<java.lang.String> value = jwt.claim(Claims.given_name.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.given_name)
    Optional<java.lang.String> getOptionalValueGIVEN_NAME(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.given_name.name());
        return value;
    }
// +++ End given_name

    // +++ Begin preferred_username
    @Produces
    @Claim(standard= Claims.preferred_username)
    java.lang.String getRawValuePREFERRED_USERNAME() {
        Optional<java.lang.String> value = jwt.claim(Claims.preferred_username.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.preferred_username)
    Optional<java.lang.String> getOptionalValuePREFERRED_USERNAME(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.preferred_username.name());
        return value;
    }
// +++ End preferred_username

    // +++ Begin email
    @Produces
    @Claim(standard= Claims.email)
    java.lang.String getRawValueEMAIL() {
        Optional<java.lang.String> value = jwt.claim(Claims.email.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.email)
    Optional<java.lang.String> getOptionalValueEMAIL(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.email.name());
        return value;
    }
// +++ End email

    // +++ Begin email_verified
    @Produces
    @Claim(standard= Claims.email_verified)
    java.lang.Boolean getRawValueEMAIL_VERIFIED() {
        Optional<java.lang.Boolean> value = jwt.claim(Claims.email_verified.name());
        return value.orElse(false);
    }
    @Produces
    @Claim(standard=Claims.email_verified)
    Optional<java.lang.Boolean> getOptionalValueEMAIL_VERIFIED(InjectionPoint ip) {
        Optional<java.lang.Boolean> value = jwt.claim(Claims.email_verified.name());
        return value;
    }
// +++ End email_verified

    // +++ Begin gender
    @Produces
    @Claim(standard= Claims.gender)
    java.lang.String getRawValueGENDER() {
        Optional<java.lang.String> value = jwt.claim(Claims.gender.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.gender)
    Optional<java.lang.String> getOptionalValueGENDER(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.gender.name());
        return value;
    }
// +++ End gender

    // +++ Begin birthdate
    @Produces
    @Claim(standard= Claims.birthdate)
    java.lang.String getRawValueBIRTHDATE() {
        Optional<java.lang.String> value = jwt.claim(Claims.birthdate.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.birthdate)
    Optional<java.lang.String> getOptionalValueBIRTHDATE(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.birthdate.name());
        return value;
    }
// +++ End birthdate

    // +++ Begin zoneinfo
    @Produces
    @Claim(standard= Claims.zoneinfo)
    java.lang.String getRawValueZONEINFO() {
        Optional<java.lang.String> value = jwt.claim(Claims.zoneinfo.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.zoneinfo)
    Optional<java.lang.String> getOptionalValueZONEINFO(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.zoneinfo.name());
        return value;
    }
// +++ End zoneinfo

    // +++ Begin locale
    @Produces
    @Claim(standard= Claims.locale)
    java.lang.String getRawValueLOCALE() {
        Optional<java.lang.String> value = jwt.claim(Claims.locale.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.locale)
    Optional<java.lang.String> getOptionalValueLOCALE(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.locale.name());
        return value;
    }
// +++ End locale

    // +++ Begin phone_number
    @Produces
    @Claim(standard= Claims.phone_number)
    java.lang.String getRawValuePHONE_NUMBER() {
        Optional<java.lang.String> value = jwt.claim(Claims.phone_number.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.phone_number)
    Optional<java.lang.String> getOptionalValuePHONE_NUMBER(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.phone_number.name());
        return value;
    }
// +++ End phone_number

    // +++ Begin phone_number_verified
    @Produces
    @Claim(standard= Claims.phone_number_verified)
    java.lang.Boolean getRawValuePHONE_NUMBER_VERIFIED() {
        Optional<java.lang.Boolean> value = jwt.claim(Claims.phone_number_verified.name());
        return value.orElse(false);
    }
    @Produces
    @Claim(standard=Claims.phone_number_verified)
    Optional<java.lang.Boolean> getOptionalValuePHONE_NUMBER_VERIFIED(InjectionPoint ip) {
        Optional<java.lang.Boolean> value = jwt.claim(Claims.phone_number_verified.name());
        return value;
    }
// +++ End phone_number_verified

    // +++ Begin address
    @Produces
    @Claim(standard= Claims.address)
    javax.json.JsonObject getRawValueADDRESS() {
        Optional<javax.json.JsonObject> value = jwt.claim(Claims.address.name());
        return value.orElse(null);
    }
    @Produces
    @Claim(standard=Claims.address)
    Optional<javax.json.JsonObject> getOptionalValueADDRESS(InjectionPoint ip) {
        Optional<javax.json.JsonObject> value = jwt.claim(Claims.address.name());
        return value;
    }
// +++ End address

    // +++ Begin acr
    @Produces
    @Claim(standard= Claims.acr)
    java.lang.String getRawValueACR() {
        Optional<java.lang.String> value = jwt.claim(Claims.acr.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.acr)
    Optional<java.lang.String> getOptionalValueACR(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.acr.name());
        return value;
    }
// +++ End acr

    // +++ Begin amr
    @Produces
    @Claim(standard= Claims.amr)
    java.lang.String getRawValueAMR() {
        Optional<java.lang.String> value = jwt.claim(Claims.amr.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.amr)
    Optional<java.lang.String> getOptionalValueAMR(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.amr.name());
        return value;
    }
// +++ End amr

    // +++ Begin sub_jwk
    @Produces
    @Claim(standard= Claims.sub_jwk)
    javax.json.JsonObject getRawValueSUB_JWK() {
        Optional<javax.json.JsonObject> value = jwt.claim(Claims.sub_jwk.name());
        return value.orElse(null);
    }
    @Produces
    @Claim(standard=Claims.sub_jwk)
    Optional<javax.json.JsonObject> getOptionalValueSUB_JWK(InjectionPoint ip) {
        Optional<javax.json.JsonObject> value = jwt.claim(Claims.sub_jwk.name());
        return value;
    }
// +++ End sub_jwk

    // +++ Begin cnf
    @Produces
    @Claim(standard= Claims.cnf)
    java.lang.String getRawValueCNF() {
        Optional<java.lang.String> value = jwt.claim(Claims.cnf.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.cnf)
    Optional<java.lang.String> getOptionalValueCNF(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.cnf.name());
        return value;
    }
// +++ End cnf

    // +++ Begin sip_from_tag
    @Produces
    @Claim(standard= Claims.sip_from_tag)
    java.lang.String getRawValueSIP_FROM_TAG() {
        Optional<java.lang.String> value = jwt.claim(Claims.sip_from_tag.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.sip_from_tag)
    Optional<java.lang.String> getOptionalValueSIP_FROM_TAG(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.sip_from_tag.name());
        return value;
    }
// +++ End sip_from_tag

    // +++ Begin sip_date
    @Produces
    @Claim(standard= Claims.sip_date)
    java.lang.String getRawValueSIP_DATE() {
        Optional<java.lang.String> value = jwt.claim(Claims.sip_date.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.sip_date)
    Optional<java.lang.String> getOptionalValueSIP_DATE(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.sip_date.name());
        return value;
    }
// +++ End sip_date

    // +++ Begin sip_callid
    @Produces
    @Claim(standard= Claims.sip_callid)
    java.lang.String getRawValueSIP_CALLID() {
        Optional<java.lang.String> value = jwt.claim(Claims.sip_callid.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.sip_callid)
    Optional<java.lang.String> getOptionalValueSIP_CALLID(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.sip_callid.name());
        return value;
    }
// +++ End sip_callid

    // +++ Begin sip_cseq_num
    @Produces
    @Claim(standard= Claims.sip_cseq_num)
    java.lang.String getRawValueSIP_CSEQ_NUM() {
        Optional<java.lang.String> value = jwt.claim(Claims.sip_cseq_num.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.sip_cseq_num)
    Optional<java.lang.String> getOptionalValueSIP_CSEQ_NUM(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.sip_cseq_num.name());
        return value;
    }
// +++ End sip_cseq_num

    // +++ Begin sip_via_branch
    @Produces
    @Claim(standard= Claims.sip_via_branch)
    java.lang.String getRawValueSIP_VIA_BRANCH() {
        Optional<java.lang.String> value = jwt.claim(Claims.sip_via_branch.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.sip_via_branch)
    Optional<java.lang.String> getOptionalValueSIP_VIA_BRANCH(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.sip_via_branch.name());
        return value;
    }
// +++ End sip_via_branch

    // +++ Begin orig
    @Produces
    @Claim(standard= Claims.orig)
    java.lang.String getRawValueORIG() {
        Optional<java.lang.String> value = jwt.claim(Claims.orig.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.orig)
    Optional<java.lang.String> getOptionalValueORIG(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.orig.name());
        return value;
    }
// +++ End orig

    // +++ Begin dest
    @Produces
    @Claim(standard= Claims.dest)
    java.lang.String getRawValueDEST() {
        Optional<java.lang.String> value = jwt.claim(Claims.dest.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.dest)
    Optional<java.lang.String> getOptionalValueDEST(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.dest.name());
        return value;
    }
// +++ End dest

    // +++ Begin mky
    @Produces
    @Claim(standard= Claims.mky)
    java.lang.String getRawValueMKY() {
        Optional<java.lang.String> value = jwt.claim(Claims.mky.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.mky)
    Optional<java.lang.String> getOptionalValueMKY(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.mky.name());
        return value;
    }
// +++ End mky

    // +++ Begin jwk
    @Produces
    @Claim(standard= Claims.jwk)
    javax.json.JsonObject getRawValueJWK() {
        Optional<javax.json.JsonObject> value = jwt.claim(Claims.jwk.name());
        return value.orElse(null);
    }
    @Produces
    @Claim(standard=Claims.jwk)
    Optional<javax.json.JsonObject> getOptionalValueJWK(InjectionPoint ip) {
        Optional<javax.json.JsonObject> value = jwt.claim(Claims.jwk.name());
        return value;
    }
// +++ End jwk

    // +++ Begin jwe
    @Produces
    @Claim(standard= Claims.jwe)
    java.lang.String getRawValueJWE() {
        Optional<java.lang.String> value = jwt.claim(Claims.jwe.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.jwe)
    Optional<java.lang.String> getOptionalValueJWE(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.jwe.name());
        return value;
    }
// +++ End jwe

    // +++ Begin kid
    @Produces
    @Claim(standard= Claims.kid)
    java.lang.String getRawValueKID() {
        Optional<java.lang.String> value = jwt.claim(Claims.kid.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.kid)
    Optional<java.lang.String> getOptionalValueKID(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.kid.name());
        return value;
    }
// +++ End kid

    // +++ Begin jku
    @Produces
    @Claim(standard= Claims.jku)
    java.lang.String getRawValueJKU() {
        Optional<java.lang.String> value = jwt.claim(Claims.jku.name());
        return value.orElse("");
    }
    @Produces
    @Claim(standard=Claims.jku)
    Optional<java.lang.String> getOptionalValueJKU(InjectionPoint ip) {
        Optional<java.lang.String> value = jwt.claim(Claims.jku.name());
        return value;
    }
// +++ End jku
}
