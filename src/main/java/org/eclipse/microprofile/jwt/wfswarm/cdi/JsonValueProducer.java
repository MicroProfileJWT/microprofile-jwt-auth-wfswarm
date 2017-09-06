package org.eclipse.microprofile.jwt.wfswarm.cdi;

import java.lang.annotation.Annotation;

import javax.enterprise.inject.Produces;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.json.JsonArray;
import javax.json.JsonNumber;
import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonValue;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.Claims;

/**
 * A producer for JsonValue injection types
 */
public class JsonValueProducer {

    @Produces
    @Claim("")
    public JsonString getJsonString(InjectionPoint ip) {
        return getValue(ip);
    }
    @Produces
    @Claim("")
    public JsonNumber getJsonNumber(InjectionPoint ip) {
        return getValue(ip);
    }
    @Produces
    @Claim("")
    public JsonArray getJsonArray(InjectionPoint ip) {
        return getValue(ip);
    }
    @Produces
    @Claim("")
    public JsonObject getJsonObject(InjectionPoint ip) {
        return getValue(ip);
    }
    public <T extends JsonValue> T getValue(InjectionPoint ip) {
        System.out.printf("JsonValueProducer(%s).produce\n", ip);
        String name = getName(ip);
        T jsonValue = (T) MPJWTProducer.generalJsonValueProducer(name);
        return jsonValue;
    }

    String getName(InjectionPoint ip) {
        String name = null;
        for(Annotation ann : ip.getQualifiers()) {
            if(ann instanceof Claim) {
                Claim claim = (Claim) ann;
                name = claim.standard() == Claims.UNKNOWN ? claim.value() : claim.standard().name();
            }
        }
        return name;
    }
}
