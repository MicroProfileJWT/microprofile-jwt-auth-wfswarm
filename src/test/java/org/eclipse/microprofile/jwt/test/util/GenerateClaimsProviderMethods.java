package org.eclipse.microprofile.jwt.test.util;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;

import org.eclipse.microprofile.jwt.Claims;
import org.jtwig.JtwigModel;
import org.jtwig.JtwigTemplate;

/**
 * Generate a single @Req
 */
public class GenerateClaimsProviderMethods {
    public static void main(String[] args) throws IOException {
        JtwigTemplate template = JtwigTemplate.classpathTemplate("ClaimsProviderProducerMethods.twig");

        for (Claims claim : Claims.values()) {
            if(claim == Claims.UNKNOWN)
                continue;

            String nullValue = "\"\"";
            String type = claim.getType().getTypeName();
            if(type.equals(Set.class.getTypeName())) {
                type = claim.getType().getTypeName() + "<String>";
                nullValue = "java.util.Collections.emptySet()";
            } else if(type.equals("java.lang.Long")) {
                nullValue = "0l";
            } else if(type.equals("java.lang.Boolean")) {
                nullValue = "false";
            } else if(type.equals("javax.json.JsonObject")) {
                // TODO
                nullValue = "null";
            }
            String cname = claim.name().toUpperCase();

            JtwigModel model = JtwigModel.newModel()
                    .with("name", claim.name())
                    .with("cname", cname)
                    .with("nullValue", nullValue)
                    .with("type", type)
                    ;
            System.out.printf("// +++ Begin %s\n", claim.name());
            template.render(model, System.out);
            System.out.printf("\n// +++ End %s\n\n", claim.name());

        }
    }
}
