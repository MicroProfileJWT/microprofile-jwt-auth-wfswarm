package org.eclipse.microprofile.jwt.test.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.Set;

import org.eclipse.microprofile.jwt.Claims;
import org.jtwig.JtwigModel;
import org.jtwig.JtwigTemplate;

/**
 * Generate a class per Claims enum value to test handling both Provider and ClaimValue injection sites.
 * Currently this does not seem to work becuase the non-Provider injection sites are not updated
 * on each request.
 */
public class GenerateClaimValuesProducerClasses {
    public static void main(String[] args) throws IOException {
        File out = new File("out/claims");
        if(!out.exists()) {
            out.mkdirs();
        }

        System.out.println(Claims.groups.getType().getTypeName());
        System.out.println(Claims.groups.getType().toGenericString());
        Type[] gifaces = Claims.groups.getType().getGenericInterfaces();
        System.out.println(Arrays.asList(gifaces));
        for(Type gi : gifaces) {
            if(gi instanceof ParameterizedType) {
                System.out.println(((ParameterizedType)gi).getActualTypeArguments()[0]);
            }
        }

        StringBuilder typesToAdd = new StringBuilder();
        System.out.printf("Generating classes to: %s\n", out.getAbsolutePath());
        JtwigTemplate template = JtwigTemplate.classpathTemplate("ClaimValuesProducer.twig");

        for(Claims claim : Claims.values()) {
            String cname = claim.name().toUpperCase();
            switch (claim) {
                case auth_time:
                case raw_token:
                case updated_at:
                case at_hash:
                case c_hash:
                case full_name:
                case family_name:
                case middle_name:
                case given_name:
                case preferred_username:
                case email_verified:
                case phone_number:
                case phone_number_verified:
                case sub_jwk:
                case sip_from_tag:
                case sip_date:
                case sip_callid:
                case sip_cseq_num:
                case sip_via_branch:
                    String[] parts = claim.name().split("_");
                    StringBuilder tmp = new StringBuilder();
                    for(String part : parts) {
                        tmp.append(Character.toUpperCase(part.charAt(0)));
                        tmp.append(part.substring(1));
                    }
                    cname = tmp.toString();
                    break;
                case UNKNOWN:
                    continue;
            }

            String type = claim.getType().getTypeName();
            if(claim.getType().getTypeName().equals(Set.class.getTypeName())) {
                type = claim.getType().getTypeName() + "<String>";
            }
            JtwigModel model = JtwigModel.newModel()
                    .with("name", claim.name())
                    .with("cname", cname)
                    .with("type", type)
                    ;

            File outFile = new File(out, "ClaimValuesProducer"+cname+".java");
            FileOutputStream fos = new FileOutputStream(outFile);
            template.render(model, fos);
            fos.close();
            System.out.printf("Wrote %s\n", outFile.getAbsolutePath());
            typesToAdd.append(String.format("bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducer%s.class));\n", cname));
        }
        System.out.println(typesToAdd);
    }
}
