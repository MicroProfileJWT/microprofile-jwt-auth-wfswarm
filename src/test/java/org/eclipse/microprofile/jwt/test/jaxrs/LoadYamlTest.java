package org.eclipse.microprofile.jwt.test.jaxrs;

import java.net.URL;

import org.junit.Test;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.nodes.NodeId;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Representer;
import org.yaml.snakeyaml.resolver.Resolver;

/**
 * Created by starksm on 7/24/17.
 */
public class LoadYamlTest {
    private static Yaml newYaml() {
        return new Yaml(new Constructor(),
                new Representer(),
                new DumperOptions(),
                new Resolver() {
                    @Override
                    public Tag resolve(NodeId kind, String value, boolean implicit) {
                        if (value != null) {
                            if (value.equalsIgnoreCase("on") ||
                                    value.equalsIgnoreCase("off") ||
                                    value.equalsIgnoreCase("yes") ||
                                    value.equalsIgnoreCase("no")) {
                                return Tag.STR;
                            }
                        }
                        return super.resolve(kind, value, implicit);
                    }
                });
    }
    @Test
    public void loadProjectDefaults() throws Exception {
        URL res = getClass().getResource("/project-defaults.yml");
        Yaml yaml = newYaml();
        Object config = yaml.load(res.openStream());
        System.out.printf("config: %s\n", config);
    }
}
