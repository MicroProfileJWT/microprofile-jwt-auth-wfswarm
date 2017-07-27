package org.eclipse.microprofile.jwt.test.jaxrs;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;

import org.junit.Assert;
import org.junit.Test;

/**
 * Created by starksm on 7/25/17.
 */
public class KeyEncodingTest {
    @Test
    public void testURLEncodePEM() throws UnsupportedEncodingException {
        String pem = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQClH5+52mqHLdChbOfzuyue5FSDl2n1mOkpMlF1676NT79AScHVMi1IohWkuSe3W+oPLE+GAwyyr0DyolUmTkrhrMID6LamgmH8IzhOeyaxDOjwbCIUeGM1V9Qht+nTneRMhGa/oL687XioZiE1Ev52D8kMaKMNMHprL9oOZ/QM4wIDAQAB";
        String encoded = URLEncoder.encode(pem, "UTF-8");
        System.out.println(encoded);
        String pemAgain = URLDecoder.decode(encoded, "UTF-8");
        Assert.assertEquals(pem, pemAgain);
    }
}
