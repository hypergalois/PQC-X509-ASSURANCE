package de.mtg.jzlint.utils;

import java.io.IOException;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.x509.Extensions;

public final class OCSPUtils {

    private OCSPUtils() {
        // empty
    }

    public static boolean atLeastOneSingleResponseHasExtensions(byte[] ocspResponse) {

        OCSPResponse response = OCSPResponse.getInstance(ocspResponse);
        ResponseBytes responseBytes = response.getResponseBytes();
        BasicOCSPResponse basicOCSPResponse = BasicOCSPResponse.getInstance(responseBytes.getResponse().getOctets());
        ResponseData tbsResponseData = basicOCSPResponse.getTbsResponseData();
        Enumeration responses = tbsResponseData.getResponses().getObjects();

        while (responses.hasMoreElements()) {
            try {
                SingleResponse singleResponse = SingleResponse.getInstance(((ASN1Object) responses.nextElement()).getEncoded(ASN1Encoding.DER));
                Extensions singleExtensions = singleResponse.getSingleExtensions();
                if (singleExtensions != null) {
                    return true;
                }
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        }
        return false;
    }

}
