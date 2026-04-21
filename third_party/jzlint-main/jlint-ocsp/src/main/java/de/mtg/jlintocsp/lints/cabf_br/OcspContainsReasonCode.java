package de.mtg.jlintocsp.lints.cabf_br;

import java.io.IOException;
import java.util.Arrays;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;

import de.mtg.jlintocsp.JavaOCSPResponseLint;
import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.OCSPUtils;

/**
 * 7.3.2 OCSP extensions
 * The singleExtensions of an OCSP response MUST NOT contain the reasonCode (OID
 * 2.5.29.21) CRL entry extension.
 */

@Lint(
        name = "e_ocsp_contains_reasoncode",
        description = "Check if the OCSP response contains the reasonCode CRL entry extension in the singleExtensions.",
        citation = "BRs: 7.3.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABFBRs_1_7_1_Date)
public class OcspContainsReasonCode implements JavaOCSPResponseLint {

    @Override
    public LintResult execute(byte[] ocspResponse) {

        OCSPResponse response = OCSPResponse.getInstance(ocspResponse);
        ResponseBytes responseBytes = response.getResponseBytes();

        BasicOCSPResponse basicOCSPResponse = BasicOCSPResponse.getInstance(responseBytes.getResponse().getOctets());

        ResponseData tbsResponseData = basicOCSPResponse.getTbsResponseData();

        Enumeration responses = tbsResponseData.getResponses().getObjects();

        while (responses.hasMoreElements()) {
            try {
                ASN1Object singleResponseElement = (ASN1Object) responses.nextElement();
                SingleResponse singleResponse = SingleResponse.getInstance(singleResponseElement.getEncoded(ASN1Encoding.DER));
                Extensions singleExtensions = singleResponse.getSingleExtensions();

                if (singleExtensions != null) {
                    boolean reasonCodeFound = Arrays.stream(singleExtensions.getExtensionOIDs()).anyMatch(oid -> oid.equals(Extension.reasonCode));

                    if (reasonCodeFound) {
                        return LintResult.of(Status.ERROR);
                    }
                }
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(byte[] ocspResponse) {
        return OCSPUtils.atLeastOneSingleResponseHasExtensions(ocspResponse);
    }

}
