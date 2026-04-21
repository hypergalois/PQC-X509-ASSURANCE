package de.mtg.jlintocsp.lints.rfc;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.ResponseBytes;

import de.mtg.jlintocsp.JavaOCSPResponseLint;
import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;

//4.2.2.3.  Basic Response
//
//        The basic response type contains:
//
//        o  the version of the response syntax, which MUST be v1 (value is 0)
//        for this version of the basic response syntax;
//
//   ResponseData ::= SEQUENCE {
//      version              [0] EXPLICIT Version DEFAULT v1,
//      responderID              ResponderID,
//      producedAt               GeneralizedTime,
//      responses                SEQUENCE OF SingleResponse,
//      responseExtensions   [1] EXPLICIT Extensions OPTIONAL }

// Default values must not be encoded


@Lint(
        name = "e_ocsp_lint_version_default_value_encoded",
        description = "Check if the version with value 0 is encoded in the response",
        citation = "RFC 6960, Sec. 4.2.2.3 and X.690 Sec. 11.5",
        source = Source.RFC6960,
        effectiveDate = EffectiveDate.RFC6960)
public class OcspLintVersionDefaultEncoded implements JavaOCSPResponseLint {

    @Override
    public LintResult execute(byte[] ocspResponse) {

        OCSPResponse response = OCSPResponse.getInstance(ocspResponse);

        ResponseBytes responseBytes = response.getResponseBytes();
        BasicOCSPResponse basicOCSPResponse = BasicOCSPResponse.getInstance(responseBytes.getResponse().getOctets());
        BigInteger version = basicOCSPResponse.getTbsResponseData().getVersion().getValue();

        if (!version.equals(BigInteger.ZERO)) {
            return LintResult.of(Status.PASS);
        }

        try {
            byte[] encodedBasicResponse = basicOCSPResponse.getTbsResponseData().getEncoded(ASN1Encoding.DER);
            ASN1Sequence sequence = ASN1Sequence.getInstance(encodedBasicResponse);

            if (((ASN1TaggedObject) sequence.getObjectAt(0)).getTagNo() == 0) {
                return LintResult.of(Status.ERROR);
            }
        } catch (IOException e) {
            return LintResult.of(Status.FATAL);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(byte[] ocspResponse) {
        return true;
    }

}
