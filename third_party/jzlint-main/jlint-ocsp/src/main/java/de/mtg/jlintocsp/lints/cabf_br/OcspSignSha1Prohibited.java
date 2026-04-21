package de.mtg.jlintocsp.lints.cabf_br;

import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import de.mtg.jlintocsp.JavaOCSPResponseLint;
import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;

@Lint(
        name = "e_ocsp_sign_sha1_prohibited",
        description = "Check if the OCSP response is signed with SHA1 after its sunset date.",
        citation = "BRs: 7.1.3.2.1",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.OCSP_SHA1_SUNSET)
public class OcspSignSha1Prohibited implements JavaOCSPResponseLint {

    @Override
    public LintResult execute(byte[] ocspResponse) {

        OCSPResponse response = OCSPResponse.getInstance(ocspResponse);
        ResponseBytes responseBytes = response.getResponseBytes();

        BasicOCSPResponse basicOCSPResponse = BasicOCSPResponse.getInstance(responseBytes.getResponse().getOctets());
        AlgorithmIdentifier responseSignatureAlgorithm = basicOCSPResponse.getSignatureAlgorithm();

        List<String> disallowedAlgorithms = Arrays.asList(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(),
                OIWObjectIdentifiers.dsaWithSHA1.getId(), X9ObjectIdentifiers.ecdsa_with_SHA1.getId());

        String signatureAlgorithm = responseSignatureAlgorithm.getAlgorithm().getId();

        if (disallowedAlgorithms.contains(signatureAlgorithm)) {
            return LintResult.of(Status.ERROR, String.format("Disallowed signature algorithm %s in OCSP response.", signatureAlgorithm));
        }
        return LintResult.of(Status.PASS);

    }

    @Override
    public boolean checkApplies(byte[] ocspResponse) {
        return true;
    }

}
