package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;

/**************************************************************************************************
 BRs: 7.1.3
 SHA-1 MAY be used with RSA keys in accordance with the criteria defined in Section 7.1.3.
 **************************************************************************************************/

@Lint(
        name = "e_sub_cert_or_sub_ca_using_sha1",
        description = "CAs MUST NOT issue any new Subscriber certificates or Subordinate CA certificates using SHA-1 after 1 January 2016",
        citation = "BRs: 7.1.3",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.NO_SHA1)
public class SubCertOrSubCaUsingSha1 implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<String> disallowedAlgorithms = Arrays.asList(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(),
                OIWObjectIdentifiers.dsaWithSHA1.getId(), X9ObjectIdentifiers.ecdsa_with_SHA1.getId());

        String signatureAlgorithm = certificate.getSigAlgOID();

        if (disallowedAlgorithms.contains(signatureAlgorithm)) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }


}
