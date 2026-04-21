package de.mtg.jzlint.lints.mozilla;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/************************************************
 https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/
 Section 5.1.1 RSA
 CAs MUST NOT use the id-RSASSA-PSS OID (1.2.840.113549.1.1.10) within a SubjectPublicKeyInfo to represent a RSA key.
 ************************************************/

@Lint(
        name = "e_mp_rsassa-pss_in_spki",
        description = "CAs MUST NOT use the id-RSASSA-PSS OID (1.2.840.113549.1.1.10) within a SubjectPublicKeyInfo to represent a RSA key.",
        citation = "Mozilla Root Store Policy / Section 5.1.1",
        source = Source.MOZILLA_ROOT_STORE_POLICY,
        effectiveDate = EffectiveDate.MozillaPolicy27Date)
public class MpRsassaPssInSpki implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        String publicKeyOID = Utils.getPublicKeyOID(certificate);

        if (PKCSObjectIdentifiers.id_RSASSA_PSS.getId().equals(publicKeyOID)) {
            return LintResult.of(Status.ERROR, "id-RSASSA-PSS OID found in certificate SubjectPublicKeyInfo");
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }

}
