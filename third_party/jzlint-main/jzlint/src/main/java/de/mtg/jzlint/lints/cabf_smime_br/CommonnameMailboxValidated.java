package de.mtg.jzlint.lints.cabf_smime_br;

import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.SMIMEUtils;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_commonname_mailbox_validated",
        description = "If present, the commonName attribute of a mailbox-validated certificate SHALL contain a mailbox address",
        citation = "S/MIME BRs: 7.1.4.2.2a",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class CommonnameMailboxValidated implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> commonName = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.commonName.getId());

        for (AttributeTypeAndValue attributeTypeAndValue : commonName) {
            String email = attributeTypeAndValue.getValue().toString();
            if (!SMIMEUtils.isValidEmailAddress(email)) {
                return LintResult.of(Status.ERROR);
            }
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return SMIMEUtils.isMailboxValidatedCertificate(certificate);
    }

}
