package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;

/************************************************
 "A certificate MUST NOT include more than one
 instance of a particular extension."
 ************************************************/
@Lint(
        name = "e_ext_duplicate_extension",
        description = "A certificate MUST NOT include more than one instance of a particular extension",
        citation = "RFC 5280: 4.2",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class ExtDuplicateExtension implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {


        List<String> oids = new ArrayList<>();

        Set<String> criticalExtensionOIDs = certificate.getCriticalExtensionOIDs();

        if (setContainsDuplicates(oids, criticalExtensionOIDs)) {
            return LintResult.of(Status.ERROR);
        }

        Set<String> nonCriticalExtensionOIDs = certificate.getNonCriticalExtensionOIDs();

        if (setContainsDuplicates(oids, nonCriticalExtensionOIDs)) {
            return LintResult.of(Status.ERROR);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return certificate.getVersion() == 3;
    }

    private boolean setContainsDuplicates(List<String> oids, Set<String> extensionOIDs) {

        if (extensionOIDs == null || extensionOIDs.isEmpty()) {
            return false;
        }

        for (String extensionOID : extensionOIDs) {
            if (oids.remove(extensionOID)) {
                return true;
            }
            oids.add(extensionOID);
        }
        return false;
    }
}
