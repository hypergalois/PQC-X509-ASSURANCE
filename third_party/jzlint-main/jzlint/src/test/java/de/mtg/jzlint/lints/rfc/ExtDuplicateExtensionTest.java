package de.mtg.jzlint.lints.rfc;

import java.lang.reflect.InvocationTargetException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;

import de.mtg.jzlint.LintJSONResult;
import de.mtg.jzlint.LintJSONResults;
import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Runner;
import de.mtg.jzlint.Status;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(LintTestExtension.class)
class ExtDuplicateExtensionTest {

    @Test
    void testCase01() throws NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {

        X509Certificate certificate = Mockito.mock(X509Certificate.class);

        Set<String> criticalOIDs = new HashSet<>();
        criticalOIDs.add("2.5.29.19");
        criticalOIDs.add("2.5.29.1");
        criticalOIDs.add("2.5.29.15");
        Set<String> nonCriticalOIDs = new HashSet<>();
        nonCriticalOIDs.add("2.5.29.19");
        nonCriticalOIDs.add("2.5.29.14");

        when(certificate.getCriticalExtensionOIDs()).thenReturn(criticalOIDs);
        when(certificate.getNonCriticalExtensionOIDs()).thenReturn(nonCriticalOIDs);
        when(certificate.getNotBefore()).thenReturn(new Date());
        when(certificate.getVersion()).thenReturn(3);

        Runner runner = new Runner();
        LintJSONResult lint = runner.lint(certificate, "e_ext_duplicate_extension");
        assertEquals(Status.ERROR.name().toLowerCase(), lint.getResult().toLowerCase());
        String resultString = new LintJSONResults(Arrays.asList(lint)).getResultString();
        assertNotNull(resultString);
        assertFalse(resultString.isEmpty());
        assertTrue(resultString.contains("e_ext_duplicate_extension"));
    }

    @LintTest(
            name = "e_ext_duplicate_extension",
            filename = "extSANDuplicated.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

    @LintTest(
            name = "e_ext_duplicate_extension",
            filename = "multDupeExts.pem",
            expectedResultStatus = Status.ERROR)
    void testCase03() {
    }

    @LintTest(
            name = "e_ext_duplicate_extension",
            filename = "caBasicConstCrit.pem",
            expectedResultStatus = Status.PASS)
    void testCase04() {
    }
}