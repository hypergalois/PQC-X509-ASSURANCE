package de.mtg.jzlint;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import de.mtg.jzlint.utils.DateUtils;

public class Runner {

    public static final String CHECK_APPLIES = "checkApplies";
    public static final String EXECUTE = "execute";

    public Runner() {
        // empty
    }

    public LintJSONResults lint(X509Certificate certificate)
            throws NoSuchMethodException, IllegalAccessException, InstantiationException, InvocationTargetException {

        LintClassesContainer lintClassesContainer = LintClassesContainer.getInstance();
        List<Class<?>> lintClasses = lintClassesContainer.getLintClasses().stream().filter(cl -> cl.isAnnotationPresent(Lint.class)).toList();

        List<LintJSONResult> result = new ArrayList<>();

        for (Class<?> lintClass : lintClasses) {
            Lint lintAnnotation = lintClass.getAnnotation(Lint.class);
            LintJSONResult lintResult = getLintResult(certificate, lintClass, lintAnnotation);
            if (lintResult != null) {
                result.add(lintResult);
            }
        }

        return new LintJSONResults(result);
    }

    public LintJSONResult lintForClassName(X509Certificate certificate, String lintClassName)
            throws NoSuchMethodException, IllegalAccessException, InstantiationException, InvocationTargetException, ClassNotFoundException {
        Class<?> lintClass = Class.forName(lintClassName);
        Lint lintAnnotation = lintClass.getAnnotation(Lint.class);
        return getLintResult(certificate, lintClass, lintAnnotation);
    }

    public LintJSONResult lint(X509Certificate certificate, String lintName)
            throws NoSuchMethodException, IllegalAccessException, InstantiationException, InvocationTargetException {

        LintClassesContainer lintClassesContainer = LintClassesContainer.getInstance();
        List<Class<?>> lintClasses = lintClassesContainer.getLintClasses().stream().filter(cl -> cl.isAnnotationPresent(Lint.class)).toList();

        for (Class<?> lintClass : lintClasses) {
            Lint lintAnnotation = lintClass.getAnnotation(Lint.class);
            String name = lintAnnotation.name();

            // if lint name is present then run only this lint
            if (lintName != null && !name.equalsIgnoreCase(lintName)) {
                continue;
            }

            return getLintResult(certificate, lintClass, lintAnnotation);
        }
        return new LintJSONResult(lintName, Status.NA);
    }

    public LintJSONResult lintForClassName(X509CRL crl, String lintClassName)
            throws NoSuchMethodException, IllegalAccessException, InstantiationException, InvocationTargetException, ClassNotFoundException {
        Class<?> lintClass = Class.forName(lintClassName);
        Lint lintAnnotation = lintClass.getAnnotation(Lint.class);
        return getLintResult(crl, lintClass, lintAnnotation);
    }

    public LintJSONResult lint(X509CRL crl, String lintName)
            throws NoSuchMethodException, IllegalAccessException, InstantiationException, InvocationTargetException {

        LintClassesContainer lintClassesContainer = LintClassesContainer.getInstance();
        List<Class<?>> lintClasses = lintClassesContainer.getLintClasses().stream().filter(cl -> cl.isAnnotationPresent(Lint.class)).toList();

        for (Class<?> lintClass : lintClasses) {

            Lint lintAnnotation = lintClass.getAnnotation(Lint.class);
            String name = lintAnnotation.name();

            // if lint name is present then run only this lint
            if (lintName != null && !name.equalsIgnoreCase(lintName)) {
                continue;
            }

            return getLintResult(crl, lintClass, lintAnnotation);
        }
        return new LintJSONResult(lintName, Status.NA);
    }

    private LintJSONResult getLintResult(X509Certificate certificate, Class<?> lintClass, Lint lintAnnotation)
            throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {

        Method checkAppliesMethod;
        try {
            checkAppliesMethod = lintClass.getMethod(CHECK_APPLIES, X509Certificate.class);
        } catch (NoSuchMethodException noSuchMethodException) {// it is a CRL lint
            return null;
        }
        Method executeMethod = lintClass.getMethod(EXECUTE, X509Certificate.class);
        Object object = lintClass.getDeclaredConstructor().newInstance();

        boolean checkApplies = (boolean) checkAppliesMethod.invoke(object, certificate);

        if (checkApplies) {

            if (!DateUtils.isIssuedOnOrAfter(certificate, lintAnnotation.effectiveDate().getZonedDateTime())) {
                return new LintJSONResult(lintAnnotation.name(), Status.NE);
            }

            if (IneffectiveDate.EMPTY != lintAnnotation.ineffectiveDate() &&
                    DateUtils.isIssuedOnOrAfter(certificate, lintAnnotation.ineffectiveDate().getZonedDateTime())) {
                return new LintJSONResult(lintAnnotation.name(), Status.NE);
            }

            LintResult lintResult = (LintResult) executeMethod.invoke(object, certificate);
            return new LintJSONResult(lintAnnotation.name(), lintResult.getStatus());
        } else {
            return new LintJSONResult(lintAnnotation.name(), Status.NA);
        }
    }

    private LintJSONResult getLintResult(X509CRL crl, Class<?> lintClass, Lint lintAnnotation)
            throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        Method checkAppliesMethod = lintClass.getMethod(CHECK_APPLIES, X509CRL.class);
        Method executeMethod = lintClass.getMethod(EXECUTE, X509CRL.class);
        Object object = lintClass.getDeclaredConstructor().newInstance();

        boolean checkApplies = (boolean) checkAppliesMethod.invoke(object, crl);

        if (checkApplies) {

            if (!DateUtils.isIssuedOnOrAfter(crl, lintAnnotation.effectiveDate().getZonedDateTime())) {
                return new LintJSONResult(lintAnnotation.name(), Status.NE);
            }

            if (IneffectiveDate.EMPTY != lintAnnotation.ineffectiveDate() &&
                    DateUtils.isIssuedOnOrAfter(crl, lintAnnotation.ineffectiveDate().getZonedDateTime())) {
                return new LintJSONResult(lintAnnotation.name(), Status.NE);
            }

            LintResult lintResult = (LintResult) executeMethod.invoke(object, crl);
            return new LintJSONResult(lintAnnotation.name(), lintResult.getStatus());
        } else {
            return new LintJSONResult(lintAnnotation.name(), Status.NA);
        }
    }

}
