package de.mtg.jzlint;

import java.io.IOException;
import java.net.JarURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.function.Predicate;
import java.util.jar.JarEntry;
import java.util.stream.Collectors;

public class LintClassesContainer {

    public static final String JZLINT_PACKAGE_NAME = "de/mtg/jzlint/lints";
    public static final String JLINT_EXT_PACKAGE_NAME = "de/mtg/jlint/lints";
    public static final String JLINT_OCSP_PACKAGE_NAME = "de/mtg/jlintocsp/lints";
    public static final String JLINT_ISSUER_PACKAGE_NAME = "de/mtg/jlintissuer/lints";
    public static final String JLINT_PQC_PACKAGE_NAME = "de/mtg/jlint/pqc/lints";

    private static LintClassesContainer lintClassesContainer;
    private List<Class<?>> lintClasses;

    private LintClassesContainer(List<Class<?>> lintClasses) {
        this.lintClasses = lintClasses;
    }

    public static synchronized LintClassesContainer getInstance() {

        if (lintClassesContainer == null) {
            try {
                List<Class<?>> jzLintClasses = getClasses(JZLINT_PACKAGE_NAME);
                List<Class<?>> jLintExtClasses = getClasses(JLINT_EXT_PACKAGE_NAME);
                List<Class<?>> jLintIssuerClasses = getClasses(JLINT_ISSUER_PACKAGE_NAME);
                List<Class<?>> jLintOCSPClasses = getClasses(JLINT_OCSP_PACKAGE_NAME);
                List<Class<?>> jLintPQCClasses = getClasses(JLINT_PQC_PACKAGE_NAME);

                jzLintClasses.addAll(jLintExtClasses);
                jzLintClasses.addAll(jLintIssuerClasses);
                jzLintClasses.addAll(jLintOCSPClasses);
                jzLintClasses.addAll(jLintPQCClasses);
                lintClassesContainer = new LintClassesContainer(jzLintClasses);
            } catch (ClassNotFoundException | URISyntaxException | IOException ex) {
                throw new RuntimeException(ex);
            }
        }

        return lintClassesContainer;
    }

    public List<Class<?>> getLintClasses() {
        return lintClasses;
    }

    private static List<Class<?>> getClasses(String packageName) throws IOException, ClassNotFoundException, URISyntaxException {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();

        URL urlResource = classLoader.getResource(packageName);
        URLConnection urlConnection = urlResource.openConnection();

        List<Class<?>> classes = new ArrayList<>();

        if (urlConnection instanceof JarURLConnection) {
            Enumeration<JarEntry> entries = ((JarURLConnection) urlConnection).getJarFile().entries();

            while (entries.hasMoreElements()) {
                JarEntry jarEntry = entries.nextElement();
                if (jarEntry.getName().endsWith(".class")) {
                    String className = jarEntry.getName().replace("/", ".");
                    // remove .class
                    classes.add(Class.forName(className.substring(0, className.length() - 6)));
                }
            }
        } else {

            Enumeration<URL> resources = classLoader.getResources(packageName);
            List<Path> lintClassesCandidates = new ArrayList<>();

            while (resources.hasMoreElements()) {
                URL resource = resources.nextElement();
                Files.walk(Paths.get(resource.toURI())).filter(Files::isRegularFile).forEach(lintClassesCandidates::add);
            }

            for (Path path : lintClassesCandidates) {
                String className = path.getName(path.getNameCount() - 1).toString();
                // remove .class
                className = className.substring(0, className.length() - 6);
                StringBuilder stringBuilder = new StringBuilder();
                stringBuilder.append(path.getName(path.getNameCount() - 6));
                stringBuilder.append(".");
                stringBuilder.append(path.getName(path.getNameCount() - 5));
                stringBuilder.append(".");
                stringBuilder.append(path.getName(path.getNameCount() - 4));
                stringBuilder.append(".");
                stringBuilder.append(path.getName(path.getNameCount() - 3));
                stringBuilder.append(".");
                stringBuilder.append(path.getName(path.getNameCount() - 2));
                stringBuilder.append(".");
                stringBuilder.append(className);
                classes.add(Class.forName(stringBuilder.toString()));
            }
        }
        Predicate<Class<?>> lintAnnotationPresent = c -> c.isAnnotationPresent(Lint.class);
        return classes.stream().filter(lintAnnotationPresent).collect(Collectors.toList());
    }

}
