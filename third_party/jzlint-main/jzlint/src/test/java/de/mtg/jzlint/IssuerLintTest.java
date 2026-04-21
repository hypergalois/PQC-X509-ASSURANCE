package de.mtg.jzlint;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.junit.jupiter.api.Test;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Test
public @interface IssuerLintTest {

    public String name();
    public String filenameCertificate();
    public String filenameIssuerCertificate();
    public Status expectedResultStatus();
    public String expectedResultDetails() default "";
    public String certificateDescription() default "";
}
