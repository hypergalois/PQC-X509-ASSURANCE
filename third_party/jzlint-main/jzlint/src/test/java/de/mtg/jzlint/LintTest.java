package de.mtg.jzlint;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.junit.jupiter.api.Test;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Test
public @interface LintTest {

    String name();
    String filename();
    Status expectedResultStatus();
    String expectedResultDetails() default "";
    String certificateDescription() default "";

}
