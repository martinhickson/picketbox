package org.jboss.test.security;

import static org.junit.Assert.assertEquals;

import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;

import org.jboss.security.PicketBoxLogger;
import org.junit.BeforeClass;
import org.junit.Test;

public class PicketBoxLoggerUnitTestCase {

    @BeforeClass
    public static void configureConsoleLogging() {
        System.setProperty("org.jboss.logging.provider", "jdk");

        java.util.logging.Logger rootLogger = LogManager.getLogManager().getLogger("");
        rootLogger.setLevel(Level.ALL);
        for (Handler handler : rootLogger.getHandlers()) {
            handler.setLevel(Level.ALL);
        }
    }

    @Test
    public void testGeneratedLoggerWritesToConsole() {
        System.out.println("Exercising " + PicketBoxLogger.LOGGER.getClass().getName());

        PicketBoxLogger.LOGGER.unsupportedHashEncodingFormat("unit-test-format");

        assertEquals("org.jboss.security.PicketBoxLogger_$logger", PicketBoxLogger.LOGGER.getClass().getName());
    }
}
