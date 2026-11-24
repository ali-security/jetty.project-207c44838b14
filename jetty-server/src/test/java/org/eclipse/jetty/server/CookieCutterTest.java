//
//  ========================================================================
//  Copyright (c) 1995-2018 Mort Bay Consulting Pty. Ltd.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

package org.eclipse.jetty.server;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

import java.util.Arrays;

import javax.servlet.http.Cookie;

import org.junit.Test;

public class CookieCutterTest
{
    private Cookie[] parseCookieHeaders(String... headers)
    {
        CookieCutter cutter = new CookieCutter();
        for (String header : headers)
        {
            cutter.addCookieField(header);
        }
        return cutter.getCookies();
    }

    private void assertCookie(String prefix, Cookie cookie,
                              String expectedName,
                              String expectedValue,
                              int expectedVersion,
                              String expectedPath)
    {
        assertThat(prefix + ".name", cookie.getName(), is(expectedName));
        assertThat(prefix + ".value", cookie.getValue(), is(expectedValue));
        assertThat(prefix + ".version", cookie.getVersion(), is(expectedVersion));
        assertThat(prefix + ".path", cookie.getPath(), is(expectedPath));
    }

    /**
     * CVE-2023-26049 : cookie exfiltration through a quoted cookie value.
     * <p>
     * A ';' inside a quoted section used to be appended to the value instead of ending the
     * cookie, so an attacker able to set a single cookie could have the value of a following
     * (possibly HttpOnly) cookie reported as part of the value of the cookie they control.
     * </p>
     */
    @Test
    public void testCookieSmugglingViaQuotedValue()
    {
        // The advisory example: a quoted section holding a ';' and a second name=value pair.
        assertNoCookieSmuggling("other=\"quoted=;HttpOnly_cookie=secret\"", "other", "HttpOnly_cookie", "secret");
        // Same attack with a space after the ';', as a browser would emit it.
        assertNoCookieSmuggling("other=\"quoted=; HttpOnly_cookie=secret\"", "other", "HttpOnly_cookie", "secret");
        // Same attack relying on the unterminated quote instead of the closing one.
        assertNoCookieSmuggling("other=\"quoted=; HttpOnly_cookie=secret", "other", "HttpOnly_cookie", "secret");
        // Same attack with an escape sequence inside the quoted section.
        assertNoCookieSmuggling("other=\"quoted=\\\";HttpOnly_cookie=secret\"", "other", "HttpOnly_cookie", "secret");
        // The GHSA-p26g-97m4-6q7c illustration verbatim.
        assertNoCookieSmuggling("DISPLAY_LANGUAGE=\"b; JSESSIONID=1337; c=d\"", "DISPLAY_LANGUAGE", "JSESSIONID", "1337");

        // A legitimate cookie preceding the attacker controlled one must still be parsed.
        String rawCookie = "SESSION=1234; other=\"quoted=;HttpOnly_cookie=secret\"";
        assertNoCookieSmuggling(rawCookie, "other", "HttpOnly_cookie", "secret");
        Cookie[] cookies = parseCookieHeaders(rawCookie);
        assertThat("Cookies.length (" + dump(cookies) + ")", cookies.length, is(1));
        assertCookie("Cookies[0]", cookies[0], "SESSION", "1234", 0, null);

        // A legitimate cookie following the attacker controlled one must still be parsed.
        rawCookie = "DISPLAY_LANGUAGE=\"b; JSESSIONID=1337; c=d\"; JSESSIONID=real";
        assertNoCookieSmuggling(rawCookie, "DISPLAY_LANGUAGE", "1337");
        cookies = parseCookieHeaders(rawCookie);
        assertThat("Cookies.length (" + dump(cookies) + ")", cookies.length, is(1));
        assertCookie("Cookies[0]", cookies[0], "JSESSIONID", "real", 0, null);
    }

    private void assertNoCookieSmuggling(String rawCookie, String attackerName, String... smuggled)
    {
        Cookie[] cookies = parseCookieHeaders(rawCookie);

        for (Cookie cookie : cookies)
        {
            // The attacker controlled cookie must be dropped, not reported with a value
            // built out of the cookies that follow it in the field.
            assertThat("Cookie.name of <" + rawCookie + "> (" + dump(cookies) + ")",
                cookie.getName(), is(not(attackerName)));
            for (String text : smuggled)
            {
                assertThat("Cookie[" + cookie.getName() + "].value of <" + rawCookie + ">",
                    cookie.getValue(), not(containsString(text)));
            }
        }
    }

    /**
     * The value of a cookie with no name must not be carried over and reported as the value
     * of the next cookie in the field.
     */
    @Test
    public void testNamelessValueNotSmuggled()
    {
        Cookie[] cookies = parseCookieHeaders("=secret; other=\"q\"; x=y");

        assertThat("Cookies.length (" + dump(cookies) + ")", cookies.length, is(2));
        assertCookie("Cookies[0]", cookies[0], "other", "q", 0, null);
        assertCookie("Cookies[1]", cookies[1], "x", "y", 0, null);
    }

    /**
     * The attributes following a rejected cookie must not be applied to the previous cookie.
     */
    @Test
    public void testRejectedCookieAttributes()
    {
        Cookie[] cookies = parseCookieHeaders("$Version=1; a=b; c=\"x;y\"; $Path=/evil; $Domain=evil.com");

        assertThat("Cookies.length (" + dump(cookies) + ")", cookies.length, is(1));
        assertCookie("Cookies[0]", cookies[0], "a", "b", 1, null);
        assertThat("Cookies[0].domain", cookies[0].getDomain(), nullValue());
    }

    /**
     * Example from RFC2965.
     * <p>
     * Comma separation is not supported by RFC6265, and the characters that are not valid
     * cookie-octets cause the spoofed cookie to be discarded entirely rather than reported
     * with a value carrying the rest of the field.
     * </p>
     */
    @Test
    public void testRFC2965_CookieSpoofingExample()
    {
        String rawCookie = "$Version=\"1\"; session_id=\"1234\", " +
                "$Version=\"1\"; session_id=\"1111\"; $Domain=\".cracker.edu\"";

        Cookie[] cookies = parseCookieHeaders(rawCookie);

        assertThat("Cookies.length (" + dump(cookies) + ")", cookies.length, is(1));
        assertCookie("Cookies[0]", cookies[0], "session_id", "1111", 1, null);
        assertThat("Cookies[0].domain", cookies[0].getDomain(), is(".cracker.edu"));
    }

    /**
     * A rejected cookie must not stop the cookies that follow it in the same field from being
     * parsed, and a long run of empty cookies must not be mistaken for one huge cookie.
     */
    @Test
    public void testExcessiveSemicolons()
    {
        char[] excessive = new char[65535];
        Arrays.fill(excessive, ';');
        String rawCookie = "foo=bar; " + new String(excessive) + "; xyz=pdq";

        Cookie[] cookies = parseCookieHeaders(rawCookie);

        assertThat("Cookies.length", cookies.length, is(2));
        assertCookie("Cookies[0]", cookies[0], "foo", "bar", 0, null);
        assertCookie("Cookies[1]", cookies[1], "xyz", "pdq", 0, null);
    }

    /**
     * The authoritative table of what the RFC6265 parser produces: each row is the raw
     * cookie field followed by the expected "name=value" of each parsed cookie.
     */
    @Test
    public void testRFC6265CookieParsing()
    {
        for (String[] row : RFC6265_COOKIES)
        {
            String input = row[0];
            String[] expected = Arrays.copyOfRange(row, 1, row.length);
            String param = input + " -> " + Arrays.asList(expected);

            Cookie[] cookies = parseCookieHeaders(input);

            assertThat("Cookies.length of <" + param + "> (" + dump(cookies) + ")",
                cookies.length, is(expected.length));
            for (int i = 0; i < cookies.length; i++)
            {
                Cookie cookie = cookies[i];
                assertThat("Cookies[" + i + "] of <" + param + "> (" + dump(cookies) + ")",
                    cookie.getName() + "=" + cookie.getValue(), is(expected[i]));
            }
        }
    }

    private static final String[][] RFC6265_COOKIES = {
        {"A=1; B=2; C=3", "A=1", "B=2", "C=3"},
        {"A=\"1\"; B=2; C=3", "A=1", "B=2", "C=3"},
        {"A=\"1\"; B=\"2\"; C=\"3\"", "A=1", "B=2", "C=3"},
        {"A=1; B=2; C=\"3", "A=1", "B=2"},
        {"A=1; B=2; C=\"", "A=1", "B=2"},
        {"A=1 ; B=2; C=3", "A=1", "B=2", "C=3"},
        {"A= 1; B=2; C=3", "A=1", "B=2", "C=3"},
        {"A=\"1; B=2\"; C=3", "C=3"},
        {"A=\"1; B=2; C=3"},
        {"A=\"1 B=2\"; C=3", "A=1 B=2", "C=3"},
        {"A=\"\"1; B=2; C=3", "B=2", "C=3"},
        {"A=\"\" ; B=2; C=3", "A=", "B=2", "C=3"},
        {"A=\"\"; B=2; C=3", "A=", "B=2", "C=3"},
        {"A=1\"\"; B=2; C=3", "B=2", "C=3"},
        {"A=1\"; B=2; C=3", "B=2", "C=3"},
        {"A=1\"1; B=2; C=3", "B=2", "C=3"},
        {"A=\" 1\"; B=2; C=3", "A= 1", "B=2", "C=3"},
        {"A=\"1 \"; B=2; C=3", "A=1 ", "B=2", "C=3"},
        {"A=\" 1 \"; B=2; C=3", "A= 1 ", "B=2", "C=3"},
        {"A=\" 1 1 \"; B=2; C=3", "A= 1 1 ", "B=2", "C=3"},
        {"A=1,; B=2; C=3", "B=2", "C=3"},
        {"A=\"1,\"; B=2; C=3", "B=2", "C=3"},
        {"A=\\1; B=2; C=3", "B=2", "C=3"},
        {"A=\"\\1\"; B=2; C=3", "B=2", "C=3"},
        {"A=1\u0007; B=2; C=3", "B=2", "C=3"},
        {"A=\"1\u0007\"; B=2; C=3", "B=2", "C=3"},
        {"\u20AC"},
        {"@={}"},
        {"$X=Y; N=V", "N=V"},
        {"N=V; $X=Y", "N=V"}
    };

    private static String dump(Cookie[] cookies)
    {
        StringBuilder sb = new StringBuilder();
        for (Cookie cookie : cookies)
        {
            sb.append("<").append(cookie.getName()).append(">=<").append(cookie.getValue()).append("> | ");
        }
        if (sb.length() > 0)
            sb.delete(sb.length() - 2, sb.length() - 1);
        return sb.toString();
    }
}
