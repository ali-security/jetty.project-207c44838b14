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
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import javax.servlet.http.Cookie;

import org.eclipse.jetty.http.QuotedCSV;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;


/* ------------------------------------------------------------ */
/** Cookie parser
 * <p>Optimized stateful cookie parser.  Cookies fields are added with the
 * {@link #addCookieField(String)} method and parsed on the next subsequent
 * call to {@link #getCookies()}.
 * If the added fields are identical to those last added (as strings), then the 
 * cookies are not re parsed.
 *
 */
public class CookieCutter
{
    private static final Logger LOG = Log.getLogger(CookieCutter.class);

    private Cookie[] _cookies;
    private Cookie[] _lastCookies;
    private final List<String> _fieldList = new ArrayList<>();
    int _fields;
    
    public CookieCutter()
    {  
    }
    
    public Cookie[] getCookies()
    {
        if (_cookies!=null)
            return _cookies;
        
        if (_lastCookies!=null && _fields==_fieldList.size())
            _cookies=_lastCookies;
        else
            parseFields();
        _lastCookies=_cookies;
        return _cookies;
    }
    
    public void setCookies(Cookie[] cookies)
    {
        _cookies=cookies;
        _lastCookies=null;
        _fieldList.clear();
        _fields=0;
    }
    
    public void reset()
    {
        _cookies=null;
        _fields=0;
    }
    
    public void addCookieField(String f)
    {
        if (f==null)
            return;
        f=f.trim();
        if (f.length()==0)
            return;
            
        if (_fieldList.size()>_fields)
        {
            if (f.equals(_fieldList.get(_fields)))
            {
                _fields++;
                return;
            }
            
            while (_fieldList.size()>_fields)
                _fieldList.remove(_fields);
        }
        _cookies=null;
        _lastCookies=null;
        _fieldList.add(_fields++,f);
    }
    
    
    protected void parseFields()
    {
        _lastCookies=null;
        _cookies=null;
        
        List<Cookie> cookies = new ArrayList<>();

        int version = 0;

        // delete excess fields
        while (_fieldList.size()>_fields)
            _fieldList.remove(_fields);
        
        // For each cookie field
        for (String hdr : _fieldList)
        {
            // Parse the header
            String name = null;
            String value = null;

            Cookie cookie = null;

            boolean invalue=false;
            boolean quoted=false;
            boolean escaped=false;
            boolean quoteClosed=false;
            boolean reject=false;
            int tokenstart=-1;
            int tokenend=-1;
            for (int i = 0, length = hdr.length(), last=length-1; i < length; i++)
            {
                char c = hdr.charAt(i);
                
                // Handle quoted values for name or value
                if (quoted)
                {
                    if (isRFC6265RejectedCharacter(quoted,c))
                    {
                        reject=true;
                        continue;
                    }

                    if (escaped)
                    {
                        escaped=false;
                        continue;
                    }
                    
                    switch (c)
                    {
                        case '"':
                            tokenend=i;
                            quoted=false;
                            quoteClosed=true;

                            // handle quote as last character specially
                            if (i==last)
                            {
                                if (invalue)
                                    value = hdr.substring(tokenstart, tokenend+1);
                                else
                                {
                                    name = hdr.substring(tokenstart, tokenend+1);
                                    value = "";
                                }
                            }
                            break;
                            
                        case '\\':
                            escaped=true;
                            continue;

                        case ';':
                            // A ';' is not a cookie-octet. It must not be appended to the
                            // quoted value, otherwise the value of a following (possibly
                            // HttpOnly) cookie can be smuggled into this cookie's value.
                            // Reject the whole cookie instead.
                            reject=true;
                            continue;

                        default:
                            continue;
                    }
                }
                else
                {
                    // Handle name and value state machines
                    if (invalue)
                    {
                        // parse the value
                        switch (c)
                        {
                            case ' ':
                            case '\t':
                                continue;
                                
                            case '"':
                                if (tokenstart<0)
                                {
                                    // An opening quote as the last character is an
                                    // unterminated quote, so the cookie is discarded
                                    quoted=true;
                                    tokenstart=i;
                                    tokenend=i;
                                    continue;
                                }
                                // A DQUOTE may not appear once the cookie-value has started
                                reject=true;
                                continue;

                            case ';':
                                if (tokenstart>=0)
                                    value = hdr.substring(tokenstart, tokenend+1);
                                else
                                    value="";
                                tokenstart = -1;
                                invalue=false;
                                break;
                                
                            default:
                                if (quoteClosed || isRFC6265RejectedCharacter(quoted,c))
                                {
                                    // Content after a closed quoted section, or a character that
                                    // is not a cookie-octet, is not a valid cookie-value
                                    reject=true;
                                    continue;
                                }

                                if (tokenstart<0)
                                    tokenstart=i;
                                tokenend=i;
                                if (i==last)
                                {
                                    value = hdr.substring(tokenstart, tokenend+1);
                                    break;
                                }
                                continue;
                        }
                    }
                    else
                    {
                        // parse the name
                        switch (c)
                        {
                            case ' ':
                            case '\t':
                                continue;
                                
                            case '"':
                                if (tokenstart<0)
                                {
                                    quoted=true;
                                    tokenstart=i;
                                }
                                tokenend=i;
                                // An opening quote as the last character is an unterminated quote
                                if (i==last && !quoted)
                                {
                                    name = hdr.substring(tokenstart, tokenend+1);
                                    value = "";
                                    break;
                                }
                                continue;

                            case ';':
                                if (tokenstart>=0)
                                {
                                    name = hdr.substring(tokenstart, tokenend+1);
                                    value = "";
                                }
                                tokenstart = -1;
                                break;

                            case '=':
                                if (tokenstart>=0)
                                    name = hdr.substring(tokenstart, tokenend+1);
                                tokenstart = -1;
                                invalue=true;
                                quoteClosed=false;
                                continue;
                                
                            default:
                                if (isRFC6265RejectedCharacter(quoted,c))
                                    reject=true;

                                if (tokenstart<0)
                                    tokenstart=i;
                                tokenend=i;
                                if (i==last)
                                {
                                    name = hdr.substring(tokenstart, tokenend+1);
                                    value = "";
                                    break;
                                }
                                continue;
                        }
                    }
                }

                // If after processing the current character we have a value and a name, then it is a cookie
                if (value!=null && name!=null)
                {
                   
                    name=QuotedCSV.unquote(name);
                    value=QuotedCSV.unquote(value);
                    
                    try
                    {
                        if (name.startsWith("$"))
                        {
                            String lowercaseName = name.toLowerCase(Locale.ENGLISH);
                            if (reject)
                            {
                                // Ignore an attribute with an invalid value
                            }
                            else if ("$path".equals(lowercaseName))
                            {
                                if (cookie!=null)
                                    cookie.setPath(value);
                            }
                            else if ("$domain".equals(lowercaseName))
                            {
                                if (cookie!=null)
                                    cookie.setDomain(value);
                            }
                            else if ("$port".equals(lowercaseName))
                            {
                                if (cookie!=null)
                                    cookie.setComment("$port="+value);
                            }
                            else if ("$version".equals(lowercaseName))
                            {
                                version = Integer.parseInt(value);
                            }
                        }
                        else if (reject)
                        {
                            // Discard the invalid cookie, and do not let the
                            // attributes that follow it apply to a previous cookie
                            cookie = null;
                        }
                        else
                        {
                            cookie = new Cookie(name, value);
                            if (version > 0)
                                cookie.setVersion(version);
                            cookies.add(cookie);
                        }
                    }
                    catch (Exception e)
                    {
                        LOG.debug(e);
                    }

                    name = null;
                    value = null;
                }

                // A ';' ends the cookie: no name, value or rejection carries over to the next one
                if (c==';')
                {
                    name = null;
                    value = null;
                    reject = false;
                    quoteClosed = false;
                }
            }
        }

        _cookies = (Cookie[]) cookies.toArray(new Cookie[cookies.size()]);
        _lastCookies=_cookies;
    }
    
    protected boolean isRFC6265RejectedCharacter(boolean inQuoted, char c)
    {
        /* From RFC6265 - Section 4.1.1 - Syntax
         *  cookie-octet  = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
         *                  ; US-ASCII characters excluding CTLs,
         *                  ; whitespace DQUOTE, comma, semicolon,
         *                  ; and backslash
         *
         * Note: DQUOTE and semicolon are used as separator by the parser,
         * so we can consider them authorized.
         */
        return c > 127 ||  // 8-bit characters
            Character.isISOControl(c) || // control characters
            c == ',' || // comma
            c == '\\';  // backslash
    }
}
