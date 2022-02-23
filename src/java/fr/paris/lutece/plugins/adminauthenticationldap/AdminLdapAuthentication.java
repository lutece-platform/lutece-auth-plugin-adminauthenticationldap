/*
 * Copyright (c) 2002-2021, City of Paris
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice
 *     and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice
 *     and the following disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 *  3. Neither the name of 'Mairie de Paris' nor 'Lutece' nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * License 1.0
 */
package fr.paris.lutece.plugins.adminauthenticationldap;

import fr.paris.lutece.plugins.adminauthenticationldap.business.AdminLdapUser;
import fr.paris.lutece.plugins.adminauthenticationldap.service.LdapService;
import fr.paris.lutece.portal.business.user.AdminUser;
import fr.paris.lutece.portal.business.user.AdminUserDAO;
import fr.paris.lutece.portal.business.user.AdminUserHome;
import fr.paris.lutece.portal.business.user.authentication.AdminAuthentication;
import fr.paris.lutece.portal.business.user.log.UserLog;
import fr.paris.lutece.portal.business.user.log.UserLogHome;
import fr.paris.lutece.portal.service.admin.AdminAuthenticationService;
import fr.paris.lutece.portal.service.admin.AdminUserService;
import fr.paris.lutece.portal.service.util.AppLogService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;
import fr.paris.lutece.util.http.SecurityUtil;
import fr.paris.lutece.util.ldap.LdapUtil;
import org.apache.commons.lang3.StringUtils;

import java.text.MessageFormat;
import java.util.*;

import javax.naming.CommunicationException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

/**
 * Data authentication module for admin authentication
 */
public class AdminLdapAuthentication implements AdminAuthentication
{
    private static final String PROPERTY_AUTH_SERVICE_NAME = "adminauthenticationldap.service.name";
    private static final String PROPERTY_COOKIE_AUTHENTIFICATION = "adminauthenticationldap.cookie.authenticationMode"; // mode d?authentification, login/pwd ou
                                                                                                                        // certificat

    private static final String PROPERTY_URL_LOGIN_PAGE = "adminauthenticationldap.url.loginPage";
    private static final String PROPERTY_URL_CHANGE_PASSWORD = "adminauthenticationldap.url.changePasswordPage";
    private static final String PROPERTY_URL_DO_LOGIN = "adminauthenticationldap.url.doLogin";
    private static final String PROPERTY_URL_DO_LOGOUT = "adminauthenticationldap.url.doLogout";
    private static final String PROPERTY_URL_NEW_ACCOUNT = "adminauthenticationldap.url.newAccount";
    private static final String PROPERTY_URL_VIEW_ACCOUNT = "adminauthenticationldap.url.viewAccount";
    private static final String PROPERTY_URL_LOST_PASSWORD = "adminauthenticationldap.url.lostPassword";
    private static final String PROPERTY_URL_LOST_LOGIN = "adminauthenticationldap.url.lostLogin";

    private static final String PROPERTY_MAX_ACCESS_FAILED = "access_failures_max";
    private static final String PROPERTY_INTERVAL_MINUTES = "access_failures_interval";

    public static final String AUTH_SERVICE_NAME = AppPropertiesService.getProperty( PROPERTY_AUTH_SERVICE_NAME );

    /* comparator for sorting - date ascendant order */
    public static final Comparator<AdminUser> COMPARATOR_USER = ( user1, user2 ) -> {
        int nOrder = user1.getLastName( ).toUpperCase( ).compareTo( user2.getLastName( ).toUpperCase( ) );

        if ( nOrder == 0 )
        {
            nOrder = user1.getFirstName( ).toUpperCase( ).compareTo( user2.getFirstName( ).toUpperCase( ) );

            if ( nOrder == 0 )
            {
                nOrder = user1.getEmail( ).toUpperCase( ).compareTo( user2.getEmail( ).toUpperCase( ) );
            }
        }

        return nOrder;
    };

    public AdminLdapAuthentication( )
    {
        super( );
    }

    @Override
    public String getAuthServiceName( )
    {
        return AUTH_SERVICE_NAME;
    }

    @Override
    public String getAuthType( HttpServletRequest request )
    {
        Cookie [ ] cookies = request.getCookies( );
        String strAuthType = request.getAuthType( );

        for ( Cookie cookie : cookies )
        {
            if ( cookie.getName( ).equals( AppPropertiesService.getProperty( PROPERTY_COOKIE_AUTHENTIFICATION ) ) )
            {
                strAuthType = cookie.getValue( );
            }
        }

        return strAuthType;
    }

    @Override
    public AdminUser login( String strAccessCode, String strUserPassword, HttpServletRequest request ) throws LoginException
    {
        // Test the number of errors during an interval of minutes
        int nMaxFailed = AdminUserService.getIntegerSecurityParameter( PROPERTY_MAX_ACCESS_FAILED );
        int nIntervalMinutes = AdminUserService.getIntegerSecurityParameter( PROPERTY_INTERVAL_MINUTES );

        if ( ( nMaxFailed > 0 ) && ( nIntervalMinutes > 0 ) )
        {
            // Creating a record of connections log
            UserLog userLog = new UserLog( );
            userLog.setAccessCode( strAccessCode );
            userLog.setIpAddress( SecurityUtil.getRealIp( request ) );
            userLog.setDateLogin( new java.sql.Timestamp( new java.util.Date( ).getTime( ) ) );

            int nNbFailed = UserLogHome.getLoginErrors( userLog, nIntervalMinutes );

            if ( nNbFailed > nMaxFailed )
            {
                throw new FailedLoginException( );
            }
        }

        LdapService.login( strAccessCode, strUserPassword );

        AdminUser user = AdminUserHome.findUserByLogin( strAccessCode );
        if ( user == null )
        {
            AdminUserHome.create( getUserPublicData( strAccessCode ) );
        }
        else
        {
            AdminUser user2 = getUserPublicData( strAccessCode );

            if ( COMPARATOR_USER.compare( user, user2 ) != 0 )
            {
                user.setEmail( user2.getEmail( ) );
                user.setFirstName( user2.getFirstName( ) );
                user.setLastName( user2.getLastName( ) );
                AdminUserHome.update( user );
            }
        }

        return user;
    }

    @Override
    public void logout( AdminUser user )
    {
    }

    @Override
    public AdminUser getAnonymousUser( )
    {
        throw new java.lang.UnsupportedOperationException( "La methode getAnonymousUser() n'est pas encore implementee." );
    }

    @Override
    public boolean isExternalAuthentication( )
    {
        return false;
    }

    @Override
    public AdminUser getHttpAuthenticatedUser( HttpServletRequest request )
    {
        return null;
    }

    @Override
    public String getLoginPageUrl( )
    {
        return AppPropertiesService.getProperty( PROPERTY_URL_LOGIN_PAGE );
    }

    @Override
    public String getChangePasswordPageUrl( )
    {
        return AppPropertiesService.getProperty( PROPERTY_URL_CHANGE_PASSWORD );
    }

    @Override
    public String getDoLoginUrl( )
    {
        return AppPropertiesService.getProperty( PROPERTY_URL_DO_LOGIN );
    }

    @Override
    public String getDoLogoutUrl( )
    {
        return AppPropertiesService.getProperty( PROPERTY_URL_DO_LOGOUT );
    }

    @Override
    public String getNewAccountPageUrl( )
    {
        return AppPropertiesService.getProperty( PROPERTY_URL_NEW_ACCOUNT );
    }

    @Override
    public String getViewAccountPageUrl( )
    {
        return AppPropertiesService.getProperty( PROPERTY_URL_VIEW_ACCOUNT );
    }

    @Override
    public String getLostPasswordPageUrl( )
    {
        return AppPropertiesService.getProperty( PROPERTY_URL_LOST_PASSWORD );
    }

    @Override
    public String getLostLoginPageUrl( )
    {
        return AppPropertiesService.getProperty( PROPERTY_URL_LOST_LOGIN );
    }

    @Override
    public Collection<AdminUser> getUserList( String strParameterLastName, String strParameterFirstName, String strParameterEmail )
    {
        return LdapService.getAdminUserSearchResult( strParameterLastName, strParameterFirstName, strParameterEmail );
    }

    @Override
    public AdminUser getUserPublicData( String strId )
    {
        return LdapService.getAdminUser( strId );
    }

}
