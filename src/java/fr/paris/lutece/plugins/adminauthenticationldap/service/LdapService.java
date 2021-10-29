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
package fr.paris.lutece.plugins.adminauthenticationldap.service;

import fr.paris.lutece.plugins.adminauthenticationldap.AdminLdapAuthentication;
import fr.paris.lutece.plugins.adminauthenticationldap.business.AdminLdapUser;
import fr.paris.lutece.portal.business.user.AdminUser;
import fr.paris.lutece.portal.service.util.AppLogService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;
import fr.paris.lutece.util.ldap.LdapUtil;
import org.apache.commons.lang.StringUtils;

import javax.naming.CommunicationException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.security.auth.login.FailedLoginException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class LdapService
{

    private static final String PROPERTY_BIND_DN = "adminauthenticationldap.ldap.connectionName";
    private static final String PROPERTY_BIND_PASSWORD = "adminauthenticationldap.ldap.connectionPassword";
    private static final String PROPERTY_USER_SUBTREE = "adminauthenticationldap.ldap.userSubtree";
    private static final String PROPERTY_USER_DN_SEARCH_BASE = "adminauthenticationldap.ldap.userBase";
    private static final String PROPERTY_ROOT_DN_SEARCH_BASE = "adminauthenticationldap.ldap.rootBase";
    private static final String PROPERTY_INITIAL_CONTEXT_PROVIDER = "adminauthenticationldap.ldap.initialContextProvider";
    private static final String PROPERTY_PROVIDER_URL = "adminauthenticationldap.ldap.connectionUrl";
    private static final String PROPERTY_USER_DN_SEARCH_FILTER_BY_ACCESS_CODE = "adminauthenticationldap.ldap.userSearch.filterAccessCode";
    private static final String PROPERTY_USER_DN_SEARCH_FILTER_BY_CRITERIA = "adminauthenticationldap.ldap.userSearch.filterCriteria";
    private static final String PROPERTY_USER_DN_SEARCH_GROUP_FILTER = "adminauthenticationldap.ldap.userSearch.groupFilter";
    private static final String PROPERTY_USER_ATTRIBUTE_NAME_ACCESS_CODE = "adminauthenticationldap.ldap.dn.attributeName.accessCode";
    private static final String PROPERTY_USER_ATTRIBUTE_NAME_FAMILY_NAME = "adminauthenticationldap.ldap.dn.attributeName.family";
    private static final String PROPERTY_USER_ATTRIBUTE_NAME_GIVEN_NAME = "adminauthenticationldap.ldap.dn.attributeName.given";
    private static final String PROPERTY_USER_ATTRIBUTE_NAME_EMAIL = "adminauthenticationldap.ldap.dn.attributeName.email";
    private static final String PROPERTY_USER_ATTRIBUTE_GROUP = "adminauthenticationldap.ldap.dn.attributeName.groupMemberOf";
    private static final String PROPERTY_USER_ATTRIBUTE_DN = "adminauthenticationldap.ldap.dn.attributeName.distinguishedName";

    private static final String ATTRIBUTE_ACCESS_CODE = AppPropertiesService.getProperty( PROPERTY_USER_ATTRIBUTE_NAME_ACCESS_CODE );
    private static final String ATTRIBUTE_FAMILY_NAME = AppPropertiesService.getProperty( PROPERTY_USER_ATTRIBUTE_NAME_FAMILY_NAME );
    private static final String ATTRIBUTE_GIVEN_NAME = AppPropertiesService.getProperty( PROPERTY_USER_ATTRIBUTE_NAME_GIVEN_NAME );
    private static final String ATTRIBUTE_EMAIL = AppPropertiesService.getProperty( PROPERTY_USER_ATTRIBUTE_NAME_EMAIL );
    private static final String ATTRIBUTE_GROUP = AppPropertiesService.getProperty( PROPERTY_USER_ATTRIBUTE_GROUP );
    private static final String ATTRIBUTE_DN = AppPropertiesService.getProperty( PROPERTY_USER_ATTRIBUTE_DN );

    private static final String BIND_DN = AppPropertiesService.getProperty( PROPERTY_BIND_DN );
    private static final String BIND_PASSWORD = AppPropertiesService.getProperty( PROPERTY_BIND_PASSWORD );
    private static final String SEARCH_SCOPE = AppPropertiesService.getProperty( PROPERTY_USER_SUBTREE, "false" );
    private static final String SEARCH_FILTER_BY_CRITERIA = AppPropertiesService.getProperty( PROPERTY_USER_DN_SEARCH_FILTER_BY_CRITERIA );
    private static final String SEARCH_FILTER_BY_ACCESS_CODE = AppPropertiesService.getProperty( PROPERTY_USER_DN_SEARCH_FILTER_BY_ACCESS_CODE );
    private static final String INITIAL_CONTEXT_PROVIDER = AppPropertiesService.getProperty( PROPERTY_INITIAL_CONTEXT_PROVIDER );
    private static final String PROVIDER_URL = AppPropertiesService.getProperty( PROPERTY_PROVIDER_URL );
    private static final String USER_DN_SEARCH_BASE = AppPropertiesService.getProperty( PROPERTY_USER_DN_SEARCH_BASE, "" );
    private static final String ROOT_DN_SEARCH_BASE = AppPropertiesService.getProperty( PROPERTY_ROOT_DN_SEARCH_BASE );
    private static final String SEARCH_FILTER_GROUP = AppPropertiesService.getProperty( PROPERTY_USER_DN_SEARCH_GROUP_FILTER );

    // Constant
    private static final String CONSTANT_WILDCARD = "*";

    private LdapService( )
    {
    }

    public static DirContext getAdminContext( )
    {
        return getNewContext( BIND_DN, BIND_PASSWORD );
    }

    public static DirContext getNewContext( String strDN, String strPassword )
    {
        try
        {
            return LdapUtil.getContext( INITIAL_CONTEXT_PROVIDER, PROVIDER_URL, strDN, strPassword );
        }
        catch( Exception e )
        {
            AppLogService.error( "Unable to open a new connection to LDAP to " + PROVIDER_URL, e );
            return null;
        }
    }

    public static void freeContext( DirContext context )
    {
        try
        {
            if ( context != null )
            {
                LdapUtil.freeContext( context );
            }
        }
        catch( NamingException e )
        {
            AppLogService.error( "Unable to free ldap context ", e );
        }
    }

    private static String getUserBindDN( String strAccessCode )
    {
        StringBuilder sb = new StringBuilder( );
        sb.append( ATTRIBUTE_ACCESS_CODE ).append( "=" );
        sb.append( strAccessCode );
        sb.append( "," );
        sb.append( USER_DN_SEARCH_BASE );
        if ( StringUtils.isNotEmpty( ROOT_DN_SEARCH_BASE ) )
        {
            sb.append( "," ).append( ROOT_DN_SEARCH_BASE );
        }

        return sb.toString( );
    }

    public static SearchResult getUserSearchResult( String strId )
    {
        List<SearchResult> srList = getUserSearchResult( 1, getCompleteFilter( SEARCH_FILTER_BY_ACCESS_CODE ), strId );
        if ( srList.size( ) != 1 )
        {
            return null;
        }
        return srList.get( 0 );
    }

    public static AdminUser getAdminUser( String strId )
    {
        return getUserFromSr( getUserSearchResult( strId ) );
    }

    public static AdminUser getUserFromSr( SearchResult sr )
    {
        AdminUser user = null;
        if ( sr != null )
        {
            String strLastName = getSrAttribute( sr, ATTRIBUTE_FAMILY_NAME );
            String strFirstName = getSrAttribute( sr, ATTRIBUTE_GIVEN_NAME );
            String strEmail = getSrAttribute( sr, ATTRIBUTE_EMAIL );
            String strAccessCode = getSrAttribute( sr, ATTRIBUTE_ACCESS_CODE );

            if ( strAccessCode != null && !"".equals( strAccessCode ) )
            {
                user = new AdminUser( );
                user.setAuthenticationService( AdminLdapAuthentication.AUTH_SERVICE_NAME );
                user.setAccessCode( strAccessCode );
                user.setLastName( strLastName );
                user.setFirstName( strFirstName );
                user.setEmail( strEmail );
            }
        }
        return user;
    }

    public static List<SearchResult> getUserSearchResult( String strParameterLastName, String strParameterFirstName, String strParameterEmail )
    {
        return getUserSearchResult( 0, getCompleteFilter( SEARCH_FILTER_BY_CRITERIA ), checkSyntax( strParameterLastName ),
                checkSyntax( strParameterFirstName ), checkSyntax( strParameterEmail ) );
    }

    public static List<AdminUser> getAdminUserSearchResult( String strParameterLastName, String strParameterFirstName, String strParameterEmail )
    {
        List<AdminUser> userList = new ArrayList<>( );

        for ( SearchResult sr : getUserSearchResult( strParameterLastName, strParameterFirstName, strParameterEmail ) )
        {
            AdminUser user = getUserFromSr( sr );
            if ( user != null )
            {
                userList.add( user );
            }
        }
        return userList;
    }

    public static List<SearchResult> getUserSearchResult( int nLimit, String strLdapSearchFilterTmpl, String... lstSearchParameter )
    {
        List<SearchResult> srList = new ArrayList<>( );

        if ( lstSearchParameter != null && lstSearchParameter.length > 0 )
        {

            String strUserSearchFilter = MessageFormat.format( strLdapSearchFilterTmpl, (Object [ ]) lstSearchParameter );

            SearchControls scUserSearchControls = new SearchControls( );
            scUserSearchControls.setSearchScope( getUserDnSearchScope( ) );
            scUserSearchControls.setReturningObjFlag( true );
            scUserSearchControls.setCountLimit( nLimit );

            NamingEnumeration<SearchResult> userResults;
            DirContext context = getAdminContext( );

            try
            {
                userResults = LdapUtil.searchUsers( context, strUserSearchFilter, USER_DN_SEARCH_BASE + "," + ROOT_DN_SEARCH_BASE, "", scUserSearchControls );
                AppLogService.debug( " Search users params  : " + strUserSearchFilter );

                while ( ( userResults != null ) && userResults.hasMore( ) )
                {
                    SearchResult sr = userResults.next( );
                    srList.add( sr );
                }
            }
            catch( NamingException e )
            {
                AppLogService.error( "Error while searching for users  with search filter : " + getDebugInfo( strUserSearchFilter ), e );
            }
            finally
            {
                freeContext( context );
            }

        }
        return srList;
    }

    public static String getSrAttribute( SearchResult sr, String strAttributeName )
    {
        try
        {
            return sr.getAttributes( ).get( strAttributeName ).get( ).toString( );
        }
        catch( NamingException e )
        {
            AppLogService.error( "Error while getting attribute + '" + strAttributeName + "' from ldap.", e );
        }
        return null;
    }

    private static String getDebugInfo( String strUserSearchFilter )
    {
        StringBuilder sb = new StringBuilder( );
        sb.append( "userBase : " );
        sb.append( USER_DN_SEARCH_BASE );
        sb.append( "\nuserSearch : " );
        sb.append( strUserSearchFilter );

        return sb.toString( );
    }

    private static String checkSyntax( String in )
    {
        return ( ( ( in == null ) || ( in.equals( "" ) ) ) ? CONSTANT_WILDCARD : in + CONSTANT_WILDCARD );
    }

    private static String getCompleteFilter( String strFilter )
    {
        StringBuilder sb = new StringBuilder( );
        sb.append( "(&" );
        sb.append( strFilter );
        if ( StringUtils.isNotEmpty( ATTRIBUTE_GROUP ) && StringUtils.isNotEmpty( SEARCH_FILTER_GROUP ) )
        {
            sb.append( "(" ).append( ATTRIBUTE_GROUP ).append( "=" ).append( SEARCH_FILTER_GROUP );
            if ( StringUtils.isNotEmpty( ROOT_DN_SEARCH_BASE ) )
            {
                sb.append( "," ).append( ROOT_DN_SEARCH_BASE );
            }
            sb.append( ")" );
        }
        sb.append( ")" );

        return sb.toString( );
    }

    private static int getUserDnSearchScope( )
    {
        if ( SEARCH_SCOPE.equalsIgnoreCase( "true" ) )
        {
            return SearchControls.SUBTREE_SCOPE;
        }
        return SearchControls.ONELEVEL_SCOPE;
    }

    public static void login( String strAccessCode, String strUserPassword ) throws FailedLoginException
    {
        DirContext context = null;
        try
        {
            SearchResult sr = getUserSearchResult( strAccessCode );
            if ( sr != null )
            {
                context = LdapUtil.bindUser( INITIAL_CONTEXT_PROVIDER, PROVIDER_URL, getSrAttribute( sr, ATTRIBUTE_DN ), strUserPassword );
            }
            else
            {
                throw new FailedLoginException( );
            }
        }
        catch( NamingException e )
        {
            throw new FailedLoginException( );
        }
        finally
        {
            freeContext( context );
        }
    }

}
