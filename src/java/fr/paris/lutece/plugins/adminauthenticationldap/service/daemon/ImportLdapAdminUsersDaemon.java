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
package fr.paris.lutece.plugins.adminauthenticationldap.service.daemon;

import fr.paris.lutece.plugins.adminauthenticationldap.AdminLdapAuthentication;
import fr.paris.lutece.plugins.adminauthenticationldap.service.LdapService;
import fr.paris.lutece.portal.business.user.AdminUser;
import fr.paris.lutece.portal.business.user.AdminUserHome;
import fr.paris.lutece.portal.service.daemon.Daemon;
import fr.paris.lutece.portal.service.i18n.I18nService;
import fr.paris.lutece.portal.service.util.AppLogService;

import java.util.Locale;

public class ImportLdapAdminUsersDaemon extends Daemon
{

    private static final String MESSAGE_USER_CREATED = "adminauthenticationldap.user.created";
    private static final String MESSAGE_USER_UPDATED = "adminauthenticationldap.user.updated";

    @Override
    public void run( )
    {
        setLastRunLogs( UpdateAdminUsers( ) );
    }

    private String UpdateAdminUsers( )
    {
        StringBuilder sb = new StringBuilder( );

        for ( AdminUser userLdap : LdapService.getAdminUserSearchResult( "", "", "" ) )
        {
            AdminUser userDb = AdminUserHome.findUserByLogin( userLdap.getAccessCode( ) );
            if ( userDb == null )
            {
                AdminUserHome.create( userLdap );
                addDaemonLog( sb, MESSAGE_USER_CREATED, userLdap.getAccessCode( ) );
            }
            else
            {
                if ( userDb.isStatusActive() && AdminLdapAuthentication.COMPARATOR_USER.compare( userDb, userLdap ) != 0 )
                {
                    userDb.setEmail( userLdap.getEmail( ) );
                    userDb.setFirstName( userLdap.getFirstName( ) );
                    userDb.setLastName( userLdap.getLastName( ) );
                    AdminUserHome.update( userDb );
                    addDaemonLog( sb, MESSAGE_USER_UPDATED, userLdap.getAccessCode( ) );
                }
            }
        }

        return sb.toString( );
    }

    private void addDaemonLog( StringBuilder sb, String strMessageKey, String... args )
    {
        String strMessage = I18nService.getLocalizedString( strMessageKey, args, I18nService.getDefaultLocale( ) );
        sb.append( "\n" ).append( strMessage );
        AppLogService.info( strMessage );
    }

}
