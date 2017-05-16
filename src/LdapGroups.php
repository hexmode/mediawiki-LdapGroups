<?php
/*
 * Copyright (C) 2017  Mark A. Hershberger
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

namespace LdapGroups;

use GlobalVarConfig;
use ConfigFactory;
use MWException;
use User;

class LdapGroups {
	protected $ldap;
	protected $param;
	protected $ldapGroupMap;
	protected $mwGroupMap;

	public function __construct( $param ) {
		wfDebug( __METHOD__ );
		$this->param = $param;
		$this->setupGroupMap();
	}

	static public function makeConfig() {
		return new GlobalVarConfig( 'LdapGroups' );
	}

	static public function newFromIniFile( $iniFile = null ) {
		if ( !is_readable( $iniFile ) ) {
			throw new MWException( "Can't read '$iniFile'" );
		}
		$data = parse_ini_file( $iniFile );
		if ( $data === false ) {
			throw new MWException( "Error reading '$iniFile'" );
		}

		return new LdapGroups( $data );
	}

	protected function setGroupRestrictions( $groupMap = [] ) {
		global $wgGroupPermissions, $wgAddGroups, $wgRemoveGroups;
		foreach( $groupMap as $name => $DNs ) {
			if ( !isset( $wgGroupPermissions[$name] ) ) {
				$wgGroupPermissions[$name] = $wgGroupPermissions['user'];
			}
		}

		$groups = array_keys( $groupMap );
		$nonLDAPGroups = array_diff( array_keys( $wgGroupPermissions ),
									 $groups );

		// Restrict the ability of users to change these rights
		foreach (
			array_unique( array_keys( $wgGroupPermissions ) ) as $group )
		{
			if ( isset( $wgGroupPermissions[$group]['userrights'] ) &&
				 $wgGroupPermissions[$group]['userrights'] ) {
				$wgGroupPermissions[$group]['userrights'] = false;
				if ( !isset( $wgAddGroups[$group] ) ) {
					$wgAddGroups[$group] = $nonLDAPGroups;
				}
				if ( !isset( $wgRemoveGroups[$group] ) ) {
					$wgRemoveGroups[$group] = $nonLDAPGroups;
				}
			}
		}
	}

	protected function doGroupMapUsingChain( $userDN ) {
		list($cn, $rest) = explode( ",", $userDN );

		foreach( $this->ldapGroupMap as $groupDN => $group ) {
			$entry = $this->doLDAPSearch(
				"(&(objectClass=user)($cn)" .
				"(memberOf:1.2.840.113556.1.4.1941:=$groupDN))" );
			if( $entry[ 'count' ] === 1 ) {
				$this->ldapData['memberof'][] = $groupDN;
			}
		}
	}

	protected function setupGroupMap() {
		$config
			= ConfigFactory::getDefaultInstance()->makeConfig( 'LdapGroups' );
		$groupMap = $config->get("Map");

		foreach( $groupMap as $name => $DNs ) {
			foreach ($DNs as $key) {
				$lowLDAP = strtolower( $key );
				$this->mwGroupMap[ $name ][] = $lowLDAP;
				$this->ldapGroupMap[ $lowLDAP ] = $name;
			}
		}
		$this->setGroupRestrictions( $groupMap );
	}

	protected function setupConnection() {
		$this->ldap = ldap_connect( $this->param['server'] );
		if ( !$this->ldap ) {
			throw new MWException( "Error Connecting to LDAP server!" );
		}
		ldap_set_option( $this->ldap, LDAP_OPT_REFERRALS, 0 );
		ldap_set_option( $this->ldap, LDAP_OPT_PROTOCOL_VERSION, 3 );
		if ( !ldap_bind( $this->ldap, $this->param['user'],
						 $this->param['pass'] )
		) {
			throw new MWException( "Couldn't bind to LDAP server: " .
								   ldap_error( $this->ldap ) );
		}
	}

	protected function doLDAPSearch( $match ) {
		wfProfileIn( __METHOD__ );
		$runTime = -microtime( true );
		$key = wfMemcKey( 'ldapgroups', $match );
		$cache = wfGetMainCache();
		$entry = $cache->get( $key );
		if ( $entry === false ) {
			wfProfileIn( __METHOD__ . " - LDAP Search" );
			if ( !$this->ldap ) {
				$this->setupConnection();
			}

			$res = ldap_search( $this->ldap, $this->param['basedn'],
								$match, [ "*" ] );
			if ( !$res ) {
				wfProfileOut( __METHOD__ . " - LDAP Search" );
				wfProfileOut( __METHOD__ );
				throw new MWException( "Error in LDAP search: " .
									   ldap_error( $this->ldap ) );
			}

			$entry = ldap_get_entries( $this->ldap, $res );
			$cache->set( $key, $entry, 3600 * 24 );

			wfProfileOut( __METHOD__ . " - LDAP Search" );
		}
		wfProfileOut( __METHOD__ );
		$runTime += microtime( true );
		wfDebugLog( __CLASS__, "Ran LDAP search for '$match' in $runTime seconds.\n" );
		return $entry;
	}

	public function fetchLDAPData( User $user ) {
		$email = $user->getEmail();
		if( !$email ) {
			// Fail early
			throw new MWException( "No email found for $user" );
		}

		wfDebug( __METHOD__ . ": Fetching user data for $user from LDAP\n" );
		$entry = $this->doLDAPSearch( $this->param['searchattr'] .
									"=" . $user->getEmail() );

		if ( $entry['count'] === 0 ) {
			wfProfileOut( __METHOD__ );
			throw new MWException( "No user found with the ID: " .
								   $user->getEmail() );
		}
		if ( $entry['count'] !== 1 ) {
			wfProfileOut( __METHOD__ );
			throw new MWException( "More than one user found " .
								   "with the ID: $user" );
		}

		$this->ldapData = $entry[0];
		$config
			= ConfigFactory::getDefaultInstance()->makeConfig( 'LdapGroups' );
		if ( $config->get( "UseMatchingRuleInChainQuery" ) ) {
			$this->doGroupMapUsingChain( $this->ldapData['dn'] );
		}

		return $this->ldapData;
	}

	public function mapGroups( User $user ) {
		# Create a list of LDAP groups this person is a member of
		$memberOf = [];
		if ( isset( $this->ldapData['memberof'] ) ) {
			wfDebugLog( __METHOD__, "memberof: " .var_export( $this->ldapData['memberof'], true ) );
			$tmp = array_map( 'strtolower',$this->ldapData['memberof'] );
			unset( $tmp['count'] );
			$memberOf = array_flip( $tmp );
		}

		wfDebugLog( "In Groups: ", implode( ", ", $user->getGroups() ) );
		# This is a list of LDAP groups that map to MW groups we already have
		$hasControlledGroups = array_intersect( $this->ldapGroupMap,
												$user->getGroups() );

		# This is a list of groups that map to MW groups we do NOT already have
		$notControlledGroups = array_diff( $this->ldapGroupMap,
										   $user->getGroups() );

		# LDAP-mapped MW Groups that should be added because they aren't
		# in the user's list of MW groups
		$addThese = array_keys(
			array_flip( array_intersect_key( $notControlledGroups,
											 $memberOf ) ) );

		# MW Groups that should be removed because the user doesn't have any
		# of LDAP groups
		foreach ( array_keys( $this->mwGroupMap ) as $checkGroup ) {
			$matched = array_intersect( $this->mwGroupMap[$checkGroup],
										array_flip( $memberOf ) );
			if( count( $matched ) === 0 ) {
				wfDebugLog( __METHOD__, "removing: $checkGroup" );
				$user->removeGroup( $checkGroup );
			}
		}

		foreach ( $addThese as $group ) {
			$user->addGroup( $group );
			wfDebugLog( __METHOD__, "Adding: $group" );
		}
		// saving now causes problems.
		#$user->saveSettings();
	}

	// This hook is probably not the right place.
	static public function loadUser( $user, $email ) {
		$config
			= ConfigFactory::getDefaultInstance()->makeConfig( 'LdapGroups' );
		$here = self::newFromIniFile( $config->get("IniFile") );

		$here->fetchLDAPData( $user, $email );

		// Make sure user is in the right groups;
		$here->mapGroups( $user );
	}
}
