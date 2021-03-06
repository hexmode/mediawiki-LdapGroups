<?php

/**
 * Extension for syncing MediaWiki groups with a directory server's groups.
 *
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
	static private $lg;

	/**
	 * Constructor for LdapGroups
	 * @param string $param extension
	 */
	public function __construct( $param ) {
		wfDebug( __METHOD__ );
		$this->param = $param;
		$this->setupGroupMap();
	}

	/**
	 * Get the config accessor
	 * @return GlobalVarConfig
	 */
	public static function makeConfig() {
		return new GlobalVarConfig( 'LdapGroups' );
	}

	/**
	 * The ini constructor
	 * @param string $iniFile to read from for old style mapping.
	 * @return LdapGroups
	 * @throws MWException
	 */
	public static function newFromIniFile( $iniFile ) {
		if ( self::$lg ) {
			return self::$lg;
		}

		if ( !$iniFile ) {
			$config
				= ConfigFactory::getDefaultInstance()
				->makeConfig( 'LdapGroups' );
			$iniFile = $config->get( "IniFile" );
		}

		if ( !is_readable( $iniFile ) ) {
			throw new MWException( "Can't read '$iniFile'" );
		}
		$data = parse_ini_file( $iniFile );
		if ( $data === false ) {
			throw new MWException( "Error reading '$iniFile'" );
		}

		return new LdapGroups( $data );
	}

	/**
	 * Shortcut for self::neFromIniFile()
	 * @return LdapGroups
	 * @throws MWException
	 */
	public static function init() {
		self::newFromIniFile();
	}

	/**
	 * Restrict what can be done with these groups on
	 * Special:UserRights
	 * @param array $groupMap The map
	 */
	protected function setGroupRestrictions( array $groupMap = [] ) {
		global $wgGroupPermissions, $wgAddGroups, $wgRemoveGroups;
		foreach ( $groupMap as $name => $DNs ) {
			if ( !isset( $wgGroupPermissions[$name] ) ) {
				$wgGroupPermissions[$name] = $wgGroupPermissions['user'];
			}
		}

		$groups = array_keys( $groupMap );
		$nonLDAPGroups = array_diff( array_keys( $wgGroupPermissions ),
									 $groups );

		// Restrict the ability of users to change these rights
		foreach (
			array_unique( array_keys( $wgGroupPermissions ) ) as $group
		) {
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

	/**
	 * Set up a group map for the user using chained groups.
	 * See http://ldapwiki.com/wiki/1.2.840.113556.1.4.1941
	 * @param User $user to map
	 * @param string $userDN the DN for the user
	 */
	protected function doGroupMapUsingChain( User $user, $userDN ) {
		list( $cn, $rest ) = explode( ",", $userDN );

		foreach ( $this->ldapGroupMap as $groupDN => $group ) {
			$entry = $this->doLDAPSearch(
				"(&(objectClass=user)($cn)" .
				"(memberOf:1.2.840.113556.1.4.1941:=$groupDN))" );
			if ( $entry[ 'count' ] === 1 ) {
				$this->addMemberof( $user, $groupDN );
			}
		}
	}

	/**
	 * Global Maps
	 *
	 * @return array of mapping
	 */
	protected function setupGroupMap() {
		$config
			= ConfigFactory::getDefaultInstance()->makeConfig( 'LdapGroups' );
		$groupMap = $config->get( "Map" );

		foreach ( $groupMap as $name => $DNs ) {
			foreach ( $DNs as $key ) {
				$lowLDAP = strtolower( $key );
				$this->mwGroupMap[ $name ][] = $lowLDAP;
				$this->ldapGroupMap[ $lowLDAP ] = $name;
			}
		}
		$this->setGroupRestrictions( $groupMap );
		return $groupMap;
	}

	/**
	 * Set up the connection
	 * @throw MWException
	 */
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

	/**
	 * Do a search
	 * @param string $match ldap match
	 * @return array array with results
	 * @throw MWException
	 */
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
		wfDebugLog(
			__CLASS__, "Ran LDAP search for '$match' in $runTime seconds.\n"
		);
		return $entry;
	}

	/**
	 * Get the LDAP data for the user
	 * @param User $user the user
	 * @return array data for this user
	 * @throw MWException
	 */
	public function getLDAPData( User $user ) {
		if ( !isset( $this->ldapData[ $user->getId() ] ) ) {
			$email = $user->getEmail();
			if ( !$email ) {
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

			$this->ldapData[ $user->getId() ] = $entry[0];
			$config
				= ConfigFactory::getDefaultInstance()->makeConfig( 'LdapGroups' );
			if ( $config->get( "UseMatchingRuleInChainQuery" ) ) {
				$this->doGroupMapUsingChain(
					$user, $this->ldapData[ $user->getId() ]['dn']
				);
			}

		}
		return $this->ldapData[ $user->getId() ];
	}

	/**
	 * Convenience function to add user to a group from the extended queries
	 *
	 * @param User $user to add to
	 * @param string $groupDN that the user
	 */
	protected function addMemberof( User $user, $groupDN ) {
		$this->ldapData[ $user->getId() ]['memberof'][] = $groupDN;
	}

	protected function getLdapMemberships( User $user ) {
		$memberof = [];
		$ldapData = $this->getLDAPData( $user );
		if ( isset( $ldapData['memberof'] ) ) {
			wfDebugLog(
				__METHOD__, "memberof: " .
				var_export( $ldapData['memberof'], true )
			);
			$tmp = array_map( 'strtolower', $ldapData['memberof'] );
			unset( $tmp['count'] );
#			$memberof = array_flip( $tmp );
			$memberof = $tmp;
		}
		return $memberof;
	}

	public function getGroups( User $user ) {
		$memberof = $this->getLdapMemberships( $user );
		$groups = [];
		foreach ( $memberof as $groupDn ) {
			if ( isset( $this->ldapGroupMap[ $groupDn ] ) ) {
				$groups[ $this->ldapGroupMap[ $groupDn ] ] = true;
			}
		}
		return array_keys( $groups );
	}

	protected function alreadyInControlledGroups( User $user ) {
		return array_intersect( $this->ldapGroupMap, $user->getGroups() );
	}

	protected function notInControlledGroups( User $user ) {
		return array_diff( $this->ldapGroupMap, $user->getGroups() );
	}

	protected function addControlledGroups( $memberOf, $notInControlledGroups ) {
		return array_keys( array_flip(
			array_intersect_key( $notInControlledGroups, $memberOf )
		) );
	}

	/**
	 * Map this user's MW groups based on its LDAP groups
	 * @param User $user to map
	 */
	public function mapGroups( User $user ) {
		# Create a list of LDAP groups this person is a member of
		$memberOf = [];
		if ( isset( $this->ldapData['memberof'] ) ) {
			wfDebugLog(
				__METHOD__, "memberof: "
				. var_export( $this->ldapData['memberof'], true )
			);
			$tmp = array_map( 'strtolower', $this->ldapData['memberof'] );
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
			if ( count( $matched ) === 0 ) {
				wfDebugLog( __METHOD__, "removing: $checkGroup" );
				$user->removeGroup( $checkGroup );
			}
		}

		foreach ( $ldapGroups as $in ) {
			if ( !in_array( $in, $groups ) ) {
				$user->addGroup( $in );
			}
		}
	}
}
