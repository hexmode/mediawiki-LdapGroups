<?php

namespace LdapGroups;

use GlobalVarConfig;
use MWException;
use User;

class LdapGroups {
	protected $ldap;
	protected $param;
	protected $ldapGroupMap;
	protected $mwGroupMap;

	public function __construct( $param ) {
		wfDebug( __METHOD__ );
		$this->ldap = ldap_connect( $param['server'] );
		if ( !$this->ldap ) {
			throw new MWException( "Error Connecting to LDAP server.!" );
		}
		$this->param = $param;

		ldap_set_option( $this->ldap, LDAP_OPT_REFERRALS, 0 );
		ldap_set_option( $this->ldap, LDAP_OPT_PROTOCOL_VERSION, 3 );
		if ( !ldap_bind( $this->ldap, $this->param['user'],
						 $this->param['pass'] )
		) {
			throw new MWException( "Couldn't bind to LDAP server: " .
								   ldap_error( $this->ldap ) );
		}

		$this->setupGroupMap();
	}

	protected function setupGroupMap() {
		// FIXME: This should be in memcache so it can be dynamically updated
		global $wgLDAPGroupMap;
		$groupMap = $wgLDAPGroupMap;

		global $wgGroupPermissions, $wgAddGroups, $wgRemoveGroups;

		$groups = array_keys( $groupMap );
		$nonLDAPGroups = array_diff( array_keys( $wgGroupPermissions ),
									 $groups );

		foreach( $groupMap as $name => $DNs ) {
			if ( !isset( $wgGroupPermissions[$name] ) ) {
				$wgGroupPermissions[$name] = $wgGroupPermissions['user'];
			}
			foreach ($DNs as $key) {
				$lowLDAP = strtolower( $key );
				$this->mwGroupMap[ $name ][] = $lowLDAP;
				$this->ldapGroupMap[ $lowLDAP ] = $name;
			}
		}

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

	static public function newFromIniFile( $iniFile = null ) {
		if ( !is_readable( $iniFile ) ) {
			throw new MWException( "Can't read $iniFile" );
		}
		$data = parse_ini_file( $iniFile );
		if ( $data === false ) {
			throw new MWException( "Error reading $iniFile" );
		}

		return new LdapGroups( $data );
	}

	protected function doLDAPSearch( $match ) {
		$basedn = $this->param['basedn'];

		wfProfileIn( __METHOD__ . " - LDAP Search" );
		$runTime = -microtime( true );
		$res = ldap_search( $this->ldap, $basedn, $match, [ "*" ] );
		if ( !$res ) {
			wfProfileOut( __METHOD__ );
			throw new MWException( "Error in LDAP search: " .
								   ldap_error( $this->ldap ) );
		}

		$entry = ldap_get_entries( $this->ldap, $res );
		$runTime += microtime( true );
		wfProfileOut( __METHOD__ . " - LDAP Search" );
		wfDebugLog( __CLASS__, "Ran LDAP search in $runTime seconds.\n" );
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

		return $this->ldapData;
	}

	public function mapGroups( User $user ) {
		# Create a list of LDAP groups this person is a member of
		$memberOf = [];
		if ( isset( $this->ldapData['memberof'] ) ) {
			$tmp = array_map( 'strtolower',$this->ldapData['memberof'] );
			unset( $tmp['count'] );
			$memberOf = array_flip( $tmp );
		}

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
				$user->removeGroup( $checkGroup );
			}
		}

		foreach ( $addThese as $group ) {
			$user->addGroup( $group );
		}
	}

	// This hook is probably not the right place.
	static public function loadUser( $user, $email ) {
		// FIXME use config
		global $IP;
		$here = self::newFromIniFile( "$IP/ldap.ini" );

		$here->fetchLDAPData( $user, $email );

		// Make sure user is in the right groups;
		$here->mapGroups( $user );
	}
}
