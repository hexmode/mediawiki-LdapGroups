<?php

namespace LdapGroups;

class LdapGroups {
	protected $ad;
	protected $param;
	protected $groupMap;

	public function __construct( $param ) {
		wfDebug( __METHOD__ );
		$this->ad = ldap_connect( $param['server'] );
		if ( !$this->ad ) {
			throw new \MWException( "Error Connecting to AD!" );
		}
		$this->param = $param;

		ldap_set_option( $this->ad, LDAP_OPT_REFERRALS, 0 );
		ldap_set_option( $this->ad, LDAP_OPT_PROTOCOL_VERSION, 3 );
		if ( !ldap_bind( $this->ad, $this->param['user'],
						 $this->param['pass'] )
		) {
			throw new \MWException( "Couldn't bind to LDAP server: " .
								   ldap_error( $this->ad ) );
		}

		$this->setupGroupMap();
	}

	protected function setupGroupMap() {
		// FIXME: This should be dynamically loaded
		// key needs to be lower case
		$this->groupMap
            = [ "cn=g00285178,ou=groups,dc=cdiad,dc=ge,dc=com" => "NavAndGuidance",
                "cn=opma_nixusers,ou=security group,dc=cdiad,dc=ge,dc=com" => "NixUsers" ];
	}

	static public function newFromIniFile( $iniFile = null ) {
		if ( !is_readable( $iniFile ) ) {
			throw new \MWException( "Can't read $iniFile" );
		}
		$data = parse_ini_file( $iniFile );
		if ( $data === false ) {
			throw new \MWException( "Error reading $iniFile" );
		}

		return new LdapGroups( $data );
	}

	protected function doADSearch( $match, $search = null ) {
		if ( $search === null ) {
			$search = $this->param['searchattr'] . "=";
		}
		$basedn = $this->param['basedn'];

		wfProfileIn( __METHOD__ . " - AD Search" );
		$runTime = -microtime( true );
		$res = ldap_search(
			$this->ad,
			$basedn,
			"$search$match",
			[ "*" ]
		);
		if ( !$res ) {
			wfProfileOut( __METHOD__ );
			throw new \MWException( "Error in AD search: " .
								   ldap_error( $this->ad ) );
		}

		$entry = ldap_get_entries( $this->ad, $res );
		$runTime += microtime( true );
		wfProfileOut( __METHOD__ . " - AD Search" );
		wfDebugLog( __CLASS__, "Ran AD search in $runTime seconds.\n" );
		return $entry;
	}

	public function fetchADData( \User $user ) {
		wfDebug( __METHOD__ . ": Fetching user data for $user from AD\n" );
		$entry = $this->doADSearch( 'Mark.Hershberger@ge.com' );

		if ( $entry['count'] === 0 ) {
			wfProfileOut( __METHOD__ );
			throw new \MWException( "No user found with the ID: " . $user->getEmail() );
		}
		if ( $entry['count'] !== 1 ) {
			wfProfileOut( __METHOD__ );
			throw new \MWException( "More than one user found " .
								   "with the ID: $user" );
		}

		$this->adData = $entry[0];

		return $this->adData;
	}

	public function mapGroups( \User $user ) {
		$groups = [];
		if ( isset( $this->adData['memberof'] ) ) {
			$groups = array_flip(
                array_map(
                    function ($g) {
                        return strtolower( $g );
                    }, array_values( $this->adData['memberof'] ) ) );
		}

		$inGroups = array_flip( $user->getGroups() );
		foreach ( $this->groupMap as $ADGroup => $MWGroup ) {
			if ( isset( $groups[ $ADGroup ] ) && !isset( $inGroups[ $MWGroup ] )  ) {
				wfDebugLog( __METHOD__, "Adding $user to $MWGroup" );
				$user->addGroup( $MWGroup );
                $user->saveSettings();
			} else if ( !isset( $groups[ $ADGroup ] ) && isset( $inGroups[ $MWGroup ] )  ) {
				wfDebugLog( __METHOD__, "Removing $user from $MWGroup" );
				$user->removeGroup( $MWGroup );
                $user->saveSettings();
			}
		}
	}

	// This hook is probably not the right place.
	static public function loadUser( $user, $email ) {
		// FIXME use config
        global $IP;
		$here = self::newFromIniFile( "$IP/ldap.ini" );

		$here->fetchADData( $user, $email );

		// Make sure user is in the right groups;
		$here->mapGroups( $user );
	}
}

