#!/usr/bin/perl

package SMBConfig;

use strict;
use warnings;
use Exporter;
use Config::Simple;
use Data::Dumper;
use File::HomeDir;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

$VERSION     = 1.00;
@ISA         = qw(Exporter);
@EXPORT      = ( );
@EXPORT_OK   = qw(open param close);
%EXPORT_TAGS = ( DEFAULT => [qw(&open &param &close)] );

our $cfg_filename       = File::HomeDir->my_home . "/.smug-bak";
our $user_agent         = "smugbak/0.2";
our $api_url            = "https://api.smugmug.com/services/api/rest/1.3.0/";
our $auth_url           = "http://api.smugmug.com/services/oauth/authorize.mg";
our $auth_access        = "Full";
our $auth_permissions   = "Read";

our $cfg;

sub open {
    if (! -e $cfg_filename ) {
        my $new_cfg = new Config::Simple(syntax=>'ini');

        $new_cfg->param("smugmug.api_key", "");
        $new_cfg->param("smugmug.nickname", "");

        $new_cfg->param("backup.directory", File::HomeDir->my_home . "/smug-bak");
        $new_cfg->param("backup.last_timestamp", "0");
        $new_cfg->param("backup.overwrite", "1");
        $new_cfg->param("backup.verbose", "0");

        $new_cfg->param("auth.method", "anonymous");
        $new_cfg->param("auth.site_pass", "");
        $new_cfg->param("auth.oauth_consumer_key", "");
        $new_cfg->param("auth.oauth_consumer_secret", "");
        $new_cfg->param("auth.oauth_token", "");
        $new_cfg->param("auth.oauth_token_secret", "");

        $new_cfg->write("$cfg_filename") or
            die "Could not create config file ($cfg_filename)";
        chmod 0600, $cfg_filename;

        print "Created default configuration file: $cfg_filename\n";
        print "Please update this file with your settings and re-run.\n";
        exit;
    }

    $cfg = new Config::Simple("$cfg_filename");
}

sub param {
    return $cfg->param(@_);
}

sub save {
    $cfg->save or die "Could not write config file ($cfg_filename)";
}

1;
