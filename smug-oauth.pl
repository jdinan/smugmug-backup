#!/usr/bin/perl

use strict;
use warnings;
no warnings 'once';

require SMBConfig;

use LWP::UserAgent;
use XML::Simple;
use Data::Dumper;
use Digest::SHA qw(hmac_sha1_base64);
use URI::Escape qw(uri_escape);

SMBConfig::open();

my $ua = LWP::UserAgent->new;
our $xml = new XML::Simple;

if ($#ARGV + 1 < 1) {
    print "Usage: $0 auth|check\n";
    exit;
}

if ($ARGV[0] eq "auth") {
    my $oauth_request_token;
    my $oauth_request_token_secret;

    ## Get the request token
    my $params = ""
        . "method=smugmug.auth.getRequestToken"
        . "&oauth_consumer_key=" . uri_escape(SMBConfig::param('auth.oauth_consumer_key'))
        . "&oauth_nonce=" . uri_escape(SMBConfig::param('auth.nonce'))
        . "&oauth_signature_method=HMAC-SHA1"
        . "&oauth_timestamp=" . time
        . "&oauth_version=1.0"
        ;

    my $text = "GET&" . uri_escape("$SMBConfig::api_url") . "&" . uri_escape($params);
    my $key  = SMBConfig::param('auth.oauth_consumer_secret') . "&";
    my $signature = uri_escape(hmac_sha1_base64($text, $key) . "=");
    my $url  = "$SMBConfig::api_url?$params&oauth_signature=$signature";

    my $res = $ua->get("$url");

    if ($res->is_success) {
        my $token = $xml->XMLin($res->content, KeyAttr=>[]);
        print "Please authorize at: $SMBConfig::auth_url"
            . "?oauth_token=$token->{Auth}->{Token}->{id}"
            . "&Access=$SMBConfig::auth_access"
            . "&Permissions=$SMBConfig::auth_permissions\n";
        $oauth_request_token = $token->{Auth}->{Token}->{id};
        $oauth_request_token_secret = $token->{Auth}->{Token}->{Secret};
        print "Press ENTER to continue.\n";
        <STDIN>;
    }
    else {
        die "Unable to request OAuth token";
    }


    ## Get the access token
    $params = ""
        . "method=smugmug.auth.getAccessToken"
        . "&oauth_consumer_key=" . uri_escape(SMBConfig::param('auth.oauth_consumer_key'))
        . "&oauth_nonce=" . uri_escape(SMBConfig::param('auth.nonce'))
        . "&oauth_signature_method=HMAC-SHA1"
        . "&oauth_timestamp=" . time
        . "&oauth_token=" . uri_escape("$oauth_request_token")
        . "&oauth_version=1.0"
        ;

    $text = "GET&" . uri_escape("$SMBConfig::api_url") . "&" . uri_escape($params);
    $key  = SMBConfig::param('auth.oauth_consumer_secret') ."&$oauth_request_token_secret";
    $signature = uri_escape(hmac_sha1_base64($text, $key) . "=");
    $url  = "$SMBConfig::api_url?$params&oauth_signature=$signature";

    $res = $ua->get("$url");

    if ($res->is_success) {
        my $token = $xml->XMLin($res->content, KeyAttr=>[]);
        SMBConfig::param('auth.oauth_token', $token->{Auth}->{Token}->{id});
        SMBConfig::param('auth.oauth_token_secret', $token->{Auth}->{Token}->{Secret});
        SMBConfig::save();
        print "Authentication successful\n";
    }
    else {
        SMBConfig::param('auth.oauth_token', "");
        SMBConfig::param('auth.oauth_token_secret', "");
        SMBConfig::save();
        die "Unable to get access token";
        exit;
    }
}


else {
    ## Perform an authenticated request
    my $params = ""
        . "method=smugmug.auth.checkAccessToken"
        . "&oauth_consumer_key=" . uri_escape(SMBConfig::param('auth.oauth_consumer_key'))
        . "&oauth_nonce=" . uri_escape(SMBConfig::param('auth.nonce'))
        . "&oauth_signature_method=HMAC-SHA1"
        . "&oauth_timestamp=" . time
        . "&oauth_token=" . uri_escape(SMBConfig::param('auth.oauth_token'))
        . "&oauth_version=1.0"
        ;

    my $text = "GET&" . uri_escape("$SMBConfig::api_url") . "&" . uri_escape($params);
    my $key  = SMBConfig::param('auth.oauth_consumer_secret') ."&". SMBConfig::param('auth.oauth_token_secret');
    my $signature = uri_escape(hmac_sha1_base64($text, $key) . "=");
    my $url  = "$SMBConfig::api_url?$params&oauth_signature=$signature";

    my $res = $ua->get("$url");
    die "Request failed" if not $res->is_success;

    my $albums = $xml->XMLin($res->content, KeyAttr=>[]);
    print Dumper($albums);
}
