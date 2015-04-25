#!/usr/bin/perl

use strict;
use warnings;
no warnings 'once';

use lib "/home/jdinan/projects/smug-bak";
require "SMBConfig.pm";

use LWP::Simple;
use LWP::UserAgent;
use XML::Simple;
use Data::Dumper;
use File::Path qw(make_path);
use File::Slurp qw(read_file read_dir);
use Digest::SHA qw(hmac_sha1_base64);
use URI::Escape qw(uri_escape);
use String::Random qw( random_string );
use MIME::Base64 qw( encode_base64 );
use Digest::MD5;

SMBConfig::open();

my $upload_url  = "http://upload.smugmug.com/";
my $warn_exists = 0;
my $no_upload   = 1;
my $nuploaded   = 0;

$| = 1; # Don't buffer STDOUT

################################################################################
## UTILITY ROUTINES
################################################################################

##
## Ensure that the reference passed in corresponds to an array.  If not,
## it's a single item, so return it as an array containing itself.
##
sub ensure_array {
    my ($i) = @_;

    if (ref $i ne 'ARRAY') {
        return [ $i ];
    } else {
        return $i;
    }
}

################################################################################
## FETCH/UPLOAD CONTENT
################################################################################
my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 2 }, agent => "$SMBConfig::user_agent");
my $xml = new XML::Simple;
my $nonce;
my $timestamp = 0;

##
## Ensure that nonce and timestamp are fresh
##
sub ensure_nonce {
    # If we are issuing more than one request per second, we need to generate a
    # new nonce.  Because the nonce is random, it's possible (but unlikely) for
    # us to generate the same one again.  But that doesn't matter if the
    # timestamp has advanced
    #lock $nonce;
    #lock $timestamp;
    if (!$timestamp) {
        $nonce = encode_base64( random_string('.' x 20), '' );
    }

    my $last_nonce = $nonce;
    my $last_timestamp = $timestamp;
    $timestamp = time;
    while ($last_timestamp == $timestamp and $last_nonce eq $nonce) {
        $nonce = encode_base64( random_string('.' x 20), '' );
        $timestamp = time;
    }
}


##
## Request someting from SmugMug
##  $url -- URL fragment
##
sub smug_req {
    my $args = "";
    my $url;
    my $auth_method = SMBConfig::param('auth.method');

    ensure_nonce();

    my @arglist = @_;

    # Push additional args into the request
    if ($auth_method eq "anonymous") {
        push @arglist, "APIKey=". SMBConfig::param("smugmug.api_key");
    }
    elsif ($auth_method eq "site") {
        push @arglist, "APIKey=" . SMBConfig::param("smugmug.api_key");
        push @arglist, "NickName=" . SMBConfig::param("smugmug.nickname");
        push @arglist, "SitePassword=" . SMBConfig::param("auth.site_pass");
    }
    elsif ($auth_method eq "oauth") {
        push @arglist, "oauth_consumer_key=" . uri_escape(SMBConfig::param('auth.oauth_consumer_key'));
        push @arglist, "oauth_nonce=" . uri_escape($nonce);
        push @arglist, "oauth_signature_method=HMAC-SHA1";
        push @arglist, "oauth_timestamp=" . $timestamp;
        push @arglist, "oauth_token=" . uri_escape(SMBConfig::param('auth.oauth_token'));
        push @arglist, "oauth_version=1.0";
    }
    else {
        die "Unrecognized auth.method '$auth_method'";
    }

    # Sort the arguments, required for OAuth
    my $first_arg = 1;
    foreach my $arg (sort @arglist) {
        if ($first_arg) {
            $args .= "$arg";
            $first_arg = 0;
        } else {
            $args .= "&$arg";
        }
    }

    # Generate the URL
    if ($auth_method eq "oauth") {
        my $text = "GET&" . uri_escape("$SMBConfig::api_url") . "&" . uri_escape($args);
        my $key  = SMBConfig::param('auth.oauth_consumer_secret') ."&". SMBConfig::param('auth.oauth_token_secret');
        my $sig  = uri_escape(hmac_sha1_base64($text, $key) . "=");
        $url     = "$SMBConfig::api_url?$args&oauth_signature=$sig";
    }
    else {
        $url = "$SMBConfig::api_url?$args";
    }

    my $res = $ua->get($url);
    if (not $res->is_success) {
        print "Smug request error:\n";
        print Dumper( $res->status_line );
        print "Request was: $url\n";
        #print "Retrying ...\n";
        #return smug_req(@_);
        die;
    }
    my $resp = $xml->XMLin($res->content, KeyAttr=>[]);

    if ( $resp->{stat} ne "ok" ) {
        print ( Dumper $resp );
        die;
    }

    return $resp;
}


##
## Upload a file
##   $filename -- Filename for the output file
##
sub upload_file {
    my ($file, $filename, $album_id) = @_;
    my $skip = 0;
    my $url = "$upload_url";

    ensure_nonce();
    print "  + Uploading: $filename\n";

    return unless not $no_upload;

    my $imgdata = read_file($file, binmode => ":raw");

    my $ctx = Digest::MD5->new;
    $ctx->add("$imgdata");
    my $md5sum = uri_escape($ctx->hexdigest);

    my $key, my $sig, my $auth, my $text, my $res;
    $auth = ""
        . "oauth_consumer_key=\"". uri_escape(SMBConfig::param('auth.oauth_consumer_key')) ."\","
        . "oauth_nonce=\"". uri_escape($nonce) ."\","
        . "oauth_signature_method=\"HMAC-SHA1\","
        . "oauth_timestamp=\"". $timestamp ."\","
        . "oauth_token=\"". uri_escape(SMBConfig::param('auth.oauth_token')) ."\","
        . "oauth_version=\"1.0\""
        ;

    $text = ""
        . "oauth_consumer_key=" . uri_escape(SMBConfig::param('auth.oauth_consumer_key'))
        . "&oauth_nonce=" . uri_escape($nonce)
        . "&oauth_signature_method=HMAC-SHA1"
        . "&oauth_timestamp=" . $timestamp
        . "&oauth_token=" . uri_escape(SMBConfig::param('auth.oauth_token'))
        . "&oauth_version=1.0"
        ;

    $text  = "POST&" . uri_escape("$url") . "&" . uri_escape($text);
    $key   = SMBConfig::param('auth.oauth_consumer_secret') ."&". SMBConfig::param('auth.oauth_token_secret');
    $sig   = uri_escape(hmac_sha1_base64($text, $key) . "=");
    $auth  = "OAuth realm=\"$url\",$auth,oauth_signature=\"$sig\"";

    ## Request the file using the authorization header method
    $res = $ua->post($url,
        Authorization => $auth,
        'X-Smug-AlbumID' => $album_id,
        'X-Smug-Version' => "1.3.0",
        'X-Smug-FileName' => "$filename",
        'Content-MD5' => $md5sum,
        Content => $imgdata);

    if ($res->is_success) {
        ## TODO: Need to check for error messages in the response
        # print Dumper($res->content);
        # print "Success\n";
    } else {
        print Dumper($res);
        die "Error uploading $url -> $filename";
    }

    $nuploaded++;
}

################################################################################
## BEGIN MAIN
################################################################################

if ( @ARGV != 1 ) {
    print "Usage: $0 <category name>\n";
    exit;
}

my $cat_name = $ARGV[0];
my $cat_id = -1;

## Look up the ID for the given parent category
my $cats = smug_req("method=smugmug.categories.get"); 
$cats->{Categories}->{Category} = ensure_array($cats->{Categories}->{Category});

foreach my $cat (@{ $cats->{Categories}->{Category} }) {
    if ($cat->{Name} eq $cat_name) {
        $cat_id = $cat->{id};
        print "Found category '$cat_name' ID $cat_id\n";
        last;
    }
}

die "Could not find category '$cat_name'\n" unless $cat_id >= 0;

## Build the hash of albums
our $albums = smug_req("method=smugmug.albums.get");
$albums->{Albums}->{Album} = ensure_array($albums->{Albums}->{Album});

## For each directory, create an album and upload the files
my @dirs = read_dir ".";

for my $dir ( @dirs ) {
    my $album_id = -1;
    my $album_key = "";

    # Skip ., .., and hidden directories
    if ($dir =~ /^\./) { next; }

    if (not -d $dir) {
        print "Warning: skipping non-album '$dir'\n";
        next;
    }

    ## Check whether the album exists
    foreach my $album (@{ $albums->{Albums}->{Album} }) {
        if ($album->{Title} eq $dir) {
            # print "Found album '$dir' ID $album->{id}\n";
            if ($album->{Category}->{id} != $cat_id) {
                print " - Warning: Categories don't match. Expected $cat_id, got $album->{Category}->{id} ($album->{Category}->{Name})\n";
            }
            $album_id = $album->{id};
            $album_key = $album->{Key};
            last;
        }
    }

    ## If not, create it
    if ($album_id == -1) {
        my $album_resp = smug_req("method=smugmug.albums.create", "Title=" . uri_escape($dir), "CategoryID=$cat_id",
                                    "SortMethod=DateTimeOriginal");
        $album_id = $album_resp->{Album}->{id};
        $album_key = $album_resp->{Album}->{Key};
        print "Created album '$dir'\n";

        # Fetch the updated album hash
        $albums = smug_req("method=smugmug.albums.get");
        $albums->{Albums}->{Album} = ensure_array($albums->{Albums}->{Album});
    }

    print " + Album: $dir, Id: $album_id\n";

    ## Build a hash of MD5 sums for all images already in the album
    my $images = {};
    my $image_list = smug_req("method=smugmug.images.get", "AlbumID=$album_id", "AlbumKey=$album_key");

    if ( exists $image_list->{Album}->{Images}->{Image} ) {
        $image_list->{Album}->{Images}->{Image} = ensure_array($image_list->{Album}->{Images}->{Image});
        foreach my $image (@{ $image_list->{Album}->{Images}->{Image} }) {
            my $image_info = smug_req("method=smugmug.images.getInfo", "ImageID=$image->{id}", "ImageKey=$image->{Key}");
            if ( exists $images->{$image_info->{Image}->{FileName}} ) {
                if ( $images->{$image_info->{Image}->{FileName}} eq $image_info->{Image}->{MD5Sum} ) {
                    print "  - Warning: Repeat instance of file '$image_info->{Image}->{FileName}' (IDENTICAL) \n";
                } else {
                    print "  - Warning: Repeat instance of file '$image_info->{Image}->{FileName}' (DIFFERENT) \n";
                }
            }
            $images->{$image_info->{Image}->{FileName}} = $image_info->{Image}->{MD5Sum};
        }
    }

    my @files = read_dir "$dir";

    ## Upload all media files in the directory
    for my $filename ( @files ) {
        my $file = "$dir/$filename";

        if (-f $file and ($filename =~ /\.jpe?g$/i or $filename =~ /\.avi/i or $filename =~ /\.mpe?g/i or $filename =~ /\.png$/i)) {
            # Avoid uploading duplicates and warn if a different file with the
            # same name exists
            if ( exists $images->{$filename} ) {
                my $imgdata = read_file($file, binmode => ":raw");
                my $ctx = Digest::MD5->new;
                $ctx->add("$imgdata");
                my $md5sum = uri_escape($ctx->hexdigest);

                if ( $images->{$filename} ne $md5sum and $warn_exists ) {
                    print "  * Warning: '$filename' skipped; file exists already and differs ($images->{$filename} ne $md5sum)\n";
                }
            }
            else {
                upload_file($file, $filename, $album_id);
            }
        }
        elsif ( -d $file and $filename eq "tn" ) {
            # Do nothing
        }
        elsif ( -d $file ) {
            print "  -> Pushing sub-album '$file' to the list of albums\n";
            push @dirs, "$file";
        }
        elsif ( $filename =~ /\.html?$/ or $filename eq "album.conf" ) {
            # Do nothing
        }
        else {
            print "  - Warning: Skipping '$file'\n";
        }
    }
}

print "Done -- Uploaded $nuploaded files.\n";
