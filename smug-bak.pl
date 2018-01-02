#!/usr/bin/perl

use strict;
use warnings;
no warnings 'once';

use threads;
use threads::shared;

require SMBConfig;

use LWP::Simple;
use LWP::UserAgent;
use XML::Simple;
use Data::Dumper;
use File::Path qw(make_path);
use Digest::SHA qw(hmac_sha1_base64);
use URI::Escape qw(uri_escape);
use String::Random qw( random_string );
use MIME::Base64 qw( encode_base64 );
use Digest::MD5;

SMBConfig::open();

## Global Variables
our $tid = 0;
our $nfetched :shared = 0;
our $start_time = time;
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
## THE CATEGORY UNMANGLER
################################################################################
our $cat_dict;

##
## Build up the category->path unmangler
##
sub unmangle_cats {
    print "Building categories -> directories unmangler ...\n";
    my $cats = smug_req("method=smugmug.categories.get"); 

    $cats->{Categories}->{Category} = ensure_array($cats->{Categories}->{Category});

    ## Build up the categories tree, starting with cats and recurse on subcats
    foreach my $cat (@{ $cats->{Categories}->{Category} }) {
        $cat_dict->{$cat->{id}}->{Name} = "$cat->{Name}";
        $cat_dict->{$cat->{id}}->{Parent} = "";
        add_subcats($cat->{id}, 0);
    }
}


##
## Recursively add subcategories to the tree
##  $id    -- ID number of the category
##  $depth -- Depth in the tree
##
sub add_subcats {
    my ($id, $depth) = @_;

    my $subcats = smug_req("method=smugmug.subcategories.get", "CategoryID=$id");

    return unless exists $subcats->{SubCategories}->{SubCategory};
    $subcats->{SubCategories}->{SubCategory} = ensure_array($subcats->{SubCategories}->{SubCategory});

    foreach my $subcat (@{ $subcats->{SubCategories}->{SubCategory} }) {
        if (! exists $cat_dict->{$subcat->{id}} || $cat_dict->{$subcat->{id}}->{Depth} < $depth) {
            $cat_dict->{$subcat->{id}}->{Name} = $subcat->{Name};
            $cat_dict->{$subcat->{id}}->{Parent} = $id;
            $cat_dict->{$subcat->{id}}->{Depth} = $depth;
        }
        add_subcats($subcat->{id}, $depth+1);
    }
}


##
## Convert a category/subcatetory into a directory path
##  $id -- ID number of the category
##
sub cat_to_path {
    my ($id) = @_;
    my $path = "";

    while ($id ne "") {
        $path = "$cat_dict->{$id}->{Name}/$path";
        $id = $cat_dict->{$id}->{Parent};
    }

    return $path;
}

################################################################################
## FETCH CONTENT
################################################################################
our $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 2 }, agent => "$SMBConfig::user_agent");
our $xml = new XML::Simple;
our $nonce;
our $timestamp = 0;

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
        $nonce = encode_base64( sprintf("%03d", $tid) . random_string('.' x 17), '' );
    }

    my $last_nonce = $nonce;
    my $last_timestamp = $timestamp;
    $timestamp = time;
    while ($last_timestamp == $timestamp and $last_nonce eq $nonce) {
        $nonce = encode_base64( sprintf("%03d", $tid) . random_string('.' x 17), '' );
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

    # Push additional args into the request
    if ($auth_method eq "anonymous") {
        push @_, "APIKey=". SMBConfig::param("smugmug.api_key");
    }
    elsif ($auth_method eq "site") {
        push @_, "APIKey=" . SMBConfig::param("smugmug.api_key");
        push @_, "NickName=" . SMBConfig::param("smugmug.nickname");
        push @_, "SitePassword=" . SMBConfig::param("auth.site_pass");
    }
    elsif ($auth_method eq "oauth") {
        push @_, "oauth_consumer_key=" . uri_escape(SMBConfig::param('auth.oauth_consumer_key'));
        push @_, "oauth_nonce=" . uri_escape($nonce);
        push @_, "oauth_signature_method=HMAC-SHA1";
        push @_, "oauth_timestamp=" . $timestamp;
        push @_, "oauth_token=" . uri_escape(SMBConfig::param('auth.oauth_token'));
        push @_, "oauth_version=1.0";
    }
    else {
        die "Unrecognized auth.method '$auth_method'";
    }

    # Sort the arguments, required for OAuth
    my $first_arg = 1;
    foreach my $arg (sort @_) {
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
    die $res->status_line unless ($res->is_success);
    my $resp = $xml->XMLin($res->content, KeyAttr=>[]);

    if ( $resp->{stat} ne "ok" ) {
        print ( Dumper $resp );
        die;
    }

    return $resp;

}


##
## Fetch an "image" object (may contain video)
##  $id  -- Image ID
##  $key -- Image Key
##  $dir -- Directory in which to store file
##
sub fetch_image {
    my ( $id, $key, $dir ) = @_;
    my $was_video = 0;

    my $image_info = smug_req("method=smugmug.images.getInfo", "ImageID=$id", "ImageKey=$key");
    (my $filename_base = $image_info->{Image}->{FileName}) =~ s/\.[^.]+$//;
    my $md5 = defined $image_info->{Image}->{MD5Sum} ? $image_info->{Image}->{MD5Sum} : "";

    ## Fetch video, if there is any
    foreach my $res ( "320", "640", "960", "1280", "1920" ) {
        my $file = "Video${res}URL";

        if (defined $image_info->{Image}->{$file}) {
            my $filename_ext = substr $image_info->{Image}->{$file}, rindex($image_info->{Image}->{$file}, '.') + 1;
            my $filename = "$filename_base-$res.$filename_ext";

            # Note: videos don't have MD5 sums
            fetch_file($image_info->{Image}->{$file}, "$dir/$filename", "");
            $was_video = 1;
        }
    }

    ## Fetch the Original.  If this was video, the Original is a JPG image.
    my $filename = $was_video ? "$filename_base.jpg" : $image_info->{Image}->{FileName};
    fetch_file($image_info->{Image}->{OriginalURL}, "$dir/$filename", $md5);
}


##
## Download a file
##   $url -- URL for the file
##   $filename -- Filename for the output file
##
sub fetch_file {
    my ($url, $filename, $md5) = @_;
    my $skip = 0;

    ensure_nonce();

    if (-e "$filename") {
        if ($md5 and SMBConfig::param("backup.use_md5")) {
            my $ctx = Digest::MD5->new;
            open (my $fh, '<', "$filename") or die "Can't open '$filename': $!";
            binmode ($fh);
            $ctx->addfile($fh);
            $skip = $ctx->hexdigest eq $md5;
            close $fh;
            printf("%2d:  * Updating: $filename\n", $tid) if (!$skip and SMBConfig::param("backup.verbose"));
        }
        elsif (SMBConfig::param("backup.skip_existing")) {
            $skip = 1;
        }
    }

    if ($skip) {
        printf("%2d:  - Skipping: $filename\n", $tid) if SMBConfig::param("backup.verbose") > 1;
    }
    elsif (SMBConfig::param('auth.method') eq "oauth") {
        my $key, my $sig, my $auth, my $text, my $res, my $imgfile;
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

        $text  = "GET&" . uri_escape("$url") . "&" . uri_escape($text);
        $key   = SMBConfig::param('auth.oauth_consumer_secret') ."&". SMBConfig::param('auth.oauth_token_secret');
        $sig   = uri_escape(hmac_sha1_base64($text, $key) . "=");
        $auth  = "OAuth realm=\"$url\",$auth,oauth_signature=\"$sig\"";

        printf("%2d:  + Fetching: $filename\n", $tid) if (SMBConfig::param("backup.verbose"));

        ## Request the file using the authorization header method
        $res = $ua->get($url, Authorization => $auth);
        if ($res->is_success) {
            open($imgfile, ">:raw", "$filename") or die "Cannot open '$imgfile': $!";
            binmode $imgfile;
            print $imgfile $res->decoded_content( charset => 'none' );
            close $imgfile;
            lock $nfetched;
            ++$nfetched;
        } else {
            print Dumper($res);
            die "Error downloading $url -> $filename";
        }
    }
    else {
        printf("%2d:    * Fetching: $filename\n", $tid) if (SMBConfig::param("backup.verbose"));
        getstore($url, "$filename") or die "Error downloading $url -> $filename";
        lock $nfetched;
        ++$nfetched;
    }
}

################################################################################
## PROCESSING FUNCTIONS
################################################################################

sub process_album {
    my ($album) = @_;
    my $dir = SMBConfig::param("backup.directory");

    if (exists $album->{SubCategory}) {
        $dir .= "/" . cat_to_path($album->{SubCategory}->{id}) . $album->{Title};
    } else {
        $dir .= "/" . cat_to_path($album->{Category}->{id}) . $album->{Title};
    }

    printf("%2d: Album: $dir\n", $tid);
    ## FIXME: This probably needs a lock
    make_path "$dir" unless (-d "$dir");

    my $images = smug_req("method=smugmug.images.get", "AlbumID=$album->{id}",
            "AlbumKey=$album->{Key}", "LastUpdated=".SMBConfig::param("backup.last_timestamp"));

    if ($images->{Album}->{ImageCount} <= 0) {
        printf("%2d:  * Warning: album is empty (ImageCount == $images->{Album}->{ImageCount})\n", $tid);
    }

    return unless exists $images->{Album}->{Images}->{Image};
    $images->{Album}->{Images}->{Image} = ensure_array($images->{Album}->{Images}->{Image});

    foreach my $image (@{ $images->{Album}->{Images}->{Image} }) {
        fetch_image($image->{id}, $image->{Key}, $dir);
    }
}

our @work :shared;
sub worker {
    ($tid) = @_;

    while (1) {
        my $item;
        {
            lock @work;
            $item = pop @work or return;
        }
        process_album($item);
    }
}

################################################################################
## BEGIN MAIN
################################################################################

if (! -d SMBConfig::param("backup.directory")) {
    print "Creating backup directory '". SMBConfig::param("backup.directory") ."'\n";
    make_path SMBConfig::param("backup.directory") or
            die "Error creating directory '". SMBConfig::param("backup.directory") ."'";
}

# Build up the category unmangler
unmangle_cats();

# Get the list of albums
our $albums = smug_req("method=smugmug.albums.get");
$albums->{Albums}->{Album} = ensure_array($albums->{Albums}->{Album});

# Create a shared work list that contains the album IDs
foreach my $album (@{ $albums->{Albums}->{Album} }) {
    push @work, shared_clone $album;
}

# Fork worker threads.  Each thread will grab an album from the work list and
# perform a backup of that album.  This helps to hide the latency from multiple
# round trip communications to request image info and image files.
#
# TODO: Use threads for fetching images instead.  The current solution won't
# help when we have only one album to backup.
my @threads;
for (my $i = 0; $i < SMBConfig::param("backup.threads"); $i++) {
    push @threads, threads->create('worker', $i);
}

foreach my $thread (@threads) {
    $thread->join();
}

SMBConfig::param("backup.last_timestamp", $start_time);
SMBConfig::save();
print "\nDone -- fetched $nfetched files.\n";
