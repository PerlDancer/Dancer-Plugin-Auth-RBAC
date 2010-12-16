use strict;
use warnings;

use File::Temp qw/tempdir/;
use Test::More import => ['!pass'];

use Dancer ':syntax';
use Dancer::Test;

use t::lib::TestApp;
use t::lib::TestApp::Schema;

my $dir = tempdir( CLEANUP => 1 );
my $dbfile = File::Spec->catfile( $dir, 'test.db' );

my $dsn = "dbi:SQLite:dbname=$dbfile";

set plugins => {
    DBIC => {
        'schema' => {
            schema_class => 't::lib::TestApp::Schema',
            dsn          => $dsn,
        }
    },
    'Auth::RBAC' => {
        credentials => {
            class => 'DBIx::Class',
        },
        storer      => {
            schema     => 'schema',
            user_model => 't::lib::TestApp::Schema::User',
        }
    }
};

my $schema = t::lib::TestApp::Schema->connect($dsn);
$schema->deploy;

response_status_is    [ GET => '/' ], 200,   "GET / is found";
response_content_like [GET => '/'], qr/^ok/;

done_testing;
