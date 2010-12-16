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
            options => {
              password_field => 'password',
            }
        },
        storer      => {
            schema     => 'schema',
            user_model => 't::lib::TestApp::Schema::User',
        }
    }
};

my $schema = t::lib::TestApp::Schema->connect($dsn);

my @users = (
    [ 1, 'franck', 's3kr3t' ],
    [ 2, 'sukria', 'sukr1a' ],
    [ 3, 'sawyer', 's4wyer' ],
);

$schema->deploy;
$schema->populate( 'Role',
    [ [ 'id', 'role' ], [ 1, 'admin' ], [ 2, 'user' ] ] );
$schema->populate( 'User', [ [ 'id', 'username', 'password' ], @users ], );
$schema->populate( 'UserRole',
    [ [ 'id', 'user', 'roleid' ], [ 1, 1, 1 ], [ 2, 2, 2 ], [ 3, 3, 2 ], ] );

$ENV{QUERY_STRING} =
  join( '&', 'username=' . $users[0]->[1], 'password=' . $users[0]->[2] );

response_status_is [ GET => "/" ], 200, "GET / is found";
response_content_like [ GET => '/' ], qr/^ok/;

done_testing;

