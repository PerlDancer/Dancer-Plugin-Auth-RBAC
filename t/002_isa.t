use strict;
use warnings;

use Test::More tests => 15, import => ['!pass'];
use Test::Exception;
use File::Temp qw/tempdir/;

BEGIN {
    use_ok 'Dancer', ':syntax';
    use_ok 'Dancer::Plugin::Auth::RBAC';
}

my $dir = tempdir(CLEANUP => 1);
set appdir => $dir;

my @settings    = <DATA>;
set session     => "YAML";
set plugins     => from_yaml("@settings");

{
    diag 'login and roles tested, no credentials supplied';
    my $auth;
    dies_ok { auth } "auth die without user informations";
    ok !defined $auth, "auth failed";
}

{
    diag 'login and roles tested, fake credentials supplied';
    my $auth = auth('foo','bar');
    ok !defined $auth, "auth failed with fake credentials";
}

{
    diag 'login and roles tested, real credentials supplied (user)';
    my $auth = auth('user01', 'foobar');
    ok 'Dancer::Plugin::Auth::RBAC' eq ref $auth, 'instance initiated';
    ok !$auth->errors, 'login successful, no errors';
    ok $auth->asa('guest'), 'is a guest';
    ok $auth->asa('user'), 'is a user';
    ok !$auth->asa('admin'), 'is not a admin';
    $auth->revoke;
}

{
    diag 'login and roles tested, real credentials supplied (admin)';
    my $auth = auth( 'user02', 'barbaz' );
    ok 'Dancer::Plugin::Auth::RBAC' eq ref $auth, 'instance initiated';
    ok !$auth->errors, 'login successful, no errors';
    ok !$auth->asa('guest'), 'is not a guest';
    ok !$auth->asa('user'),  'is not a user';
    ok $auth->asa('admin'), 'is a admin';
    $auth->revoke;
}

__END__
Auth::RBAC:
  credentials:
    class: Config
    options:
      accounts:
        user01:
          password: foobar
          roles:
            - guest
            - user
        user02:
          password: barbaz
          roles:
            - admin
  permissions:
    class: Config
    options:
      control:
        admin:
          permissions:
            manage accounts:
              operations:
                - view
                - create
                - update
                - delete
        user:
          permissions:
            manage accounts:
              operations:
                - view
                - create
        guests:
          permissions:
            manage accounts:
              operations:
                - view
