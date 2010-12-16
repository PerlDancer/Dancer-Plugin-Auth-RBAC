use strict;
use warnings;
use Test::More tests => 11, import => ['!pass'];
use Test::Exception;
use File::Temp qw/tempdir/;

BEGIN {
    use_ok 'Dancer', ':syntax';
    use_ok 'Dancer::Plugin::Auth::RBAC';
}

my $dir = tempdir( CLEANUP => 1 );
set appdir => $dir;

my @settings = <DATA>;
set session => "YAML";
set plugins => from_yaml("@settings");

diag 'login without credentials';
eval { my $auth = auth(); };
like $@, qr/credentials are missing/;

diag 'login and roles tested';
my $auth = auth( { username => 'user01', password => 'foobar' } );
isa_ok $auth, 'Dancer::Plugin::Auth::RBAC';
ok $auth->asa('guest'), 'is a guest';
ok $auth->asa('user'),  'is a user';
ok !$auth->asa('admin'), 'is not a admin';
$auth->revoke;

diag 'login and roles tested, real credentials supplied (admin)';
$auth = auth( { username => 'user02', password => 'barbaz' } );
ok 'Dancer::Plugin::Auth::RBAC' eq ref $auth, 'instance initiated';
ok !$auth->asa('guest'), 'is not a guest';
ok !$auth->asa('user'),  'is not a user';
ok $auth->asa('admin'), 'is a admin';
$auth->revoke;

__END__
Auth::RBAC:
  credentials:
    class: Config
    options:
      password_field: password
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
