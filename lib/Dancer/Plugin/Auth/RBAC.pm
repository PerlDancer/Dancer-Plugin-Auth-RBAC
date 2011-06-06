# ABSTRACT: Dancer Authentication, Security and Role-Based Access Control Framework!

package Dancer::Plugin::Auth::RBAC;

use strict;
use warnings;

use Carp;

use Dancer qw/:syntax/;
use Dancer::Plugin;

register auth => sub {
    my $auth = Dancer::Plugin::Auth::RBAC->new();
    $auth->authenticate(@_);
};

register authd => sub {
    if ( session('user') ) {
        if ( session('user')->{id} ) {
            return true;
        }
    }
    return false;
};

sub new {
    my $class = shift;

    my $settings = plugin_setting;

    my $credentials_class = $class->_load_class( 'credentials', $settings );
    my $credentials = $credentials_class->new(
        settings => $settings->{credentials}->{options} );

    my $permissions_class = $class->_load_class( 'permissions', $settings );
    my $permissions = $permissions_class->new(
        settings => $settings->{permissions}->{options} );

    my $self = {
        settings    => $settings,
        credentials => $credentials,
        permissions => $permissions,
    };

    bless $self, $class;

    my $user = session('user');

    if ($user) {
        $user->{error} = [];    # reset authentications errors
    }
    else {
        $user = {
            id    => undef,
            roles => [],
        };
    }

    session 'user' => $user;

    return $self;
}

sub authenticate {
    my $self = shift;

    Carp::croak "credentials are missing" unless scalar @_;

    my ( $username, $password ) = @_;

    $self->{credentials}->authorize( $username, $password )
      ? return $self
      : return undef;
}

sub _load_class {
    my ( $class, $ns, $settings ) = @_;

    my $load_class =
      join( '::', __PACKAGE__, ucfirst($ns), $settings->{$ns}->{class} );
    Dancer::ModuleLoader->load($load_class);

    return $load_class;
}

sub asa {
    my $self = shift;
    $self->{permissions}->subject_asa($self->{user}, @_);
}

sub can {
    my $self = shift;
    $self->{permissions}->subject_can($self->{user}, @_);
}

sub roles {
    my $self = shift;

    if (@_) {
        $self->_set_roles(@_);
    }
    else {
        $self->_get_roles();
    }
}

sub _get_roles {
    my $self = shift;
    my $user = session('user');
    if ($user && $user->{id}) {
        return $user->{roles};
    }
}

sub _set_roles {
    my ($self, @roles) = @_;
    my $user = session('user');

    if ($user && $user->{id}) {
        push @{ $user->{roles} }, @roles;
        session 'user' => $user;
    }
}

sub errors {
    my $self = shift;
    return @{ session('user')->{error} };
}

sub revoke {
    my $self = shift;
    return session 'user' => {};
}

register_plugin;

1;

=head1 SYNOPSIS


    post '/login' => sub {

        my $auth =
          auth( { username => params->{user}, password => params->{pass} } );

        return "not authorized" if !$auth;

        if ( $auth->asa('guest') ) {
            ...;
        }

        if ( $auth->can( 'manage_accounts', 'create' ) ) {
            ...;
        }
    };

Note! The authentication framework relies heavily on your choosen session engine,
please remember to set that appropiately in your application configuration file.

=head1 DESCRIPTION

Dancer::Plugin::Auth::RBAC is an authentication framework and role-based
access control system. As a role-based access control system
Dancer::Plugin::Auth::RBAC can be complex but will give you the most
flexibilty over all other access control philosophies.

The Dancer::Plugin::Auth::RBAC plugin provides your application with the
ability to easily authenticate and restrict access to specific users and
groups by providing a tried and tested RBAC (role-based access control)
system. Dancer::Plugin::Auth::RBAC provides this level of sophistication with
minimal configuration.  

The Dancer::Plugin::Auth::RBAC authentication framework relies on the
L<Dancer::Plugin::Auth::RBAC::Credentials> namespace to do the actual
authentication, and likewise relies on the
L<Dancer::Plugin::Auth::RBAC::Permissions> namespace to handle access control.

=head2 METHODS

=head3 auth

    $auth = auth($login, $pass);

New authorization instance

=head3 authd

    return authd();

Is the current user authorized?

=head3 asa

    $auth->asa($role);

Check if the authenticated user has the specified role

=head3 can

    $auth->can($operation);

Check if the authenticated user has permission

    $auth->can($operation, $action)

To perform a specific action

=head3 roles

    $auth->roles(@roles);

Get or set roles for the current logged in user

=head3 revoke

    $auth->revoke();

revoke authorization (logout)

=head1 CONFIGURATION

The following configuration example is based on
L<Dancer::Plugin::Auth::RBAC::Credentials::Config> and
L<Dancer::Plugin::Auth::RBAC::Permissions::Config>.  This framework also ship
with L<Dancer::Plugin::Auth::RBAC::Credentials::SQLite>,
L<Dancer::Plugin::Auth::RBAC::Credentials::MySQL>,
L<Dancer::Plugin::Auth::RBAC::Credentials::PostrgeSQL> which are arguably
easier to setup and utilize.

    plugins:
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

