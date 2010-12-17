# ABSTRACT: Dancer Authentication, Security and Role-Based Access Control Framework!

package Dancer::Plugin::Auth::RBAC;
use strict;
use warnings;
use Carp;
use Dancer qw/:syntax/;
use Dancer::Plugin;
use Dancer::ModuleLoader;

register auth => sub {
    return Dancer::Plugin::Auth::RBAC->new(@_) 
};

register authd => sub {
    if ( session('user') && session('user')->{id}) {
        return true;
    }
    return false;
};

sub new {
    my ($class, $userinfo) = @_;

    Carp::croak "credentials are missing" unless $userinfo;
    
    my $settings = plugin_setting;
    my $self = { settings => $settings, };

    bless $self, $class;

    my $credentials_class = $self->_load_class('credentials');

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

    $credentials_class->new(
        settings => $self->{settings}->{credentials}->{options} )
      ->authorize($userinfo) ? return $self : return undef;
}

sub _load_class {
    my ( $self, $ns ) = @_;

    my $class =
      join( '::', __PACKAGE__, ucfirst($ns),
        $self->{settings}->{$ns}->{class} );
    Dancer::ModuleLoader->load($class);

    return $class;
}

sub asa {
    my $self = shift;

    my $class = $self->_load_class('permissions');

    return $class->new(
        settings => $self->{settings}->{permissions}->{options} )
      ->subject_asa(@_);
}

sub can {
    my $self = shift;

    my $class = $self->_load_class('permissions');
    return $class->new(
        settings => $self->{settings}->{permissions}->{options} )
      ->subject_can(@_);
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
        my $auth = auth({username => params->{user}, password => params->{pass}});
        if (!$auth) {
           return "not authorized";
        }else{
            if ($auth->asa('guest')) {
                ...
            }
            
            if ($auth->can('manage_accounts', 'create')) {
                ...
            }
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

Dancer::Plugin::Auth::RBAC exports the auth() and authd() keywords:

    $auth = auth($login, $pass)     # new authorization instance
    $auth->asa($role)               # check if the authenticated user has the specified role
    $auth->can($operation)          # check if the authenticated user has permission
    $auth->can($operation, $action) # to perform a specific action
    $auth->roles(@roles)            # get or set roles for the current logged in user
    $auth->revoke()                 # revoke authorization (logout)
    
    return authd()                  # is the current user authorized?

The Dancer::Plugin::Auth::RBAC authentication framework relies on the
L<Dancer::Plugin::Auth::RBAC::Credentials> namespace to do the actual
authentication, and likewise relies on the
L<Dancer::Plugin::Auth::RBAC::Permissions> namespace to handle access control.
The following configuration example is based on
L<Dancer::Plugin::Auth::RBAC::Credentials::Config> and
L<Dancer::Plugin::Auth::RBAC::Permissions::Config>.

=head1 CONFIGURATION

    plugins:
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

