# ABSTRACT: Dancer Authentication, Security and Role-Based Access Control Framework!

package Dancer::Plugin::Auth::RBAC;
use strict;
use warnings;
use Dancer qw/:syntax/;
use Dancer::Plugin;

our $settings = {};

register auth => sub { 
    $settings = plugin_setting;
    return Dancer::Plugin::Auth::RBAC->new(@_) 
};

register authd => sub {
    if ( session('user') ) {
        if ( session('user')->{id} ) {
            return true;
        }
    }
    return false;
};

=head1 SYNOPSIS

    post '/login' => sub {
        
        my $auth = auth(params->{user}, params->{pass});
        if (! $auth->errors) {
        
            if ($auth->asa('guest')) {
                ...
            }
            
            if ($auth->can('manage_accounts', 'create')) {
                ...
            }
            
        }
        else {
            print $auth->errors;
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
    $auth->errors()                 # authentication errors if any
    $auth->revoke()                 # revoke authorization (logout)
    
    return authd()                  # is the current user authorized?

The Dancer::Plugin::Auth::RBAC authentication framework relies on the
L<Dancer::Plugin::Auth::RBAC::Credentials> namespace to do the actual
authentication, and likewise relies on the
L<Dancer::Plugin::Auth::RBAC::Permissions> namespace to handle access control.
The following configuration example is based on
L<Dancer::Plugin::Auth::RBAC::Credentials::Config> and
L<Dancer::Plugin::Auth::RBAC::Permissions::Config>.  This framework also ship
with L<Dancer::Plugin::Auth::RBAC::Credentials::SQLite>,
L<Dancer::Plugin::Auth::RBAC::Credentials::MySQL>,
L<Dancer::Plugin::Auth::RBAC::Credentials::PostrgeSQL> which are arguably
easier to setup and utilize.

=head1 CONFIGURATION

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

=cut

sub new {
    my $class = shift;
    my @credentials = @_;
    
    my $credentialsClass =
    __PACKAGE__ . "::Credentials::" . $settings->{credentials}->{class};
    {
        no warnings 'redefine';
        $credentialsClass =~ s/::/\//g;
        require "$credentialsClass.pm";
        $credentialsClass =~ s/\//::/g;
    }
    
    my $self = {};
    bless $self, $class;
    
    # return $credentialsClass->new
    # unless scalar @credentials;
    
    my $user = session('user');
    
    if ($user) {
        # reset authentication errors
        $user->{error} = [];
    }
    else {
        # initialize user session object
        $user = {
            id    => undef,
            name  => undef,
            login => undef,
            roles => [],
            error => []
        };
    }
    
    session 'user' => $user;
    
    #return $credentialsClass->new->authorize($settings->{credentials}->{options}, @credentials)
    #? $self : undef;
    
    $credentialsClass->new->authorize($settings->{credentials}->{options}, @credentials);
    return $self;
}

sub asa {
    my $self = shift;
    my $permissionsClass =
    __PACKAGE__ . "::Permissions::" . $settings->{permissions}->{class};
    {
        no warnings 'redefine';
        $permissionsClass =~ s/::/\//g;
        require "$permissionsClass.pm";
        $permissionsClass =~ s/\//::/g;
    }
    return $permissionsClass->new->subject_asa($settings->{permissions}->{options}, @_);
}

sub can {
    my $self = shift;
    my $permissionsClass =
    __PACKAGE__ . "::Permissions::" . $settings->{permissions}->{class};
    {
        no warnings 'redefine';
        $permissionsClass =~ s/::/\//g;
        require "$permissionsClass.pm";
        $permissionsClass =~ s/\//::/g;
    }
    return $permissionsClass->new->subject_can($settings->{permissions}->{options}, @_);
}

sub roles {
    my $self = shift;
    if (@_) {
        my $user = session('user');
        if ($user) {
            if ($user->{id}) {
                push @{$user->{roles}}, @_;
                session 'user' => $user;
            }
        }
    }
    else {
        my $user = session('user');
        if ($user) {
            if ($user->{id}) {
                return $user->{roles};
            }
        }
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
