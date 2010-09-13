# ABSTRACT: Dancer Authentication, Security and Role-Based Access Control Framework!

package Dancer::Plugin::Authorize;
use strict;
use warnings;
use Dancer qw/:syntax/;
use Dancer::Plugin;

my  $settings = plugin_setting;

foreach my $key (keys %{ $settings }) {
    
    register $key => sub {
        
        my $credentialsClass =
        __PACKAGE__ . "::Credentials::" . $settings->{$key}->{credentials}->{class};
        {
            no warnings 'redefine';
            $credentialsClass =~ s/::/\//g;
            require "$credentialsClass.pm";
            $credentialsClass =~ s/\//::/g;
        }
        
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
        
        return $credentialsClass->new->authorize($settings->{$key}->{credentials}->{options}, @_);
        
    };
    
    register $key . '_err' => sub {
        
        return @{ session('user')->{error} };
        
    };
    
    register $key . '_asa' => sub {
        
        my $permissionsClass =
        __PACKAGE__ . "::Permissions::" . $settings->{$key}->{permissions}->{class};
        {
            no warnings 'redefine';
            $permissionsClass =~ s/::/\//g;
            require "$permissionsClass.pm";
            $permissionsClass =~ s/\//::/g;
        }
        return $permissionsClass->new->subject_asa($settings->{$key}->{permissions}->{options}, @_);
        
    };
    
    register $key . '_can' => sub {
        
        my $permissionsClass =
        __PACKAGE__ . "::Permissions::" . $settings->{$key}->{permissions}->{class};
        {
            no warnings 'redefine';
            $permissionsClass =~ s/::/\//g;
            require "$permissionsClass.pm";
            $permissionsClass =~ s/\//::/g;
        }
        return $permissionsClass->new->subject_can($settings->{$key}->{permissions}->{options}, @_);
        
    };
    
}

=head1 SYNOPSIS

    post '/login' => sub {
    
        if (auth(params->{user}, params->{pass})) {
            
            if (auth_asa('guest')) {
                ...
            }
            
            if (auth_can('manage_accounts', 'create')) {
                ...
            }
            
        }
        else {
            print auth_err;
        }
    
    };

Note! The authentication framework relies heavily on your choosen session engine,
please remember to set that appropiately in your application configuration file.

=head1 DESCRIPTION

Dancer::Plugin::Authorize is an authentication framework and role-based access control system.
As a role-based access control system Dancer::Plugin::Authorize give you the ultimate in flexibilty
and scalability.

Mainly under the Authorize plugin section in the configuration file you'll have a
keyword which defines all the authentication information needed for that particular
authentication scheme, this keyword exists solely to accomidate use-cases where
multiple authentication schemes are needed. e.g. an application may need
to authenticate different types of users differents, i.e. users may need LDAP
authentication and customers may need DBIC authentication. etc.

Dancer::Plugin::Authorize then creates the following functions using your keywords:

$keyword = 'foo';
foo() # authentication function
foo_asa($role) # check if the authenticated user has the specified role
foo_can($permission, $action) # check if the authenticated user has permission to perform a specific action
foo_err() # authentication errors 

The Dancer::Plugin::Authorize authentication framework relies on the L<Dancer::Plugin::Authorize::Credentials>
namespace to do the actual authentication, and likewise relies on the L<Dancer::Plugin::Authorize::Permissions>
namespace to handle access control.

=head1 CONFIGURATION

plugins:
  Authorize:
    auth: # keyword allows one to setup multiple authentication schemes
      credentials:
        class: Config
        options:
          ... # options are determined by the requirements of the credentials class
          ... e.g.
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
          ... # options are determined by the requirements of the permissions class
          ... e.g.
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

register_plugin;

1;
