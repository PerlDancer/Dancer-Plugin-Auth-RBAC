# ABSTRACT: Dancer Authentication, Security and Role-Based Access Control Framework!

package Dancer::Plugin::Authorize;
use strict;
use warnings;
use Dancer::Plugin;

my  $settings = plugin_setting;

foreach my $keyword (keys %{ $settings }) {
    
    register $keyword => sub {
        
        my $credentialsClass =
        __PACKAGE__ . "::Credentials::" . $settings->{credentials}->{class};
        {
            no warnings 'redefine';
            require $credentialsClass;
        }
        return $credentialsClass->authorize($settings->{credentials}->{options}, @_);
        
    };
    
    register $keyword . '_asa' => sub {
        
        my $permissionsClass =
        __PACKAGE__ . "::Permissions::" . $settings->{permissions}->{class};
        {
            no warnings 'redefine';
            require $permissionsClass;
        }
        return $permissionsClass->subject_asa($settings->{permissions}->{options}, @_);
        
    };
    
    register $keyword . '_can' => sub {
        
        my $permissionsClass =
        __PACKAGE__ . "::Permissions::" . $settings->{permissions}->{class};
        {
            no warnings 'redefine';
            require $permissionsClass;
        }
        return $permissionsClass->subject_can($settings->{permissions}->{options}, @_);
        
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

};

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
