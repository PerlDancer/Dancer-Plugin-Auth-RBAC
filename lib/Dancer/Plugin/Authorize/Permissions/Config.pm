# ABSTRACT: Dancer::Plugin::Authorize access control via the Dancer configuration file!

package Dancer::Plugin::Authorize::Permissions::Config;

use strict;
use warnings;
use base qw/Dancer::Plugin::Authorize::Permissions/;

=head1 SYNOPSIS

    plugins:
      Authorize:
        mykeyword: 
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
                        
    # in Dancer application
    
    my $role = 'guests';
    if (mykeyword_asa($role)) {
        return 1;
    }

=head1 DESCRIPTION

Dancer::Plugin::Authorize::Permissions::Config uses your Dancer application
configuration file as role-based access control system. 

=head1 METHODS

=method subject_asa

The subject_asa method (found in every permissions class) validates whether a user
has the role defined in the supplied argument.

    return 1 if subject_asa($self, $options, $role);

=cut

sub subject_asa {
    my ($self, $options, @arguments) = @_;
    my $role = shift @arguments;
    my $user = $self->credentials;
    my $settings = $class::settings;
    
    if ($role) {
        if (grep { /$role/ } @{$user->{roles}}) {
            return 1;
        }
    }
    
    return 0;
}

=method subject_can

The subject_can method (found in every permissions class) validates whether a user
is responsible for (or is authorized to operate) a particular operation and can
perform the specified action under that operation.

    return 1 if subject_can($self, $options, $operation, $action);

=cut

sub subject_can {
    my ($self, $options, @arguments) = @_;
    my ($operation, $action) = @arguments;
    my $settings = $class::settings;
    
    my $user  = $self->credentials;
    my $roles = $options->{control};
    
    foreach my $role ( @{$user->{roles}} ) {
        
        if (defined $roles->{$role}->{permissions}) {
            
            my $permissions = $roles->{$role}->{permissions};
            if (defined $permissions->{$operation}) {
                
                if (defined $permissions->{$operation}->{operations}) {
                    
                    my $operations = $permissions->{$operation}->{operations};
                    if (grep { /$action/ } @{$operations}) {
                        
                        return 1;
                        
                    }
                    
                }
                
            }
            
        }
        
    }
    
    return 0;
}

1;