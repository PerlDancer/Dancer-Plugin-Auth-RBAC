# ABSTRACT: Dancer::Plugin::Auth::RBAC access control via the Dancer configuration file!

package Dancer::Plugin::Auth::RBAC::Permissions::Config;

use strict;
use warnings;
use base qw/Dancer::Plugin::Auth::RBAC::Permissions/;

sub subject_can {
    my ( $self, $operation, $action ) = @_;

    my $user  = $self->credentials;
    my $roles = $self->{settings}->{control};

    foreach my $role ( @{ $user->{roles} } ) {
        my $permissions = $self->_role_has_permissions( $roles, $role );
        next if !defined $permissions;

        return 1 if !defined $permissions->{$operation};

        my $can = $self->_can_do_operation( $permissions, $operation, $action );
        return 1 if $can;
    }
    return 0;
}

sub _role_has_permissions {
    my ( $self, $roles, $role ) = @_;

    defined $roles->{$role}->{permissions}
      ? return $roles->{$role}->{permissions}
      : return undef;
}

sub _can_do_operation {
    my ( $self, $permissions, $operation, $action ) = @_;

    return 1 if !defined $action;
    if ( defined $permissions->{$operation} ) {
        if ( my $op = $permissions->{$operation}->{operations} ) {
            return 1 if grep { $_ eq $action } @{$op};
        }
    }
    return undef;
}

sub subject_asa {
    my ($self, $role) = @_;
    my $user = $self->credentials;

    if ($role) {
        if (grep { $_ eq $role } @{$user->{roles}}) {
            return 1;
        }
    }
    
    return 0;
}

1;

=head1 SYNOPSIS

    plugins:
      Auth::RBAC:
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

=head1 DESCRIPTION

Dancer::Plugin::Auth::RBAC::Permissions::Config uses your Dancer application
configuration file as role-based access control system. 

=method subject_asa

The subject_asa method (found in every permissions class) validates whether a user
has the role defined in the supplied argument.

    return 1 if subject_asa($self, $options, $role);

=method subject_can

The subject_can method (found in every permissions class) validates whether a user
is responsible for (or is authorized to operate) a particular operation and can
perform the specified action under that operation.

    return 1 if subject_can($self, $options, $operation, $action);
