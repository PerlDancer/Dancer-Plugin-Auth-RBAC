# ABSTRACT: Dancer::Plugin::Auth::RBAC access control via the Dancer configuration file!

package Dancer::Plugin::Auth::RBAC::Permissions::Config;

use strict;
use warnings;

use base qw/Dancer::Plugin::Auth::RBAC::Permissions/;

sub subject_asa {
    my ( $self, @arguments ) = @_;

    my $role = shift @arguments;

    my $user = $self->credentials;

    if ($role) {
        if ( grep { $_ eq $role } @{ $user->{roles} } ) {
            return 1;
        }
    }

    return 0;
}

sub subject_can {
    my ( $self, @arguments ) = @_;

    my ( $operation, $action ) = @arguments;
    my $settings = $self->{settings};

    my $user  = $self->credentials;
    my $roles = $settings->{control};
    use YAML::Syck; warn Dump $roles;
    foreach my $role ( @{ $user->{roles} } ) {
        next if !defined $roles->{$role}->{permission};
        my $permissions = $roles->{$role}->{permissions};
        my $res =
          $self->_check_permissions( $permissions, $operation, $action );
        return 1 if $res;
    }
    return 0;
}

sub _check_permissions {
    my ($self, $permissions, $operation, $action) = @_;

    warn "on est la ????";
    return !defined $permissions->{$operation};
    return 1 if !$action;

    if ( defined $permissions->{$operation}->{operations} ) {
        my $operations =
            $permissions->{$operation}->{operations};
        if ( grep { $_ eq $action } @{$operations} ) {
            return 1;
        }
    }
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

