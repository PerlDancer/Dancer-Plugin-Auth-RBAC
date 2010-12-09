# ABSTRACT: Dancer::Plugin::Auth::RBAC Permissions base class and guide!

package Dancer::Plugin::Auth::RBAC::Permissions;

use strict;
use warnings;

use Dancer qw/:syntax/;

sub new {
    my $class = shift;
    my $self  = {};
    bless $self, $class;
    return $self;
}

sub credentials {
    my $self = shift;
    if (@_) {
        $self->_set_credentials(@_);
    }
    else {
        $self->_get_credentials();
    }
}

sub _get_credentials {
    my $self = shift;
    return session('user');
}

sub _set_credentials {
    my $self = shift;
    return session 'user' => @_;
}

sub permissions {
    my $self = shift;
    if (@_) {
        $self->_set_permissions(@_);
    }
    else {
        $self->_get_permissions();
    }
}

sub _set_permissions {
    my $self = shift;
    return session 'roles' => @_;
}

sub _get_permissions {
    my $self = shift;
    return session('roles');
}

sub errors {
    my ($self, @errors) = @_;
    my $user = session('user');
    push @{$user->{error}}, @errors; 
    return session 'user' => $user;
}

1;

=head1 SYNOPSIS

    package Dancer::Plugin::Auth::RBAC::Permissions::MyPermissionsClass;
    use base 'Dancer::Plugin::Auth::RBAC::Permissions';
    
    # every permissions class must have subject_asa and subject_can routines
    # the following defines a custom routine for checking the user's role
    
    sub subject_asa {
        my ($self, $options, @arguments) = @_;
        my $role = shift @arguments;
        ...
    }
    
    1;

=head1 DESCRIPTION

The Dancer::Plugin::Auth::RBAC::Permissions class should be used as a base class in
your custom role-based acess control/permissions classes. When used as a base class, this
class provides instantiation and simple error handling for your classes. 

=cut
