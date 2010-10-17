# ABSTRACT: Dancer::Plugin::Authorize Permissions base class and guide!

package Dancer::Plugin::Authorize::Permissions;

use strict;
use warnings;

use Dancer qw/:syntax/;

=head1 SYNOPSIS

    package Dancer::Plugin::Authorize::Permissions::MyPermissionsClass;
    use base 'Dancer::Plugin::Authorize::Permissions';
    
    # every permissions class must have subject_asa and subject_can routines
    # the following defines a custom routine for checking the user's role
    
    sub subject_asa {
        my ($self, $options, @arguments) = @_;
        my $role = shift @arguments;
        ...
    }
    
    1;

=head1 DESCRIPTION

The Dancer::Plugin::Authorize::Permissions class should be used as a base class in
your custom role-based acess control/permissions classes. When used as a base class, this
class provides instantiation and simple error handling for your classes. 

=cut

sub new {
    my $class = shift;
    my $self  = {};
    bless $self, $class;
    return $self;
}

sub credentials {
    my $self = shift;
    if (@_) {
        return session 'user' => @_;
    }
    else {
        return session('user');
    }
}

sub permissions {
    my $self = shift;
    if (@_) {
        return session 'roles' => @_;
    }
    else {
        return session('roles');
    }
}

sub errors {
    my ($self, @errors) = @_;
    my $user = session('user');
    push @{$user->{error}}, @errors; 
    return session 'user' => $user;
}

1;