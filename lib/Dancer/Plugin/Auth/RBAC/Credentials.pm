# ABSTRACT: Dancer::Plugin::Auth::RBAC Credentials base class and guide!

package Dancer::Plugin::Auth::RBAC::Credentials;

use strict;
use warnings;

use Dancer qw/:syntax/;

sub new {
    my ($class, %params) = @_;
    my $self  = \%params;
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

sub errors {
    my ($self, @errors) = @_;
    my $user = session('user');
    push @{$user->{error}}, @errors; 
    #return session 'user' => $user;
    session 'user' => $user;
    return @errors;
}

sub authorize {
    my ($self, $userinfo) = @_;

    my $user = $self->find_user($userinfo);
    if (!$user) {
        # XXXX
        return
    }

    if (!$self->check_password($user, $userinfo)) {
        # XXX
        return
    }

    my $session_data = $self->set_authenticated($user);
    $self->credentials($session_data);
    return 1;
}

1;

=head1 SYNOPSIS

    package Dancer::Plugin::Auth::RBAC::Credentials::MyAuthorizationClass;
    use base 'Dancer::Plugin::Auth::RBAC::Credentials';
    
    # every authentication class must have an authorize routine
    sub authorize {
        my ($self, $options, @arguments) = @_;
        my ($login, $password) = @arguments;
        ...
    }
    
    1;

=head1 DESCRIPTION

The Dancer::Plugin::Auth::RBAC::Credentials class should be used as a base class in
your custom credentials/authorization classes. When used as a base class, this
class provides instantiation and simple error handling for your authorization classes. 
