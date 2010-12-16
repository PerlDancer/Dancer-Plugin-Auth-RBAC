package Dancer::Plugin::Auth::RBAC::Credentials::DBIx::Class;

use strict;
use warnings;
use base qw/Dancer::Plugin::Auth::RBAC::Credentials/;
use Dancer::Plugin::DBIC;

sub authorize {
    my ($self, $options, $login, $password ) = @_;

    if (!$login) {
        return $self->_check_from_session($login);
    }

    return $self->_check_credentials();
}

sub _check_from_session {
    my ($self, ) = @_;
    my $user = $self->credentials;

    if ((defined $user->{id} || defined $user->{login}) && !@{$user->{error}}) {
        return $user;
    }else{
        $self->errors("you are not authorized", "your session may have ended");
        return undef;
    }
}

sub _check_credentials {
    my ($self, $login, $password) = @_;

    if (!$password) {
        $self->errors("login and password are required");
        return undef;
    }

    my $user = schema->resultset('User')->find({login => $login, password => $password});

    if (!$user) {
        $self->errors("login and/or password is invalid");
        return undef;
    }

    # XXX build session

}

1;
