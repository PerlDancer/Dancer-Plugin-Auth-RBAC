# ABSTRACT: ...

package Dancer::Plugin::Auth::RBAC::Credentials::DBIx::Class;

use strict;
use warnings;
use Carp;
use base qw/Dancer::Plugin::Auth::RBAC::Credentials/;
use Dancer::Plugin::DBIC;

sub find_user {
    my ( $self, $userinfo ) = @_;

    # XXX key in config ?
    schema->resultset('User')->find( { username => $userinfo->{username} } );
}

sub check_password {
    my ( $self, $user, $userinfo ) = @_;
    my $key = $self->{settings}->{password_field};
    if ( $user->$key eq $userinfo->{$key} ) {
        return 1;
    }
    else {
        return undef;
    }
}

sub set_authenticated {
    my ( $self, $user ) = @_;

    return { id => $user->username, };
}

1;
