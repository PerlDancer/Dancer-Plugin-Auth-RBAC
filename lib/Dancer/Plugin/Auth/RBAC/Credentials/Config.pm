# ABSTRACT: Dancer::Plugin::Auth::RBAC authentication via the Dancer configuration file!

package Dancer::Plugin::Auth::RBAC::Credentials::Config;

use strict;
use warnings;
use Carp;
use base qw/Dancer::Plugin::Auth::RBAC::Credentials/;

sub authorize {
    my ($self, $userinfo) = @_;

    $self->_authorize($userinfo);
}

sub _authorize {
    my ($self, $userinfo) = @_;

    my $user = $self->_find_user($userinfo);
    if (!$user) {
        # XXX
    }

    $self->errors("password is invalid")
        if !$self->_check_password($user, $userinfo);

    my $session_data = {
        id => $user->{username},
        roles => $user->{roles},
    };
    $self->credentials($session_data);
    return 1;
    # if (!$login && !$password) {
    #     $self->errors('login and/or password is invalid');
    #     return undef;
    # }

    # my $accounts = $self->{settings}->{accounts};

    # # if ($accounts->{$login}->{password} eq $password) {
    # #     my $session_data = {
    # #         id    => $login,
    # #         name  => $accounts->{$login}->{name} || ucfirst($login),
    # #         login => $login,
    # #         roles => [@{$accounts->{$login}->{roles}}],
    # #         error => []
    # #     };
    # #     return $self->credentials($session_data);
    # # }
    # # $self->errors('login and/or password is invalid');
    # return undef;
}

sub _find_user {
    my ( $self, $userinfo ) = @_;

    # XXX key in config ?
    my $id = $userinfo->{username};
    if ( my $user = $self->{settings}->{accounts}->{$id} ) {
        $user->{username} = $id;
        return $user;
    }
    else {
        return undef;
    }
}

sub _check_password {
    my ( $self, $user, $userinfo ) = @_;

    my $key = $self->{settings}->{password_field};

    if ( $user->{$key} = $userinfo->{$key} ) {
        return 1;
    }
    else {
        return undef;
    }
}

1;

=head1 SYNOPSIS

    # in your app code
    my $auth = auth($login, $password);
    if ($auth) {
        # login successful
    }
    
    # use your own encryption (if the user account password is encrypted)
    my $auth = auth($login, encrypt($password));
    if ($auth) {
        # login successful
    }

=head1 DESCRIPTION

Dancer::Plugin::Auth::RBAC::Credentials::Config uses your Dancer application
configuration file as the application's user management system.

=head1 CONFIGURATION

    plugins:
      Auth::RBAC:
        credentials:
          class: Config
          options: 
            accounts:
              user01:
                name: Joe Schmoe
                password: foobar
                roles:
                  - guest
                  - user
              user02:
                name: Jacque Fock
                password: barbaz
                roles:
                  - admin

=method authorize

The authorize method (found in every authentication class) validates a user against
the defined datastore using the supplied arguments and configuration file options.

=cut
