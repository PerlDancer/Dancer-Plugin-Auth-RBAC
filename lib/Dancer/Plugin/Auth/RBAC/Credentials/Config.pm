# ABSTRACT: Dancer::Plugin::Auth::RBAC authentication via the Dancer configuration file!

package Dancer::Plugin::Auth::RBAC::Credentials::Config;

use strict;
use warnings;
use Carp;
use base qw/Dancer::Plugin::Auth::RBAC::Credentials/;

sub find_user {
    my ($self, $userinfo) = @_;

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

sub check_password {
    my ($self, $user, $userinfo) = @_;
    my $key = $self->{settings}->{password_field};

    if ( $user->{$key} eq $userinfo->{$key} ) {
        return 1;
    }
    else {
        return undef;
    }
}

sub set_authenticated {
    my ($self, $user) = @_;

    return {
        id => $user->{username},
        roles => $user->{roles},
    };
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
