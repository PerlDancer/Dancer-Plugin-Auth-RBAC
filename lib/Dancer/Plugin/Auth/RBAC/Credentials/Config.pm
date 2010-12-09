# ABSTRACT: Dancer::Plugin::Auth::RBAC authentication via the Dancer configuration file!

package Dancer::Plugin::Auth::RBAC::Credentials::Config;

use strict;
use warnings;
use base qw/Dancer::Plugin::Auth::RBAC::Credentials/;

sub authorize {
    my ($self, $options, $login, $password) = @_;
    
    my $settings = $Dancer::Plugin::Auth::RBAC::settings;

    if (!$login) {
        return $self->_is_user_authorized();
    }

    if (!$password) {
        $self->errors('login and password are required');
        return 0;
    }

    $self->_authorize($options, $login, $password);
}

sub _is_user_authorized {
    my $self = shift;

    # check if current user session is authorized
    my $user = $self->credentials;
    if ( ( $user->{id} || $user->{login} ) && !@{ $user->{error} } ) {
        return $user;
    }
    else {
        $self->errors( 'you are not authorized',
            'your session may have ended' );
        return 0;
    }
}

sub _authorize {
    my ($self, $options, $login, $password) = @_;

    if (!$login && !$password) {
        $self->errors('login and/or password is invalid');
        return 0;
    }

    my $accounts = $options->{accounts};

    if ($accounts->{$login}->{password} eq $password) {
        my $session_data = {
            id    => $login,
            name  => $accounts->{$login}->{name} || ucfirst($login),
            login => $login,
            roles => [@{$accounts->{$login}->{roles}}],
            error => []
        };
        return $self->credentials($session_data);
    }
    $self->errors('login and/or password is invalid');
    return 0;
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
