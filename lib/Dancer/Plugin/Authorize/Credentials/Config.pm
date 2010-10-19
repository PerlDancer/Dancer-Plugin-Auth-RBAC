# ABSTRACT: Dancer::Plugin::Authorize authentication via the Dancer configuration file!

package Dancer::Plugin::Authorize::Credentials::Config;

use strict;
use warnings;
use base qw/Dancer::Plugin::Authorize::Credentials/;

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

Dancer::Plugin::Authorize::Credentials::Config uses your Dancer application
configuration file as the application's user management system.

=head1 CONFIGURATION

    plugins:
      Authorize:
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

sub authorize {
    
    my ($self, $options, @arguments) = @_;
    my ($login, $password) = @arguments;
    
    my $settings = $Dancer::Plugin::Authorize::settings;
    
    if ($login) {
    
    # authorize a new account using supplied credentials
        
        my $accounts = $options->{accounts};
        
        unless ($password) {
            $self->errors('login and password are required');
            return undef;
        }
    
        if (defined $accounts->{$login}) {
            
            if (defined $accounts->{$login}->{password}) {
                
                if ($accounts->{$login}->{password} =~ /^$password$/) {
                    
                    my $session_data = {
                        id    => $login,
                        name  => $accounts->{$login}->{name} || ucfirst($login),
                        login => $login,
                        roles => [@{$accounts->{$login}->{roles}}],
                        error => []
                    };
                    return $self->credentials($session_data);
                    
                }
                else {
                    $self->errors('login and/or password is invalid');
                    return undef;
                }
                
            }
            else {
                $self->errors('attempting to access as inaccessible account');
                return undef;
            }
            
        }
        else {
            $self->errors('login and/or password is invalid');
            return undef;
        }
    
    }
    else {
        
    # check if current user session is authorized
        
        my $user = $self->credentials;
        if (($user->{id} || $user->{login}) && !@{$user->{error}}) {
            
            return $user;
            
        }
        else {
            $self->errors('you are not authorized', 'your session may have ended');
            return undef;
        }
        
    }
    
}

1;